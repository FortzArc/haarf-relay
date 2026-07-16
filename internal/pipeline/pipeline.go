// Package pipeline wires input lines through parse → redact → enrich →
// emit, and owns per-run bookkeeping: event IDs, provenance stamping,
// quarantine routing, and counters.
package pipeline

import (
	"crypto/rand"
	"fmt"

	"github.com/oklog/ulid/v2"

	"github.com/FortzArc/haarf-relay/internal/emit"
	"github.com/FortzArc/haarf-relay/internal/enrich"
	"github.com/FortzArc/haarf-relay/internal/metrics"
	"github.com/FortzArc/haarf-relay/internal/parse"
	"github.com/FortzArc/haarf-relay/internal/redact"
)

// Quarantiner spools an unforwardable line. Implemented by
// quarantine.Writer; kept as a local interface so tests can capture.
type Quarantiner interface {
	Write(reason string, line []byte) error
}

// Options configures a pipeline run.
type Options struct {
	// IDFunc mints event IDs. Defaults to random ULIDs; tests inject a
	// deterministic sequence so golden output is byte-stable.
	IDFunc func() string
	// RelayVersion / SchemaVersion are stamped into every event's
	// hc_agent.relay.* provenance fields.
	RelayVersion  string
	SchemaVersion string
	// Redactor applies the allowlist policy. Required: a pipeline without
	// redaction must be impossible to construct by accident.
	Redactor *redact.Redactor
	// Quarantine receives lines that failed parsing or redaction. When nil
	// the line is counted as dropped instead — never emitted, never spooled
	// in plaintext.
	Quarantine Quarantiner
	// Enricher attaches HAARF requirement IDs and evaluates watch rules.
	// Optional: a nil enricher emits events with empty requirement IDs.
	Enricher *enrich.Enricher
	// Metrics receives safety and health counters. Optional.
	Metrics *metrics.Registry
}

// Stats counts a run's outcomes. An unparsed line is one no parser claimed;
// parse errors and redact errors are quarantined (or dropped when no
// quarantine is configured — QuarantineDropped).
type Stats struct {
	Parsed            map[string]int // by parser name
	Unparsed          int
	ParseErrors       int
	RedactErrors      int
	Quarantined       int
	QuarantineDropped int
	FieldsDropped     int            // residual keys removed by the allowlist
	Redactions        map[string]int // by scrubber name
	EnrichMiss        int            // events no mapping rule matched
	Emitted           int
}

type Pipeline struct {
	reg   *parse.Registry
	out   emit.Emitter
	opts  Options
	stats Stats
}

func New(reg *parse.Registry, out emit.Emitter, opts Options) *Pipeline {
	if opts.IDFunc == nil {
		opts.IDFunc = func() string {
			return ulid.MustNew(ulid.Now(), rand.Reader).String()
		}
	}
	if opts.Redactor == nil {
		opts.Redactor = redact.NewRedactor(redact.DefaultPolicy())
	}
	return &Pipeline{
		reg:  reg,
		out:  out,
		opts: opts,
		stats: Stats{
			Parsed:     make(map[string]int),
			Redactions: make(map[string]int),
		},
	}
}

// Process runs one line through the pipeline. Unparsed lines are counted;
// parse and redact failures quarantine the line (fail-closed). Only emit and
// quarantine-write failures propagate: a destination that cannot accept
// events must back-pressure the input, and a quarantine that cannot spool
// must stop the pipeline rather than leak or lose the event.
func (p *Pipeline) Process(line []byte) error {
	parser := p.reg.Match(line)
	if parser == nil {
		p.stats.Unparsed++
		return nil
	}
	ev, err := parser.Parse(line)
	if err != nil {
		p.stats.ParseErrors++
		if m := p.opts.Metrics; m != nil {
			m.ParseIncomplete()
			m.Quarantined("parse_error")
		}
		return p.quarantine("parse_error: "+err.Error(), line)
	}
	p.stats.Parsed[parser.Name()]++

	res, err := p.opts.Redactor.Redact(ev)
	for name, n := range res.Redactions {
		p.stats.Redactions[name] += n
	}
	p.stats.FieldsDropped += res.Dropped
	if err != nil {
		p.stats.RedactErrors++
		if m := p.opts.Metrics; m != nil {
			m.Quarantined("redact_error")
		}
		return p.quarantine("redact_error: "+err.Error(), line)
	}

	if p.opts.Enricher != nil {
		eres := p.opts.Enricher.Enrich(ev)
		if eres.Miss {
			p.stats.EnrichMiss++
			if m := p.opts.Metrics; m != nil {
				m.EnrichMiss()
			}
		}
		if m := p.opts.Metrics; m != nil {
			m.Watch(eres.Watch)
		}
	}

	if ev.EventID == "" {
		ev.EventID = p.opts.IDFunc()
	}
	ev.RelayVersion = p.opts.RelayVersion
	ev.SchemaVersion = p.opts.SchemaVersion

	if err := p.out.Emit(ev); err != nil {
		return fmt.Errorf("emit: %w", err)
	}
	p.stats.Emitted++
	if m := p.opts.Metrics; m != nil {
		m.EventEmitted(ev.SourceFormat, ev.PolicyDecision, ev.PolicyLayer, ev.Raw)
	}
	return nil
}

func (p *Pipeline) quarantine(reason string, line []byte) error {
	if p.opts.Quarantine == nil {
		p.stats.QuarantineDropped++
		return nil
	}
	if err := p.opts.Quarantine.Write(reason, line); err != nil {
		return fmt.Errorf("quarantine: %w", err)
	}
	p.stats.Quarantined++
	return nil
}

// Close flushes the output and returns final stats.
func (p *Pipeline) Close() (Stats, error) {
	return p.stats, p.out.Flush()
}
