// Package pipeline wires input lines through parse → (redact → enrich, M2/M3)
// → emit, and owns per-run bookkeeping: event IDs, provenance stamping, and
// counters.
package pipeline

import (
	"crypto/rand"
	"fmt"

	"github.com/oklog/ulid/v2"

	"github.com/FortzArc/haarf-relay/internal/emit"
	"github.com/FortzArc/haarf-relay/internal/parse"
)

// Options configures a pipeline run.
type Options struct {
	// IDFunc mints event IDs. Defaults to random ULIDs; tests inject a
	// deterministic sequence so golden output is byte-stable.
	IDFunc func() string
	// RelayVersion / SchemaVersion are stamped into every event's
	// hc_agent.relay.* provenance fields.
	RelayVersion  string
	SchemaVersion string
}

// Stats counts a run's outcomes. An unparsed line is one no parser claimed;
// a parse error is a claimed line the parser rejected (quarantine, from M2).
type Stats struct {
	Parsed      map[string]int // by parser name
	Unparsed    int
	ParseErrors int
	Emitted     int
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
	return &Pipeline{
		reg:   reg,
		out:   out,
		opts:  opts,
		stats: Stats{Parsed: make(map[string]int)},
	}
}

// Process runs one line through the pipeline. Unparsed lines and parse
// errors are counted, not fatal; only emit failures propagate, because a
// destination that cannot accept events must back-pressure the input.
func (p *Pipeline) Process(line []byte) error {
	parser := p.reg.Match(line)
	if parser == nil {
		p.stats.Unparsed++
		return nil
	}
	ev, err := parser.Parse(line)
	if err != nil {
		p.stats.ParseErrors++
		return nil
	}
	p.stats.Parsed[parser.Name()]++

	if ev.EventID == "" {
		ev.EventID = p.opts.IDFunc()
	}
	ev.RelayVersion = p.opts.RelayVersion
	ev.SchemaVersion = p.opts.SchemaVersion

	if err := p.out.Emit(ev); err != nil {
		return fmt.Errorf("emit: %w", err)
	}
	p.stats.Emitted++
	return nil
}

// Close flushes the output and returns final stats.
func (p *Pipeline) Close() (Stats, error) {
	return p.stats, p.out.Flush()
}
