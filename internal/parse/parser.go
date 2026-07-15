// Package parse holds the parser registry and the format parsers that turn
// raw log lines into CanonicalEvents.
package parse

import (
	"github.com/FortzArc/haarf-relay/internal/event"
)

// Parser converts one log format into CanonicalEvents. Implementations are
// registered in priority order; the first Sniff match owns the line.
type Parser interface {
	// Name is the stable format identifier, e.g. "haarf_audit". It is
	// stamped into hc_agent.relay.source_format on every event.
	Name() string
	// Sniff is a cheap structural check. It must not allocate on a miss:
	// in mixed pipelines the dominant cost is Sniff on non-matching lines.
	Sniff(line []byte) bool
	// Parse produces a CanonicalEvent from a line Sniff accepted. Errors
	// route the line to quarantine, never to an output.
	Parse(line []byte) (*event.CanonicalEvent, error)
}

// Registry holds parsers in priority order.
type Registry struct {
	parsers []Parser
}

func NewRegistry(parsers ...Parser) *Registry {
	return &Registry{parsers: parsers}
}

// Match returns the first parser whose Sniff accepts the line, or nil if no
// parser claims it.
func (r *Registry) Match(line []byte) Parser {
	for _, p := range r.parsers {
		if p.Sniff(line) {
			return p
		}
	}
	return nil
}
