package redact

import (
	"fmt"
	"strings"

	"github.com/FortzArc/haarf-relay/internal/event"
)

// Redactor applies the allowlist-first policy to a CanonicalEvent:
// unknown residual keys are dropped, string values of allowed keys are run
// through the scrubber chain, and structured values under allowed keys are
// an error (they cannot be deterministically scrubbed) — the caller must
// quarantine the event, never forward it.
type Redactor struct {
	allowExact  map[string]struct{}
	allowPrefix []string
	scrubbers   []Scrubber
}

// Result reports what one Redact call did.
type Result struct {
	Redactions map[string]int // by scrubber name; only non-zero entries
	Dropped    int            // residual keys removed by the allowlist
}

func NewRedactor(p *Policy) *Redactor {
	r := &Redactor{
		allowExact: make(map[string]struct{}, len(p.Allow)),
		scrubbers:  scrubberChain(p.Scrubbers),
	}
	for _, pat := range p.Allow {
		if prefix, ok := strings.CutSuffix(pat, ".*"); ok {
			r.allowPrefix = append(r.allowPrefix, prefix+".")
		} else {
			r.allowExact[pat] = struct{}{}
		}
	}
	return r
}

func (r *Redactor) allowed(key string) bool {
	if _, ok := r.allowExact[key]; ok {
		return true
	}
	for _, p := range r.allowPrefix {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// Redact mutates ev in place. On error the event is unsafe to emit.
func (r *Redactor) Redact(ev *event.CanonicalEvent) (Result, error) {
	res := Result{Redactions: make(map[string]int)}

	// Free-form struct fields that originate in source logs are scrubbed;
	// parser-controlled enums (Operation, PolicyDecision, PolicyLayer) and
	// relay-minted values (EventID, hashes, provenance) are not source text.
	ev.Model = r.scrubInto(ev.Model, &res)
	ev.Provider = r.scrubInto(ev.Provider, &res)
	ev.ToolName = r.scrubInto(ev.ToolName, &res)
	ev.AutonomyLevel = r.scrubInto(ev.AutonomyLevel, &res)
	ev.OversightMode = r.scrubInto(ev.OversightMode, &res)

	for k, v := range ev.Raw {
		if !r.allowed(k) {
			delete(ev.Raw, k)
			res.Dropped++
			continue
		}
		switch val := v.(type) {
		case string:
			ev.Raw[k] = r.scrubInto(val, &res)
		case float64, int, int64, bool, nil:
			// scalar, nothing to scrub
		default:
			// Nested object/array under an allowed key: no deterministic
			// scrub is possible. Fail closed.
			return res, fmt.Errorf("unredactable structured value under allowed key %q (%T)", k, v)
		}
	}

	for _, n := range res.Redactions {
		ev.PHIRedactions += n
	}
	return res, nil
}

func (r *Redactor) scrubInto(s string, res *Result) string {
	if s == "" {
		return s
	}
	for _, sc := range r.scrubbers {
		var n int
		s, n = sc.Scrub(s)
		if n > 0 {
			res.Redactions[sc.Name()] += n
		}
	}
	return s
}
