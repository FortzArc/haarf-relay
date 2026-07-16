// Package enrich attaches HAARF requirement IDs to canonical events and
// evaluates safety watch rules, both driven by a mapping data file
// (mappings/haarf_map.json) — never by code. When HAARF publishes a new
// requirement revision, users update the JSON file; no binary release.
//
// Condition grammar (the value side of a "when" entry):
//
//	"execute_tool"   exact match
//	"RT-1|RT-3"      any-of set
//	"!read_a|read_b" field must be present AND not in the set
//	"*"              field must be present (non-empty)
//
// A literal "|", "!" or "*" inside a matched value is not supported in this
// version of the grammar.
package enrich

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/FortzArc/haarf-relay/internal/event"
)

//go:embed default_map.json
var defaultMapJSON []byte

// Rule attaches requirement IDs to every event its conditions match.
type Rule struct {
	When   map[string]string `json:"when"`
	Attach []string          `json:"attach"`
}

// WatchRule increments a named safety counter (exposed on /metrics) for
// every event its conditions match. This is how deployment-specific policy
// knowledge — e.g. which tools are unauthorized for which scenario — enters
// the relay as data.
type WatchRule struct {
	Metric string            `json:"metric"`
	When   map[string]string `json:"when"`
}

// Mapping is the parsed haarf_map.json.
type Mapping struct {
	Version string      `json:"version"`
	Rules   []Rule      `json:"rules"`
	Watch   []WatchRule `json:"watch"`
}

// metricName is the Prometheus metric-name charset; watch rules feed metric
// names into the exposition endpoint, so they are validated at load time.
var metricName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func validate(m *Mapping) error {
	if m.Version == "" {
		return fmt.Errorf("mapping: missing version")
	}
	for i, r := range m.Rules {
		if len(r.When) == 0 {
			return fmt.Errorf("mapping: rules[%d]: empty when clause", i)
		}
		if len(r.Attach) == 0 {
			return fmt.Errorf("mapping: rules[%d]: empty attach list", i)
		}
	}
	for i, w := range m.Watch {
		if !metricName.MatchString(w.Metric) {
			return fmt.Errorf("mapping: watch[%d]: invalid metric name %q", i, w.Metric)
		}
		if len(w.When) == 0 {
			return fmt.Errorf("mapping: watch[%d]: empty when clause", i)
		}
	}
	return nil
}

func parseMapping(data []byte) (*Mapping, error) {
	var m Mapping
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("mapping: invalid JSON: %w", err)
	}
	if err := validate(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// DefaultMapping returns the embedded mapping, byte-identical to the
// repository's mappings/haarf_map.json (enforced by test).
func DefaultMapping() *Mapping {
	m, err := parseMapping(defaultMapJSON)
	if err != nil {
		panic("enrich: embedded default_map.json is invalid: " + err.Error())
	}
	return m
}

// LoadMapping reads and validates a mapping file.
func LoadMapping(path string) (*Mapping, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mapping: %w", err)
	}
	m, err := parseMapping(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// WatchMetrics returns the distinct metric names the mapping can increment,
// in first-appearance order, so the metrics registry can pre-register them —
// a zero must be scrapeable as a zero, not as an absent series.
func (m *Mapping) WatchMetrics() []string {
	seen := make(map[string]struct{}, len(m.Watch))
	var names []string
	for _, w := range m.Watch {
		if _, ok := seen[w.Metric]; !ok {
			seen[w.Metric] = struct{}{}
			names = append(names, w.Metric)
		}
	}
	return names
}

// Result reports what one Enrich call did.
type Result struct {
	// Miss is true when no rule matched: the event went out with empty
	// requirement IDs — a visible coverage gap, never a silent one.
	Miss bool
	// Watch lists the watch metrics fired by this event, one entry per
	// matching watch rule.
	Watch []string
}

// Enricher applies a mapping to events. It is stateless and safe for
// sequential pipeline use.
type Enricher struct {
	m *Mapping
}

func New(m *Mapping) *Enricher { return &Enricher{m: m} }

// Version returns the mapping version stamped into events.
func (e *Enricher) Version() string { return e.m.Version }

// Enrich attaches requirement IDs from all matching rules (union, rule
// order, deduplicated), stamps the mapping version, and evaluates watch
// rules.
func (e *Enricher) Enrich(ev *event.CanonicalEvent) Result {
	ev.MappingVersion = e.m.Version

	var res Result
	matched := 0
	seen := make(map[string]struct{})
	for _, r := range e.m.Rules {
		if !matches(ev, r.When) {
			continue
		}
		matched++
		for _, id := range r.Attach {
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				ev.RequirementIDs = append(ev.RequirementIDs, id)
			}
		}
	}
	res.Miss = matched == 0

	for _, w := range e.m.Watch {
		if matches(ev, w.When) {
			res.Watch = append(res.Watch, w.Metric)
		}
	}
	return res
}

func matches(ev *event.CanonicalEvent, when map[string]string) bool {
	for key, cond := range when {
		if !matchCond(lookup(ev, key), cond) {
			return false
		}
	}
	return true
}

func matchCond(val, cond string) bool {
	switch {
	case cond == "*":
		return val != ""
	case strings.HasPrefix(cond, "!"):
		return val != "" && !inSet(val, cond[1:])
	default:
		return inSet(val, cond)
	}
}

func inSet(val, set string) bool {
	for _, alt := range strings.Split(set, "|") {
		if val == alt {
			return true
		}
	}
	return false
}

// lookup resolves a dotted wire-format key against the event: struct-owned
// keys map to their fields; anything else falls through to the residual Raw
// map (string values only — a condition never matches structured values).
func lookup(ev *event.CanonicalEvent, key string) string {
	switch key {
	case "gen_ai.operation.name":
		return ev.Operation
	case "gen_ai.request.model":
		return ev.Model
	case "gen_ai.provider.name":
		return ev.Provider
	case "gen_ai.tool.name":
		return ev.ToolName
	case "hc_agent.policy.decision":
		return ev.PolicyDecision
	case "hc_agent.policy.layer":
		return ev.PolicyLayer
	case "hc_agent.autonomy.level":
		return ev.AutonomyLevel
	case "hc_agent.oversight.mode":
		return ev.OversightMode
	case "hc_agent.relay.source_format":
		return ev.SourceFormat
	default:
		if s, ok := ev.Raw[key].(string); ok {
			return s
		}
		return ""
	}
}
