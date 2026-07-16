// Package metrics maintains the relay's safety and health counters and
// renders them in the Prometheus text exposition format on /metrics.
//
// It is hand-rolled rather than importing prometheus/client_golang: the
// metric set is small and fixed, and a compliance-evidence tool wants the
// smallest reviewable dependency tree it can get (§7 of the design doc —
// the SBOM is part of the product).
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Raw-map keys (set by the haarf_audit parser, allowlisted by the default
// redaction policy) from which trial coverage is tracked.
const (
	KeyScenario  = "hc_agent.haarf.scenario_id"
	KeyCondition = "hc_agent.haarf.condition"
	KeyTrialID   = "hc_agent.haarf.trial_id"
)

// Registry accumulates counters for one relay process. All methods are
// safe for concurrent use: the pipeline writes while the HTTP endpoint
// renders.
type Registry struct {
	mu sync.Mutex

	build map[string]string // label → value, rendered as relay_build_info

	events     map[[3]string]uint64 // format, decision, layer
	redactions map[string]uint64    // scrubber
	quarantine map[string]uint64    // reason class
	watch      map[string]uint64    // safety counters from mapping watch rules
	watchOrder []string
	enrichMiss uint64

	// Audit completeness: complete = events that parsed with every
	// mandatory field; total additionally counts lines a parser claimed
	// but could not fully parse. tc_ratio = complete / total.
	tcComplete uint64
	tcTotal    uint64

	// Distinct trials seen, per (scenario, condition). The gauge is the
	// relay-side half of evidence-gap detection: the expected trial count
	// lives with the operator (or the conformance suite), the observed
	// count lives here.
	trials map[[2]string]map[string]struct{}
}

// New creates a registry. buildLabels become relay_build_info labels;
// watchNames pre-registers safety counters at zero so "no unsafe events"
// is a scrapeable fact, not an absent series.
func New(buildLabels map[string]string, watchNames []string) *Registry {
	r := &Registry{
		build:      buildLabels,
		events:     make(map[[3]string]uint64),
		redactions: make(map[string]uint64),
		quarantine: make(map[string]uint64),
		watch:      make(map[string]uint64),
		trials:     make(map[[2]string]map[string]struct{}),
	}
	for _, n := range watchNames {
		if _, ok := r.watch[n]; !ok {
			r.watch[n] = 0
			r.watchOrder = append(r.watchOrder, n)
		}
	}
	return r
}

// EventEmitted records one event that made it through the pipeline.
// raw is the event's residual field map (for trial coverage tracking).
func (r *Registry) EventEmitted(format, decision, layer string, raw map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events[[3]string{format, decision, layer}]++
	r.tcComplete++
	r.tcTotal++

	scenario, _ := raw[KeyScenario].(string)
	condition, _ := raw[KeyCondition].(string)
	trial, _ := raw[KeyTrialID].(string)
	if scenario != "" && trial != "" {
		key := [2]string{scenario, condition}
		if r.trials[key] == nil {
			r.trials[key] = make(map[string]struct{})
		}
		r.trials[key][trial] = struct{}{}
	}
}

// ParseIncomplete records a line a parser claimed but could not fully
// parse — evidence existed and was not complete, so it lowers tc_ratio.
func (r *Registry) ParseIncomplete() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tcTotal++
}

// Redactions adds per-scrubber redaction counts.
func (r *Registry) Redactions(byScrubber map[string]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, n := range byScrubber {
		r.redactions[name] += uint64(n)
	}
}

// Quarantined records a fail-closed event by reason class
// ("parse_error" | "redact_error").
func (r *Registry) Quarantined(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.quarantine[reason]++
}

// EnrichMiss records an event no mapping rule matched.
func (r *Registry) EnrichMiss() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enrichMiss++
}

// Watch increments the named safety counters fired by one event.
func (r *Registry) Watch(names []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range names {
		if _, ok := r.watch[n]; !ok {
			r.watchOrder = append(r.watchOrder, n)
		}
		r.watch[n]++
	}
}

// Handler serves the Prometheus text exposition.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Write(r.Render())
	})
}

// Render produces the exposition deterministically (sorted label sets) so
// dumps are diffable.
func (r *Registry) Render() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder

	if len(r.build) > 0 {
		keys := sortedKeys(r.build)
		var lbl []string
		for _, k := range keys {
			lbl = append(lbl, fmt.Sprintf("%s=%q", k, r.build[k]))
		}
		fmt.Fprintf(&b, "# HELP relay_build_info Relay provenance: the exact version, schema, and mapping that produced this evidence.\n")
		fmt.Fprintf(&b, "# TYPE relay_build_info gauge\n")
		fmt.Fprintf(&b, "relay_build_info{%s} 1\n", strings.Join(lbl, ","))
	}

	fmt.Fprintf(&b, "# HELP haarf_events_total Events emitted, by source format and policy outcome.\n")
	fmt.Fprintf(&b, "# TYPE haarf_events_total counter\n")
	for _, k := range sorted3(r.events) {
		fmt.Fprintf(&b, "haarf_events_total{decision=%q,format=%q,layer=%q} %d\n",
			k[1], k[0], k[2], r.events[k])
	}

	// Safety counters from mapping watch rules, in mapping order.
	help := map[string]string{
		"haarf_uta_total":  "Unauthorized tool attempts (denied by RBAC) — the leading indicator.",
		"haarf_utsr_total": "Unauthorized tool executions observed — any nonzero value is a page.",
		"haarf_cmr_total":  "Contraindication misses observed.",
		"haarf_pisr_total": "Policy-injection successes observed.",
	}
	for _, name := range r.watchOrder {
		if h, ok := help[name]; ok {
			fmt.Fprintf(&b, "# HELP %s %s\n", name, h)
		}
		fmt.Fprintf(&b, "# TYPE %s counter\n", name)
		fmt.Fprintf(&b, "%s %d\n", name, r.watch[name])
	}

	fmt.Fprintf(&b, "# HELP haarf_enrich_miss_total Events no mapping rule matched (requirement-coverage gaps).\n")
	fmt.Fprintf(&b, "# TYPE haarf_enrich_miss_total counter\n")
	fmt.Fprintf(&b, "haarf_enrich_miss_total %d\n", r.enrichMiss)

	fmt.Fprintf(&b, "# HELP haarf_phi_redactions_total Values scrubbed from allowed fields, by scrubber.\n")
	fmt.Fprintf(&b, "# TYPE haarf_phi_redactions_total counter\n")
	for _, k := range sortedKeysU(r.redactions) {
		fmt.Fprintf(&b, "haarf_phi_redactions_total{scrubber=%q} %d\n", k, r.redactions[k])
	}

	fmt.Fprintf(&b, "# HELP relay_quarantine_total Fail-closed events, by reason.\n")
	fmt.Fprintf(&b, "# TYPE relay_quarantine_total counter\n")
	for _, k := range sortedKeysU(r.quarantine) {
		fmt.Fprintf(&b, "relay_quarantine_total{reason=%q} %d\n", k, r.quarantine[k])
	}

	fmt.Fprintf(&b, "# HELP haarf_tc_complete_total Events parsed with all mandatory audit fields.\n")
	fmt.Fprintf(&b, "# TYPE haarf_tc_complete_total counter\n")
	fmt.Fprintf(&b, "haarf_tc_complete_total %d\n", r.tcComplete)
	fmt.Fprintf(&b, "# HELP haarf_tc_events_total Events claimed by a parser (complete or not).\n")
	fmt.Fprintf(&b, "# TYPE haarf_tc_events_total counter\n")
	fmt.Fprintf(&b, "haarf_tc_events_total %d\n", r.tcTotal)
	if r.tcTotal > 0 {
		fmt.Fprintf(&b, "# HELP haarf_tc_ratio Audit completeness: complete events / claimed events.\n")
		fmt.Fprintf(&b, "# TYPE haarf_tc_ratio gauge\n")
		fmt.Fprintf(&b, "haarf_tc_ratio %g\n", float64(r.tcComplete)/float64(r.tcTotal))
	}

	fmt.Fprintf(&b, "# HELP haarf_trials_observed Distinct trials that produced at least one audit event, per scenario and condition.\n")
	fmt.Fprintf(&b, "# TYPE haarf_trials_observed gauge\n")
	for _, k := range sorted2(r.trials) {
		fmt.Fprintf(&b, "haarf_trials_observed{condition=%q,scenario=%q} %d\n",
			k[1], k[0], len(r.trials[k]))
	}

	return []byte(b.String())
}

func escape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s // %q adds quote escaping
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysU(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sorted3(m map[[3]string]uint64) [][3]string {
	keys := make([][3]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		if a[1] != b[1] {
			return a[1] < b[1]
		}
		return a[2] < b[2]
	})
	return keys
}

func sorted2(m map[[2]string]map[string]struct{}) [][2]string {
	keys := make([][2]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		return a[1] < b[1]
	})
	return keys
}
