package redact

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/FortzArc/haarf-relay/internal/event"
)

func testEvent() *event.CanonicalEvent {
	return &event.CanonicalEvent{
		Model:          "gemini-2.5-flash",
		ToolName:       "order_imaging",
		PolicyDecision: "allow",
		Raw: map[string]any{
			"hc_agent.haarf.trial_id":    "RT-1_baseline_0",
			"hc_agent.haarf.scenario_id": "RT-1",
			"hc_agent.haarf.condition":   "baseline",
			"hc_agent.tool.args_hash":    "d55677b9e3366c4c",
		},
	}
}

func TestRedactorAllowlist(t *testing.T) {
	r := NewRedactor(DefaultPolicy())
	ev := testEvent()
	ev.Raw["hc_agent.haarf.tool_args"] = map[string]any{"mrn": "SYN-001"}
	ev.Raw["hc_agent.haarf.note"] = "patient Maribel Quintanilla"
	ev.Raw["totally.unknown"] = "SSN: 987-65-4320"

	res, err := r.Redact(ev)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if res.Dropped != 3 {
		t.Errorf("Dropped = %d, want 3", res.Dropped)
	}
	for _, k := range []string{"hc_agent.haarf.tool_args", "hc_agent.haarf.note", "totally.unknown"} {
		if _, ok := ev.Raw[k]; ok {
			t.Errorf("unknown key %q survived the allowlist", k)
		}
	}
	for _, k := range []string{"hc_agent.haarf.trial_id", "hc_agent.tool.args_hash"} {
		if _, ok := ev.Raw[k]; !ok {
			t.Errorf("allowed key %q was dropped", k)
		}
	}
}

func TestRedactorScrubsAllowedValues(t *testing.T) {
	r := NewRedactor(DefaultPolicy())
	ev := testEvent()
	ev.ToolName = "order_imaging for Maribel Quintanilla"
	ev.Raw["hc_agent.haarf.condition"] = "baseline per Thaddeus Okonkwo-Bright"

	res, err := r.Redact(ev)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(ev.ToolName, "Maribel") {
		t.Errorf("ToolName not scrubbed: %q", ev.ToolName)
	}
	if s := ev.Raw["hc_agent.haarf.condition"].(string); strings.Contains(s, "Thaddeus") {
		t.Errorf("allowed residual not scrubbed: %q", s)
	}
	if res.Redactions["person_name"] != 2 {
		t.Errorf("Redactions[person_name] = %d, want 2", res.Redactions["person_name"])
	}
	if ev.PHIRedactions != 2 {
		t.Errorf("PHIRedactions = %d, want 2", ev.PHIRedactions)
	}
}

func TestRedactorFailsClosedOnStructuredAllowedValue(t *testing.T) {
	r := NewRedactor(DefaultPolicy())
	ev := testEvent()
	// An allowed key holding a nested structure cannot be deterministically
	// scrubbed — the event must be rejected, not partially emitted.
	ev.Raw["hc_agent.haarf.condition"] = map[string]any{"injected": "Maribel Quintanilla"}

	if _, err := r.Redact(ev); err == nil {
		t.Fatal("Redact accepted a structured value under an allowed key")
	}
}

func TestScalarResidualsSurvive(t *testing.T) {
	r := NewRedactor(&Policy{
		Mode: "allowlist", OnError: "quarantine",
		Allow:     []string{"num", "flag", "none"},
		Scrubbers: []string{"ssn"},
	})
	ev := &event.CanonicalEvent{Raw: map[string]any{"num": 42.5, "flag": true, "none": nil}}
	if _, err := r.Redact(ev); err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if len(ev.Raw) != 3 {
		t.Errorf("scalar residuals dropped: %v", ev.Raw)
	}
}

// TestShippedPolicyMatchesEmbedded pins redact/policy.yaml (the operator's
// starting point) to the embedded default — they must never drift.
func TestShippedPolicyMatchesEmbedded(t *testing.T) {
	shipped, err := os.ReadFile("../../redact/policy.yaml")
	if err != nil {
		t.Fatalf("read shipped policy: %v", err)
	}
	norm := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
	if !bytes.Equal(norm(shipped), norm(defaultPolicyYAML)) {
		t.Fatal("redact/policy.yaml differs from internal/redact/default_policy.yaml — keep them identical")
	}
}

func TestPolicyValidation(t *testing.T) {
	bad := []struct{ name, yaml string }{
		{"wrong mode", "version: 1\nmode: blocklist\nallow: [a]\non_error: quarantine\n"},
		{"wrong on_error", "version: 1\nmode: allowlist\nallow: [a]\non_error: drop\n"},
		{"empty allow", "version: 1\nmode: allowlist\nallow: []\non_error: quarantine\n"},
		{"mid-pattern wildcard", "version: 1\nmode: allowlist\nallow: [\"a.*.b\"]\non_error: quarantine\n"},
		{"unknown scrubber", "version: 1\nmode: allowlist\nallow: [a]\nscrubbers: [nope]\non_error: quarantine\n"},
		{"unknown field", "version: 1\nmode: allowlist\nallow: [a]\non_error: quarantine\nallowlist: [b]\n"},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parsePolicy([]byte(tt.yaml)); err == nil {
				t.Errorf("parsePolicy accepted invalid policy (%s)", tt.name)
			}
		})
	}
}
