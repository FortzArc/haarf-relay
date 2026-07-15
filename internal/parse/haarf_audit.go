package parse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/FortzArc/haarf-relay/internal/event"
)

// haarfAuditEntry mirrors one entry of the audit_log array produced by the
// HAARF harness middleware (haarf/audit/schema.json). The schema allows
// additional properties; we deliberately decode only what we consume.
type haarfAuditEntry struct {
	Timestamp    *float64 `json:"timestamp"` // unix seconds, fractional
	ScenarioID   string   `json:"scenario_id"`
	Condition    string   `json:"condition"`
	PatientID    string   `json:"patient_id"`
	ToolName     string   `json:"tool_name"`
	ToolArgsHash string   `json:"tool_args_hash"`
	Decision     string   `json:"decision"`
	DenialReason *string  `json:"denial_reason"`
	TrialID      string   `json:"trial_id"`
	ModelName    string   `json:"model_name"`
}

// layerPrefixes maps the denial_reason prefix written by
// haarf/harness/middleware.py to the hc_agent.policy.layer value. The HAARF
// audit schema has no layer field; the prefix is the only place the
// enforcement layer is recorded.
var layerPrefixes = []struct{ prefix, layer string }{
	{"RBAC:", "rbac"},
	{"CONTRAINDICATION:", "contraindication"},
	{"INJECTION:", "injection"},
	{"CIRCUIT_BREAKER:", "circuit_breaker"},
}

// HAARFAudit parses HAARF harness audit-log entries (JSONL).
type HAARFAudit struct {
	// hashPatient pseudonymizes patient_id. When nil (no per-deployment
	// salt configured) the patient reference is dropped entirely — an
	// unsalted or absent hash must never fall back to the raw value.
	hashPatient func(string) string
}

func NewHAARFAudit(hashPatient func(string) string) *HAARFAudit {
	return &HAARFAudit{hashPatient: hashPatient}
}

func (p *HAARFAudit) Name() string { return "haarf_audit" }

var (
	sniffToolArgsHash = []byte(`"tool_args_hash"`)
	sniffScenarioID   = []byte(`"scenario_id"`)
	sniffDecision     = []byte(`"decision"`)
)

// Sniff accepts JSON objects that carry the HAARF audit fingerprint fields.
func (p *HAARFAudit) Sniff(line []byte) bool {
	line = bytes.TrimLeft(line, " \t")
	if len(line) == 0 || line[0] != '{' {
		return false
	}
	return bytes.Contains(line, sniffToolArgsHash) &&
		bytes.Contains(line, sniffScenarioID) &&
		bytes.Contains(line, sniffDecision)
}

func (p *HAARFAudit) Parse(line []byte) (*event.CanonicalEvent, error) {
	var in haarfAuditEntry
	if err := json.Unmarshal(line, &in); err != nil {
		return nil, fmt.Errorf("haarf_audit: invalid JSON: %w", err)
	}
	if err := in.validate(); err != nil {
		return nil, fmt.Errorf("haarf_audit: %w", err)
	}

	sec, frac := math.Modf(*in.Timestamp)
	ev := &event.CanonicalEvent{
		Timestamp:      time.Unix(int64(sec), int64(frac*1e9)).UTC(),
		Operation:      "execute_tool",
		Model:          in.ModelName,
		ToolName:       in.ToolName,
		PolicyDecision: in.Decision,
		PolicyLayer:    deriveLayer(in.Decision, in.DenialReason),
		SourceFormat:   p.Name(),
		Raw: map[string]any{
			"hc_agent.haarf.trial_id":    in.TrialID,
			"hc_agent.haarf.scenario_id": in.ScenarioID,
			"hc_agent.haarf.condition":   in.Condition,
			"hc_agent.tool.args_hash":    in.ToolArgsHash,
		},
	}
	// patient_id is a raw (synthetic) MRN and tool_args / denial_reason may
	// carry clinical free text. Until the redact stage ships (M2), none of
	// them pass through: patient_id is pseudonymized or dropped, the rest
	// is dropped. The derived layer preserves the denial class as evidence.
	if p.hashPatient != nil {
		ev.PatientCtxHash = p.hashPatient(in.PatientID)
	}
	return ev, nil
}

func (in *haarfAuditEntry) validate() error {
	var missing []string
	for _, f := range []struct {
		name string
		ok   bool
	}{
		{"trial_id", in.TrialID != ""},
		{"scenario_id", in.ScenarioID != ""},
		{"condition", in.Condition != ""},
		{"timestamp", in.Timestamp != nil},
		{"patient_id", in.PatientID != ""},
		{"tool_name", in.ToolName != ""},
		{"tool_args_hash", in.ToolArgsHash != ""},
		{"decision", in.Decision != ""},
		{"model_name", in.ModelName != ""},
	} {
		if !f.ok {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}
	if in.Decision != "allow" && in.Decision != "deny" {
		return fmt.Errorf("invalid decision %q", in.Decision)
	}
	return nil
}

func deriveLayer(decision string, denialReason *string) string {
	if decision != "deny" || denialReason == nil {
		return ""
	}
	for _, lp := range layerPrefixes {
		if strings.HasPrefix(*denialReason, lp.prefix) {
			return lp.layer
		}
	}
	return ""
}
