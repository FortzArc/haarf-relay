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

// requiredFields per haarf/audit/schema.json, in schema order.
var requiredFields = []string{
	"trial_id", "scenario_id", "condition", "timestamp", "patient_id",
	"tool_name", "tool_args_hash", "decision", "model_name",
}

// consumedFields are mapped into CanonicalEvent struct fields (or
// deliberately suppressed) and therefore excluded from residual passthrough:
//   - patient_id is pseudonymized into hc_agent.patient.context_hash
//   - denial_reason is reduced to hc_agent.policy.layer; its free text is
//     clinical content and is not forwarded by this parser
//
// Everything else (tool_args included) rides through as an
// hc_agent.haarf.<key> residual for the redact stage's allowlist to judge —
// dropping unknown fields is redaction policy, not parser behavior.
var consumedFields = map[string]struct{}{
	"timestamp": {}, "scenario_id": {}, "condition": {}, "patient_id": {},
	"tool_name": {}, "tool_args_hash": {}, "decision": {},
	"denial_reason": {}, "trial_id": {}, "model_name": {},
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
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, fmt.Errorf("haarf_audit: invalid JSON: %w", err)
	}
	if err := validateRequired(m); err != nil {
		return nil, fmt.Errorf("haarf_audit: %w", err)
	}

	str := func(key string) (string, error) {
		s, ok := m[key].(string)
		if !ok {
			return "", fmt.Errorf("haarf_audit: field %q: expected string, got %T", key, m[key])
		}
		return s, nil
	}
	var fields struct {
		scenarioID, condition, patientID, toolName,
		toolArgsHash, decision, trialID, modelName string
	}
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"scenario_id", &fields.scenarioID},
		{"condition", &fields.condition},
		{"patient_id", &fields.patientID},
		{"tool_name", &fields.toolName},
		{"tool_args_hash", &fields.toolArgsHash},
		{"decision", &fields.decision},
		{"trial_id", &fields.trialID},
		{"model_name", &fields.modelName},
	} {
		s, err := str(f.key)
		if err != nil {
			return nil, err
		}
		*f.dst = s
	}
	ts, ok := m["timestamp"].(float64)
	if !ok {
		return nil, fmt.Errorf("haarf_audit: field \"timestamp\": expected number, got %T", m["timestamp"])
	}
	if fields.decision != "allow" && fields.decision != "deny" {
		return nil, fmt.Errorf("haarf_audit: invalid decision %q", fields.decision)
	}
	var denialReason *string
	switch v := m["denial_reason"].(type) {
	case string:
		denialReason = &v
	case nil:
	default:
		return nil, fmt.Errorf("haarf_audit: field \"denial_reason\": expected string or null, got %T", v)
	}

	sec, frac := math.Modf(ts)
	ev := &event.CanonicalEvent{
		Timestamp:      time.Unix(int64(sec), int64(frac*1e9)).UTC(),
		Operation:      "execute_tool",
		Model:          fields.modelName,
		ToolName:       fields.toolName,
		PolicyDecision: fields.decision,
		PolicyLayer:    deriveLayer(fields.decision, denialReason),
		SourceFormat:   p.Name(),
		Raw: map[string]any{
			"hc_agent.haarf.trial_id":    fields.trialID,
			"hc_agent.haarf.scenario_id": fields.scenarioID,
			"hc_agent.haarf.condition":   fields.condition,
			"hc_agent.tool.args_hash":    fields.toolArgsHash,
		},
	}
	if p.hashPatient != nil {
		ev.PatientCtxHash = p.hashPatient(fields.patientID)
	}
	for k, v := range m {
		if _, ok := consumedFields[k]; !ok {
			ev.Raw["hc_agent.haarf."+k] = v
		}
	}
	return ev, nil
}

func validateRequired(m map[string]any) error {
	var missing []string
	for _, f := range requiredFields {
		if v, ok := m[f]; !ok || v == nil || v == "" {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
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
