package parse

import (
	"strings"
	"testing"
)

// A well-formed entry as the HAARF harness writes it (compacted).
const validAllow = `{"timestamp":1772147146.7183628,"scenario_id":"RT-1","condition":"baseline","patient_id":"SYN-001","tool_name":"order_imaging","tool_args_hash":"d55677b9e3366c4c","tool_args":{"study":"Chest CT","mrn":"SYN-001"},"decision":"allow","denial_reason":null,"trial_id":"RT-1_baseline_0","model_name":"gemini-2.5-flash"}`

func denyLine(reason string) string {
	return `{"timestamp":1772147150.5,"scenario_id":"RT-1","condition":"haarf","patient_id":"SYN-001","tool_name":"order_medication","tool_args_hash":"abcd1234abcd1234","decision":"deny","denial_reason":"` + reason + `","trial_id":"RT-1_haarf_0","model_name":"gemini-2.5-flash"}`
}

func TestHAARFAuditParse(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantErr  string // substring of the error, empty = no error
		decision string
		layer    string
		tool     string
	}{
		{
			name:     "valid allow",
			line:     validAllow,
			decision: "allow",
			layer:    "",
			tool:     "order_imaging",
		},
		{
			name:     "deny rbac",
			line:     denyLine("RBAC: tool 'order_medication' is not in the permitted set"),
			decision: "deny",
			layer:    "rbac",
			tool:     "order_medication",
		},
		{
			name:     "deny contraindication",
			line:     denyLine("CONTRAINDICATION: 'penicillin' is a documented allergy for this patient"),
			decision: "deny",
			layer:    "contraindication",
			tool:     "order_medication",
		},
		{
			name:     "deny injection",
			line:     denyLine("INJECTION: suspicious patterns detected in tool input"),
			decision: "deny",
			layer:    "injection",
			tool:     "order_medication",
		},
		{
			name:     "deny circuit breaker",
			line:     denyLine("CIRCUIT_BREAKER: tripped after 3 consecutive failures."),
			decision: "deny",
			layer:    "circuit_breaker",
			tool:     "order_medication",
		},
		{
			name:     "deny with unrecognized reason prefix",
			line:     denyLine("SOMETHING_NEW: future enforcement layer"),
			decision: "deny",
			layer:    "",
			tool:     "order_medication",
		},
		{
			name:    "missing required fields",
			line:    `{"timestamp":1772147146.7,"scenario_id":"RT-1","condition":"baseline","tool_name":"order_imaging","tool_args_hash":"d5","decision":"allow"}`,
			wantErr: "missing required fields: trial_id, patient_id, model_name",
		},
		{
			name:    "invalid decision value",
			line:    strings.Replace(validAllow, `"decision":"allow"`, `"decision":"block"`, 1),
			wantErr: `invalid decision "block"`,
		},
		{
			name:    "wrong type: condition as array",
			line:    strings.Replace(validAllow, `"condition":"baseline"`, `"condition":["baseline"]`, 1),
			wantErr: `field "condition": expected string`,
		},
		{
			name:    "wrong type: timestamp as string",
			line:    strings.Replace(validAllow, `"timestamp":1772147146.7183628`, `"timestamp":"yesterday"`, 1),
			wantErr: `field "timestamp": expected number`,
		},
		{
			name:    "wrong type: denial_reason as object",
			line:    strings.Replace(validAllow, `"denial_reason":null`, `"denial_reason":{"code":1}`, 1),
			wantErr: `field "denial_reason": expected string or null`,
		},
		{
			name:    "malformed JSON",
			line:    validAllow[:len(validAllow)/2],
			wantErr: "invalid JSON",
		},
		{
			// A foreign JSON object that embeds a HAARF line as a string
			// value fools Sniff (substring fingerprints) but must be
			// rejected by Parse's required-field validation, not emitted.
			name:    "adversarial embedded haarf line",
			line:    `{"message":"upstream said: ` + strings.ReplaceAll(validAllow, `"`, `\"`) + `"}`,
			wantErr: "missing required fields",
		},
	}

	p := NewHAARFAudit(nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := p.Parse([]byte(tt.line))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Parse error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if ev.PolicyDecision != tt.decision {
				t.Errorf("PolicyDecision = %q, want %q", ev.PolicyDecision, tt.decision)
			}
			if ev.PolicyLayer != tt.layer {
				t.Errorf("PolicyLayer = %q, want %q", ev.PolicyLayer, tt.layer)
			}
			if ev.ToolName != tt.tool {
				t.Errorf("ToolName = %q, want %q", ev.ToolName, tt.tool)
			}
			if ev.Operation != "execute_tool" {
				t.Errorf("Operation = %q, want execute_tool", ev.Operation)
			}
			if ev.SourceFormat != "haarf_audit" {
				t.Errorf("SourceFormat = %q, want haarf_audit", ev.SourceFormat)
			}
		})
	}
}

func TestHAARFAuditSniff(t *testing.T) {
	p := NewHAARFAudit(nil)
	accepts := []string{
		validAllow,
		"  \t" + validAllow, // leading whitespace
	}
	rejects := []string{
		"",
		"plain text log line",
		// QFIRE AuditRecord: JSON, but no HAARF fingerprint fields.
		`{"ts":"2026-07-15T00:00:00Z","qfire_version":"0.4.0","event":"proxy_decision","prompt_hash":"ab","chain_id":"healthcare","chain_version":"1","terminal":"block","reason":"scope"}`,
		// Generic SDK log: has "decision"-free gen-AI shape.
		`{"model":"claude-sonnet-5","usage":{"input_tokens":10,"output_tokens":5},"finish_reason":"stop"}`,
		// Fingerprints present but not JSON.
		`tool_args_hash scenario_id decision`,
	}
	for _, line := range accepts {
		if !p.Sniff([]byte(line)) {
			t.Errorf("Sniff rejected valid line %q", line)
		}
	}
	for _, line := range rejects {
		if p.Sniff([]byte(line)) {
			t.Errorf("Sniff accepted foreign line %q", line)
		}
	}
}

func TestHAARFAuditPatientHandling(t *testing.T) {
	// Without a hasher the raw patient reference must vanish entirely.
	ev, err := NewHAARFAudit(nil).Parse([]byte(validAllow))
	if err != nil {
		t.Fatal(err)
	}
	if ev.PatientCtxHash != "" {
		t.Errorf("PatientCtxHash = %q, want empty without hasher", ev.PatientCtxHash)
	}
	assertPatientSuppressed(t, ev.Raw)

	// With a hasher the reference is pseudonymized, never raw.
	hasher := func(ref string) string { return "hashed:" + ref + ":hashed" }
	ev, err = NewHAARFAudit(hasher).Parse([]byte(validAllow))
	if err != nil {
		t.Fatal(err)
	}
	if ev.PatientCtxHash != "hashed:SYN-001:hashed" {
		t.Errorf("PatientCtxHash = %q, want hasher output", ev.PatientCtxHash)
	}
	assertPatientSuppressed(t, ev.Raw)
}

// assertPatientSuppressed checks that patient_id and denial_reason never
// ride through as residuals — they are the two consumed-and-suppressed
// fields; everything else (tool_args included) is the redact stage's job.
func assertPatientSuppressed(t *testing.T, raw map[string]any) {
	t.Helper()
	for _, k := range []string{"hc_agent.haarf.patient_id", "hc_agent.haarf.denial_reason"} {
		if v, ok := raw[k]; ok {
			t.Errorf("suppressed field passed through: Raw[%q] = %v", k, v)
		}
	}
}

func TestHAARFAuditResidualPassthrough(t *testing.T) {
	// Unknown source fields must reach Raw as hc_agent.haarf.* residuals —
	// dropping them is the redact stage's allowlist decision, not the
	// parser's.
	line := strings.Replace(validAllow, `"tool_args":{`, `"custom_note":"hello","tool_args":{`, 1)
	ev, err := NewHAARFAudit(nil).Parse([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := ev.Raw["hc_agent.haarf.custom_note"]; !ok || got != "hello" {
		t.Errorf("Raw[hc_agent.haarf.custom_note] = %v (present=%v), want \"hello\"", got, ok)
	}
	if _, ok := ev.Raw["hc_agent.haarf.tool_args"]; !ok {
		t.Error("tool_args residual missing — the redact allowlist, not the parser, must drop it")
	}
}
