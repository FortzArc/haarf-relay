// Command canary regenerates the PHI canary corpus consumed by the
// conformance suite (internal/conformance/corpus/). The corpus is fully
// deterministic: valid haarf_audit lines with synthetic PHI planted in every
// position — allowed fields, unknown fields, nested values, tool arguments —
// plus malformed lines that must land in the encrypted quarantine.
//
// canaries.txt lists the exact byte sequences that must never appear
// downstream of the relay. All values are synthetic (fake names, 555-01xx
// phone range, invalid-area SSNs, SYN- MRNs) per the test-data policy.
//
//	go run ./testdata/gen/canary -out internal/conformance/corpus
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Canary PHI values. Names must be present in the person_name scrubber
// dictionary (internal/redact/names.go) — the canary proves the shipped
// configuration catches them, so the two lists are deliberately coupled.
var canaries = []string{
	"Maribel",
	"Quintanilla",
	"Thaddeus",
	"Okonkwo-Bright",
	"987-65-4320",
	"987 65 4320",
	"987654320",
	"SYN-88231",
	"4491287",
	"03/14/1987",
	"1987-03-14",
	"(617) 555-0142",
	"555-0142",
	"maribel.q@example-hospital.org",
}

// line builds one haarf_audit JSON line from overrides of a valid base.
func line(overrides ...string) string {
	base := []string{
		`"timestamp":1772147200.25`,
		`"scenario_id":"RT-1"`,
		`"condition":"baseline"`,
		`"patient_id":"SYN-88231"`,
		`"tool_name":"order_imaging"`,
		`"tool_args_hash":"aaaa0000bbbb1111"`,
		`"decision":"allow"`,
		`"denial_reason":null`,
		`"trial_id":"CANARY_TRIAL"`,
		`"model_name":"gemini-2.5-flash"`,
	}
	fields := make([]string, 0, len(base)+len(overrides))
	for _, b := range base {
		key := b[:strings.Index(b, ":")+1]
		replaced := false
		for _, o := range overrides {
			if strings.HasPrefix(o, key) {
				fields = append(fields, o)
				replaced = true
				break
			}
		}
		if !replaced {
			fields = append(fields, b)
		}
	}
	for _, o := range overrides {
		key := o[:strings.Index(o, ":")+1]
		found := false
		for _, b := range base {
			if strings.HasPrefix(b, key) {
				found = true
				break
			}
		}
		if !found {
			fields = append(fields, o)
		}
	}
	return "{" + strings.Join(fields, ",") + "}"
}

func corpus() []string {
	return []string{
		// 1: clean allow — must emit untouched.
		line(`"tool_args":{"study":"Chest CT"}`),
		// 2: name in an allowed, scrubbed field.
		line(`"tool_name":"order_imaging for Maribel Quintanilla"`),
		// 3: SSN + phone in an allowed field.
		line(`"tool_name":"review chart SSN: 987-65-4320 then call (617) 555-0142"`),
		// 4: name in denial free text — parser derives the layer, drops the text.
		line(`"decision":"deny"`, `"denial_reason":"CONTRAINDICATION: 'penicillin' documented allergy for Thaddeus Okonkwo-Bright"`),
		// 5: PHI in an unknown top-level field — allowlist must drop it.
		line(`"note":"patient Maribel Quintanilla dob 03/14/1987"`),
		// 6: PHI in an unknown nested object.
		line(`"context":{"name":"Thaddeus Okonkwo-Bright","ssn":"987 65 4320"}`),
		// 7: PHI inside tool_args (nested residual) — dropped by allowlist.
		line(`"tool_args":{"mrn":"MRN: SYN-88231","note":"medical record number 4491287"}`),
		// 8: email + context-guarded ISO DOB in an allowed field.
		line(`"tool_name":"notify maribel.q@example-hospital.org re DOB: 1987-03-14"`),
		// 9: name split across two unknown fields.
		line(`"first":"Maribel"`, `"last":"Quintanilla"`),
		// 10: type-mangled condition — parse error → encrypted quarantine.
		line(`"condition":["haarf"]`, `"note":"SSN: 987-65-4320"`),
		// 11: type-mangled timestamp — parse error → encrypted quarantine.
		line(`"timestamp":"not-a-timestamp"`, `"tool_name":"call (617) 555-0142"`),
		// 12: clean RBAC deny — layer derivation control.
		line(`"decision":"deny"`, `"denial_reason":"RBAC: tool 'order_medication' is not in the permitted set"`),
		// 13: name in an allowed residual (condition is allowlisted).
		line(`"condition":"baseline seen by Maribel Quintanilla"`),
		// 14: obfuscated separator-less SSN behind context guard.
		line(`"tool_name":"verify SSN: 987654320 for refill"`),
	}
}

func main() {
	out := flag.String("out", "internal/conformance/corpus", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "canary: %v\n", err)
		os.Exit(1)
	}
	lines := corpus()
	if err := os.WriteFile(filepath.Join(*out, "phi_seeded.jsonl"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "canary: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*out, "canaries.txt"),
		[]byte(strings.Join(canaries, "\n")+"\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "canary: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("canary: wrote %d corpus lines, %d canary values to %s\n",
		len(lines), len(canaries), *out)
}
