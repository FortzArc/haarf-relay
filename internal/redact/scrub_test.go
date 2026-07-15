package redact

import (
	"strings"
	"testing"
)

// Per-scrubber positive and hard-negative sets. Hard negatives are the
// look-alikes a naive pattern would eat: ICD-10 codes, dosages, hashes, ISO
// timestamps, capitalized non-name phrases.
func TestScrubbers(t *testing.T) {
	tests := []struct {
		scrubber  string
		positives []string // must be fully removed
		negatives []string // must survive untouched
	}{
		{
			scrubber: "email",
			positives: []string{
				"contact maribel.q@example-hospital.org today",
				"x a+b_c.d@sub.domain.co x",
			},
			negatives: []string{
				"twitter handle @clinician",
				"array[idx]@0x4f",
			},
		},
		{
			scrubber: "ssn",
			positives: []string{
				"SSN: 987-65-4320",
				"ssn 987 65 4320",
				"SSN:987654320",
				"bare 987-65-4320 too",
			},
			negatives: []string{
				"date 2026-07-15",
				"dosage 100-20-5",     // 3-2-1, not 3-2-4
				"order 12345-67-8901", // 5-2-4
				"phone 617-555-0142",  // 3-3-4
			},
		},
		{
			scrubber: "mrn",
			positives: []string{
				"MRN: SYN-88231",
				"mrn #4491287",
				"Medical Record Number 4491287",
				"medical record no. 55123",
			},
			negatives: []string{
				"ICD-10 J45.909",
				"SHA-256 d55677b9e3366c4c",
				"dose 500mg",
				"trial 4491287", // digits without MRN context survive
			},
		},
		{
			scrubber: "dob",
			positives: []string{
				"dob 01/02/1990",
				"DOB: 1987-03-14",
				"date of birth 3/14/87",
				"born 1990/01/02",
				"bare US date 03/14/1987 is scrubbed",
			},
			negatives: []string{
				"timestamp 2026-07-15T16:48:07Z", // ISO without DOB context
				"ratio 3/4",
				"path a/b/c",
			},
		},
		{
			scrubber: "us_phone",
			positives: []string{
				"call (617) 555-0142",
				"+1 617-555-0142",
				"617.555.0142",
			},
			negatives: []string{
				"ssn-shaped 987-65-4320", // 3-2-4
				"ts 1772147146.7183628",
				"v1.2.3",
			},
		},
		{
			scrubber: "person_name",
			positives: []string{
				"seen by Maribel Quintanilla",
				"per Thaddeus Okonkwo-Bright",
				"Mary Watson Smith attending", // First Middle Last
			},
			negatives: []string{
				"Chest CT ordered",       // CT is not [A-Z][a-z]+
				"General Hospital wing",  // "General" not in dictionary
				"order Chest Radiograph", // capitalized non-name pair
				"lowercase mary watson",  // heuristic requires capitalization
			},
		},
	}

	for _, tt := range tests {
		sc := builtinScrubbers[tt.scrubber]
		if sc == nil {
			t.Fatalf("scrubber %q not registered", tt.scrubber)
		}
		for _, in := range tt.positives {
			t.Run(tt.scrubber+"/pos/"+in, func(t *testing.T) {
				out, n := sc.Scrub(in)
				if n == 0 {
					t.Fatalf("Scrub(%q) made no redactions", in)
				}
				if !strings.Contains(out, "[REDACTED:"+tt.scrubber+"]") {
					t.Errorf("Scrub(%q) = %q, want redaction marker", in, out)
				}
			})
		}
		for _, in := range tt.negatives {
			t.Run(tt.scrubber+"/neg/"+in, func(t *testing.T) {
				out, n := sc.Scrub(in)
				if n != 0 || out != in {
					t.Errorf("Scrub(%q) = %q (n=%d), want untouched", in, out, n)
				}
			})
		}
	}
}

// FuzzScrubbers asserts the two safety properties on arbitrary input:
// scrubbing is idempotent, and a scrubbed string never still contains a
// match (the doc's "a scrubbed string never matches the pattern afterward").
func FuzzScrubbers(f *testing.F) {
	f.Add("SSN: 987-65-4320 call (617) 555-0142 for Maribel Quintanilla")
	f.Add("MRN: SYN-88231 dob 01/02/1990 maribel.q@example-hospital.org")
	f.Add("clean line with nothing to scrub 12345")
	f.Add("987-65-4320987-65-4320")
	f.Fuzz(func(t *testing.T, in string) {
		for name, sc := range builtinScrubbers {
			once, _ := sc.Scrub(in)
			twice, n := sc.Scrub(once)
			if n != 0 {
				t.Errorf("%s: scrubbed output still matches: %q -> %q (n=%d)", name, in, once, n)
			}
			if twice != once {
				t.Errorf("%s: not idempotent: %q -> %q -> %q", name, in, once, twice)
			}
		}
	})
}
