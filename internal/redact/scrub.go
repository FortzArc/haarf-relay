package redact

import (
	"regexp"
	"strings"
)

// A Scrubber removes one class of PHI from string values. Scrubbers are
// deterministic by design (an audit property): pattern + dictionary, no ML.
type Scrubber interface {
	Name() string
	// Scrub returns the cleaned string and the number of redactions made.
	// Replacement text must never itself match any scrubber (idempotence,
	// enforced by the fuzz test).
	Scrub(s string) (string, int)
}

// regexScrubber pre-filters with cheap substring checks before running the
// regex — the hot path is strings that contain no PHI.
type regexScrubber struct {
	name string
	// prefilter: run the regex only if any of these lowercase substrings is
	// present. Empty means always run.
	prefilter []string
	re        *regexp.Regexp
}

func (r *regexScrubber) Name() string { return r.name }

func (r *regexScrubber) Scrub(s string) (string, int) {
	if len(r.prefilter) > 0 {
		lower := strings.ToLower(s)
		hit := false
		for _, p := range r.prefilter {
			if strings.Contains(lower, p) {
				hit = true
				break
			}
		}
		if !hit {
			return s, 0
		}
	}
	n := 0
	out := r.re.ReplaceAllStringFunc(s, func(string) string {
		n++
		return "[REDACTED:" + r.name + "]"
	})
	return out, n
}

// builtinScrubbers, keyed by policy name. Patterns are conservative: each
// has a hard-negative test set (ICD-10 codes, dosages, ISO timestamps) and
// context guards where a bare pattern would over-match.
var builtinScrubbers = map[string]Scrubber{
	"email": &regexScrubber{
		name:      "email",
		prefilter: []string{"@"},
		re:        regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
	},
	// 3-2-4 with separators anywhere; separator-less 9 digits only behind an
	// "SSN" context guard (bare 9-digit numbers are too common in logs).
	"ssn": &regexScrubber{
		name: "ssn",
		re:   regexp.MustCompile(`(?i)(?:\bssn[:#]?\s*\d{3}[- ]?\d{2}[- ]?\d{4}\b|\b\d{3}[- ]\d{2}[- ]\d{4}\b)`),
	},
	// Context-guarded: "MRN" / "medical record ..." followed by an
	// identifier. A bare digit-run pattern would eat dosages and hashes.
	"mrn": &regexScrubber{
		name:      "mrn",
		prefilter: []string{"mrn", "medical record"},
		re:        regexp.MustCompile(`(?i)\b(?:mrn|medical\s+record(?:\s+(?:number|no\.?|#))?)\s*[:#]?\s*[A-Za-z]{0,4}-?\d{4,10}\b`),
	},
	// Bare US slash-dates are scrubbed unconditionally (rare as legitimate
	// log content); dash/ISO dates only behind a DOB context guard so event
	// timestamps survive.
	"dob": &regexScrubber{
		name: "dob",
		re:   regexp.MustCompile(`(?i)(?:\b(?:dob|date\s+of\s+birth|born)\s*[:#]?\s*\d{1,4}[/-]\d{1,2}[/-]\d{1,4}\b|\b\d{2}/\d{2}/\d{4}\b)`),
	},
	"us_phone": &regexScrubber{
		name: "us_phone",
		re:   regexp.MustCompile(`(?:\+?1[-. ])?\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b`),
	},
	"person_name": &nameScrubber{},
}

// scrubberChain resolves policy names to scrubbers in the policy's order.
func scrubberChain(names []string) []Scrubber {
	chain := make([]Scrubber, 0, len(names))
	for _, n := range names {
		chain = append(chain, builtinScrubbers[n])
	}
	return chain
}

// nameScrubber redacts "First Last[-Last] [Middle]" sequences whose first
// token is in the embedded first-name dictionary. Dictionary + capitalization
// heuristic, deliberately conservative: capitalized non-name pairs ("Chest
// CT", "General Hospital") must survive.
type nameScrubber struct{}

var namePattern = regexp.MustCompile(`\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+(?:-[A-Z][a-z]+)?){1,2}\b`)

func (n *nameScrubber) Name() string { return "person_name" }

func (n *nameScrubber) Scrub(s string) (string, int) {
	count := 0
	out := namePattern.ReplaceAllStringFunc(s, func(m string) string {
		first, _, _ := strings.Cut(m, " ")
		if _, ok := firstNames[strings.ToLower(first)]; !ok {
			return m
		}
		count++
		return "[REDACTED:person_name]"
	})
	return out, count
}
