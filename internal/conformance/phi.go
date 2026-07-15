// Package conformance holds the relay's self-test suites. The PHI suite is
// simultaneously the IT-2 integration test and the shipped
// `haarf-relay conformance phi` command: it pushes a synthetic-PHI-seeded
// corpus through the full pipeline and scans every downstream byte for
// leakage.
package conformance

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/FortzArc/haarf-relay/internal/emit"
	"github.com/FortzArc/haarf-relay/internal/input"
	"github.com/FortzArc/haarf-relay/internal/parse"
	"github.com/FortzArc/haarf-relay/internal/pipeline"
	"github.com/FortzArc/haarf-relay/internal/quarantine"
	"github.com/FortzArc/haarf-relay/internal/redact"
)

//go:embed corpus/phi_seeded.jsonl corpus/canaries.txt
var corpusFS embed.FS

// PHIResult is the outcome of one PHI conformance run.
type PHIResult struct {
	CorpusLines int
	Emitted     int
	Quarantined int
	Redactions  int
	Dropped     int

	// Failures — all must be empty/zero to pass.
	OutputLeaks     []string // canaries found in emitted bytes
	CiphertextLeaks []string // canaries found in quarantine files at rest
	Errors          []string // structural failures (decrypt, wrong-key, counters)
}

func (r *PHIResult) Pass() bool {
	return len(r.OutputLeaks) == 0 && len(r.CiphertextLeaks) == 0 && len(r.Errors) == 0
}

// Report renders a human-readable summary.
func (r *PHIResult) Report() string {
	var b strings.Builder
	status := "PASS"
	if !r.Pass() {
		status = "FAIL"
	}
	fmt.Fprintf(&b, "phi conformance: %s\n", status)
	fmt.Fprintf(&b, "  corpus lines:        %d\n", r.CorpusLines)
	fmt.Fprintf(&b, "  emitted:             %d\n", r.Emitted)
	fmt.Fprintf(&b, "  quarantined:         %d (encrypted)\n", r.Quarantined)
	fmt.Fprintf(&b, "  values scrubbed:     %d\n", r.Redactions)
	fmt.Fprintf(&b, "  fields dropped:      %d\n", r.Dropped)
	for _, l := range r.OutputLeaks {
		fmt.Fprintf(&b, "  LEAK (output):       %s\n", l)
	}
	for _, l := range r.CiphertextLeaks {
		fmt.Fprintf(&b, "  LEAK (quarantine):   %s\n", l)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "  ERROR:               %s\n", e)
	}
	return b.String()
}

// RunPHI executes the suite. policyPath == "" uses the embedded default
// policy — the configuration the binary ships with must itself pass.
func RunPHI(policyPath string) (*PHIResult, error) {
	corpus, err := corpusFS.ReadFile("corpus/phi_seeded.jsonl")
	if err != nil {
		return nil, err
	}
	canaryData, err := corpusFS.ReadFile("corpus/canaries.txt")
	if err != nil {
		return nil, err
	}
	var canaries []string
	for _, c := range strings.Split(string(canaryData), "\n") {
		if c = strings.TrimRight(c, "\r"); c != "" {
			canaries = append(canaries, c)
		}
	}

	policy := redact.DefaultPolicy()
	if policyPath != "" {
		if policy, err = redact.LoadPolicy(policyPath); err != nil {
			return nil, err
		}
	}

	// Ephemeral quarantine: fresh X25519 identity, temp spool dir.
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	qdir, err := os.MkdirTemp("", "haarf-relay-conformance-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(qdir)
	qw, err := quarantine.New(qdir, identity.Recipient().String())
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	seq := 0
	p := pipeline.New(
		parse.NewRegistry(parse.NewHAARFAudit(redact.PatientHasher("conformance-salt"))),
		emit.NewJSONL(&out),
		pipeline.Options{
			IDFunc: func() string {
				seq++
				return fmt.Sprintf("%026d", seq) // deterministic: a pass must be reproducible
			},
			RelayVersion:  "conformance",
			SchemaVersion: "hc_agent/0.1",
			Redactor:      redact.NewRedactor(policy),
			Quarantine:    qw,
		},
	)

	res := &PHIResult{}
	err = input.ReadLines(bytes.NewReader(corpus), func(line []byte) error {
		res.CorpusLines++
		return p.Process(line)
	})
	if err != nil {
		return nil, err
	}
	stats, err := p.Close()
	if err != nil {
		return nil, err
	}
	res.Emitted = stats.Emitted
	res.Quarantined = stats.Quarantined
	res.Dropped = stats.FieldsDropped
	for _, n := range stats.Redactions {
		res.Redactions += n
	}

	// Gate 1: zero canary bytes in emitted output.
	for _, c := range canaries {
		if bytes.Contains(out.Bytes(), []byte(c)) {
			res.OutputLeaks = append(res.OutputLeaks, c)
		}
	}

	// Gate 2: the corpus must actually exercise the machinery.
	if res.Redactions == 0 {
		res.Errors = append(res.Errors, "no values scrubbed — scrubbers did not run")
	}
	if res.Quarantined == 0 {
		res.Errors = append(res.Errors, "nothing quarantined — fail-closed path did not run")
	}
	if res.Emitted == 0 {
		res.Errors = append(res.Errors, "nothing emitted — pipeline did not run")
	}

	// Gate 3: quarantine files are encrypted at rest (no canary bytes),
	// unreadable with the wrong key, and recoverable with the right one.
	wrongIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	spools, err := filepath.Glob(filepath.Join(qdir, "*.age"))
	if err != nil {
		return nil, err
	}
	if len(spools) != res.Quarantined {
		res.Errors = append(res.Errors,
			fmt.Sprintf("quarantine spool has %d files, stats say %d", len(spools), res.Quarantined))
	}
	recovered := 0
	for _, f := range spools {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, c := range canaries {
			if bytes.Contains(raw, []byte(c)) {
				res.CiphertextLeaks = append(res.CiphertextLeaks, c+" in "+filepath.Base(f))
			}
		}
		if _, err := quarantine.Decrypt(f, wrongIdentity); err == nil {
			res.Errors = append(res.Errors, "quarantine file decrypted with the WRONG key: "+filepath.Base(f))
		}
		env, err := quarantine.Decrypt(f, identity)
		if err != nil {
			res.Errors = append(res.Errors, "quarantine file unrecoverable with the right key: "+filepath.Base(f))
			continue
		}
		line, err := env.Line()
		if err != nil {
			res.Errors = append(res.Errors, "quarantine envelope corrupt: "+filepath.Base(f))
			continue
		}
		for _, c := range canaries {
			if bytes.Contains(line, []byte(c)) {
				recovered++
				break
			}
		}
	}
	if len(spools) > 0 && recovered == 0 {
		res.Errors = append(res.Errors, "decrypted quarantine lines contain no canaries — spool is not holding the original events")
	}

	return res, nil
}
