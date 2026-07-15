// haarf-relay converts raw AI-agent logs into HAARF-tagged, PHI-scrubbed,
// SIEM-ready compliance telemetry.
//
// Pipeline: stdin → parse(haarf_audit) → redact (allowlist + scrubbers,
// fail-closed to encrypted quarantine) → stdout JSONL.
//
// Subcommands:
//
//	haarf-relay conformance phi   run the PHI leakage self-test (exit 1 on failure)
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/FortzArc/haarf-relay/internal/conformance"
	"github.com/FortzArc/haarf-relay/internal/emit"
	"github.com/FortzArc/haarf-relay/internal/input"
	"github.com/FortzArc/haarf-relay/internal/parse"
	"github.com/FortzArc/haarf-relay/internal/pipeline"
	"github.com/FortzArc/haarf-relay/internal/quarantine"
	"github.com/FortzArc/haarf-relay/internal/redact"
)

// version is stamped at release time via -ldflags "-X main.version=v0.1.0".
var version = "0.1.0-dev"

const schemaVersion = "hc_agent/0.1"

// saltEnv holds the per-deployment secret for patient-reference
// pseudonymization. When unset, patient references are dropped, never
// forwarded raw.
const saltEnv = "HAARF_RELAY_SALT"

// recipientEnv holds the age X25519 public key quarantined events are
// encrypted to. The matching private key stays with the operator; the relay
// can only write the spool, never read it back.
const recipientEnv = "HAARF_RELAY_QUARANTINE_RECIPIENT"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "conformance" {
		os.Exit(runConformance(os.Args[2:]))
	}

	showVersion := flag.Bool("version", false, "print version and exit")
	policyPath := flag.String("redaction-policy", "", "redaction policy YAML (default: embedded policy, identical to redact/policy.yaml)")
	quarantineDir := flag.String("quarantine-dir", "", "spool dir for events that fail parse/redact (requires "+recipientEnv+"; unset = count and drop)")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	policy := redact.DefaultPolicy()
	if *policyPath != "" {
		var err error
		if policy, err = redact.LoadPolicy(*policyPath); err != nil {
			fmt.Fprintf(os.Stderr, "haarf-relay: %v\n", err)
			os.Exit(1)
		}
	}

	var q pipeline.Quarantiner
	if *quarantineDir != "" {
		qw, err := quarantine.New(*quarantineDir, os.Getenv(recipientEnv))
		if err != nil {
			fmt.Fprintf(os.Stderr, "haarf-relay: %v\n", err)
			os.Exit(1)
		}
		q = qw
	}

	reg := parse.NewRegistry(
		parse.NewHAARFAudit(redact.PatientHasher(os.Getenv(saltEnv))),
	)
	p := pipeline.New(reg, emit.NewJSONL(os.Stdout), pipeline.Options{
		RelayVersion:  version,
		SchemaVersion: schemaVersion,
		Redactor:      redact.NewRedactor(policy),
		Quarantine:    q,
	})

	if err := input.ReadLines(os.Stdin, p.Process); err != nil {
		fmt.Fprintf(os.Stderr, "haarf-relay: %v\n", err)
		os.Exit(1)
	}
	stats, err := p.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "haarf-relay: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr,
		"haarf-relay: emitted=%d parsed=%v unparsed=%d parse_errors=%d redact_errors=%d quarantined=%d quarantine_dropped=%d fields_dropped=%d redactions=%v\n",
		stats.Emitted, stats.Parsed, stats.Unparsed, stats.ParseErrors,
		stats.RedactErrors, stats.Quarantined, stats.QuarantineDropped,
		stats.FieldsDropped, stats.Redactions)
}

func runConformance(args []string) int {
	fs := flag.NewFlagSet("conformance", flag.ExitOnError)
	policyPath := fs.String("redaction-policy", "", "policy to test (default: embedded policy)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 || fs.Arg(0) != "phi" {
		fmt.Fprintln(os.Stderr, "usage: haarf-relay conformance phi [-redaction-policy file]")
		return 2
	}
	res, err := conformance.RunPHI(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "haarf-relay: conformance: %v\n", err)
		return 1
	}
	fmt.Print(res.Report())
	if !res.Pass() {
		return 1
	}
	return 0
}
