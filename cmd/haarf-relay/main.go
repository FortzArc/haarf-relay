// haarf-relay converts raw AI-agent logs into HAARF-tagged, PHI-scrubbed,
// SIEM-ready compliance telemetry.
//
// M1 scope: stdin → parse(haarf_audit) → stdout JSONL.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/FortzArc/haarf-relay/internal/emit"
	"github.com/FortzArc/haarf-relay/internal/input"
	"github.com/FortzArc/haarf-relay/internal/parse"
	"github.com/FortzArc/haarf-relay/internal/pipeline"
	"github.com/FortzArc/haarf-relay/internal/redact"
)

// version is stamped at release time via -ldflags "-X main.version=v0.1.0".
var version = "0.1.0-dev"

const schemaVersion = "hc_agent/0.1"

// saltEnv holds the per-deployment secret for patient-reference
// pseudonymization. When unset, patient references are dropped, never
// forwarded raw.
const saltEnv = "HAARF_RELAY_SALT"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	reg := parse.NewRegistry(
		parse.NewHAARFAudit(redact.PatientHasher(os.Getenv(saltEnv))),
	)
	p := pipeline.New(reg, emit.NewJSONL(os.Stdout), pipeline.Options{
		RelayVersion:  version,
		SchemaVersion: schemaVersion,
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
		"haarf-relay: emitted=%d parsed=%v unparsed=%d parse_errors=%d\n",
		stats.Emitted, stats.Parsed, stats.Unparsed, stats.ParseErrors)
}
