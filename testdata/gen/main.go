// Command gen regenerates the haarf_audit test fixtures by flattening the
// audit_log arrays embedded in the HAARF repo's committed per-trial result
// files (results/RT-*.json) into JSONL — the shape the relay ingests.
//
// Per the test-data policy, fixtures are never hand-edited: rerun this
// generator against a pinned HAARF checkout and commit the output.
//
//	go run ./testdata/gen -haarf ../haarf -scenario RT-1 -out testdata/haarf_audit/rt1.jsonl
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type trialFile struct {
	AuditLog []json.RawMessage `json:"audit_log"`
}

func main() {
	haarfDir := flag.String("haarf", "../haarf", "path to a HAARF repo checkout")
	scenario := flag.String("scenario", "RT-1", "scenario prefix to flatten (e.g. RT-1)")
	out := flag.String("out", "", "output JSONL path (required)")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "gen: -out is required")
		os.Exit(2)
	}
	if err := run(*haarfDir, *scenario, *out); err != nil {
		fmt.Fprintf(os.Stderr, "gen: %v\n", err)
		os.Exit(1)
	}
}

func run(haarfDir, scenario, out string) error {
	pattern := filepath.Join(haarfDir, "results", scenario+"_*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no trial files match %s", pattern)
	}
	sort.Strings(files) // deterministic line order across runs

	var buf bytes.Buffer
	lines := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var trial trialFile
		if err := json.Unmarshal(data, &trial); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		for _, entry := range trial.AuditLog {
			// Compact preserves key order and number literals from the
			// source file, so fixtures stay byte-faithful to what the
			// harness actually wrote.
			if err := json.Compact(&buf, entry); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			buf.WriteByte('\n')
			lines++
		}
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("gen: wrote %d lines from %d trial files to %s\n", lines, len(files), out)
	return nil
}
