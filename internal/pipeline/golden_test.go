package pipeline

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/FortzArc/haarf-relay/internal/emit"
	"github.com/FortzArc/haarf-relay/internal/input"
	"github.com/FortzArc/haarf-relay/internal/parse"
	"github.com/FortzArc/haarf-relay/internal/redact"
)

var update = flag.Bool("update", false, "rewrite golden files from current output")

// TestGoldenRT1 is the M1 exit criterion: the RT-1 fixture corpus (flattened
// from the HAARF repo's committed trial results) replays byte-for-byte to the
// committed golden output. Event IDs are minted deterministically and the
// patient salt is fixed, so the whole line is comparable — no field masking.
func TestGoldenRT1(t *testing.T) {
	runGolden(t, "../../testdata/haarf_audit/rt1.jsonl", "../../testdata/golden/rt1.golden.jsonl")
}

func runGolden(t *testing.T, fixturePath, goldenPath string) {
	t.Helper()
	fixture, err := os.Open(fixturePath)
	if err != nil {
		t.Fatalf("open fixture (run `make fixtures` first?): %v", err)
	}
	defer fixture.Close()

	var out bytes.Buffer
	seq := 0
	p := New(
		parse.NewRegistry(parse.NewHAARFAudit(redact.PatientHasher("golden-test-salt"))),
		emit.NewJSONL(&out),
		Options{
			IDFunc: func() string {
				seq++
				return fmt.Sprintf("%026d", seq) // ULID-shaped, deterministic
			},
			RelayVersion:  "golden-test",
			SchemaVersion: "hc_agent/0.1",
		},
	)

	lines := 0
	err = input.ReadLines(fixture, func(line []byte) error {
		lines++
		return p.Process(line)
	})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	stats, err := p.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}

	// Every well-formed fixture line must be owned by haarf_audit and
	// emitted — zero unparsed, zero errors (IT-1 pass criteria).
	if stats.Emitted != lines || stats.Unparsed != 0 || stats.ParseErrors != 0 {
		t.Fatalf("stats = %+v, want all %d fixture lines emitted cleanly", stats, lines)
	}

	if *update {
		if err := os.WriteFile(goldenPath, out.Bytes(), 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		t.Logf("golden updated: %s (%d lines)", goldenPath, lines)
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("open golden (run `go test ./internal/pipeline -update` to create): %v", err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("output differs from %s (regenerate with -update if the change is intentional)\ngot %d bytes, want %d bytes",
			goldenPath, out.Len(), len(want))
	}
}
