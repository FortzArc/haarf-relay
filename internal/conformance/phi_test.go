package conformance

import "testing"

// TestPHISuite is IT-2: the same engine that ships as
// `haarf-relay conformance phi`, run against the embedded default policy.
func TestPHISuite(t *testing.T) {
	res, err := RunPHI("")
	if err != nil {
		t.Fatalf("RunPHI: %v", err)
	}
	if !res.Pass() {
		t.Fatalf("PHI conformance failed:\n%s", res.Report())
	}

	// The corpus is fixed, so the shape of a passing run is exact.
	if res.CorpusLines != 14 {
		t.Errorf("CorpusLines = %d, want 14", res.CorpusLines)
	}
	if res.Emitted != 12 {
		t.Errorf("Emitted = %d, want 12", res.Emitted)
	}
	if res.Quarantined != 2 {
		t.Errorf("Quarantined = %d, want 2", res.Quarantined)
	}
	if res.Redactions < 7 {
		t.Errorf("Redactions = %d, want >= 7", res.Redactions)
	}
	if res.Dropped == 0 {
		t.Error("Dropped = 0, want allowlist drops for unknown fields")
	}
}
