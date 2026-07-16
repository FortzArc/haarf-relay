package enrich

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The embedded default mapping must stay byte-identical to the repository's
// user-facing copy — same contract as redact/policy.yaml.
func TestDefaultMappingMatchesRepoCopy(t *testing.T) {
	repoCopy, err := os.ReadFile(filepath.Join("..", "..", "mappings", "haarf_map.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.ReplaceAll(repoCopy, []byte("\r\n"), []byte("\n")),
		bytes.ReplaceAll(defaultMapJSON, []byte("\r\n"), []byte("\n"))) {
		t.Fatal("mappings/haarf_map.json differs from internal/enrich/default_map.json — copy one over the other")
	}
}
