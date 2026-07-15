package redact

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed default_policy.yaml
var defaultPolicyYAML []byte

// Policy is the parsed redaction policy (redact/policy.yaml).
type Policy struct {
	Version   int      `yaml:"version"`
	Mode      string   `yaml:"mode"`
	Allow     []string `yaml:"allow"`
	Scrubbers []string `yaml:"scrubbers"`
	OnError   string   `yaml:"on_error"`
}

// DefaultPolicy returns the policy compiled into the binary — identical to
// the redact/policy.yaml shipped in the repository (asserted by test).
func DefaultPolicy() *Policy {
	p, err := parsePolicy(defaultPolicyYAML)
	if err != nil {
		panic("embedded default policy invalid: " + err.Error()) // build defect, not runtime input
	}
	return p
}

// LoadPolicy reads and validates a policy file. Invalid config refuses to
// load with a precise error — the relay must not boot on a policy it cannot
// prove it understood.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := parsePolicy(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

func parsePolicy(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // a typo'd policy field must be an error, not a silent no-op
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if p.Mode != "allowlist" {
		return nil, fmt.Errorf("mode %q not supported (only \"allowlist\")", p.Mode)
	}
	if p.OnError != "quarantine" {
		return nil, fmt.Errorf("on_error %q not supported (only \"quarantine\")", p.OnError)
	}
	if len(p.Allow) == 0 {
		return nil, fmt.Errorf("allow list is empty; the pipeline would emit nothing")
	}
	for _, pat := range p.Allow {
		if strings.Contains(strings.TrimSuffix(pat, ".*"), "*") {
			return nil, fmt.Errorf("allow pattern %q: only a trailing .* wildcard is supported", pat)
		}
	}
	for _, name := range p.Scrubbers {
		if _, ok := builtinScrubbers[name]; !ok {
			return nil, fmt.Errorf("unknown scrubber %q", name)
		}
	}
	return &p, nil
}
