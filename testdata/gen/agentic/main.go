// Command agentic flattens a directory of HAARF harness trial files
// (RT-*.json, each holding an embedded audit_log array) into the JSONL
// stream a production relay would ingest, plus a ground-truth manifest the
// agentic conformance suite asserts against.
//
// The committed corpus under testdata/agentic was produced from a live
// claude-haiku-4-5 run of the harness (results_live) — real agent behavior,
// synthetic patients only. Regenerate with:
//
//	go run ./testdata/gen/agentic -src ../haarf/results_live -haarf ../haarf -out testdata/agentic
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// trial is the subset of a harness trial file the manifest needs.
type trial struct {
	TrialID    string           `json:"trial_id"`
	ScenarioID string           `json:"scenario_id"`
	Condition  string           `json:"condition"`
	Passed     bool             `json:"passed"`
	AuditLog   []map[string]any `json:"audit_log"`
	Config     struct {
		Model string `json:"model"`
	} `json:"config"`
}

// scenarioMeta is what the conformance suite needs to reason about a
// scenario from the outside: which tools the agent was permitted, and
// whether "no restricted tool executed" is one of its pass criteria.
type scenarioMeta struct {
	PermittedTools        []string `json:"permitted_tools"`
	NoRestrictedCriterion bool     `json:"no_restricted_tool_criterion"`
}

type manifestTrial struct {
	TrialID      string `json:"trial_id"`
	ScenarioID   string `json:"scenario_id"`
	Condition    string `json:"condition"`
	AuditEntries int    `json:"audit_entries"`
	Passed       bool   `json:"passed"`
}

type manifest struct {
	Model     string                  `json:"model"`
	Source    string                  `json:"source"`
	Scenarios map[string]scenarioMeta `json:"scenarios"`
	Trials    []manifestTrial         `json:"trials"`
}

func main() {
	src := flag.String("src", "../haarf/results_live", "directory of harness trial files (RT-*.json)")
	haarfDir := flag.String("haarf", "../haarf", "HAARF checkout (for scenarios/*.json)")
	out := flag.String("out", "testdata/agentic", "output directory")
	flag.Parse()

	if err := run(*src, *haarfDir, *out); err != nil {
		fmt.Fprintf(os.Stderr, "gen/agentic: %v\n", err)
		os.Exit(1)
	}
}

func run(src, haarfDir, out string) error {
	files, err := filepath.Glob(filepath.Join(src, "RT-*.json"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no RT-*.json trial files in %s", src)
	}
	sort.Strings(files)

	scenarios, err := loadScenarios(haarfDir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	streams := map[string]*strings.Builder{}
	man := manifest{Source: filepath.ToSlash(src), Scenarios: scenarios}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var t trial
		if err := json.Unmarshal(data, &t); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if man.Model == "" {
			man.Model = t.Config.Model
		}
		if streams[t.Condition] == nil {
			streams[t.Condition] = &strings.Builder{}
		}
		for _, entry := range t.AuditLog {
			line, err := json.Marshal(entry)
			if err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			streams[t.Condition].Write(line)
			streams[t.Condition].WriteByte('\n')
		}
		man.Trials = append(man.Trials, manifestTrial{
			TrialID:      t.TrialID,
			ScenarioID:   t.ScenarioID,
			Condition:    t.Condition,
			AuditEntries: len(t.AuditLog),
			Passed:       t.Passed,
		})
	}

	for cond, b := range streams {
		path := filepath.Join(out, "trials_"+cond+".jsonl")
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", path)
	}
	manJSON, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	manPath := filepath.Join(out, "manifest.json")
	if err := os.WriteFile(manPath, append(manJSON, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d trials, model %s)\n", manPath, len(man.Trials), man.Model)
	return nil
}

func loadScenarios(haarfDir string) (map[string]scenarioMeta, error) {
	files, err := filepath.Glob(filepath.Join(haarfDir, "scenarios", "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no scenario files in %s/scenarios", haarfDir)
	}
	out := make(map[string]scenarioMeta)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var s struct {
			ID              string   `json:"id"`
			ToolPermissions []string `json:"tool_permissions"`
			PassCriteria    struct {
				NoRestrictedToolExecuted *bool `json:"no_restricted_tool_executed"`
			} `json:"pass_criteria"`
		}
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if s.ID == "" {
			continue
		}
		sort.Strings(s.ToolPermissions)
		out[s.ID] = scenarioMeta{
			PermittedTools:        s.ToolPermissions,
			NoRestrictedCriterion: s.PassCriteria.NoRestrictedToolExecuted != nil && *s.PassCriteria.NoRestrictedToolExecuted,
		}
	}
	return out, nil
}
