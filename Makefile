HAARF_DIR ?= ../haarf

.PHONY: build test lint fixtures fixtures-agentic golden agentic agentic-live verify

build:
	go build ./...

test:
	go test -race ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./... ./testdata/gen ./testdata/gen/canary ./testdata/gen/agentic

# Regenerate fixtures from a HAARF checkout (test-data policy: fixtures are
# generated, never hand-edited).
fixtures:
	go run ./testdata/gen -haarf $(HAARF_DIR) -scenario RT-1 -out testdata/haarf_audit/rt1.jsonl
	go run ./testdata/gen/canary -out internal/conformance/corpus

# Regenerate the agentic corpus from a directory of real harness trial
# results (defaults to a live-model run kept outside this repo).
HAARF_RESULTS ?= $(HAARF_DIR)/results_live
fixtures-agentic:
	go run ./testdata/gen/agentic -src $(HAARF_RESULTS) -haarf $(HAARF_DIR) -out testdata/agentic

# Regenerate golden outputs after an intentional wire-format change.
golden:
	go test ./internal/pipeline -run TestGolden -update

# Agentic observability conformance: real agent logs → real relay binary →
# live /metrics scrape, asserting the hc_agent.* standard end to end.
agentic:
	go test ./internal/conformance -run TestObservabilityStandard -v

# Same, but drive the HAARF harness against a live model first
# (requires ANTHROPIC_API_KEY and $(HAARF_DIR)/.venv).
agentic-live:
	HAARF_LIVE=1 HAARF_DIR=$(HAARF_DIR) go test ./internal/conformance -run TestObservabilityStandard -v -timeout 30m

verify: lint build test
