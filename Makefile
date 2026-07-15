HAARF_DIR ?= ../haarf

.PHONY: build test lint fixtures golden verify

build:
	go build ./...

test:
	go test -race ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./... ./testdata/gen

# Regenerate fixtures from a HAARF checkout (test-data policy: fixtures are
# generated, never hand-edited).
fixtures:
	go run ./testdata/gen -haarf $(HAARF_DIR) -scenario RT-1 -out testdata/haarf_audit/rt1.jsonl

# Regenerate golden outputs after an intentional wire-format change.
golden:
	go test ./internal/pipeline -run TestGolden -update

verify: lint build test
