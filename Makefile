.PHONY: all build test cover vet fmt lint license license-fix vuln tidy \
	redteam redteam-corpus redteam-fuzz redteam-agent test-keys baseline clean

GO              ?= go
REDTEAM_FUZZTIME ?= 60s
LICENSE_YEAR    ?= 2026
LICENSE_HOLDER  ?= The idunn Authors

## build everything
all: build

build:
	$(GO) build ./...

## unit + integration tests with the race detector
test:
	$(GO) test -race ./...

## coverage on the lifecycle code (go-tuf is tested upstream, not here)
cover:
	$(GO) test -covermode=atomic -coverprofile=coverage.out ./core/...
	$(GO) tool cover -func=coverage.out | tail -1

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

## gofmt must be clean; print offenders and fail
fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	golangci-lint run

## every source file carries the Apache-2.0 header.
## The ignores cover generated and untracked trees: addlicense does not read
## .gitignore, so without them a local run trips over editor and fixture files
## that CI never sees.
LICENSE_IGNORE = -ignore '.idea/**' -ignore '.gotmp/**' -ignore 'test/redteam/fixtures/**'

license:
	addlicense -check $(LICENSE_IGNORE) -l apache -c "$(LICENSE_HOLDER)" -y $(LICENSE_YEAR) .

license-fix:
	addlicense $(LICENSE_IGNORE) -l apache -c "$(LICENSE_HOLDER)" -y $(LICENSE_YEAR) .

## known vulnerabilities in the dependency graph
vuln:
	govulncheck ./...

tidy:
	$(GO) mod tidy

## run the full adversarial suite (corpus + fuzzers)
redteam: redteam-corpus redteam-fuzz

## every tampered repo must be rejected, with the expected error class, no writes
redteam-corpus: baseline
	$(GO) test -tags=redteam ./test/redteam/...

## fuzz the parsers and the path sanitizer (the real bug-finders)
## TODO(redteam): add FuzzPatchApply once stage.ApplyPatch has a patch format.
##
## On Windows, `go test -fuzz` execs a worker binary out of the build temp dir,
## which endpoint protection may block ("Access is denied"). Point GOTMPDIR at a
## directory inside the excluded project tree:
##     GOTMPDIR=$(CURDIR)/.gotmp make redteam-fuzz
redteam-fuzz:
	$(GO) test -run=^$$ -fuzz=FuzzDescriptor   -fuzztime=$(REDTEAM_FUZZTIME) ./core/release
	$(GO) test -run=^$$ -fuzz=FuzzDstSanitize  -fuzztime=$(REDTEAM_FUZZTIME) ./core/stage

## generate TEST-ONLY role keys (never production)
test-keys:
	$(GO) run ./test/redteam/harness/genkeys -out test/redteam/fixtures/keys

## build the known-good baseline repo that mutations derive from
baseline: test-keys
	$(GO) run ./test/redteam/harness/genrepo -keys test/redteam/fixtures/keys \
		-out test/redteam/fixtures/valid-repo

## OPT-IN: sandboxed LLM attacker proposes new candidate attacks
redteam-agent: baseline
	@echo ">> sandboxed attacker: test keys only, no merge rights, no prod access"
	$(GO) run ./test/redteam/agent -baseline test/redteam/fixtures/valid-repo \
		-out test/redteam/corpus/_proposed

clean:
	rm -rf bin dist coverage.out
	rm -rf test/redteam/fixtures/keys test/redteam/fixtures/valid-repo
