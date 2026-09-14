.PHONY: all build test cover vet fmt lint license license-fix vuln tidy \
	e2e-local mutate mutate-survivors mutate-tools \
	redteam redteam-corpus redteam-fuzz redteam-agent test-keys baseline clean

GO              ?= go
REDTEAM_FUZZTIME ?= 60s

## Mutation testing (see the `mutate` target). The packages are the lifecycle
## code with a 100% coverage goal. The thresholds and the timeout coefficient
## live in .gremlins.yaml, which explains why they cannot be flags.
## GREMLINS_VERSION is the one CI installs; `go install` checks the module
## against sum.golang.org.
GREMLINS_VERSION ?= v0.6.0
MUTATE_PKGS     ?= ./core/txn ./core/stage ./core/updater ./core/launch
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

## local end-to-end scenarios: real binaries, a repository on 127.0.0.1
## (test/e2e/local/README.md; on Windows set GOTMPDIR to a directory that may run
## freshly built programs)
e2e-local:
	$(GO) test -tags=e2e ./test/e2e/local/...

## mutation testing: would the suite notice if the code were wrong?
##
## Coverage says a line ran; this says a line mattered. A surviving mutant is a
## test gap -- never a reason to weaken or delete a check (AGENTS.md §4, §6).
##
## The config is named explicitly so gremlins cannot pick up a different one
## from /etc, $XDG_CONFIG_HOME or $HOME; a missing file fails the run.
mutate:
	@command -v gremlins >/dev/null 2>&1 || { \
		echo "gremlins is not installed: make mutate-tools"; \
		exit 1; }
	@for pkg in $(MUTATE_PKGS); do \
		echo ">> $$pkg"; \
		gremlins unleash --config .gremlins.yaml $$pkg || exit 1; \
	done

## install the pinned mutation tool into GOBIN
mutate-tools:
	$(GO) install github.com/go-gremlins/gremlins/cmd/gremlins@$(GREMLINS_VERSION)

## the surviving and uncovered mutants only, which is the list worth reading
mutate-survivors:
	@for pkg in $(MUTATE_PKGS); do \
		echo ">> $$pkg"; \
		gremlins unleash --config .gremlins.yaml -S lc $$pkg; \
	done

## run the full adversarial suite (corpus + fuzzers)
redteam: redteam-corpus redteam-fuzz

## every tampered repo must be rejected, with the expected error class, no writes
redteam-corpus: baseline
	$(GO) test -tags=redteam ./test/redteam/...

## fuzz the parsers, the path sanitizer and the patch reader (the real bug-finders)
##
## On Windows, `go test -fuzz` execs a worker binary out of the build temp dir,
## which endpoint protection may block ("Access is denied"). Point GOTMPDIR at a
## directory inside the excluded project tree:
##     GOTMPDIR=$(CURDIR)/.gotmp make redteam-fuzz
redteam-fuzz:
	$(GO) test -run=^$$ -fuzz=FuzzDescriptor   -fuzztime=$(REDTEAM_FUZZTIME) ./core/release
	$(GO) test -run=^$$ -fuzz=FuzzDstSanitize  -fuzztime=$(REDTEAM_FUZZTIME) ./core/stage
	$(GO) test -run=^$$ -fuzz=FuzzPatchApply   -fuzztime=$(REDTEAM_FUZZTIME) ./core/stage

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
