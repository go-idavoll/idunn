.PHONY: all build test cover vet fmt lint license license-fix vuln tidy \
	e2e mutate mutate-survivors repro redteam redteam-corpus redteam-fuzz redteam-agent \
	test-keys baseline clean

GO              ?= go
REDTEAM_FUZZTIME ?= 60s

## Mutation testing (see the `mutate` target). The packages are the lifecycle
## code README sets a 100% coverage goal for; the thresholds sit below today's
## measured scores so the gate catches a regression rather than the weather, and
## they are meant to be raised as the gaps in docs/status.md are closed.
MUTATE_PKGS     ?= ./core/txn ./core/stage ./core/updater ./core/launch
MUTATE_TIMEOUT  ?= 20
MUTATE_EFFICACY ?= 75
MUTATE_MCOVER   ?= 75

## Reproducible builds (see the `repro` target).
##
## -trimpath removes the build directory from the binary, which is the one input
## that differs between two machines building the same commit. CGO_ENABLED=0
## removes the host toolchain as an input as well: a cgo build embeds paths and
## versions of a C compiler nobody recorded.
REPRO_DIR       ?= dist/repro
REPRO_CMDS      ?= installer launcher packer
REPRO_FLAGS     ?= -trimpath
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

## end-to-end: the real packer, installer, launcher and host application as
## separate processes against a served TUF repository. It builds binaries and
## talks over a socket, which is why it is not part of `make test`.
e2e:
	$(GO) test -tags=e2e -count=1 ./test/e2e/...

## mutation testing: does the suite actually notice when the code is wrong?
##
## Coverage says a line ran. This says a line mattered. A surviving mutant is a
## test-gap issue -- never a reason to weaken an assertion (AGENTS.md §4, §6).
##
## The timeout coefficient is not decoration: gremlins derives a per-mutant test
## timeout from the baseline run, and the default is too tight for suites that do
## real filesystem work, which reports every mutant as TIMED OUT and every score
## as zero.
mutate:
	@command -v gremlins >/dev/null 2>&1 || { 		echo "gremlins is not installed:"; 		echo "  go install github.com/go-gremlins/gremlins/cmd/gremlins@latest"; 		exit 1; }
	@for pkg in $(MUTATE_PKGS); do 		echo ">> $$pkg"; 		gremlins unleash 			--timeout-coefficient $(MUTATE_TIMEOUT) 			--threshold-efficacy $(MUTATE_EFFICACY) 			--threshold-mcover $(MUTATE_MCOVER) 			$$pkg || exit 1; 	done

## the surviving mutants only, which is the list worth reading
mutate-survivors:
	@for pkg in $(MUTATE_PKGS); do 		echo ">> $$pkg"; 		gremlins unleash --timeout-coefficient $(MUTATE_TIMEOUT) -S l $$pkg; 	done

## reproducible builds: the same commit must produce the same bytes, twice
##
## It is the client half of the supply-chain story. TUF says the bytes you got
## are the bytes the publisher signed; this says the bytes the publisher signed
## are the ones this source produces -- so an independent rebuild can check the
## release rather than take it on faith (docs/design.md §9, §15).
##
## Two passes in one job catch what actually breaks reproducibility in practice:
## a wall-clock stamp, an embedded absolute path, a map iterated into output.
## They do not catch a difference between two *machines*; that is what publishing
## the hashes is for, and why an independent rebuild is the real test.
repro:
	@rm -rf $(REPRO_DIR)
	@for pass in a b; do \
		for cmd in $(REPRO_CMDS); do \
			CGO_ENABLED=0 $(GO) build $(REPRO_FLAGS) \
				-o $(REPRO_DIR)/$$pass/$$cmd ./cmd/$$cmd || exit 1; \
		done; \
	done
	@cd $(REPRO_DIR)/a && sha256sum * > ../a.sha256
	@cd $(REPRO_DIR)/b && sha256sum * > ../b.sha256
	@if diff -u $(REPRO_DIR)/a.sha256 $(REPRO_DIR)/b.sha256; then \
		echo "reproducible:"; cat $(REPRO_DIR)/a.sha256; \
	else \
		echo "NOT reproducible: two builds of the same tree differ"; exit 1; \
	fi

## run the full adversarial suite (corpus + fuzzers)
redteam: redteam-corpus redteam-fuzz

## every tampered repo must be rejected, with the expected error class, no writes
redteam-corpus: baseline
	$(GO) test -tags=redteam ./test/redteam/...

## fuzz the parsers, the path sanitizer and the patch applier (the real bug-finders)
##
## On Windows, `go test -fuzz` execs a worker binary out of the build temp dir,
## which endpoint protection may block ("Access is denied"). Point GOTMPDIR at a
## directory inside the excluded project tree:
##     GOTMPDIR=$(CURDIR)/.gotmp make redteam-fuzz
redteam-fuzz:
	$(GO) test -run=^$$ -fuzz=FuzzDescriptor   -fuzztime=$(REDTEAM_FUZZTIME) ./core/release
	$(GO) test -run=^$$ -fuzz=FuzzDstSanitize  -fuzztime=$(REDTEAM_FUZZTIME) ./core/stage
	$(GO) test -run=^$$ -fuzz=FuzzPatchApply  -fuzztime=$(REDTEAM_FUZZTIME) ./internal/delta

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
