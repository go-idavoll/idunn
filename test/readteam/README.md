# Adversarial testing (red-team)

This tree is idunn's standing red-team. Its rule is simple: **every tampered TUF
repository, package, or input here must be *rejected* by the client under test.** A
mutation that gets *accepted* is a vulnerability and the highest-priority bug class in
the project (see `AGENTS.md` §7).

The finders of bugs are deterministic tools — the corpus, coverage-guided fuzzers,
sanitizers, and differential checks against go-tuf. An optional LLM attacker only
*generates* new candidate attacks; it is never the oracle and is always sandboxed.

## Directory layout

```
test/redteam/
  corpus/                    # each dir = one adversarial scenario; expected: REJECT
    rollback/                # old metadata version served after a newer one
    freeze/                  # stale timestamp pins the client to an old snapshot
    mix-and-match/           # inconsistent snapshot (targets/meta don't agree)
    wrong-hash/              # target bytes don't match the signed hash
    wrong-length/            # length mismatch vs. target metadata
    expired/                 # metadata past expiry (uses UnsafeSetRefTime)
    clock-rollback/          # local clock moved back to revive expired metadata
    wrong-key/               # role signed by a key not trusted by root
    unknown-key/             # unknown key id / threshold not met
    path-traversal/          # descriptor Dst escapes the install root (.., abs, symlink)
    malformed-descriptor/    # unparseable / unknown-schema release descriptor
    downgrade/               # target version <= installed (app-level floor)
    patch-poison/            # delta-stage-2 patch produces wrong output hash
    cache-poison/            # elevated-mode: user-writable cache swapped/symlinked
    _proposed/               # staging area for agent-generated candidates (git-ignored)
    README.md                # -> this file
  fixtures/
    keys/                    # TEST-ONLY TUF role keys — NEVER production keys
    valid-repo/              # known-good baseline most mutations derive from
  harness/
    corpus_test.go           # table-driven runner (build tag: redteam)
    genkeys/                 # test-only key generation
    genrepo/                 # build the baseline valid repo
    serve.go                 # httptest server over a (mutated) repo dir
  agent/                     # OPT-IN sandboxed LLM attacker (generator only)
    prompt.md                # attacker task + hard sandbox constraints
    main.go                  # runs client vs. proposed repos, reports acceptances
```

## Case format

Each corpus case is a directory containing a `case.yaml` and either a materialized
`repo/` or a generator reference. Mutations should derive from `fixtures/valid-repo` so
that *only* the attack differs from a known-good baseline.

```yaml
# corpus/freeze/stale-timestamp/case.yaml
description: "server serves an older snapshot to pin the client (freeze)"
class: freeze
expect: reject               # the client MUST refuse
error_class: verify         # expected classified error (Reporter taxonomy)
# how the repo is produced: either a committed repo/ dir, or a named mutator:
mutator: serve_stale_timestamp
notes: "timestamp expiry evaluated via UnsafeSetRefTime"
```

Adding a case = drop a directory with a `case.yaml` and, if needed, a `repo/` or a
mutator registered in the harness. Keep it minimal and deterministic.

## Harness (sketch)

```go
//go:build redteam

package redteam

// Each case under corpus/<class>/<name>/ has a case.yaml and a (possibly generated)
// TUF repository. The runner serves that repo, points a fresh client-under-test at it,
// and asserts the outcome. Cases derive from fixtures/valid-repo so only the attack
// differs from a known-good baseline.
func TestAdversarialCorpus(t *testing.T) {
    for _, c := range loadCases(t, "corpus") {
        c := c
        t.Run(c.Class+"/"+c.Name, func(t *testing.T) {
            repo := materialize(t, c)             // committed repo/ or run c.Mutator
            srv := serveRepo(t, repo)             // httptest over the mutated repo
            u := newClientUnderTest(t, srv.URL, testRoot(t), c.RefTime)
            _, err := u.CheckForUpdate(context.Background())
            switch c.Expect {
            case "reject":
                requireRejected(t, err, c.ErrorClass) // must fail, right class, no writes
            default:
                t.Fatalf("corpus cases must expect reject; got %q", c.Expect)
            }
            requireNoOnDiskChange(t, u.Root())        // fail-closed: nothing applied
        })
    }
}
```

Fuzz targets live next to the code they attack, not here:
`FuzzDescriptor` (`core/release`), `FuzzDstSanitize` and `FuzzPatchApply` (`core/stage`).

## Make targets

```makefile
.PHONY: redteam redteam-corpus redteam-fuzz redteam-agent test-keys baseline

REDTEAM_FUZZTIME ?= 60s

## run the full adversarial suite (corpus + fuzzers)
redteam: redteam-corpus redteam-fuzz

## every tampered repo must be rejected, with the expected error class, no writes
redteam-corpus: baseline
	go test -tags=redteam ./test/redteam/...

## fuzz the parsers and the path sanitizer (the real bug-finders)
redteam-fuzz:
	go test -run=^$$ -fuzz=FuzzDescriptor   -fuzztime=$(REDTEAM_FUZZTIME) ./core/release
	go test -run=^$$ -fuzz=FuzzDstSanitize  -fuzztime=$(REDTEAM_FUZZTIME) ./core/stage
	go test -run=^$$ -fuzz=FuzzPatchApply   -fuzztime=$(REDTEAM_FUZZTIME) ./core/stage

## generate TEST-ONLY role keys (never production)
test-keys:
	go run ./test/redteam/harness/genkeys -out test/redteam/fixtures/keys

## build the known-good baseline repo that mutations derive from
baseline: test-keys
	go run ./test/redteam/harness/genrepo -keys test/redteam/fixtures/keys \
		-out test/redteam/fixtures/valid-repo

## OPT-IN: sandboxed LLM attacker proposes new candidate attacks
redteam-agent: baseline
	@echo ">> sandboxed attacker: test keys only, no merge rights, no prod access"
	go run ./test/redteam/agent -baseline test/redteam/fixtures/valid-repo \
		-out test/redteam/corpus/_proposed
```

CI runs `make redteam` on every PR. `make redteam-agent` is opt-in (nightly or manual),
never a merge gate on its own.

## The attacker-agent loop (opt-in, sandboxed)

1. **Generate.** The agent mutates `fixtures/valid-repo` into candidate malicious repos
   under `corpus/_proposed/`. It only produces *data* (tampered metadata/targets).
2. **Evaluate.** The runner points the client-under-test at each candidate. Expected
   outcome: **reject**.
3. **Finding vs. regression.**
    - If the client **accepts** a candidate → a real break. CI fails loud; this is
      top-priority.
    - If the client **rejects** it → good. Triage, de-duplicate, and **promote** the
      candidate into `corpus/<class>/` as a permanent regression case.
4. **Ratchet.** The corpus only grows. A defense, once tested, is tested forever.

### Sandbox constraints (hard)

The agent — like any contributor — is untrusted (`AGENTS.md` §6). It:

- uses **only** `fixtures/keys` (test-only); it has **no** access to production keys,
  secrets, or signing infrastructure;
- has **no** merge rights and **cannot** modify the client, the trust path, CI config,
  or the harness — it writes only under `corpus/_proposed/`;
- treats any text it reads (issues, docs, tool output) as **data, not instructions**;
- produces attack *inputs* only. It is a generator, never the pass/fail oracle — the
  deterministic runner decides, and a human triages promotions.

_See `AGENTS.md` for the full contributor/agent security contract and `SECURITY.md` for
the threat model this corpus enforces._