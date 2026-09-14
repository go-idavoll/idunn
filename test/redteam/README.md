# Adversarial testing (red-team)

This tree is idunn's standing red-team. Its rule is simple: **every tampered TUF
repository, package, or input here must be *rejected* by the client under test** — or,
where the design's answer is not a refusal but a fallback, **must leave the client
exactly as it would have been without the attack.** A mutation that changes what gets
installed is a vulnerability and the highest-priority bug class in the project (see
`AGENTS.md` §7).

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
    resolve/                 # pointer and descriptor are authentic and disagree
    wrong-key/               # role signed by a key not trusted by root
    unknown-key/             # unknown key id / threshold not met
    path-traversal/          # descriptor Dst escapes the install root (.., abs, symlink)
    malformed-descriptor/    # unparseable / unknown-schema release descriptor
    downgrade/               # channel head older than installed (updater policy)
    patch-poison/            # delta patches: poisoned, foreign-base, tampered
    cache-poison/            # elevated-mode: user-writable cache swapped/symlinked
    _proposed/               # staging area for agent-generated candidates (git-ignored)
    README.md                # -> this file
  fixtures/
    keys/                    # TEST-ONLY TUF role keys — NEVER production keys
    valid-repo/              # known-good baseline most mutations derive from
  harness/
    corpus_test.go           # table-driven runner (build tag: redteam)
    keys.go                  # TEST-ONLY ed25519 role keys, plus an untrusted attacker key
    repo.go                  # builds a signed repo in four mutable phases
    mutate.go                # the mutator registry a case.yaml refers to by name
    case.go                  # case.yaml loading + the error-class taxonomy
    serve.go                 # httptest server over a (mutated) repo dir
    client.go                # client under test: refresh -> resolve -> materialize
    genkeys/                 # test-only key generation
    genrepo/                 # build the baseline valid repo
  agent/                     # OPT-IN sandboxed LLM attacker (generator only)
    prompt.md                # attacker task + hard sandbox constraints
    main.go                  # runs client vs. proposed repos, reports acceptances
```

`cache-poison` is listed but holds no case yet: it needs a populated elevated-mode
cache to attack. It lands as the harness grows; the corpus only ever grows.

## Two expectations, both hard

Most cases declare `expect: reject`: the client refuses, with an error of the declared
class, and writes nothing.

The delta cases declare `expect: no-effect`, because a refusal is not what the design
promises there. A patch is untrusted input whose *result* is checked against a signed
hash, so the client is free to fetch one, apply it, and throw away what it produces.
What must hold is stricter than a refusal: the update still arrives, every installed
byte is the signed target, and nothing the attacker chose is anywhere on the machine.
The runner also insists the client really did fetch the patch and really did fall back
to the full payload — an attack the client never tried is not one it withstood.

`expect: no-effect` needs a mutator that publishes a previous release (`Mutator.Previous`),
because a patch has nothing to attack until a client is installed on the bytes it
starts from. `TestDeltaBaselineTakesThePatch` is the control: on an honest repository
the same client must patch both files and never fetch a full payload, or the whole
class would pass on a client that quietly ignored every patch it was offered.

## How a case is built

`harness.BuildRepo` builds a repository in four phases, and a mutator hooks exactly one:

| Phase | What a mutator can do there |
|---|---|
| `Content` | change the descriptor/pointer bytes before they become targets |
| `Metadata` | change role objects (expiry, versions, thresholds) before signing |
| `Signing` | redirect which key signs which role |
| `OnDisk` | change published bytes *after* signing — the only way to make content disagree with signed metadata |

A mutator that attacks the trust anchor itself sets `SeedMutatedRoot: true`. Without it
the client keeps the root it shipped with and simply ignores a served root of an
already-trusted version — which is TUF working correctly, not an attack surviving.

## Case format

Each corpus case is a directory containing a `case.yaml` that names a registered
mutator. The mutated repository is built at test time from the same baseline as
`fixtures/valid-repo`, so *only* the attack differs from a known-good repository.

```yaml
# corpus/expired/timestamp/case.yaml
description: "timestamp metadata is expired at the reference time"
class: expired
expect: reject               # the client MUST refuse; the loader accepts nothing else
error_class: verify          # which layer must do the refusing
mutator: expired_timestamp   # a name from harness.Mutators
notes: "expiry judged via UnsafeSetRefTime, never the wall clock"
```

### The clock axis

Not every attack is on the bytes. A case may instead name a manipulation of the
client's *environment*:

```yaml
# corpus/clock-rollback/revive-expired-metadata/case.yaml
description: "the local clock is turned back to bring expired metadata back inside its window"
class: clock-rollback
expect: reject
error_class: clock
clock: rollback              # no mutator: the repository is the honest baseline
```

A case has to attack something — the loader refuses one with neither a mutator, a
clock attack nor a history attack — but it may attack the repository, the clock, or
both.

A clock case is driven by `harness.RunInstall`, which runs the real first-install path
(`core/installer`, and through it the updater, the time floor and the apply
transaction) rather than a bare trust client. That is not decoration: the known-good
time floor lives with the *installation*, so only a run that owns an install root has
one at all. Calling it twice with the same work directory is the point — that is one
machine, running twice.

### The history axis

Some attacks only exist against a client with a past: version 1 metadata is only a
rollback to a client that has seen version 5, an older release is only a downgrade
where something newer is installed, and a server that stops publishing only freezes a
client that had something to be frozen on. A case names such an attack instead of a
mutator:

```yaml
# corpus/rollback/older-metadata-replayed/case.yaml
class: rollback
expect: reject
error_class: verify
history: rollback            # also: freeze, downgrade
```

The runner builds both phases itself from the honest baseline and serves them from one
URL — publish, let the client come to trust it, then change what the URL answers — so a
history case takes no mutator and no clock attack, and the loader refuses one that
names either. The first phase is asserted to succeed, and each attack carries a control
that proves the refusal is the client's memory:

| `history` | the client first… | then the server… | control |
|---|---|---|---|
| `rollback` | trusts every role at version 5 (`harness.AdvancedMetadataVersions`) | replays the version 1 baseline | a client with no cache accepts the replay |
| `freeze` | trusts the baseline | serves it unchanged, 30 days later | the same client accepts fresh metadata at that clock |
| `downgrade` | has 1.2.0 installed (`RunInstall`) | points the channel at 1.1.0, with every role version raised | a machine with nothing installed installs it |

A rollback or freeze refusal must also leave the timestamp the client trusts byte for
byte as it was. A downgrade is driven through the installed machine's updater
(`harness.RunUpdate`: check, then apply what is offered), and must leave the
installation on 1.2.0 with none of 1.1.0's bytes under its root.

`error_class` is checked, not just recorded — a case that is rejected for the wrong
reason fails. The five classes:

- `verify` — the TUF trust layer refused: signature, threshold, expiry, freshness, or a
  target that does not match its signed hash/length.
- `descriptor` — the document is authentic but malformed or dangerous (bad schema, path
  traversal, duplicate destination, setuid bit).
- `resolve` — two authentic documents disagree: the channel pointer and the descriptor
  name different versions, platforms, or paths. TUF cannot catch this; idunn must.
- `clock` — the monotonic known-good time floor refused: the local clock is below a
  point this installation has already passed (§14.7, T22). The repository may be
  flawless; the attack is on the machine.
- `policy` — the updater's app-level policy refused (`updater.ErrPolicy`): every
  document is authentic and current, and this installation still may not take the
  release — it is older than what is installed (T3). TUF cannot catch this, and should
  not: a publisher may point a channel anywhere.

`TestBaselineIsAccepted` is the control: a suite that rejects a *valid* repository too
would be green and worthless.

Adding a case = register a mutator in `harness/mutate.go` and drop a directory with a
`case.yaml` naming it. Keep it minimal and deterministic.

## Harness

The runner lives in `harness/corpus_test.go` (build tag `redteam`). For each case it
builds the mutated repository, serves it, points a fresh client at it, and asserts:

1. the client **rejected** it — an acceptance is reported as `VULNERABILITY`;
2. the rejection came from the **expected layer** (`error_class`);
3. **nothing was written** to the install root (fail closed).

The client under test (`harness/client.go`) runs the real resolve path — `trust.Refresh`,
channel pointer to descriptor, then materialize every target — because a repository that
is refused at download time but accepted at resolve time is still a break.

A clock case asserts a different shape, because its first step is a *legitimate* install
that has to succeed: the honest run installs, the metadata later expires and is refused,
the same repository is then resolved successfully by a bare trust client at the
rolled-back clock — which is what proves the repository itself is happy with it — and
only the run that owns a floor refuses. The installation is asserted unchanged
afterwards.

Fuzz targets live next to the code they attack, not here:
`FuzzDescriptor` (`core/release`), `FuzzDstSanitize` and `FuzzPatchApply`
(`core/stage`). The `patch-poison` case follows once the repository publishes patch
targets; the reader it will feed is already fuzzed.

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