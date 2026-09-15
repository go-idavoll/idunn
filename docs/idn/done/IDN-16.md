# IDN-16 — Mutation testing (§12, AGENTS.md §4) — **done**

**Priority:** P2 — hardening and reach

`make mutate` runs [gremlins](https://github.com/go-gremlins/gremlins) (pinned in the
Makefile as `GREMLINS_VERSION`, installed with `make mutate-tools`) over the lifecycle
packages `core/txn`, `core/stage`, `core/updater` and `core/launch`, and fails below a
threshold on efficacy and on mutant coverage. The `Mutation` workflow runs it as one job
per package on every pull request and push that touches `core/`, `internal/`, the module
files or the Makefile, and weekly on `main`. `make mutate-survivors` prints the list
worth reading.

The thresholds (75% on both, in `.gremlins.yaml`) sit below every score recorded in
[`status.md`](../../status.md#mutation-score). They exist to catch a regression, not to be
exactly met, and raising them as gaps close is the intended ratchet. A `TIMED OUT`
mutant counts toward neither score, so a slow runner cannot turn the job red by itself.

Two practical notes. First, the thresholds cannot be command-line flags: gremlins
v0.6.0 binds `--threshold-efficacy` and `--threshold-mcover` as float flags that its
configuration layer hands back as strings, so given on the command line they are
silently ignored and a run far below them exits 0. Read from the config file they are
numbers and do gate (a run against an unreachable 99% exits 10). Re-check that whenever
the pinned version changes. Second, gremlins derives a per-mutant test timeout from the
baseline run, and its default is too tight for suites that do filesystem work: without
a `timeout-coefficient` every mutant is reported `TIMED OUT` and every score as 0%,
which reads as a catastrophe and is a misconfiguration.

It paid for itself on the first run. The record ceiling in `core/txn`'s `parse` was
covered but not *pinned*: `>` and `>=` were interchangeable as far as the suite could
tell, because the only test of it was an oversize file that the length bound refuses
first. `TestOpenAcceptsExactlyTheRecordCeilingAndRefusesOneMore` holds it now. The one
survivor left in that package is argued rather than fixed: the same ceiling in `Append`
cannot be reached, because a `BEGIN` resets the history and the transition table bounds
a transaction at six records. It stays as defence against a future table that loops —
deleting a check to raise the score is the reward-hacking AGENTS.md §6 warns about.

Open: the survivors in `core/stage` cluster in `patch.go` (the delta reader's bounds and
arithmetic) and `route.go`; `core/launch` has four. Each is a test gap to close, with a
test, before the threshold for that package is raised.
