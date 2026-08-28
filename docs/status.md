# Implementation status

What of [`design.md`](design.md) exists in code today, section by section. This file is
the map; [`backlog.md`](backlog.md) is the list of work that follows from the gaps.

Reconciled against the tree at branch `claude/idn-packer-delegations-1g5v9s`.
Legend: **done** — implemented and tested; **partial** — the path exists but a named
piece of the section is missing; **open** — contract only, or nothing.

## Summary

| Design section | Area | State |
|---|---|---|
| §2 | Module & package layout | **done** — every package in the design exists at the named path |
| §3.1 | Payload files as TUF targets | **done** |
| §3.2 | Release descriptor & channel pointer | **done** — `core/release`, strict parse, fuzzed |
| §4 | TUF roles & key management (client side) | **done** — embedded root, `Refresh`, resolve |
| §4.1 | Delegations, dedup, retention | **done** — the packer delegates per channel and per release line from the first publish, content-addressed payload targets deduplicate, and `--retain N` retires releases beyond the window together with every payload no retained release names |
| §5 | Installer flow | **done** — `core/installer` plus the `cmd/installer` binary: embedded anchor, flags, elevation decision, exit codes |
| §6.1 | Blue/green layout + pointer | **done** — `internal/layout`, symlink (POSIX) / pointer file (Windows), plus the launcher shim (`core/launch`, `cmd/launcher`) |
| §6.2 | Transaction flow, journal, recovery | **done** — `core/txn`, crash-injection tests |
| §6.3 | Updater API (`CheckForUpdate`, `Apply`) | **done** |
| §6.4 | Delta stage 1 (content-addressed reuse) | **partial** — go-tuf cache reuse works; local relink from `current`/retained versions is not implemented |
| §6.4 | Delta stage 2 (binary patches) | **open** — `stage.ApplyPatch` fails closed |
| §7 | Hook system | **done** — all six hooks defined and wired |
| §8 | Headless default, UI sidecars | **done** in `core` (no UI dependency); sidecar repos are out of tree |
| §9 | Packer | **done** — `cmd/packer publish` builds, signs and retires end to end (`internal/packer`) |
| §10 | TUF repository layout | **done** — the packer produces it, the client resolves it, a golden test pins the emitted bytes |
| §11 | Security concept | **done** as a document; per-threat coverage below |
| §12 | Test concept | **partial** — unit, adversarial corpus and an end-to-end suite over the real binaries (`test/e2e`, IDN-22); no mutation testing, one fuzz target missing |
| §13 | Cross-platform specifics | **partial** — layout, elevation and the launcher hand-over are per-OS; no `MoveFileEx` self-update of the launcher itself (IDN-17) |
| §14.1 | GC / retention | **done** — `stage.GC`, soft-fails on locked dirs |
| §14.2 | Elevation | **partial** — Windows `ElevationInteractive` done, and `cmd/installer apply` is the privileged helper it launches; `ElevationService` fails closed everywhere; POSIX interactive (`pkexec`, Authorization Services) not built |
| §14.3 | Quiesce, app lock, `OnBusy` | **done** — lock + coordinator + all three policies; `BusyDeferToRestart` keeps the staged tree in a resting `DEFERRED` journal state and the launcher finishes it at the next start. `BusyAbort` is the zero value and is not promoted; deferral is a recommendation to the host, which the design now says in those words (IDN-21) |
| §14.4 | Enterprise proxy / CA | **partial** — system trust store + `ExtraCAs` + env proxy, now under test; no PAC/WPAD resolution, no ranged resume, no mTLS |
| §14.5 | Telemetry + staged rollout | **done** — `Reporter` with a closed error-class vocabulary; local rollout bucketing |
| §14.6 | Installer downgrade preflight | **done** |
| §14.7 | Clock skew | **done** — expiry is classified as `clock_skew`, and `core/timefloor` persists the monotonic known-good time floor that refuses a rolled-back clock |
| §14.8 | Shared TUF cache in elevated mode | **open** — belongs to the unbuilt helper service |

## Threat model coverage (§11.3)

Enforced in code, with a test: T1–T6, T7 (`internal/safepath`, fuzzed), T8 (structural
— no code is ever fetched), T9 (`VerifyAfterApply`), T10 (`core/txn`), T11
(`Migrator.Rollback`), T12 (go-tuf), T13 (`internal/packer` resolves every role key
and verifies the repository before it writes anything, and refuses a root it cannot
publish under), T14 (`SchemaVersion`, `MinClientVersion`), T15
(`stage.GC`), T17 (quiesce), T19 (installer preflight, now also as a two-phase corpus
case where the channel head moves backwards under fresh metadata), T20 (`Outcome`
carries no paths or raw error strings), T21 (every staged byte re-checked against the signed hash),
T22 (`core/timefloor`: the known-good floor is checked before every refresh and
before an apply, and raised by every successful refresh).

Not yet enforced:

- **T16, T23** (LPE via the helper, cache TOCTOU) — the helper service does not exist;
  `NewService` fails closed. The Windows interactive path enforces its half: three
  validated scalars cross the boundary, nothing else.
- **T18** (enterprise DPI) — tolerated by design, but PAC and resumable downloads are
  missing, so the *availability* half is incomplete.

## Test state

`go test ./...` is green. `go test -covermode=atomic ./core/... ./internal/...`:

| Package | Coverage |
|---|---|
| `core/elevate` | 94.6% |
| `core/release` | 94.4% |
| `core/fsx` | 93.3% |
| `core/stage` | 90.8% |
| `core/updater` | 88.9% |
| `core/installer` | 86.8% |
| `core/txn` | 86.6% |
| `core/trust` | direct unit tests of the resolve layer (New 91.7%, LatestRelease 94.7%, `ReleaseVersion` 90.9%), plus the red-team corpus end to end |
| `core/fetch` | `New` 95.2% — TLS trust store, user agent, timeout, and the refusals |
| `core/hook` | no test files (interface definitions only) |
| `core/launch` | 87.5% — deferred updates applied, skipped, failed, and nothing to do |
| `core/timefloor` | 94.0% — the floor, its refusals, and a damaged or unwritable floor file |
| `internal/packer` | 86.1% — publish end to end against `core/trust`, plus golden metadata and retention (window, reference counting, the pointer protection) |
| `cmd/installer` | not in the coverage universe, but tested: a real install against a served repository |
| `test/e2e` | not in the coverage universe by design — the work happens in child processes, which carry no instrumentation |

The end-to-end suite (`make e2e`, build tag `e2e`) holds nine scenarios that drive
`cmd/packer`, `cmd/installer`, `cmd/launcher` and a host application as separate
processes against a served repository: install and launch, self-update with the
predecessor retained, a deferral finished by the launcher, a crash inside the
transaction, a failing migration, the downgrade preflight, a tampered payload, delta
stage 1, and retention. It runs on all three platforms in CI. See
[`test/e2e/README.md`](../test/e2e/README.md).

The adversarial corpus (`make redteam-corpus`, build tag `redteam`) holds 25 cases
across clock rollback, downgrade, expiry, freeze, malformed descriptors, mix-and-match,
path traversal, resolve (pointer/descriptor disagreement), rollback, unknown key, wrong
hash, wrong key, and wrong length. Most attack the repository; the clock case attacks
the machine, and the rollback, freeze and downgrade cases attack the client's *memory* —
what it already trusts and what is already installed — so they run in two phases and are
driven through the real install path where a version floor is involved. Fuzzers: `FuzzDescriptor`, `FuzzDstSanitize`.
`FuzzPatchApply` waits on a patch format (§6.4 stage 2).

## Deliberate non-goals for now

These are open in the design and stay open on purpose, not by oversight: TAP-4
multi-repository consensus, hash-bin delegations (the reserve path for extreme target
counts), Uptane, and authenticated time (Roughtime/NTS).
