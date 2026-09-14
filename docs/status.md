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
| §4.1 | Delegations, dedup, retention | **partial** — the packer delegates per channel and per release line from the first publish, and content-addressed payload targets deduplicate; retention is open (IDN-03) |
| §5 | Installer flow | **done** — `core/installer` plus the `cmd/installer` binary: embedded anchor, flags, elevation decision, exit codes |
| §6.1 | Blue/green layout + pointer | **done** — `internal/layout`, symlink (POSIX) / pointer file (Windows), plus the launcher shim (`core/launch`, `cmd/launcher`) |
| §6.2 | Transaction flow, journal, recovery | **done** — `core/txn`, crash-injection tests |
| §6.3 | Updater API (`CheckForUpdate`, `Apply`) | **done** — `Apply` installs the releases a migration floor demands in between, in order, each its own transaction (§6.4). `Policy` has no expiry switch: metadata expiry is go-tuf's alone, tested through the updater (IDN-15) |
| §6.4 | Delta stage 1 (content-addressed reuse) | **partial** — go-tuf cache reuse works, and an unchanged file is now taken from `current`/a retained version and verified against its signed target before it is staged (IDN-10); two named pieces are still missing: the reuse is a copy rather than a reflink/hardlink, and a file that changed destination between releases is not looked up by content hash |
| §6.4 | Delta stage 2 (binary patches) | **done** — the format on both sides (`stage.ApplyPatch`, `internal/delta`), the walk a skipped-releases client follows (`release.Chain`, `trust.Versions`), staging that rebuilds a changed file from the cheapest published patches and verifies every hop, a packer that emits patch targets against the last N releases (`delta:` in pack.yaml), and a `MinFromVersion` floor that is now walked rather than refused where the repository publishes releases that bridge it. Three corpus cases attack the patches (IDN-14) |
| §7 | Hook system | **done** — all six hooks defined and wired |
| §8 | Headless default, UI sidecars | **done** in `core` (no UI dependency); `idunn-fyne` is the first out-of-tree sidecar and exercises the `Observer`/`Prompter` surface end to end (IDN-19) |
| §9 | Packer | **partial** — `cmd/packer publish` builds and signs a release end to end (`internal/packer`); retention (step 4) is open |
| §10 | TUF repository layout | **done** — the packer produces it, the client resolves it, a golden test pins the emitted bytes |
| §11 | Security concept | **done** as a document; per-threat coverage below |
| §12 | Test concept | **partial** — see coverage below; no mutation testing, one fuzz target missing |
| §13 | Cross-platform specifics | **partial** — layout, elevation and the launcher hand-over are per-OS; no `MoveFileEx` self-update of the launcher itself (IDN-17) |
| §14.1 | GC / retention | **done** — `stage.GC`, soft-fails on locked dirs |
| §14.2 | Elevation | **partial** — Windows `ElevationInteractive` done for installs and updates: the unprivileged side writes nothing under the root, the helper (`cmd/installer apply`, or a host verb on `Updater.ApplyRequested`) re-resolves and runs the transaction; tested end to end through real UAC prompts (`elevated` e2e scenario). `ElevationService` fails closed everywhere; POSIX interactive (`pkexec`, Authorization Services) not built; the helper refuses a root anyone but an administrator controls (IDN-22); recovery and deferral in a system root are open (IDN-23) |
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
(`stage.GC`), T17 (quiesce), T19 (installer preflight), T20 (`Outcome` carries no paths
or raw error strings), T21 (every staged byte re-checked against the signed hash),
T22 (`core/timefloor`: the known-good floor is checked before every refresh and
before an apply, and raised by every successful refresh).

Not yet enforced:

- **T16, T23** (LPE via the helper, cache TOCTOU) — the helper service does not exist;
  `NewService` fails closed. The Windows interactive path enforces its half: three
  validated scalars cross the boundary, nothing else; the helper validates them
  again, resolves the channel head itself and refuses any other version, and keeps
  its TUF cache inside the root rather than in the user's. It refuses a
  caller-chosen root that anyone but an administrator could change — owner, ACL,
  inheritable ACEs, reparse points, drive kind (IDN-22).
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
| `internal/packer` | 86.1% — publish end to end against `core/trust`, plus golden metadata |
| `cmd/installer` | not in the coverage universe, but tested: a real install against a served repository |

The adversarial corpus (`make redteam-corpus`, build tag `redteam`) holds 25 cases
across clock rollback, expiry, malformed descriptors, mix-and-match, path traversal,
resolve (pointer/descriptor disagreement), unknown key, wrong hash, wrong key, wrong
length, and delta patches. Most attack the repository; the clock case attacks the
machine, and the three delta cases attack an update in progress — all of these are
driven through the real install path, because a time floor and a patch base both only
exist where there is an installation.

The delta cases are the ones that do not expect a refusal: a patch is untrusted input
whose result is checked against a signed hash, so they assert something stricter —
that the update still arrives, that every installed byte is the signed one, and that
nothing the attacker chose is anywhere on disk, having first established that the
client did fetch the patch and did fall back to the full payload. A control case
(`TestDeltaBaselineTakesThePatch`) keeps them honest by requiring that the same client
patches an honest repository rather than downloading it.

Fuzzers: `FuzzDescriptor`, `FuzzDstSanitize`, `FuzzPatchApply`.

The real-world update test (`test/e2e/run.sh`, workflow `E2E update` on every push to
`main`, on Linux, Windows and macOS) is the one test with nothing in process: it
publishes a host application with `cmd/packer` as the assets of a GitHub release in
the sandbox repository `go-idavoll/idunn-e2e`, installs it from github.com, publishes
further releases into the same repository, and has the installed application update
itself headlessly through `cmd/launcher`. Three scenarios: `minor` (1.0.0 → 1.1.0 →
1.2.0), `major` (1.0.0 → 2.0.0 → 2.1.0), and `floor-gap`, where 1.2.0 requires
`min_from_version` 1.1.0, which is never published, and the update must be refused
with 1.0.0 left untouched. Every step is attested — exit code, installed and running
version, version directories, last journal record, staging — into a JSON report per
job, merged into one matrix by the summary job. TUF paths are mapped onto flat asset
names by `test/e2e/ghfetch`. `E2E_MODE=local` runs the same script against a local
server. A fourth scenario, `elevated`, is Windows-only and interactive and therefore
not in CI: it installs 1.0.0 into `%ProgramFiles%` and updates to 1.1.0 through
real UAC prompts, checks that the check in between needs none, and refuses a
user-owned root twice — before the prompt, and in the helper started elevated by a
hostile caller.

## Deliberate non-goals for now

These are open in the design and stay open on purpose, not by oversight: TAP-4
multi-repository consensus, hash-bin delegations (the reserve path for extreme target
counts), Uptane, and authenticated time (Roughtime/NTS).
