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
| §4.1 | Delegations, dedup, retention | **partial** — the packer delegates per channel and per release line from the first publish, and content-addressed payload targets deduplicate; retention (`retention.keep`) retires releases beyond a per-platform window of the line being published by reference counting (IDN-03). Retiring a whole major at end of life is not built |
| §5 | Installer flow | **done** — `core/installer` plus the `cmd/installer` binary: embedded anchor, flags, elevation decision, exit codes |
| §6.1 | Blue/green layout + pointer | **done** — `internal/layout`, symlink (POSIX) / pointer file (Windows), plus the launcher shim (`core/launch`, `cmd/launcher`), which also restarts an application that asks for it (exit code 42 / `launch.Relaunch`, IDN-29) |
| §6.2 | Transaction flow, journal, recovery | **done** — `core/txn`, crash-injection tests |
| §6.3 | Updater API (`CheckForUpdate`, `Apply`) | **done** — `Apply` installs the releases a migration floor demands in between, in order, each its own transaction (§6.4). `Policy` has no expiry switch: metadata expiry is go-tuf's alone, tested through the updater (IDN-15) |
| §6.4 | Delta stage 1 (content-addressed reuse) | **partial** — go-tuf cache reuse works, and an unchanged file is now taken from `current`/a retained version and verified against its signed target before it is staged (IDN-10); two named pieces are still missing: the reuse is a copy rather than a reflink/hardlink, and a file that changed destination between releases is not looked up by content hash |
| §6.4 | Delta stage 2 (binary patches) | **done** — the format on both sides (`stage.ApplyPatch`, `internal/delta`), the walk a skipped-releases client follows (`release.Chain`, `trust.Versions`), staging that rebuilds a changed file from the cheapest published patches and verifies every hop, a packer that emits patch targets against the last N releases (`delta:` in pack.yaml), and a `MinFromVersion` floor that is now walked rather than refused where the repository publishes releases that bridge it. Three corpus cases attack the patches (IDN-14) |
| §7 | Hook system | **done** — all six hooks defined and wired |
| §8 | Headless default, UI sidecars | **done** in `core` (no UI dependency); `idunn-fyne` is the first out-of-tree sidecar and exercises the `Observer`/`Prompter` surface end to end (IDN-19) |
| §9 | Packer | **done** — `cmd/packer publish` builds and signs a release end to end (`internal/packer`), including retention (step 4, IDN-03) |
| §10 | TUF repository layout | **done** — the packer produces it, the client resolves it, a golden test pins the emitted bytes |
| §11 | Security concept | **done** as a document; per-threat coverage below |
| §12 | Test concept | **partial** — see coverage below; mutation testing gated in CI (IDN-16, [score](#mutation-score)); one fuzz target missing |
| §13 | Cross-platform specifics | **done** — layout, elevation and the launcher hand-over are per-OS, and the launcher replaces itself: the updater stages the verified launcher only after the commit, the launcher swaps it in at its next start — a rename over the name on POSIX, rename-aside plus `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` on Windows, whose crash window between the two renames is a documented residual risk repaired by the next start, the updater or `launch.Relaunch`; soft-skipped in a root the user cannot write (IDN-17, IDN-23) |
| §14.1 | GC / retention | **done** — `stage.GC`, soft-fails on locked dirs |
| §14.2 | Elevation | **partial** — Windows `ElevationInteractive` done for installs and updates: the unprivileged side writes nothing under the root, the helper (`cmd/installer apply`, or a host verb on `Updater.ApplyRequested`) re-resolves and runs the transaction; tested end to end through real UAC prompts (`elevated` e2e scenario). Linux `ElevationInteractive` via `pkexec` (fixed pkexec path, root-only helper, argv, empty environment; IDN-08), unit-tested on every OS and against a stand-in pkexec on Linux, with no e2e scenario through a real polkit agent; macOS has no prompt by decision (service mode, IDN-07). `ElevationService` works on POSIX (Unix socket, kernel peer credentials) and Windows (named pipe with a helper-built DACL, first-instance and remote-client refusal, client token user SID via impersonation; empty allow-list = SYSTEM only), both with allow-listed and re-checked roots and `updater.RequestApplier` (IDN-07); on macOS the helper is an `SMAppService` daemon (registration API, deterministic LaunchDaemon plist, optional code-signing `PeerRequirement` via the audit token; cgo, compiled and tested on the macOS CI runner only — registration itself needs a signed bundle and user approval and is not tested; IDN-08); the helper refuses a root anyone but an administrator controls (IDN-22); recovery and deferral in a system root are open (IDN-23) |
| §14.3 | Quiesce, app lock, `OnBusy` | **done** — lock + coordinator + all three policies; `BusyDeferToRestart` keeps the staged tree in a resting `DEFERRED` journal state and the launcher finishes it at the next start. `BusyAbort` is the zero value and is not promoted; deferral is a recommendation to the host, which the design now says in those words (IDN-21) |
| §14.4 | Enterprise proxy / CA | **partial** — system trust store, `ExtraCAs`, env proxy, resumable ranged downloads with offset checks, proxy authentication, mTLS client certificates, and a `ProxyResolver` seam; the OS-native resolvers (PAC/WPAD, WinHTTP, `SCDynamicStore`, GSettings) are the remainder of IDN-13 |
| §14.5 | Telemetry + staged rollout | **done** — `Reporter` with a closed error-class vocabulary; local rollout bucketing |
| §14.6 | Installer downgrade preflight | **done** |
| §14.7 | Clock skew | **done** — expiry is classified as `clock_skew`, and `core/timefloor` persists the monotonic known-good time floor that refuses a rolled-back clock |
| §14.8 | Shared TUF cache in elevated mode | **partial** — separate caches: the privileged side's lives in `<root>/.updater/tuf` (`PrivilegedCacheDir`), never the caller's; the fd hand-off that would avoid the helper's second download (`SCM_RIGHTS` / `DuplicateHandle` pulled by the helper over the now-authenticated socket or pipe) is open (IDN-07) |

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

- **T16, T23** (LPE via the helper, cache TOCTOU) — the helper service, on POSIX and
  Windows, authenticates the caller from the kernel (peer credentials; the pipe
  client's token), allow-lists and re-checks the root, and keeps a privileged cache;
  on Windows it also builds the pipe DACL, refuses a squatted pipe name and remote
  clients; on macOS it can additionally require the caller's code signature
  (`PeerRequirement`). The fd hand-off (T23) and a client-side check of the pipe's server are
  open. The
  Windows and Linux interactive paths enforce their half: three
  validated scalars cross the boundary, nothing else; the helper validates them
  again, resolves the channel head itself and refuses any other version, and keeps
  its TUF cache inside the root rather than in the user's. It refuses a
  caller-chosen root that anyone but an administrator could change — owner, ACL,
  inheritable ACEs, reparse points, drive kind (IDN-22). On Linux the helper binary
  itself is vetted too: pkexec runs it only if it and every directory above it are
  root-owned and writable by nobody else (IDN-08).
- **T18** (enterprise DPI) — tolerated by design, and the availability half now has
  resumable downloads, proxy authentication and mTLS (IDN-13). OS-native proxy
  resolution including PAC is still missing, so a machine whose proxy is configured
  only in the OS (not the environment) needs the host to supply a `ProxyResolver`.

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
| `core/fetch` | 97% — TLS trust store, user agent, timeout, the refusals, and the enterprise path: resume across dropped links, every inconsistent partial response refused, restart on 200/416, mutual TLS against a real handshake, proxy credentials on a real CONNECT and forwarded request, and a refused proxy login |
| `core/hook` | no test files (interface definitions only) |
| `core/launch` | 84.7% — deferred updates applied, skipped, failed, and nothing to do, plus the launcher swapping in a staged launcher: refusals of non-regular or implausible staged files and of a launcher outside its root, only-committed staging across every journal state, an unwritable root, crash injection at every step of both strategies with repair (`internal/launcherfile`, a real running executable on Windows) |
| `core/timefloor` | 94.0% — the floor, its refusals, and a damaged or unwritable floor file |
| `internal/packer` | 86.1% — publish end to end against `core/trust`, plus golden metadata |
| `cmd/installer` | not in the coverage universe, but tested: a real install against a served repository |

The adversarial corpus (`make redteam-corpus`, build tag `redteam`) holds 28 cases
across clock rollback, downgrade, expiry, freeze, malformed descriptors, mix-and-match,
path traversal, resolve (pointer/descriptor disagreement), rollback, unknown key, wrong
hash, wrong key, wrong length, and delta patches. Most attack the repository; the clock
case attacks the machine, and the three delta cases attack an update in progress — all
of these are driven through the real install path, because a time floor and a patch
base both only exist where there is an installation.

The rollback, freeze and downgrade cases attack the client's *memory*: the metadata it
already trusts and the release it already has installed. Each runs in two phases
against one URL — an honest publish the client comes to trust, then different bytes —
and each carries a control that shows the refusal is that memory at work: a client
with no cache accepts the replayed repository, the same client accepts fresh metadata
at the clock where withheld metadata is refused, and a machine with nothing installed
installs the older release the installed machine's updater refuses (T3, T4, T5).

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

The local end-to-end scenarios (`go test -tags=e2e ./test/e2e/local/...`, not in CI
yet, run on Windows) drive the failure paths that run needs no GitHub for, with the
same real binaries against a repository on 127.0.0.1: a busy application that
defers and the launcher that finishes it; a process killed in `download`, `apply`
and `verify`, each settled by the launcher's recovery to one exact whole version; a
failing host migration that unwinds, `Rollback` hook included; the installer's
downgrade preflight; a same-length tampered payload, refused for the hash with the
bytes attested as served whole (so a 404 or truncation cannot pass it); and
retention windows of three and two.

One of them runs in CI: `TestServiceModeInstallsAndUpdatesThroughTheHelper`, job
`helper service mode (Linux, root)`, skipped anywhere but Linux as root. It uses
the reference `cmd/helper`, built with a generated anchor through
`go build -overlay`, as a real daemon. `allow` and `serve` run as root, and the
application runs as uid 65534. A system-wide root under `/usr/local` is
installed at 1.0.0 and updated to 1.1.0 only through the helper's socket.
Pointer, state and a committed journal agree; everything under the root is
root's; the helper's TUF cache is `PrivilegedCacheDir`; and the application's
user can write nothing in the root. A uid nobody allowed is denied (`ErrDenied`),
and a request for a release behind the channel head is refused with nothing
changed.

## Supply chain

| Property | State |
|---|---|
| Reproducible packer output | pinned by `internal/packer`'s golden test (IDN-01) |
| Reproducible binaries | `scripts/repro.sh`: `cmd/installer`, `cmd/launcher`, `cmd/packer` for linux/windows/darwin × amd64/arm64, built twice from two directories with two empty caches, gated in CI (`reproducible builds`), digests and Go version in the job summary (IDN-18) |
| Build provenance | `Release provenance` workflow on `v*` tags, `actions/attest-build-provenance`; binaries kept as a workflow artifact, no GitHub release is published yet (IDN-18, partly done) |
| Trust anchor | embedded `root.json`, never fetched |

## Mutation score

`make mutate` (gremlins v0.6.0, configured by `.gremlins.yaml`) over the lifecycle packages,
run as the `Mutation` workflow (IDN-16). *Efficacy* is the share of covered mutants the
suite kills; *mutant coverage* is the share of mutants any test reaches at all. Measured
on the tree that closed IDN-16 (Windows, Go 1.25):

| Package | Killed | Lived | Not covered | Efficacy | Mutant coverage |
|---|---|---|---|---|---|
| `core/txn` | 74 | 1 | 2 | 98.7% | 97.4% |
| `core/updater` | 150 | 17 | 5 | 89.8% | 97.1% |
| `core/stage` | 142 | 29 | 9 | 83.0% | 95.0% |
| `core/launch` | 18 | 4 | 0 | 81.8% | 100% |

CI gates at 75% on both (`.gremlins.yaml`), which catches a regression without failing on the weather;
the numbers above are what to raise it towards, per package. `core/launch` is the
closest to the line: it has few mutants, so a single new survivor moves it by about
four points.

A surviving mutant is a test gap, never a reason to weaken an assertion — a change that
raises this score by deleting a check is the reward-hacking AGENTS.md §6 asks reviewers
to look for. The one survivor in `core/txn` is argued rather than fixed: the record
ceiling in `Append` cannot be reached, because a `BEGIN` resets the history and the
transition table bounds a transaction at six records. It stays as defence against a
future table that loops. The survivors in `core/stage` cluster in `patch.go` (the delta
reader's bounds and arithmetic).

## Deliberate non-goals for now

These are open in the design and stay open on purpose, not by oversight: TAP-4
multi-repository consensus, hash-bin delegations (the reserve path for extreme target
counts), Uptane, and authenticated time (Roughtime/NTS).
