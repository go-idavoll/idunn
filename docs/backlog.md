# Backlog

Everything [`design.md`](design.md) describes that the code does not do yet, as
work items. The status map it derives from is [`status.md`](status.md).

IDs are stable — reference them in commits and PRs (`feat(packer): IDN-01 …`).
Priority is about unblocking: P0 items block a first usable release, P1 items block
a *trustworthy* one, P2 items are hardening and reach.

---

## P0 — blocks a first end-to-end release

### IDN-01 — Packer: publish a TUF repository (§9)
`cmd/packer` prints "not implemented". Nothing in this repo can produce the
repository the client already knows how to consume; only the red-team harness builds
one, with test keys, for tests.

Scope: read `pack.yaml`; add each payload file as a target with `dst`/`mode`/`kind` in
`custom`; write the release descriptor and the channel pointer as targets; sign the
delegated targets role, then `snapshot` and `timestamp`; consistent snapshots on.

Done when: a `publish` run produces a repository that `core/trust` resolves end to
end; role keys come from env/HSM only and a missing key aborts before any file is
written (T13); output is byte-identical across two runs with the same inputs
(AGENTS.md §1.7); golden test on the emitted metadata.

### IDN-02 — Packer: delegations from day 1 (§4.1)
Targets must land in a delegated role per channel and major (`stable-v2`, `beta`), not
in the top-level `targets.json`. The design calls this mandatory rather than optional
because retrofitting it later is a migration for every client.

Done when: `targets.json` contains delegations only, and a client that follows one
channel loads only that delegation.

### IDN-03 — Packer: retention (§4.1, §9 step 4)
Remove targets of retired releases beyond a keep window, respecting delta patch
sources. Without it the delegation grows for the lifetime of the product.

### IDN-04 — `cmd/installer`: the actual binary (§5)
`core/installer` is complete and tested; the binary around it is a stub. Needs the
embedded `root.json` (`go:embed`), flag parsing (`--root`, `--channel`, `--version`),
the elevation decision via `elevate.NeedsElevation`, and exit codes that distinguish
`ErrRefused` from a real failure.

### IDN-05 — Launcher shim (§6.1, §13, §14.3)
The layout the design draws starts with a small stable launcher that execs
`current/app` and, before it does, applies a pending staged update while no lock is
held. It does not exist. Two features depend on it: `BusyDeferToRestart` (IDN-06) and
Windows self-replacement of the launcher itself.

---

## P1 — blocks a trustworthy release

### IDN-06 — `BusyDeferToRestart` actually defers (§14.3)
Today it rolls back cleanly and returns `ErrDeferred`, which is correct but throws
away the staged tree. Needs a resting journal state for a deferred transaction that
recovery will not undo, plus the launcher (IDN-05) to finish it at next start.

### IDN-07 — Privileged helper service and its IPC (§14.2, §14.8, T16, T23)
`elevate.NewService` fails closed. This is the largest remaining piece and the one
with the most attack surface: peer-credential authentication (Windows named-pipe
client token, Linux `SO_PEERCRED`, macOS audit token), a full TUF `Refresh` +
verification inside the privileged context, request-shape validation, rate limiting,
and the read-only fd hand-off (`SCM_RIGHTS` / `DuplicateHandle` pulled by the helper)
that avoids both a second download and path-based TOCTOU.

Done when: the helper installs only what it verified itself, never a caller-supplied
path, and the corpus grows cases for a hostile caller.

### IDN-08 — POSIX interactive elevation (§14.2)
`ElevationInteractive` exists on Windows only; `interactive_other.go` returns
`ErrNotImplemented`. Needs `pkexec`/polkit on Linux and Authorization Services /
`SMAppService` on macOS, with the same three-scalar request grammar the Windows path
already enforces.

### IDN-09 — Monotonic known-good time floor (§14.7, T22)
Persist `max(build time, timestamp of the last validly seen metadata)` and refuse a
local clock below it. Expiry is already classified as `clock_skew`; the floor — the
part that actually defends clock rollback — is missing.

### IDN-10 — Local reuse of already-installed files (§6.4 stage 1, second half)
`stage.stageFile` always takes bytes from the trust layer. Unchanged files present in
`current/` or a retained version should be reused by verified content hash
(reflink/CoW, else hardlink, else copy) — re-hashed, never adopted on name alone.
Needs the signed hash surfaced from `core/trust`, which the `Materializer` interface
does not expose yet.

### IDN-11 — Test coverage for `core/trust` and `core/fetch`
Both sit at 0% under `make cover`. `core/trust` is covered end to end by the red-team
corpus, `core/fetch` not at all. The 100% goal for lifecycle code (§12) is not met
while the wrapper around the trust core has no direct tests of its resolve logic —
pointer/descriptor disagreement, path-vs-content mismatch, `ReleaseVersion`.

### IDN-12 — Streaming targets instead of whole-file buffers
`trust.Target` holds every payload in memory because go-tuf's `DownloadTarget`
returns a slice (`TODO(stage)` in `core/trust`). A multi-hundred-megabyte payload is
a memory spike today. Needs a fetcher that exposes the response body.

---

## P2 — hardening and reach

### IDN-13 — Enterprise transport: PAC, resume, mTLS (§14.4, T18)
`fetch.New` uses `http.ProxyFromEnvironment` and honours the system trust store.
Missing: OS-native proxy resolution incl. PAC (WinHTTP/WinINET, `SCDynamicStore`,
GSettings) behind a `ProxyResolver`; ranged/resumable downloads (`Options.Resume` is
accepted and ignored today); proxy auth; mTLS client certificates.

### IDN-14 — Delta stage 2: intra-file binary patches (§6.4)
`stage.ApplyPatch` fails closed. Needs a chosen patch format (`zstd --patch-from`,
bsdiff), patch targets emitted by the packer against the last N versions, descriptor
`custom` references, fallback to the full target on mismatch, and `FuzzPatchApply`
(the `TODO(redteam)` in the Makefile).

### IDN-15 — Descriptor-level validity window (§6.3 `EnforceExpiry`)
Schema 1 descriptors carry no validity window, so `Policy.EnforceExpiry` currently
governs nothing beyond TUF's own metadata expiry (`TODO(release)` in
`core/updater`). Either add the field in schema 2 or drop the flag.

### IDN-16 — Mutation testing (§12, AGENTS.md §4)
`go-mutesting` (or equivalent) as the quality bar for assertions. Coverage is high;
nothing currently measures whether the tests would fail if the code were wrong.

### IDN-17 — Windows launcher self-replacement (§13)
Updating the launcher binary itself: rename-self plus
`MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`, or a restart. Depends on IDN-05.

### IDN-18 — Reproducible builds and provenance in CI (§9, §15)
Bit-identical artifacts and SLSA provenance as supply-chain proof beside TUF. Partly
enforced for packer output by IDN-01; this is the CI half.

### IDN-19 — UI sidecars (§8)
`idunn-fyne`, `idunn-bubbletea`, `idunn-web` are named in the README and do not
exist. Out of tree by design — one reference implementation would prove the
`Observer`/`Prompter` surface is sufficient.

### IDN-20 — Decide the mythology naming question (§2.1)
Left explicitly open in the design. Functional names are canonical in code today,
which is the recommended middle path; the decision is whether mythological names are
adopted as branding. Closing it costs nothing and removes a recurring question.

### IDN-21 — Reconcile the `OnBusy` default with the design (§6.3, §14.3)
`design.md` names `BusyDeferToRestart` the default and the recommended one; the code
leaves the zero value `BusyAbort` in place, because Go's zero value must be the
failing one and deferring does not work yet (IDN-06). Once it does, decide: either
`New` promotes an unset `OnBusy` to `BusyDeferToRestart`, or the design text drops
the claim. Today the two disagree.
