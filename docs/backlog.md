# Backlog

Everything [`design.md`](design.md) describes that the code does not do yet, as
work items. The status map it derives from is [`status.md`](status.md).

IDs are stable — reference them in commits and PRs (`feat(packer): IDN-01 …`).
Priority is about unblocking: P0 items block a first usable release, P1 items block
a *trustworthy* one, P2 items are hardening and reach.

---

## P0 — blocks a first end-to-end release

### IDN-01 — Packer: publish a TUF repository (§9) — **done**
`cmd/packer publish` reads `pack.yaml` and produces a repository `core/trust`
resolves end to end. Engine in `internal/packer`, contract in
[`packer.md`](packer.md). Two deviations from the sketch in the design, both argued
there: payload targets are content-addressed (which is what makes the §4.1 dedup
claim true), and `custom` is not used (`dst`/`mode`/`kind` are properties of a
release's *use* of a target and already live in the descriptor).

### IDN-02 — Packer: delegations from day 1 (§4.1) — **done**
`targets.json` holds delegations and no targets. The split is per channel
(`stable`) and per release line (`v2`) rather than one role per `(channel, major)`
pair, because a descriptor's target path deliberately carries no channel and the
patterns would otherwise overlap; the property the design asks for — disjoint
patterns, a client loading only what it follows — holds and is tested against
go-tuf's own matcher. See [`packer.md`](packer.md) §5.

### IDN-22 — End-to-end tests against the real binaries (§12) — **done**
`test/e2e` (build tag `e2e`, `make e2e`) drives the whole chain as separate
processes: `cmd/packer` publishes into a repository whose root came from a
throwaway ceremony, an HTTP server hands it out, and `cmd/installer`,
`cmd/launcher` and a host application built from `test/e2e/fixtures/app` consume
it. Nine scenarios cover install, self-update, deferral finished by the launcher,
a crash inside the transaction, a failing migration, the downgrade preflight, a
tampered payload, delta stage 1, and retention. CI runs it on all three
platforms, because that is where the install pointer, the launcher hand-over and
GC over a locked directory differ.

It is not in the coverage universe on purpose: the work happens in child
processes, which carry no instrumentation, so tagging it into that job would cost
runtime and credit nothing.

### IDN-03 — Packer: retention (§4.1, §9 step 4) — **done**
`--retain N` keeps the newest N releases per platform in the release line being
published and retires the rest, together with every payload no retained release still
names. Content addressing made it a reference-counting problem rather than a
path-guessing one, which is also what lets two releases share one payload safely.

Three boundaries, argued in [`packer.md`](packer.md) §4.1: it never retires a release
a channel pointer still names (read with the client's own parser, not inferred from a
path — that would be the freeze attack with the publisher holding the knife), it never
touches another release line (an end-of-life decision needing a key this publish was
not given), and it refuses a window of one. It is off by default, because deleting a
published target is the one thing a publish cannot undo.

### IDN-04 — `cmd/installer`: the actual binary (§5) — **done**
The binary carries its trust anchor and repository description in
`cmd/installer/anchor/` (`go:embed`), parses `--root`/`--channel`/`--version`, makes
the elevation decision via `elevate.NeedsElevation`, and distinguishes refusal (3),
a declined prompt (4) and "needs privileges it cannot get" (5) from a real failure
(1). It also implements the privileged `apply` verb, so a build that embeds an
anchor is its own elevation helper — the three-scalar request grammar of §14.2 with
nothing else crossing the boundary.

### IDN-05 — Launcher shim (§6.1, §13, §14.3) — **done**
`cmd/launcher` is the shim; everything it does beyond flag parsing lives in
`core/launch`, so a host may write its own. It settles an interrupted transaction,
applies a deferred update while no lock is held, and hands over: `execve` on POSIX so
nothing of it survives into the running process, a parent that passes the exit code
through on Windows. No network, no keys, no TUF client — every byte it moves was
verified when it was staged.

---

## P1 — blocks a trustworthy release

### IDN-06 — `BusyDeferToRestart` actually defers (§14.3) — **done**
The staged tree stays and the journal moves to `DEFERRED`, a resting state recovery
neither undoes nor finishes — and one it does not sweep the staged version or the hook
scratch space up behind, which is what would otherwise turn a deferred update into a
lost one. The launcher completes it at the next start. Applying the same version again
while it waits is a no-op rather than a re-download; a *different* version supersedes
it, so a machine that never restarts cannot wedge the updater.

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

### IDN-09 — Monotonic known-good time floor (§14.7, T22) — **done**
`core/timefloor` persists `max(build time, clock at the last successful refresh)` in
the install root and refuses a local clock below it — before the refresh whose expiry
check depends on that clock, and again before an apply, since Apply does not refresh.
The floor only ever rises, and it can only refuse: it makes nothing acceptable that
go-tuf would have rejected (AGENTS.md §1.2).

The design says "timestamp of the last validly seen metadata". TUF metadata carries
only `expires`, which lies in the future by construction and would refuse every honest
clock as a lower bound; what is recorded is the local clock at the moment metadata
verified, which is the evidence that actually exists.

### IDN-10 — Local reuse of already-installed files (§6.4 stage 1, second half)
`stage.stageFile` always takes bytes from the trust layer. Unchanged files present in
`current/` or a retained version should be reused by verified content hash
(reflink/CoW, else hardlink, else copy) — re-hashed, never adopted on name alone.
Needs the signed hash surfaced from `core/trust`, which the `Materializer` interface
does not expose yet.

The end-to-end suite (IDN-22) put a number on what is missing: a payload target's
path carries its release line (`payloads/v<major>/<sha256>`), and the go-tuf cache
is keyed by path, so identical bytes republished under a new major are fetched
again. Reuse keyed on the *content* of what is already installed is what closes
that, and it is the same mechanism this item asks for.

### IDN-11 — Test coverage for `core/trust` and `core/fetch` — **done**
Both had no unit test at all. `core/trust` now has direct tests of the layer the
corpus cannot reach: two authentic documents that disagree — pointer/descriptor
version and platform mismatch, a pointer naming a descriptor it is not entitled to,
a descriptor that contradicts its own path — plus `ReleaseVersion`, the cache path,
and materialization. `core/fetch` covers the trust store (`ExtraCAs` makes a private
authority verifiable, an unknown one stays refused), the user agent, the timeout,
and the refusals. Three corpus cases were added for the resolve mutators that were
registered but never exercised by a case.

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
`MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`, or a restart. IDN-05 is done, so this is
unblocked: the launcher exists and, on Windows, is the parent process for the lifetime
of the application — which is exactly what makes replacing it there need a mechanism of
its own.

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

### IDN-21 — Reconcile the `OnBusy` default with the design (§6.3, §14.3) — **done**
Decided the second way: the design text drops the claim, `New` promotes nothing, and
`BusyAbort` stays the zero value.

Promoting an unset `OnBusy` to `BusyDeferToRestart` was the other option and is the
worse one. Go cannot distinguish "left unset" from "deliberately chosen", so the
promotion would turn a forgotten line of host configuration into a change of behaviour
in the apply path — an update that quietly stays staged and lands at the next start, on
a host that never asked for one. Deferral remains what §14.3 recommends to a host whose
running application updates itself; a host that wants it says so.
