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

**IDN-07a — protocol, authorization, POSIX transport — done.** `elevate.NewHelper` is
the privileged listener and `elevate.NewService` the unprivileged caller's `Elevator`.
The wire format carries the same three validated scalars as the command line, as lines,
because the request grammar forbids every byte that would need escaping. The helper
decides who is asking (kernel peer credentials, never a claim), how often (a minimum
interval), and what is asked (the grammar and `AllowedRoots`), before it does any work.
`Applier` is the seam a host implements around `core/installer` with its own embedded
anchor — `core/elevate` cannot construct one, on purpose. Peer credentials: Linux
`SO_PEERCRED` and macOS `LOCAL_PEERCRED`.

The hostile-caller cases live in `core/elevate/service_test.go` rather than in
`test/redteam/corpus`, and that is deliberate: the corpus is built out of tampered
*repositories*, and none of these tampers with one. The repository is honest; the
attacker is the process on the other end of the socket. Each case asserts that the
privileged applier was never reached, and the two that matter most — a root outside the
allowed set, a uid outside the allowed set — were checked against the mutation that
removes the guard.

**IDN-07b — Windows named pipe — done.** `listenLocal`/`dialLocal` over
`github.com/Microsoft/go-winio`, with the access decision in the pipe's security
descriptor rather than in a check of our own. That is not a concession to the library's
API — it is the stronger arrangement: the kernel evaluates the descriptor when a client
opens the pipe, so a caller who may not ask never reaches any of our code, not even the
parser. `SecurityDescriptor` (SDDL) is therefore mandatory on Windows, because a pipe
created without one inherits a default DACL, and "whatever the default turns out to be"
is not an access decision anyone made. `AllowedUIDs` is refused there, and
`SecurityDescriptor` refused everywhere else: a setting meant for the other platform is
a refusal rather than a value quietly ignored.

The dependency is justified under AGENTS.md §3. The alternative was several hundred
lines of hand-written overlapped I/O implementing `net.Listener` and `net.Conn` over
`CreateNamedPipe`, at a privilege boundary, on a platform this change could be built
for but not exercised on. A reviewed, widely deployed implementation of exactly this —
containerd and Docker use it for the same purpose — is the smaller risk, and it is
confined to one file.

**IDN-07c — macOS audit token.** `LOCAL_PEERTOKEN` identifies the signed application
rather than only the user; it refines the `LOCAL_PEERCRED` check that is in place.

**Still open for all three: T23.** The helper uses its own TUF cache in its own
directory, and nothing yet enforces that the directory is not writable by an
unprivileged user, nor is there the read-only fd hand-off (`SCM_RIGHTS` /
`DuplicateHandle` pulled by the helper) that would avoid both a second download and a
path-based TOCTOU (§14.8).

### IDN-08 — POSIX interactive elevation (§14.2) — **Linux done, macOS open**
Linux is `pkexec`, with the same three-scalar request grammar the Windows path
enforces — and one thing better than Windows: pkexec is exec'd with an argument
vector, so the scalars are never rendered into a string anything has to re-split.
pkexec is looked for at absolute paths rather than through `PATH`, because the program
found through `PATH` is the one that shows an authentication dialog with the system's
face on it. The environment handed across is empty: what pkexec sanitizes is *our*
environment, and the smallest thing to sanitize is nothing. A dismissed dialog is
`ErrDeclined`, never a failure to retry. An example polkit policy is in
[`examples/org.idunn.apply.policy`](examples/org.idunn.apply.policy).

macOS is open, and not by oversight. The counterpart is Authorization Services
(`AuthorizationExecuteWithPrivileges`, deprecated since 10.7) or a launchd helper
registered with `SMAppService` and reached over XPC. Both are Objective-C frameworks
with no pure-Go binding, so the choice is a cgo dependency in `core` — which changes
how the whole module cross-compiles — or a helper built outside it. That is a
maintainer decision, so `newInteractive` fails closed there with the reason in the doc
comment rather than being guessed at.

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

### IDN-10 — Local reuse of already-installed files (§6.4 stage 1, second half) — **done**
`stage.stageFile` now offers each file's destination in `current/` and every retained
version as a candidate, and takes it only if the trust layer says the bytes *are* the
signed target. The name and the length select what to read; go-tuf decides whether it
may be used (`trust.SignedLength`, `trust.Accepts`) — there is no second opinion about
acceptability anywhere in `core/stage` (AGENTS.md §1.2, §1.5).

The end-to-end suite (IDN-22) is what put a number on the gap: a payload target's path
carries its release line (`payloads/v<major>/<sha256>`) and the go-tuf cache is keyed by
path, so identical bytes republished under a new major were fetched again. That scenario
now asserts two of three payloads across a major bump, and fails at three.

It also turned up a second half of the same problem: `VerifyAfterApply` re-downloaded
every target to compare against, which would have sent the reused bytes over the wire
after all. It now checks the installed file against the *signed* target instead of
against a second copy — cheaper, and the stronger statement.

**Not done, and deliberately:** reuse is a verified copy, not a reflink or a hardlink.
The network saving §6.4 stage 1 is about is fully delivered; the disk saving is not.
A hardlink would make one version directory's content changeable by a write to
another, which is a property blue/green should not quietly give up, and a reflink
needs per-OS syscalls (`FICLONE`, `clonefile`, ReFS) that belong in `core/fsx` with
their own tests. Tracked as the remainder of this item.

### IDN-11 — Test coverage for `core/trust` and `core/fetch` — **done**
Both had no unit test at all. `core/trust` now has direct tests of the layer the
corpus cannot reach: two authentic documents that disagree — pointer/descriptor
version and platform mismatch, a pointer naming a descriptor it is not entitled to,
a descriptor that contradicts its own path — plus `ReleaseVersion`, the cache path,
and materialization. `core/fetch` covers the trust store (`ExtraCAs` makes a private
authority verifiable, an unknown one stays refused), the user agent, the timeout,
and the refusals. Three corpus cases were added for the resolve mutators that were
registered but never exercised by a case.

### IDN-12 — Streaming targets instead of whole-file buffers — **blocked upstream**
`trust.Target` holds every payload in memory. This is not a shortcut taken here: at
go-tuf v2.4.2 — the newest release — the fetcher contract is

```go
DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error)
```

and `Updater.DownloadTarget` verifies with `VerifyLengthHashes` over the complete
slice. There is no seam below that line to stream through. Getting one locally would
mean fetching and verifying beside go-tuf rather than through it, which AGENTS.md §1.2
forbids and which is not worth a memory optimisation. **The fix belongs upstream:** a
`Fetcher` that can hand back an `io.ReadCloser`, and a `DownloadTarget` that verifies
incrementally.

What *was* in this repository's hands is done: `trust.Options.MaxTargetBytes`
(default 2 GiB) refuses a target whose signed length is above the ceiling **before a
byte of it is requested**. The signed length is the allocation about to be made, and a
repository is untrusted input even when correctly signed — so the failure mode changes
from an OOM kill with no diagnosis to a typed refusal that names the option to raise.

Done when: go-tuf exposes a streaming target download, and `core/fetch` implements it.

---

## P2 — hardening and reach

### IDN-13 — Enterprise transport: PAC, resume, mTLS (§14.4, T18) — **mostly done**

Done: **resumable downloads** (`Options.Resume`), **proxy authentication** and **mTLS
client certificates**, plus the **`ProxyResolver` seam** the OS-native answers plug
into. `Options.Resume` is no longer accepted and ignored.

Resume is the half of T18 that was missing, and it is missing for a reason worth
stating: a link that drops at forty megabytes turns a hundred-megabyte release into an
update that never completes, however often it is retried *from the start*. It changes
nothing about trust — the bytes are a concatenation of two responses, a server or a
TLS-terminating proxy can serve a different second half, and that produces the wrong
hash which go-tuf refuses, exactly as it refuses a wrong first half. What the fetcher
does have to get right is the offset: a 206 that begins somewhere other than where the
request asked would produce a file that is neither of the two it was made from, which
would be corruption this layer introduced, so it is refused rather than concatenated.

Open: the **OS-native proxy resolvers**, PAC included — WinHTTP/WinINET,
`SCDynamicStore`, GSettings. Each needs either cgo or a substantial per-platform
implementation, and none of them can be exercised on a CI runner that has no proxy
configuration to read. The interface they slot into exists, so a host that needs one
today can supply it without waiting for this. `http.ProxyFromEnvironment` remains the
default.

### IDN-14 — Delta stage 2: intra-file binary patches (§6.4) — **done**
The format is `internal/delta`: a two-opcode instruction stream, copy-from-base and
insert-literal. Neither candidate the design named was taken, and the reason is where
the code runs. zstd `--patch-from` and bsdiff would each be a dependency in the *apply*
path — the one place in this project where a bug is a bug in what lands on a user's
disk — and each brings a decoder far larger than the problem. What is needed is two
instructions, and an apply small enough that a reviewer can hold it in their head and a
fuzzer can cover it exhaustively. The trade is compression ratio against a suffix sort,
and it is cheap: a worse patch costs bandwidth, because the result is checked against
the signed target hash either way.

`--patch-against N` emits patches from the last N releases of each platform, and only
where the patch is meaningfully smaller than the payload. Nothing in the descriptor
points at them: the client derives the target path from the hash it has and the hash it
wants (`release.PatchPath`), which is the "discovery by convention" §6.4 asks for — so a
publisher can start or stop emitting patches with no client noticing except in its
bandwidth. Retention retires a patch when the payload it *produces* is retired; the
payload it starts from may be long gone, and a client running a retired version is
exactly who the patch forward is for.

`FuzzPatchApply` is in `internal/delta` and in `make redteam-fuzz`. The apply path is
the one that runs on bytes the repository chose *before* the check that decides whether
they were the right ones, so every offset and length is bounded twice over and the
output is a single allocation from a bounded header.

The `patch-poison` corpus directory stays empty, and the case for it lives in
`core/stage/patch_test.go`: a patch published at the path that promises one payload
while reconstructing another is discarded in favour of the full download. It is not a
repository mutation of the kind the corpus harness builds — the repository is honest and
the patch is a legitimately signed target — so it belongs where it can actually be
built, next to the code it constrains.

### IDN-15 — Descriptor-level validity window (§6.3 `EnforceExpiry`) — **done, by removal**
Decided the second way: the flag is gone.

It governed nothing. Schema 1 descriptors carry no validity window, so the only expiry
in play was TUF's own — checked inside go-tuf during `Refresh`, before this package
decides anything, and not relaxable from above by design. Adding a second, app-level
window in schema 2 was the alternative and is worse: it is exactly the parallel check
AGENTS.md §1.2 warns about, and it buys nothing `timestamp.expires` does not already
give. Removing the field rather than leaving it forced to `true` is the point — a knob
that cannot be turned is one somebody will eventually believe in.

### IDN-16 — Mutation testing (§12, AGENTS.md §4)
`go-mutesting` (or equivalent) as the quality bar for assertions. Coverage is high;
nothing currently measures whether the tests would fail if the code were wrong.

### IDN-17 — Launcher self-replacement (§13) — **done**
The layout is why this needed a step of its own on every platform, not only Windows: a
release's files land *inside* a version directory and the shim lives above it, beside
`current` and `versions/`, so the blue/green swap never touches it. `core/launch` now
carries the new launcher the last few centimetres, at the start after the update that
brought it — the one moment a program may replace the file it is executing from.

Which file in a release *is* the launcher stays host knowledge (`Options.SelfSource`,
a linker variable in `cmd/launcher`, exactly like `appBinary`). No new `kind` was added
to the descriptor schema for it, and a release cannot nominate the thing everyone
clicks next.

POSIX needs no ceremony — a running program holds its image by inode, so a rename over
the name is enough. Windows keeps an image section on the file and refuses to replace
it, but does allow the running executable to be *renamed*, which is the mechanism:
move it aside, write the new one at the name that is clicked, then clean the leftover
up — the next start sweeps it, and `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` is the
backstop behind that. If the rename fails, nothing is written: a half-replaced launcher
is the one outcome that leaves a machine unable to start its application at all.

A failed refresh never fails a start. `cmd/launcher` also grew `--version`, which is
the question that has no answer once the shim can replace itself: the launcher in the
install root is no longer necessarily the one that was installed.

### IDN-18 — Reproducible builds and provenance in CI (§9, §15)
Bit-identical artifacts and SLSA provenance as supply-chain proof beside TUF. Partly
enforced for packer output by IDN-01; this is the CI half.

### IDN-19 — UI sidecars (§8)
`idunn-fyne`, `idunn-bubbletea`, `idunn-web` are named in the README and do not
exist. Out of tree by design — one reference implementation would prove the
`Observer`/`Prompter` surface is sufficient.

### IDN-20 — Decide the mythology naming question (§2.1) — **done**
Functional names are canonical in code; mythological names are branding for the
umbrella `idunn` and nothing below it.

The first half is what the code has always done, so deciding it costs nothing. The
second half is the part that needed deciding: not `heimdall`, not `bifrost`, not as an
internal codename. A codename that lives in a README is charming; one that turns up in
a stack trace an auditor is reading is a question they have to stop and ask, and the
boundary is easier to hold at zero than at two.

### IDN-21 — Reconcile the `OnBusy` default with the design (§6.3, §14.3) — **done**
Decided the second way: the design text drops the claim, `New` promotes nothing, and
`BusyAbort` stays the zero value.

Promoting an unset `OnBusy` to `BusyDeferToRestart` was the other option and is the
worse one. Go cannot distinguish "left unset" from "deliberately chosen", so the
promotion would turn a forgotten line of host configuration into a change of behaviour
in the apply path — an update that quietly stays staged and lands at the next start, on
a host that never asked for one. Deferral remains what §14.3 recommends to a host whose
running application updates itself; a host that wants it says so.
