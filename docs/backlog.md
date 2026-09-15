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

### IDN-03 — Packer: retention (§4.1, §9 step 4) — **done**
`retention.keep` in `pack.yaml` keeps the newest N releases per platform of the
release line being published and removes the rest from its delegation. It is off
unless configured, refuses a window below two, and refuses — rather than widens — a
window that would drop a release a channel pointer names, the one being published
included. What else goes is a reference count over the retained descriptors: a
payload stays while any of them names it, a patch while its base or its result does,
which contains every patch a client walking from a retained release to the head can
use. Anything in the line it cannot classify, or a retained descriptor it cannot
read and verify, is a refusal. Metadata is re-signed through the normal flow; files
are deleted only after `timestamp.json` is written. Tested against `core/trust`, the
installer and the updater: a retained release still resolves and updates to the
head. Not handled: a `min_from_version` floor naming a release outside the window is
not protected — a client below it may be refused rather than walked, which fails closed
(see [`packer.md`](packer.md) §4).

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

### IDN-07 — Privileged helper service and its IPC (§14.2, §14.8, T16, T23) — **POSIX and Windows done**
`elevate.NewHelper` (privileged side) and `elevate.NewService` (the `Elevator` for
`ElevationService`) speak a line protocol over a Unix socket that carries exactly the
three scalars of the request grammar. The helper, in this order: authenticates the
peer from the kernel (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS; an empty
`AllowedUIDs` means root only), rate-limits, parses (fixed keys and order, length
bounds, no CR, nothing buffered after the terminator; fuzzed), checks the root against
`AllowedRoots` **and** `CheckPrivilegedRoot` — at start and again per request — and
only then calls its `Applier`. The answer is a class, never an error text.
`updater.RequestApplier` is that applier: the helper's own channel, options built per
root with `PrivilegedCacheDir`, then `ApplyRequested`. The socket's directory must
belong to the helper's user and be writable by nobody else, and so must every
directory above it unless sticky; an overlong socket path (macOS: 103 bytes) is refused
by name. The exchange deadline bounds reading and answering, never the apply;
cancelling the caller stops its wait, not the apply.

On Windows the same helper listens on a named pipe (go-winio v0.6.2, used for
`ListenPipe` and `DialPipeAccessImpLevel` only). The endpoint is `\\.\pipe\<name>` with a
strict name grammar, checked by `NewHelper` and `NewService`. The helper builds the
pipe's security descriptor from SIDs — protected DACL, `FILE_ALL_ACCESS` for SYSTEM,
Administrators and its own account, read/write/read-attributes/synchronize only for
each `AllowedSIDs` account, nothing for anyone else — and creates the first instance
with `FILE_CREATE`, so a squatter on the name stops it from starting; remote clients are
rejected by the pipe and, again, by the helper when the pipe reports a client computer
(SMB, including `\\localhost`). Per connection the client is identified by its token:
`ImpersonateNamedPipeClient`, `OpenThreadToken` as self, `RevertToSelf` on a locked
thread that is discarded if reverting fails; the token's user SID is compared with
`AllowedSIDs` (canonical account SIDs; empty = SYSTEM only). The caller dials at
identification level; an anonymous-level client is refused. The pid is logged only.
`AllowedUIDs` on Windows and `AllowedSIDs` on POSIX are refused. Tests run real pipes:
the POSIX hostile-caller corpus plus squatter, second helper, DACL read back and judged,
SMB-loopback client (at open, and at `authorizeConn` on a pipe without the flag),
anonymous client, and the option and endpoint refusals.

Still open:

- **Server check on the client side** (Windows): `NewService` does not verify that the
  pipe it reached is served by SYSTEM (`GetNamedPipeServerProcessId` + token). A
  squatter while the helper is down cannot install anything — the helper is the one
  that re-verifies — but can answer `ok` for an apply that never happened (the updater
  reads the pointer back) and learn the caller's identity at identification level.
- ~~**macOS daemon registration**~~ — built under IDN-08: `SMAppService` registration,
  the LaunchDaemon plist, and the audit token (`LOCAL_PEERTOKEN`) with an optional
  code-signing `PeerRequirement` on top of the uid allow-list.
- **fd hand-off** (`SCM_RIGHTS` / `DuplicateHandle` pulled by the helper) to avoid the
  second download; today the helper downloads again, into its privileged cache.

### IDN-08 — POSIX interactive elevation (§14.2) — **Linux done; macOS service mode built**
**Linux** (§14.2.2): `NewInteractive` runs `pkexec <helper> apply --root R --channel
C --version V` as an argument vector, with an empty environment, no controlling
terminal and `/dev/null` streams. pkexec is taken from `/usr/bin/pkexec` or
`/bin/pkexec` only, and must resolve to a root-owned setuid file nobody else can
replace; the helper, symlinks resolved, and every directory above it must be
root-owned and writable by nobody else, and the resolved path is what runs. pkexec
126 is `ErrDeclined`, 127 and any other non-zero status `ErrHelper`; cancelling stops
the wait, not the apply. The decisions are in `core/elevate/pkexec.go` behind an
injected system seam, so their negative tests run on every OS; the real launcher is
tested on Linux against a stand-in pkexec, and the real prompt behind
`IDUNN_TEST_PKEXEC=1`. Example polkit action: `docs/examples/org.idunn.apply.policy`
(`auth_admin`, not `auth_admin_keep`).

Open on Linux: no e2e scenario drives a real polkit agent (CI has none); the helper
runs with pkexec's scrubbed environment, so an environment-only proxy does not
reach its download (IDN-13).

**Decided (maintainer): macOS uses `SMAppService`, as service mode** — the IDN-07
helper registered as a LaunchDaemon — not a one-shot prompt. Sparkle's `SMJobSubmit`
and `AuthorizationExecuteWithPrivileges` are not options.

Done on macOS (design §14.2, "the macOS helper daemon"):
- `elevate.DaemonStatus` / `RegisterDaemon` / `UnregisterDaemon` /
  `OpenLoginItemsSettings` over `SMAppService`, with a strictly validated plist name
  and `SMAppServiceStatus` mapped to `DaemonState` (unknown values fail closed).
  `ErrNotImplemented` off darwin, in `CGO_ENABLED=0` builds, and below macOS 13.
- `elevate.DaemonPlist`: a deterministic LaunchDaemon plist from validated fields
  (`Label`, `BundleProgram` below `Contents/`, `ProgramArguments`,
  `AssociatedBundleIdentifiers`, `RunAtLoad`, `KeepAlive{SuccessfulExit:false}`),
  golden-tested; no environment, user, `Program` or extra keys can be expressed.
- `HelperOptions.PeerRequirement`: the peer's audit token (`LOCAL_PEERTOKEN`) judged
  with `SecCodeCopyGuestWithAttributes` + `SecCodeCheckValidity` against the
  requirement, in addition to the uid. Refused at start where it cannot be checked
  or does not compile. The decision (`admitPeer`) is pure Go and tested everywhere.
- Socket location guidance for the daemon (`/Library/Application Support/<label>/`;
  `/var/run` fails the unchanged ancestor rule), recorded by a darwin test.
- CI: the macOS job asserts cgo is on, runs the bridge's tests by name, and the
  `CGO_ENABLED=0` fail-closed tests.

Still open on macOS:
- The signed, notarized bundle that carries `Contents/Library/LaunchDaemons/<label>.plist`
  and the helper (IDN-26, IDN-27), and an end-to-end run of registration, approval
  and a real update through the daemon — which needs that bundle and a person to
  approve, so it cannot run unattended in CI.
- The host's approval UX: when to register, how to explain `DaemonRequiresApproval`,
  and what the updater does while approval is outstanding.
- Maintainer decisions: macOS 13 as the floor for system-wide installs; who signs the
  helper (same Team ID as the app is assumed by the example requirement); whether
  the shipped darwin commands, today `CGO_ENABLED=0` for reproducibility, need a cgo
  build to register the daemon or whether only the host application does.
- Unverified until the macOS runner reports: the positive real-peer test (the Go
  linker's ad-hoc signature passing `SecCodeCheckValidity`) and the socket-parent
  verdicts.

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

### IDN-10 — Local reuse of already-installed files (§6.4 stage 1, second half) — **partly done**
`stage.stageFile` now looks for the file it is about to write in the live version and
then in the retained ones, newest first, and stages the local bytes when
`trust.VerifyTarget` says they are the signed content. Nothing is adopted on name
alone: the candidate is size-filtered against the signed length, read, and verified,
and every way of failing that — tampered, bit-rotted, unreadable, swapped between the
stat and the read — falls back to fetching the target, never to a weaker check. The
`Materializer` interface carries the two methods this needs (`TargetLength`,
`VerifyTarget`), so staging still never holds a signed hash of its own.

What is left of the design text: the reuse is a plain copy, not reflink/CoW or a
hardlink, which needs an fsx operation that does not exist; and the lookup is keyed on
the destination a file lands at rather than on a content-hash index over the installed
tree, so a file that moved between releases is fetched. Both are efficiency, not
correctness — and the verified-base half that IDN-14 depends on is in place.

### IDN-11 — Test coverage for `core/trust` and `core/fetch` — **done**
Both had no unit test at all. `core/trust` now has direct tests of the layer the
corpus cannot reach: two authentic documents that disagree — pointer/descriptor
version and platform mismatch, a pointer naming a descriptor it is not entitled to,
a descriptor that contradicts its own path — plus `ReleaseVersion`, the cache path,
and materialization. `core/fetch` covers the trust store (`ExtraCAs` makes a private
authority verifiable, an unknown one stays refused), the user agent, the timeout,
and the refusals. Three corpus cases were added for the resolve mutators that were
registered but never exercised by a case.

### IDN-12 — Streaming targets instead of whole-file buffers — **done in this repository, one buffer left upstream**
Every byte of a release used to exist in memory at least twice — the `[]byte` go-tuf
hands over and the buffer staging writes — and a delta added a base and an output beside
them, so a chain held two payloads plus a patch. For a release whose bulk is a browser
runtime that is gigabytes of resident memory for an operation whose working set is one
file at a time.

What is done:

- `trust.Materialize(targetPath, io.Writer)` streams a verified target, and
  `trust.VerifyStream(targetPath, io.Reader)` gives a verdict on bytes that are never
  all in memory. `MaterializeTarget` is built on the first and `stage.Materializer` is
  those two plus `TargetLength` — staging no longer has a way to ask for a payload as a
  `[]byte`.
- `core/stage` produces every file through `fsx.WriteStreamAtomic` with the verifier
  teed into the bytes that land, so what was checked is what a reader will see. Reuse
  copies and verifies in one pass; `ApplyPatchStream` reads its base and its patch
  through `io.ReaderAt` and writes the reconstruction sequentially; a chain spills its
  intermediate hops to `.updater/staging/.scratch`, which is removed either way.
  `ApplyPatch` remains as the buffered wrapper the packer's round-trip check and
  `FuzzPatchApply` use, implemented in terms of the streaming one so there is a single
  reader.
- `VerifyAfterApply` re-reads through `VerifyStream`, so the belt-and-braces check no
  longer costs as much memory as the install that just finished.
- `Materialize` probes the go-tuf cache without writing anywhere before it streams, so a
  planted cache entry cannot reach the caller half-way, and it reads that cache itself
  rather than through `Updater.FindCachedTarget`, whose unbounded `os.ReadFile` reads an
  oversized planted entry whole (**T23**). An entry that does not verify is removed and
  re-downloaded. `FindCachedTarget` is no longer called anywhere: `Target`, the small
  remaining whole-buffer door for the pointer and the descriptor this package parses
  itself, is `Materialize` into a buffer, so every cache read in the process is the
  bounded, verifying one.
- The ceiling is unchanged and still the guard on the one buffer that remains:
  `trust.Options.MaxTargetBytes` (default `trust.DefaultMaxTargetBytes`, 2 GiB; negative
  is refused by `trust.New`) refuses a target whose signed length is above it **before a
  byte of it is requested or read**, through `targetInfo`, which `Materialize`,
  `VerifyStream`, `TargetLength`, `Target` and so `LatestRelease`/`ReleaseVersion` all
  start at.

**The part that deserves a reviewer's attention.** Streaming needs a verdict on bytes
that are never all in memory, and go-tuf v2.4.2 has none: `metadata.TargetFiles` exposes
only `VerifyLengthHashes([]byte)`. `TargetFiles.Equal` is *not* a substitute — its
`Hashes.Equal` passes as soon as one algorithm in common matches and ignores the rest,
where `VerifyLengthHashes` requires every signed algorithm and refuses one it does not
know; building on it would have been a weakening dressed as reuse. So `core/trust`
computes the digest incrementally itself, which is a hand-written check beside go-tuf's
and is the thing AGENTS.md §1.2 is about. It is held to being *the same* check: it lives
in the one package that may see signed material, it takes the signed length and hashes
from go-tuf alone, it refuses in every case go-tuf refuses (plus a stream that runs past
the signed length, which the `[]byte` form cannot encounter), and the equivalence is
enforced rather than claimed — `FuzzVerifyStreamMatchesGoTUF` fails the build the moment
the two verdicts differ on any input, with the individual refusals pinned beside it.

What is left, and it is upstream: a go-tuf `Fetcher` that can hand back an
`io.ReadCloser` and a `DownloadTarget` that verifies incrementally, then `core/fetch`
implementing it (and `fetch.Options.Resume` with it, whose `partial.body` is the other
whole-file buffer). Until then one copy of the largest target exists during its first
download, inside go-tuf, and `core/trust/stream.go` is the file that would be deleted by
the fix.

### IDN-24 — A default install root that follows the platform's conventions (§5, §6.1, §14.2) — **done**
`cmd/installer` requires `--root` and only makes it absolute; nothing proposes a
location, so every host has to know where per-user and system-wide software lives on
every OS, and gets it wrong in a different way each time. The launcher defaults to
its own directory, which is only right once something put it in the right place. The
one path that does follow the platform today is the TUF cache (`os.UserCacheDir`).

Wanted: a `--scope user|machine` (default `user`, matching `ElevationNone`) that
derives the root from a build-time application name (`-ldflags -X`, like
`appBinary`), with `--root` still overriding:

| OS | user | machine |
|---|---|---|
| Windows | `FOLDERID_UserProgramFiles` (`%LocalAppData%\Programs\<app>`) | `FOLDERID_ProgramFiles\<app>` |
| Linux | `$XDG_DATA_HOME/<app>` (`~/.local/share/<app>`) | `/opt/<app>` |
| macOS | `~/Library/Application Support/<bid>` + `~/Applications/<app>.app` | `/Library/Application Support/<bid>` + `/Applications/<app>.app` |

Known folders on Windows come from `SHGetKnownFolderPath`, never from environment
variables a caller controls — the machine root is what the elevated helper vets
(IDN-22), and it must not be steerable. macOS has two paths, not one: where the
versions live and where the bundle a user starts lives; that split is IDN-26's.
Linux needs a decision on the launcher's discoverability (a `.desktop` entry, a
`~/.local/bin` link) or an explicit statement that it is the host's job.

**As built.** `installer.DefaultRoot(Scope, App)` derives the root by the table above
— the versions root only; the macOS bundle path stays IDN-26's. `cmd/installer` takes
`--scope user|machine` (default `user`) and the identity from the build
(`-X main.appName=…` for Windows and Linux, `-X main.bundleID=…` for macOS, not flags).
Decisions made on the way:
- `--root` and `--scope` together are a usage error, not a precedence rule: which of
  the two wins decides whether the install is elevated.
- A build without an identity keeps the old contract (`--root` required, exit 2); an
  identity no root can be derived from is the build's defect (exit 1).
- The application name is one plain component — ASCII letters, digits, space, `.`,
  `_`, `-`, no leading/trailing space or dot, no Windows device name — refused, never
  escaped. The bundle identifier is reverse-DNS.
- Machine roots consult nothing from the environment: known folders on Windows
  (`FOLDERID_UserProgramFiles` with `KF_FLAG_DONT_VERIFY`, since it does not exist
  before the first per-user install), constants elsewhere. User roots follow `$HOME`
  and an absolute `$XDG_DATA_HOME`; a relative one is ignored, as the XDG spec requires.
- Linux discoverability is the host's job: idunn creates no `.desktop` entry and no
  link on `$PATH`.
- The launcher is unchanged: it still defaults to its own directory, which is now the
  right place once the installer put it there.

### IDN-25 — Symlink entries in a release (§3.1, §3.2, §6.4)
A descriptor names regular files of kind exe/lib/data and nothing else; the packer
takes a file list and staging refuses a symlink anywhere below a version directory.
A macOS `.app` cannot be expressed that way: frameworks carry `Versions/Current` and
top-level links into it, and the code signature seals them as links. Linux shared
libraries (`libfoo.so -> libfoo.so.1`) have the same shape.

Wanted: a `symlink` entry with a relative target, validated by `safepath` so it can
never resolve outside the version directory (no absolute target, no `..` that climbs
past the root after resolution, no link through a link), created by staging after
the files it may point at, covered by the release digest like every other entry, and
refused by the packer when the source tree's link escapes. Staging's own "no symlink
on the way down" defence stays: it applies to the directories it walks while writing,
which a release link must not be allowed to become.

### IDN-26 — macOS: the application bundle as the live pointer (§6.1, §13)
On darwin `current` is a symlink in the root, but what a user starts, what the Dock,
Launch Services and TCC know, is `/Applications/<app>.app` (or `~/Applications`). A
bundle cannot be the blue/green layout inside itself: any change below `Contents/`
breaks its seal and, on Apple Silicon, gets the process killed at launch. Every
mature macOS updater therefore replaces the whole signed bundle — Sparkle 2 swaps it
with `renamex_np(old, new, RENAME_SWAP)` from a launchd job
(`Autoupdate/SUPlainInstaller.m`, `Sparkle/SUFileManager.m`).

Wanted, keeping the journal and the retained versions Sparkle does not have:
- `versions/<v>/<app>.app` holds complete bundles; staging assembles one there
  (reusing verified files through `clonefile`, which is also IDN-10's missing
  reflink half).
- The darwin `SetPointer` is a `RENAME_SWAP` between the staged bundle and the
  bundle at the install path; the previous bundle lands in `versions/<old>`, so a
  rollback is a second swap. Staging must be on the bundle's volume (compare
  `st_dev`; `RENAME_SWAP` does not cross volumes) — verify on the CI runner that
  `/Applications` (a firmlink into the Data volume) and `/Library/Application
  Support` qualify.
- Recovery cannot read a marker inside the bundle (writing one breaks the seal); it
  identifies which version sits at the install path by the signed digest of a file
  in it (`Contents/_CodeSignature/CodeResources`).
- Before the swap: owner and group matched to the bundle being replaced,
  `com.apple.quarantine` removed (clones copy it from the installed bundle),
  `futimes` on the bundle root so Launch Services notices, `gktool scan` where it
  exists (14.4+).
- Refuse up front, with a message that says what to do, when the bundle runs
  translocated (`/AppTranslocation/` in the path) or from a read-only volume
  (`statfs` `MNT_RDONLY`) — there is nothing an update could replace.

Depends on IDN-25; the default paths come from IDN-24.

### IDN-27 — macOS: Apple code signing as a gate before the swap (§13, §14.2)
TUF decides what is authentic; this is the platform's own check that the result will
run, as an additional refusal that can never accept something TUF refused.

Decided: AGENTS.md §1.2 carries an explicit carve-out for it. It answers a different
question — not "are these the publisher's bytes" but "will macOS launch them" — which
a release signed in TUF but broken for Gatekeeper (a missing notarization, a nested
binary signed with the wrong identity) otherwise fails only after the swap. It runs
after TUF accepted every byte and can only narrow the funnel, never widen it.

`SecStaticCodeCheckValidity` on the staged bundle with
`kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode` against
a requirement built into the binary — `anchor apple generic and certificate
leaf[subject.OU] = "<TEAMID>" and identifier "<bid>"` — not against the installed
bundle's designated requirement as Sparkle does, so a tampered installed bundle
cannot lower the bar.

Open: how to reach Security.framework. The calls needed are plain C with pointer and
integer arguments — `CFURLCreateFromFileSystemRepresentation`,
`SecStaticCodeCreateWithPath`, `SecRequirementCreateWithString`,
`SecStaticCodeCheckValidityWithErrors`, `CFErrorCopyDescription`, `CFRelease`; no
structs by value, no callbacks, no variadics.
- `/usr/bin/codesign --verify --strict --deep -R=<req> <bundle>`: no dependency, no
  cgo; the verdict is the exit status, so no output is parsed. Absolute path (SIP
  protects it), empty environment. Costs one process per apply. **Unverified:**
  whether `/usr/bin/codesign` exists on a macOS without the Command Line Tools —
  sources disagree; signing needs `codesign_allocate` from the CLT, verifying may
  not. Check on a clean install before choosing this; if it is absent, only the
  framework routes remain.
- Pure-Go FFI without cgo — `github.com/go-webgpu/goffi` (MIT, v0.6.x) or
  `github.com/ebitengine/purego` (Apache-2.0, beta, Tier 1 on darwin, more
  deployments). Both replace the cgo runtime with a fake one under
  `CGO_ENABLED=0`, which changes process startup for the whole binary — including
  the helper that runs as root — and is a new `core` dependency (AGENTS.md §3).
  goffi's advantages (zero-alloc calls, full struct ABI) buy nothing for six calls
  per apply.
- cgo: exact and dependency-free, but ends cross-compiling darwin from another OS.

Leaning: `codesign` first; FFI only if the process spawn proves a problem. A build
without a Team ID follows the proposal in IDN-31: no requirement compiled in, no gate.
On Apple Silicon the linker's ad-hoc signature is still needed for anything to run;
that is the build's concern, not the gate's.

### IDN-29 — Install and restart (§6.1, §14.3) — **done (Windows, Linux)**
A running application that applied or deferred an update can ask to be started
again, and the launcher finishes the update in between — the moment the application
is gone and nobody is writing.

- **Exit code 42** (`launch.RelaunchExitCode`). A launcher that stays the
  application's parent — `cmd/launcher` on Windows, where a process cannot replace
  itself — sets `IDUNN_LAUNCHER_SUPERVISED=1` for the application; when it exits with
  42, the launcher runs `launch.Start` again (recovery, then the deferred update),
  resolves `current` anew and starts the application with the same arguments. 42
  because exit statuses are eight bits on POSIX; a larger code would arrive modulo 256.
  Quick relaunches are bounded: more than three in a row, each after a run of under
  30 s, end the loop instead of spinning; a longer run resets the count.
- **`launch.Relaunch(RelaunchOptions{Launcher, Root, Args})`** for the application:
  under a supervising launcher it returns 42 for the application to exit with; on
  POSIX it replaces the process with the launcher (`execve`, same pid for the service
  manager); on Windows without a supervising launcher it starts the launcher with
  `--after-pid <own pid>` and returns 0. That launcher waits (up to 60 s) for the
  instance to exit and applies or starts nothing while it is up — a migration under a
  live application is what deferring exists to prevent.
- Verified by `TestInstallAndRestart` (`test/e2e/local`, real processes): a running
  1.0.0 holding its own lock defers 1.1.0, releases the lock, relaunches — under the
  launcher and started directly — and the launcher finishes the update and starts
  1.1.0. Green on Windows; the POSIX `execve` path runs in CI.

macOS has no launcher in front of the bundle; install on quit and relaunch there is
IDN-28.

### IDN-30 — Replacing the privileged helper itself (§14.2)
The helper (`cmd/helper`) is installed once, with administrator rights, and today
replaced only by uninstalling it and installing the new build: `install.sh` and
`install-service.ps1` refuse an existing installation, and an application update never
touches the helper that performs it. A publisher whose helper has a bug, or whose
trust anchor or allowed roots change, has no in-place path.

Needed: a way for a new helper to arrive with a release and be put in place — a
separate elevation during or after the update (a UAC/pkexec prompt, or the service
replacing itself through a staged binary it verified), with the same guarantees as the
application's own update: the new helper's bytes verified against TUF before they run
as root, the old helper kept as a rollback target, the service/daemon registration
(SCM, systemd unit, `SMAppService` — re-registration and approval behaviour on macOS
are unverified, see `scripts/macos/README.md`) updated atomically, and the caller list
and state directory carried over. Interacts with IDN-17 (launcher self-replacement)
and IDN-23 (recovery and deferral for system-wide installs).

### IDN-28 — macOS: install on quit and relaunch (§14.3)
There is no launcher on macOS — the bundle is what starts — so `DEFERRED` cannot be
completed "at the next start" without starting the application twice. The macOS
shape is Sparkle's: a helper shipped in `Contents/Helpers/`, signed with the same
Team ID (macOS 13's App Management lets a process modify only bundles of its own
team without a prompt), started when the application wants the update applied; it
waits for the application's process to exit (optionally asking it to quit with an
Apple event), resumes the deferred transaction, swaps (IDN-26) and relaunches through
Launch Services — only on success, and only if the application was running.

The helper takes the same three scalars as the elevated `apply` verb and no path from
its caller; for a system-wide install it is the thing IDN-08 elevates.

### IDN-31 — Windows: Authenticode as a gate before the swap (§13)
The Windows counterpart of IDN-27, under the same AGENTS.md §1.2 carve-out: after TUF
accepted every byte, and only as an additional refusal. Smart App Control and
WDAC/AppLocker publisher rules refuse an unsigned or wrongly signed exe or DLL; without
a gate that surfaces only after the swap, as an application that does not start.

`WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`) is in `golang.org/x/sys/windows`
— no cgo, no new dependency. Every staged file of kind `exe` and `lib` is checked, and
the signer is pinned against a value built into the binary (leaf certificate subject or
the publisher's certificate thumbprints, with room for a rotation), not against the
signature of the installed version, so a tampered installation cannot lower the bar.

Open: revocation. A full chain check goes to the network; a gate that fails every
offline update is unusable, a gate that silently skips revocation is weaker than it
looks. Candidates: `WTD_REVOKE_WHOLECHAIN` with `WTD_CACHE_ONLY_URL_RETRIEVAL`, or
`WTD_REVOKE_NONE` with the reason written down.

**Unsigned applications stay supported.** Plenty of publishers have no certificate —
open source projects, internal line-of-business tools, test builds — and TUF, not
Authenticode, is what makes an idunn update trustworthy. Proposed, for IDN-27 and this
item alike:
- **No pinned publisher: no gate.** The zero value keeps today's behaviour; the updater
  applies unsigned files as it does now. Unlike the `OnBusy` case (IDN-21) this is not
  a forgotten line changing behaviour: leaving the pin out changes nothing. The
  launcher and installer say once, in their log, that the platform signature is not
  checked.
- **A pinned publisher makes the signature mandatory**, for every `exe` and `lib`
  file of every later release: unsigned, signed by someone else, or invalid is a
  refusal before the swap, classified as its own error (not `verify` — the bytes are
  the publisher's, the OS would not run them).
- **The pin travels with the binary that checks**, so transitions follow from which
  version is installed: an unsigned 1.0 updates to a signed 1.1 that introduces the
  pin (1.0 has no gate), and from then on every release must be signed. Dropping
  signing again takes a signed release whose binary no longer carries the pin; an
  unsigned release published straight after would be refused by every client still on
  a pinned version. The packer gate (IDN-32) is where that mistake is caught before it
  ships.
- A pin never lets through anything TUF refused, and an unsigned application never
  gains from a gate it does not have — the gate only narrows.
- Windows itself may still refuse an unsigned application (Smart App Control, WDAC);
  that is the host's deployment question, which the gate would only make visible
  earlier.

### IDN-35 — Uninstall (§5, §6.1)
Nothing removes an installation today; only the helper has uninstall scripts. Decided:
uninstall is a **verb of the launcher** (`launcher uninstall [--quiet] [--purge]`), not
a separate binary — the launcher is the one file that stays on disk above `versions/`,
replaces itself (IDN-17) and needs no network and no keys, and one binary less is one
binary less to sign and ship. The logic lives in a `core/uninstall` package, so a host
that writes its own launcher gets the same behaviour.

Wanted:
- **Offline.** No TUF client, no fetch; it works with the server gone and the metadata
  expired.
- **Only what idunn owns.** The root is accepted only if it holds a valid idunn state
  file whose application ID matches the one compiled in; otherwise refuse with no
  change. Only layout names are removed (`current`, `versions/`, the meta directory,
  the launcher); the root itself only if it is empty afterwards. The walk never follows
  a symlink, junction or other reparse point — `os.RemoveAll` is not relied on for that.
- **Crash-safe.** An `uninstalling` record in the journal, then: pointer removed (the
  application can no longer start), integrations removed (IDN-36), `versions/` deleted,
  meta directory last. A launcher that finds the record completes the uninstall instead
  of starting the application. Every step is idempotent.
- **Running instances** are handled as for an update: the lock and `hook.Coordinator`;
  refuse or ask, never delete under a live process.
- **Host hooks**, compiled in (AGENTS.md §1.3): `BeforeUninstall` may veto,
  `PurgeData` removes the application's own data under `--purge`. The TUF cache and the
  time floor belong to idunn and are always removed.
- **System-wide installs** require administrator rights directly (UAC, pkexec,
  authorization on macOS): the service or daemon is stopped and unregistered (the logic
  of `uninstall-service.ps1` and `uninstall.sh`, in Go). The privileged helper gets
  **no** uninstall verb — an allowed caller must not be able to remove a system-wide
  application without administrator rights.

Open: how the launcher removes itself on Windows, where a running image and its
directory cannot be deleted. A copy started from `%TEMP%` (NSIS, Inno Setup) collides
with Defender ASR rules for unknown executables; `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`
needs administrator rights and leaves files until a reboot; a delayed `cmd /c` removal
looks like malware to EDR. Leaning: remove everything but the launcher, then schedule
the launcher and the empty root for removal.

Negative tests: a root without a valid state file or with another application ID; a
junction or symlink below the root pointing outside, whose target must survive; crash
injection at every journal boundary; a running instance; a system-wide uninstall
without administrator rights; a helper caller asking to uninstall.

### IDN-36 — OS integrations as a recorded manifest; Windows "Installed apps" (§5, §13)
The installer registers things outside the root — the Windows uninstall entry, Start
menu shortcuts, file associations, URL protocols, autostart, a scheduled task, the
helper service. Uninstall (IDN-35) must remove exactly those and guess nothing, so what
was registered is recorded, as MSI does: `<meta>/integrations.json`, written before each
registration takes effect, reversed by `Unregister`. A `core/integrate` package with a
per-OS implementation provides `Register`, `Refresh` and `Unregister`.

Windows uninstall entry, `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\<id>`
(user) or the same key in the 64-bit view of `HKLM` (machine): `DisplayName`,
`Publisher`, `DisplayIcon`, `DisplayVersion`, `InstallLocation`, `InstallDate`,
`EstimatedSize`, `UninstallString` and `QuietUninstallString` naming the launcher verb.
When an MSI installed the application (IDN-34), Windows Installer owns the entry and
idunn writes none of its own.

- **`DisplayVersion` is derived state, never a source of truth.** winget, Intune and
  SCCM detect the installed version through it, so a stale value makes them "upgrade"
  forever. It is refreshed after a commit and reconciled against the pointer by the
  launcher at start; a failed write is reported and never rolls back a committed
  update (the swap is the transaction, the registry is not part of it). In a
  system-wide install the refresh is the helper's, which can write `HKLM`.
- **Modify and repair belong to the sidecar.** Decided: idunn exposes the API to set
  and manage the entry — including `ModifyPath`, `NoModify` and `NoRepair` — and the
  actions behind it (update now, repair, uninstall), but core registers no modify
  command itself: without a UI there is nothing sensible for "Modify" to open, so the
  default is `NoModify=1`, `NoRepair=1`. A sidecar (`idunn-fyne`, `idunn-web`, …)
  calls the API to register its own entry point and presents the dialog. Settings has
  no "update" button for Win32 applications; "Modify" is the only hook.
- **Repair** is a core operation the sidecar calls: re-verify every installed file of
  the current version against its TUF target hash and re-materialize what differs
  (the verification already exists for reuse, IDN-10). Unlike uninstall it needs the
  network when a file has to be fetched.

macOS and Linux integrations (`.desktop` entries, icons, `~/.local/bin` links, systemd
user units, `SMAppService` registration) use the same manifest; their specifics are
IDN-37.


---

## P2 — hardening and reach

### IDN-13 — Enterprise transport: PAC, resume, mTLS (§14.4, T18) — **partial**
Done: **resumable ranged downloads** (`Options.Resume`, `ResumeAttempts`, exponential
backoff capped at 30 s), **proxy authentication** (`ProxyUser`/`ProxyPassword`, Basic,
attached only to a proxy the resolver chose; a 407 is `fetch.ErrProxyAuth` and is never
retried), **mTLS client certificates** (`ClientCertPEM`/`ClientKeyPEM`, caller-supplied
bytes only, refused at construction if unusable), and the **`ProxyResolver` seam**
(nil = `http.ProxyFromEnvironment`; a resolver error fails the request, never goes
direct).

Resume widens how bytes are obtained, not what is accepted: go-tuf's hash check still
decides. The fetcher's own obligation is the offset — a 206 is used only if it carries
exactly one well-formed `Content-Range` starting at the requested byte, consistent with
its `Content-Length`, the total length and strong ETag seen before, and the body does not
overrun it; anything else fails closed with no bytes returned. A 200 to a range request
or a 416 starts over from zero; `If-Range` carries a strong ETag so a changed file comes
back whole. Negative tests: lying/malformed/duplicated `Content-Range`, wrong offset,
overrun, truncated and zero-byte resumes, total above the ceiling, 200 to a range, proxy
auth failure (no credential disclosure, no retry), credentials never sent direct, mTLS
without a certificate and with one from another authority.

Open: the **OS-native proxy resolvers**, PAC/WPAD included — WinHTTP/WinINET,
`SCDynamicStore`, GSettings. Each needs cgo or a substantial per-platform implementation
and cannot be exercised on a runner with no proxy configuration; a host that needs one
today supplies a `ProxyResolver`. Also open: hosts (`cmd/installer`) do not yet expose
these options, and a client key held in an OS store or HSM (a `crypto.Signer` rather
than PEM bytes) is not supported.

### IDN-14 — Delta stage 2: intra-file binary patches (§6.4) — **done**
Done: the format and both halves of it. `stage.ApplyPatch` reads idunn's delta
container — the bsdiff arrangement of control runs, byte-wise differences and
literals, deflate-compressed — bounded by the signed target length, fuzzed by
`FuzzPatchApply`, standard library only so `core` gains no dependency.
`internal/delta` generates one: anchors on identical 64-byte blocks found through a
rolling hash, grows each run for as long as the two files keep roughly agreeing (which
is what absorbs a relink's scattered pointer changes), and emits the same container.

Measured on a 200 MiB stand-in for a browser runtime, rebuilt with 1% rewritten, 50k
scattered byte changes and a megabyte inserted: a 3.3 MiB patch (1.64%), six seconds
to generate, a quarter of a second to apply
(`IDUNN_SCALE=1 go test ./internal/delta -run ReleaseScale`). A raw-dictionary zstd
delta — the other candidate the design named — was measured first: usable below 32 MiB
of base, 43% of the target at 64 MiB and 63% at 96 MiB with the Go implementations
available, so it was dropped.

Also done: the walk. A full target is self-contained, so reaching the head is one step;
a patch turns one exact set of bytes into another, so a client that skipped releases
cannot jump and has to follow what it missed. `release.Chain` produces that walk and
refuses everything it cannot answer unambiguously, and `trust.Versions` says which
releases exist — read out of the signed targets metadata, where every descriptor's path
already states its version, so no new document is published or signed for it.

Also done: the client side of applying one. `release.PatchPath` derives the target path
of a patch from the two content hashes the descriptors already carry — so discovery
needs no descriptor field and no schema bump, and the signed metadata answers whether a
patch exists before a byte is fetched. `core/updater` collects the byte-level history of
the walk into a `stage.Route`; `core/stage` reconstructs each changed file from the
cheapest published set of hops (a shortest path by patch bytes, weights straight out of
the signed metadata, the full target as the upper bound), verifies every intermediate
against that release's signed hash, and answers every failure — no patch published, a
poisoned patch, a missing base, a route that costs more than the file — with the
download it was trying to avoid.

Also done: the publishing side. A publish emits a patch from each of the last N
releases of a platform to the file it now ships, under the path both sides derive from
the two content hashes, in the release line's own delegated role. It skips what is not
worth carrying — an unchanged file, a rewritten one, a patch above `max_ratio` of the
file it rebuilds — and it re-reads its base out of the repository and checks it against
the hash it is published under first, so a locally rotted payload cannot become a patch
that fails on every client. `delta:` in pack.yaml configures both bounds.

Also done: the migration case. A `MinFromVersion` floor is the one refusal a path can
answer — unlike a downgrade or a client too old for the layout, it says only that this
install is too far back to arrive in one step. Where the repository publishes releases
that bridge the gap, `CheckForUpdate` offers the release and `Apply` installs the
releases in between in order, each a complete update with its own transaction, its own
migration hooks and its own commit; the walk it takes is the shortest the floors allow,
never passes through another channel, and is planned with the same `applicable()` the
apply enforces, so the planner cannot pick a step the apply then refuses. A step that
fails leaves the install on the last release that committed — a published release, not a
half-state — and says so.

One thing a walk has to do first is see the releases it walks through. A repository
delegates per release line, and a client loads a delegated role only when it resolves a
target in it — so a client that has just resolved a 2.0.0 head knows the 2.x descriptors
and no others, and would conclude that the 1.5.0 it has to step through was never
published. `trust.OpenLine` makes a line's role load; the walk opens every line between
the installed release and the one it is going to, bounded, before it asks which releases
exist. `internal/packer` tests this against a real delegated repository, because a fake
history that knows every release cannot show it.

Also done: the corpus cases. The harness publishes a previous release and the patches
between it and the head — in the content-addressed layout the packer really produces —
and drives the whole story: a machine installed on the older release, updated to the
newer one against a repository whose patches are the attacker's. Three cases attack it:
a properly signed patch that reconstructs bytes of the attacker's choosing, a valid
patch published under the path of a different pair of payloads, and a patch whose
published bytes disagree with the signed target. None expects a refusal — a patch is not
trusted, so the client may try it and discard the result — and all three assert the
stricter thing instead: the update arrives, every installed byte is the signed one, and
nothing the attacker chose is anywhere on disk. `TestDeltaBaselineTakesThePatch` is the
control that keeps them from passing on a client that ignores patches altogether.

IDN-14 is **done**.

### IDN-15 — Descriptor-level validity window (§6.3 `EnforceExpiry`) — **done, by removal**
Decided the second way: the flag is gone. This is a public API break —
`updater.Policy` no longer has an `EnforceExpiry` field, and a host that set it no
longer compiles; deleting the line is the whole migration, because the value was
ignored.

It governed nothing. Schema 1 descriptors carry no validity window, so the only expiry
in play was TUF's own — checked inside go-tuf during `Refresh`, before this package
decides anything, and not relaxable from above by design. Adding a second, app-level
window in schema 2 was the alternative and is worse: it is exactly the parallel check
AGENTS.md §1.2 warns about, and it buys nothing `timestamp.expires` does not already
give. Removing the field rather than leaving it forced to `true` is the point — a knob
that cannot be turned is one somebody will eventually believe in.

`TestExpiredMetadataIsRefusedThroughTheUpdater` (`core/updater`) is the proof that
nothing was lost: a real go-tuf client, a signed repository a month past its timestamp
window, the most permissive `Policy`, and a refusal classified as expiry with nothing
written — beside a control that the same setup inside the window offers the release.

### IDN-16 — Mutation testing (§12, AGENTS.md §4) — **done**
`make mutate` runs [gremlins](https://github.com/go-gremlins/gremlins) (pinned in the
Makefile as `GREMLINS_VERSION`, installed with `make mutate-tools`) over the lifecycle
packages `core/txn`, `core/stage`, `core/updater` and `core/launch`, and fails below a
threshold on efficacy and on mutant coverage. The `Mutation` workflow runs it as one job
per package on every pull request and push that touches `core/`, `internal/`, the module
files or the Makefile, and weekly on `main`. `make mutate-survivors` prints the list
worth reading.

The thresholds (75% on both, in `.gremlins.yaml`) sit below every score recorded in
[`status.md`](status.md#mutation-score). They exist to catch a regression, not to be
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

### IDN-17 — Launcher self-replacement (§13) — **done**
The layout is why this needed a step of its own on every platform, not only Windows: a
release's files land *inside* a version directory and the launcher lives above it, beside
`current` and `versions/`, so the blue/green swap never touches it. The work is split
along the line AGENTS.md §1.2 draws: the **updater** — which holds the bytes go-tuf just
verified — stages the new launcher, and the **launcher** only swaps that staged file in
at its next start, the one moment a program may replace the file it is executing from.
The launcher has no TUF client and checks no hash.

**Which file is the launcher.** Host knowledge, compiled in exactly like the
application's own path: `updater.Options.Launcher` (`stage.Launcher{Source, Name}`) —
the destination at which a release ships it (e.g. `bin/acme-launcher.exe`) and its file
name directly in the install root (e.g. `acme.exe`). No `kind` was added to the
descriptor schema; a release cannot nominate the program everyone starts next or where
it goes. `Source` must pass the `Dst` sanitizer in clean form; `Name` must be a single
file name that is no layout name, no Windows device and no idunn scratch/leftover name.
Both or neither; anything else is `ErrConfig` from `updater.New` and `ErrStage` from
`Stage`, before a byte is fetched.

**Staging and the journal.** While staging, the file at `Source` is written twice from
the same in-memory verified bytes: into the version directory as always, and — atomically
(scratch, fsync, rename), mode `layout.MetaFileMode` — as the transaction's *pending*
launcher, `.updater/staging/<version>.launcher/<Name>`. Only after the COMMITTED record
is durable is it *promoted* by rename to `.updater/launcher.next/<Name>`, the one file
the launcher swaps in (`layout.PromoteLauncher`). Every commit path promotes: `Apply`
right after its commit record, and `txn` wherever it settles a committed transaction —
recovery of a COMMITTED journal (a crash between the record and the promotion), the
roll-forward of an interrupted SWAPPED/MIGRATED one, `ResumeDeferred`, and `Rollback`
on an already committed one — always before the staging tree is swept, and only while
`current` names that version. Nothing else creates the staged file, so:

- an update that never commits (rolled back in-process or by recovery, refused by
  go-tuf, still `DEFERRED`) never offers its launcher; its pending file lives under
  `staging/` and goes with the rest of that tree;
- a crash at any point after the commit leaves the launcher either pending (the next
  recovery promotes it) or staged — never neither;
- a pending entry that is not exactly one regular file with a valid name, or a
  `launcher.next` that is not a real directory, fails recovery closed and is left for
  inspection. A failed promotion inside `Apply` does not unmake the committed update: it
  is reported, the staging tree is kept, and the next recovery retries.

Keying the staged file by `Name` means a launcher takes only the file staged for its own
file name: a second binary in the same root cannot swap another launcher over itself.

**What the launcher refuses.** `core/launch` swaps only a plain file staged for the name
it runs under, into the root it serves: a link or reparse point or other non-regular file
as the staged file, a `launcher.next` that is not a real directory, a staged file that is
empty or over 64 MiB, a link or directory at its own name, and a launcher that does not
sit directly in the root (so `--root` elsewhere cannot copy that root's staged file over
itself) are all `ErrSelfRefused`, and the old launcher stays. No staged file means nothing
to swap, silently. The staged file is removed after a successful swap; a start that dies
before that finds it identical to the launcher and only removes it. The protection is the
filesystem permission of the install root, exactly as for the launcher binary itself:
whoever can write `.updater/` can write the launcher directly.

**How.** POSIX: an atomic rename over the name; the running process keeps its inode.
Windows keeps an image section on a running executable and refuses to replace it, but
allows it to be *renamed*: the new launcher is written and flushed beside it first, the
running one is renamed to `<name>.idunn-old-<n>`, the new one is renamed in, and the old
image is removed by a later repair, with `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` as the
backstop. If the final rename fails the old launcher is renamed back. The mechanism lives
in `internal/launcherfile`. Verified against a real running executable on Windows.

**Residual risk: the Windows crash window, and its repair.** Windows has no atomic
replace of a mapped image, so a crash (power loss, kill) between the two renames leaves
no launcher under the name users start — until something repairs it. This is accepted
and documented rather than closed. The repair (`launcherfile.Repair`: name empty and a
leftover beside it → rename the newest leftover back; name present → remove leftovers
and scratch) runs wherever it can: at every `launch.Start` before recovery, and — because
the launcher that would repair itself is the one that is missing — from the application's
side too: `Updater.Apply` and `Updater.ApplyRequested` (and `Updater.RepairLauncher` for a
host that wants it at its own start), and `launch.Relaunch` before it starts the launcher.
A start that finds no launcher and no leftover but a staged one writes the staged one.
What remains: a user who double-clicks the launcher's name after such a crash and before
the application (or its service helper) has run once finds nothing to start — the
shortcut is broken until then. A repair that itself fails is reported (`Result.SelfErr`,
an Observer event, the `Relaunch` error) and no swap is attempted on top of it. Two
repairs racing a swap from another process (a second instance's updater while a launcher
is between its renames) can make that swap fail; it fails back to the old launcher and
the staged file stays for the next start.

**Soft failure.** Nothing about the launcher fails a start or an update: the outcome is
`Result.SelfErr`, `cmd/launcher` reports it on stderr and hands over to the application
anyway, and the updater reports repair failures through the Observer. In a root this
process cannot write — a system-wide install started by an ordinary user — the first
write (the scratch file) is refused, nothing under the root changes, the staged launcher
stays, and the error is `ErrSelfNotWritable`; replacing the launcher there needs the
elevated side, which nothing starts from a launcher yet (IDN-23).

`cmd/launcher` also grew `--version`: once the launcher can replace itself, the one in
the install root is no longer necessarily the one that was installed.

### IDN-18 — Reproducible builds and provenance in CI (§9, §15) — **partly done**
`scripts/repro.sh` (`make repro`) builds `cmd/installer`, `cmd/launcher` and
`cmd/packer` for linux, windows and darwin on amd64 and arm64 twice and fails unless
every binary is byte-identical. The passes are made to differ in what must not matter —
pass b builds a copy of the tree in another directory, and each pass has its own empty
`GOCACHE`, without which the second build is a cache hit that compares equal by
construction — and the flags pin what would otherwise leak in: `-trimpath` (no build or
module-cache path), `-buildvcs=false` (the bytes depend on the source, not on `.git`),
`-ldflags=-buildid=`, `CGO_ENABLED=0`, and a scrubbed `GOFLAGS`/`GOAMD64`. Without
`-trimpath` the two directories do produce different bytes, so the check is not vacuous.
CI's `reproducible builds` job runs it on every pull request and push and writes the
digests and the exact `go version` into the job summary.

Two passes on one runner catch what breaks reproducibility in practice — an embedded
path, a wall-clock stamp, a map iterated into output. They cannot catch a difference
between two machines or toolchains; publishing the digests and the Go version is what
makes an independent rebuild possible, not a substitute for one.

Provenance: the `Release provenance` workflow runs on `v*` tags. Its build job runs the
same script with `contents: read`; a separate attest job, the only one holding
`id-token: write` and `attestations: write`, checks out nothing, verifies the binaries
it downloaded against the digests the build job handed over as a job output, and signs
them with `actions/attest-build-provenance` (SHA-pinned). Check a binary with
`gh attestation verify <file> --repo go-idavoll/idunn`.

Still open, and why this is *partly*:

- The workflow attests binaries and keeps them as a workflow artifact; it does not
  create a GitHub release. Where released binaries are published (and whether that
  job gets `contents: write`) is a maintainer decision.
- The release build stamps no `main.clientVersion` or `main.buildTime` into
  `cmd/installer`. A host's installer that sets them stays reproducible only if the
  values are derived from the commit (tag, `SOURCE_DATE_EPOCH`), never from `date`.
- No second, independent rebuild (another runner or OS) compares digests yet.

The packer's half — byte-identical repository output from the same inputs and
reference time — was closed by IDN-01 and is pinned by a golden test.

### IDN-19 — UI sidecars (§8)
`idunn-bubbletea` and `idunn-web` are named in the README and do not exist. Out of
tree by design. [`idunn-fyne`](https://github.com/go-idavoll/idunn-fyne) is the
first one and shows the `Observer`/`Prompter` surface is sufficient: it drives a
real `updater.Apply` — staging, journal, atomic swap, GC — with no change to
`core`.

Two gaps it surfaced, both small and neither blocking:

- `updater.classify` is unexported, and it matches `layout.ErrLayout` and
  `safepath.ErrUnsafe`, which are under `internal/`. A sidecar cannot reproduce
  the taxonomy exactly, so those errors fall into its "unknown" class. An
  exported `updater.Classify(error) string` would close it.
- `hook.Event.Progress` used to be hardcoded to `-1` at both emitters, so a UI had no
  progress to show and had to derive one from the phase. Closed by IDN-12:
  `stage.Stager.Progress` reports bytes as a release is written, and the updater turns
  that into events carrying the file, its source (reuse / patch / download), and the
  release's byte progress against a total known before the first byte moves. Events
  outside staging still say `-1`, which is honest — a quiesce has no byte count.

A packing assistant lives in the same repository. It shells out to
`cmd/packer publish` because `internal/packer` is not importable from another
module; a public `packer.ValidateConfig([]byte) error` and a `--json` flag on
`publish` would let it stop mirroring unexported rules and parsing human-readable
output.

### IDN-20 — Decide the mythology naming question (§2.1) — **done**
Functional names are canonical in code; mythological names are branding for the
umbrella `idunn` and nothing below it.

The first half is what the code has always done, so deciding it costs nothing. The
second half is the part that needed deciding: not `heimdall`, not `bifrost`, not as an
internal codename. A codename that lives in a README is charming; one that turns up in
a stack trace an auditor is reading is a question they have to stop and ask, and the
boundary is easier to hold at zero than at two.

### IDN-22 — The elevated helper vets the install root it is asked to write (§14.2, T16) — **done**
The root is one of the three scalars, and the caller chooses it. A helper running as
administrator that writes into a directory a non-administrator can modify can be
redirected by a junction planted between two of its operations. `elevate.AcceptRequest`
is what a helper calls first: the request grammar, then `CheckPrivilegedRoot`, which
refuses — before anything is written — a root that is a network path or on anything
but a fixed local disk (a SUBST drive included); any path component that is a
reparse point; an owner other than SYSTEM, Administrators or TrustedInstaller on the
root, its ancestors, or what a helper writes in an existing root; an ancestor that
grants anyone else delete, `FILE_DELETE_CHILD`, `WRITE_DAC` or `WRITE_OWNER`; and a
root (or the directory it will be created in) that grants anyone else a right to
create, delete or re-permission — including rights they would only inherit. Callers
run the same check before the prompt. POSIX judges owner and mode bits the same way;
POSIX ACLs are not read.

A group other than those three — a domain group of operators — is refused too; the
check cannot tell a trusted group from another. Contents of version directories below
their top level are not examined: the helper never writes into an existing one and
verifies every byte it reuses.

### IDN-23 — Recovery and deferral for system-wide installs (§14.2, §14.3)
An interrupted transaction in a root the launcher cannot write can only be recovered
by the elevated helper, and today nothing starts one for that: the launcher reports
the failed recovery and starts the application. Likewise `BusyDeferToRestart` in the
helper leaves a staged update the unprivileged launcher cannot finish. The same holds
for a new launcher the helper staged (IDN-17): the unprivileged launcher reports
`ErrSelfNotWritable` and keeps running the old one. All three need either a launcher
that elevates for this (a prompt at start) or the service mode (IDN-07).

### IDN-21 — Reconcile the `OnBusy` default with the design (§6.3, §14.3) — **done**
Decided the second way: the design text drops the claim, `New` promotes nothing, and
`BusyAbort` stays the zero value. No API or behaviour change.

Promoting an unset `OnBusy` to `BusyDeferToRestart` was the other option and is the
worse one. Go cannot distinguish "left unset" from "deliberately chosen", so the
promotion would turn a forgotten line of host configuration into a change of behaviour
in the apply path — an update that quietly stays staged and lands at the next start, on
a host that never asked for one. Deferral remains what §14.3 recommends to a host whose
running application updates itself; a host that wants it says so.
`TestUnsetOnBusyAbortsRatherThanDefers` (`core/updater`) pins the zero value.

### IDN-32 — Packer: require platform signatures at publish time (§9, T13)
The OS signature must be inside the bytes before the packer hashes them; a file signed
after `publish` fails its TUF hash on every client, and a file never signed fails only
on the machines that enforce signatures. Both are publish-time mistakes, and the packer
already refuses what would fail on every client (a `dst` `safepath` rejects).

Wanted: an optional `platform_signature` block in `pack.yaml` — required or not, and
per OS the expected identity (Windows: certificate subject or thumbprints; darwin: Team
ID and identifier) — checked for every `exe` and `lib` file and for bundles. The packer
**verifies only**; it never signs. OS signing keys live in HSMs, Azure Trusted Signing
or the keychain, and notarization is a network round trip to Apple; neither belongs in
the tool that holds the TUF keys.

Open: a full chain check is only possible on the target OS (`WinVerifyTrust`,
`codesign`); on another OS the packer can only check that a signature is present and
names the expected signer. Whether that weaker check is offered, or the gate requires
publishing from the target OS, is to decide.

### IDN-33 — Signing without losing dedup and reproducibility (§4.1, §9, IDN-18)
A signature carries a timestamp, so re-signing an unchanged DLL produces new bytes: a new
content-addressed payload target, no reuse on the client, a pointless patch. And signed
bytes are not reproducible, which IDN-18's comparison does not cover.

Wanted: a signing step keyed by the digest of the *unsigned* build — a file whose
unsigned digest equals the previous release's is not re-signed; the signed file is
taken from that release. Publish the unsigned digests next to the signed ones, so an
independent rebuild can be related to what shipped. For Authenticode the signed hash
excludes the checksum and the certificate table; whether the unsigned build's
Authenticode digest matches the signed file's (padding added when signing) is
**unverified**. For Mach-O, whether `codesign --remove-signature` restores the unsigned
bytes is **unverified**.

### IDN-34 — Installer packages and the publishing pipeline (§5, §9)
The signature of an installer package is checked when the package installs and never
again; an update bypasses the package and places files directly. So every file idunn
ships must carry its own OS signature, and a package is only the wrapper around the
first install. The order, to be documented: build, sign each file (inside out on
macOS), notarize and staple, `packer publish`, then package, sign the package, notarize
the package.

Wanted: scripts (not `core`) and documentation, generalising `scripts/macos` and
`scripts/windows` from the helper to the application:

| OS | fits idunn | does not |
|---|---|---|
| Windows | signed `cmd/installer`; an MSI (WiX) that installs only the launcher and the bootstrap | MSIX / Microsoft Store: read-only install location, updates only through the Store or App Installer |
| macOS | a notarized `.dmg` with the `.app` (user scope); a `.pkg` signed with a Developer ID Installer certificate (system scope with the helper daemon) | Mac App Store: self-updating is not permitted |
| Linux | a tarball or installer; a deb/rpm that installs only the launcher | Flatpak, Snap: read-only, their own update mechanism |

An MSI or deb/rpm must not list anything below `versions/` among its files, or a
Windows Installer repair or a package verification reverts or flags what idunn
updated. A deb/rpm's `prerm`/`postrm` calls the launcher's uninstall verb (IDN-35).
Worth evaluating: an offline installer — `cmd/installer` with a TUF snapshot of the
first release embedded, so the bytes are still TUF-verified and the package signature
stays a wrapper.

idunn sets no Mark-of-the-Web and no `com.apple.quarantine` on what it downloads, so
SmartScreen and Gatekeeper's first-launch assessment see only the first installer —
another reason for the gates in IDN-27 and IDN-31.

### IDN-37 — Uninstall on macOS and Linux: leftovers and registrations (IDN-35, IDN-36)
- **macOS, user scope:** a user drags the `.app` to the Trash, and nothing runs;
  `~/Library/Application Support/<bid>` with `versions/` and the TUF cache stay behind.
  The uninstall verb is reachable from the application (a menu item through the
  sidecar, or the helper in `Contents/Helpers`, IDN-28); the leftovers of a bundle that
  was only trashed are documented, not cleaned up — nothing starts again to do it.
- **macOS, system scope:** `SMAppService.unregister` for the daemon, removal of the
  bundle with administrator rights, `pkgutil --forget` for a `.pkg` install.
  **Unverified:** whether macOS 13+ Background Task Management disables the daemon on
  its own when the bundle is trashed.
- **Linux:** the verb removes the `.desktop` entry, icons, the `~/.local/bin` link and
  systemd user units from the manifest, and the helper unit for a system-wide install.

### IDN-38 — Release notes, signed and delivered with the release (§3, §8, §9)
idunn delivers the update and the sidecars show it, so the question "what changes?"
belongs to the same path. Today a host has to fetch notes from somewhere else, with
nothing tying them to the release a user is asked to install.

Wanted, as data and never as code (AGENTS.md §1.3):

- **Delivered as TUF targets, discovered by name**, the way patches are (§3 of
  `packer.md`): `notes/v<major>/<version>/index.json` plus one file per language,
  `notes/v<major>/<version>/<lang>.md`. The index lists the languages and an optional
  link; the signed metadata answers whether notes exist at all. **The descriptor is not
  touched:** `release.ParseDescriptor` refuses unknown fields, so a `notes` field would
  make every deployed client refuse every new release. A client that knows nothing
  about notes never asks for the path. The release-line delegation takes the pattern
  `notes/v<major>/*` next to `payloads/v<major>/*` — a re-sign of `targets`, disjoint
  like the others, no client migration.
- **Link, embedded text, or both.** A publisher who keeps notes on a website ships
  only the index with `url`; one who wants them offline and bound to the release ships
  the text. The URL is `https` only, without credentials, validated by the packer and
  again by the client, and handed to the sidecar as a value — core opens nothing.
- **Bounded and strict.** The index goes through a strict parser like the descriptor
  (schema version, no unknown fields, fuzzed); a language tag is validated (BCP 47
  subset) before it becomes part of a path; the text has a size ceiling checked
  against the signed length before a byte is fetched.
- **Plain Markdown, rendered by the sidecar as untrusted text:** no raw HTML, no
  images or other remote content loaded automatically, links shown before they open.
  What the notes say is signed; what a renderer would do with active content is not.
- **API, called by the sidecar**, in line with IDN-36: something like
  `Updater.ReleaseNotes(ctx, rel, NotesOptions{Languages, Since})`, returning one entry
  per version with its language, text and link. `Since` is the installed version, so
  an update from 1.0 to 1.3 shows 1.1, 1.2 and 1.3 — the versions come from the signed
  targets metadata, as for multi-hop patches. The fallback order of languages is the
  caller's; with no match, the first language in the index. Notes are fetched on
  request, before `Apply`, and never required: a missing, oversized or malformed note
  is reported and does not block the update. Headless hosts never fetch them.
- **Packer:** `pack.yaml` takes `notes: { url: …, files: { en: CHANGELOG.md, de: … } }`;
  the notes are retired with their release (IDN-03).

Open: whether one release's notes may differ per platform (a `<os>-<arch>` override
next to the shared file) or stay one text per version; and whether `hook.Prompter`,
which today takes a plain question, grows a variant that carries the notes, or the
sidecar composes the question itself from the API.
