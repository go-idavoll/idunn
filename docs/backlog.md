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

On macOS the proven one-shot shape is Sparkle 2's: `AuthorizationCopyRights` for a
custom right with `kAuthorizationRuleAuthenticateAsAdmin`, then the helper submitted
as a run-once launchd job in the system domain (`SMJobSubmit`,
`InstallerLauncher/SUInstallerLauncher.m`). That API is deprecated; its replacement,
`SMAppService.daemon` (macOS 13+), registers a permanent daemon the user has to
approve under Login Items, which fits the service mode (IDN-07) better than a prompt.
Decide which one, and whether macOS 13 is the floor. Whatever runs elevated is the
IDN-28 helper; `AuthorizationExecuteWithPrivileges` is not an option.

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

### IDN-12 — Streaming targets instead of whole-file buffers — **partly done, streaming blocked upstream**
`trust.Target` holds every payload in memory, and at go-tuf v2.4.2 — the newest
release — that is structural rather than a shortcut taken here: the fetcher contract is

```go
DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error)
```

and `Updater.DownloadTarget` verifies with `VerifyLengthHashes` over the complete
slice. There is no seam below that line to stream through. Getting one locally would
mean fetching and verifying beside go-tuf rather than through it, which AGENTS.md §1.2
forbids and which a memory optimisation does not justify.

What was in this repository's hands is done: the allocation is bounded.
`trust.Options.MaxTargetBytes` (default `trust.DefaultMaxTargetBytes`, 2 GiB; negative
is refused by `trust.New`) refuses a target whose signed length is above the ceiling
**before a byte of it is requested or read**. The signed length is the allocation about
to be made, and a repository is untrusted input even when correctly signed, so the
failure mode changes from an OOM kill with no diagnosis into an `ErrTrust` that names
the option to raise. The check sits where every path starts — the download and the
go-tuf cache read behind `Target` (and so `LatestRelease`, `ReleaseVersion`,
`MaterializeTarget`), and `TargetLength`/`VerifyTarget`, which size and admit what
reuse (IDN-10), patch bases and patch outputs (IDN-14) and `VerifyAfterApply` read
beside go-tuf. It can only refuse; verification is untouched. Negative tests: one byte
under the signed length is refused with nothing requested and nothing cached, the
exact length is fetched, a cached target is refused too, and staging neither reads a
reuse candidate or patch base nor fetches a patch for a target above the ceiling.

What is left: streaming itself — a go-tuf `Fetcher` that can hand back an
`io.ReadCloser` and a `DownloadTarget` that verifies incrementally, then
`core/fetch` implementing it (and `fetch.Options.Resume` with it). Also upstream:
`FindCachedTarget` reads the cached file with an unbounded `os.ReadFile` before it
compares the length, so an oversized file planted in the local cache is read whole
even though its signed length is within the ceiling (the cache is local, owner-only
state — T23).

### IDN-24 — A default install root that follows the platform's conventions (§5, §6.1, §14.2)
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

Leaning: `codesign` first; FFI only if the process spawn proves a problem. Also decide
whether a build without a Team ID is refused on darwin or skips the gate with a
warning.

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


---

## P2 — hardening and reach

### IDN-13 — Enterprise transport: PAC, resume, mTLS (§14.4, T18)
`fetch.New` uses `http.ProxyFromEnvironment` and honours the system trust store.
Missing: OS-native proxy resolution incl. PAC (WinHTTP/WinINET, `SCDynamicStore`,
GSettings) behind a `ProxyResolver`; ranged/resumable downloads (`Options.Resume` is
accepted and ignored today); proxy auth; mTLS client certificates.

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
- `hook.Event.Progress` is hardcoded to `-1` at both emitters, so a UI has no
  progress to show and must derive one from the phase. Worth revisiting if
  `core/stage` ever grows a per-target callback.

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
helper leaves a staged update the unprivileged launcher cannot finish. Both need
either a launcher that elevates for this (a prompt at start) or the service mode
(IDN-07).

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
