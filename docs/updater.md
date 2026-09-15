# The updater

How `core/updater` behaves, what it guarantees, and where it stops. This documents
the code as it stands; the reasoning behind the shape is in
[`design.md`](design.md) §6, and what is still missing is in
[`status.md`](status.md).

The updater sequences an update. It decides nothing about trust: which bytes are
acceptable is answered by `core/trust` (go-tuf) before this package sees them, and
there is no second verification path beside it.

---

## 1. The two calls

```go
u, err := updater.New(updater.Options{
    Trust:   trustClient,          // go-tuf wrapper
    FS:      fsx.OS(),
    Root:    "/opt/acme",
    Channel: "stable",
})

rel, err := u.CheckForUpdate(ctx)  // nil, nil == already up to date
if rel != nil {
    err = u.Apply(ctx, rel)
}
```

`CheckForUpdate` is read-only: TUF refresh, resolve the channel pointer, compare
against what is installed, apply the policy floors, decide the rollout bucket. It
never touches the install root.

`Apply` is the transaction. It is safe to call again after a crash: the first thing
it does is settle whatever the journal still holds.

## 2. What `New` refuses

Configuration errors are `ErrConfig`, raised at construction rather than mid-
transaction: no trust client, no filesystem, no root, no channel, `RetainVersions`
below 2 (that would leave no rollback target), a negative `QuiesceTimeout`, an
unknown `OnBusy` or elevation mode, an elevated mode with no `Elevator`, or a
`Launcher` that is half set or could address anything but one clean destination in a
release and one file name directly in the root (see *Updating the launcher*).

There is no switch for metadata expiry, and there is not going to be one. It is
checked inside go-tuf during `Refresh`, which runs before this package decides
anything, and the freeze defence *is* that check — a flag that could relax it would
be a way to ask for the attack. An earlier `EnforceExpiry` existed and was always
forced to `true`; it was removed rather than kept as decoration, because a knob that
cannot be turned is a knob somebody will eventually believe in (IDN-15).
`TestExpiredMetadataIsRefusedThroughTheUpdater` drives a real go-tuf client against
a signed repository past its timestamp window, under the most permissive `Policy`
there is, and requires the refusal.

Defaults: `RetainVersions` 2, `QuiesceTimeout` 30s, `OnBusy` `BusyAbort` (the zero
value fails rather than forces), `Elevation` `ElevationNone`, `Now` `time.Now`, `OS`
/ `Arch` the running platform.

## 3. Check: what makes a release applicable

After go-tuf has accepted the metadata, three app-level questions remain — none of
which the repository can answer:

- **Platform and channel.** The descriptor must be for the channel, OS and arch that
  were asked for. A properly signed descriptor for another platform is still the
  wrong one.
- **`MinClientVersion`.** If the release demands one and this client does not state
  its own `ClientVersion`, the update is refused: an unknown version cannot be shown
  to be new enough.
- **Downgrade and `MinFromVersion`.** TUF has already refused metadata that goes
  backwards; these decide whether *this* install may make *this* jump. Not newer and
  `AllowDowngrade` false ⇒ refused. Installed below the release's migration floor ⇒
  refused.

All of these are `ErrPolicy`.

**Installed version** is read from the `current` pointer, not from `state.json`. The
pointer is what actually decides which code runs.

**Staged rollout.** A descriptor with `rollout` in (0,1) admits only clients whose
bucket falls under it. The bucket is `sha256(clientID + "\x00" + version)` mapped to
[0,1) — computed locally, never sent anywhere, and mixed with the version so a client
that is unlucky once does not stay unlucky forever. No `ClientID` means staying out:
a bucket that flip-flops between checks would install a canary and then be offered it
again. No `rollout` field means a full rollout.

## 4. Apply: the transaction

```
recover ─► re-read state ─► Checker ─► Prompter ─► journal:BEGIN
   ─► stage (verified bytes → versions/<v>/)          journal:STAGED
   ─► quiesce (app lock + Coordinator)
   ─► Migrator.Migrate                                journal:MIGRATED
   ─► swap `current`                                  journal:SWAPPED
   ─► VerifyAfterApply (optional) ─► write state      journal:COMMITTED
   ─► remove staging ─► GC old versions
        │
   on error at any point ─► txn.Rollback ─► journal:ROLLED_BACK
```

Notable properties, each for a reason:

- **Recovery runs first.** An interrupted transaction is settled before a new one
  opens, because `BEGIN` replaces the journal's history. A crashed update is never
  silently built on top of.
- **The plan is re-validated.** A `Release` may be minutes old and the tree may have
  moved under it. If `current` no longer matches `FromVersion`, `Apply` fails with
  `ErrStale` rather than applying a plan derived from a state that no longer exists.
- **Staging is assembled aside and promoted with one rename.** Nothing incomplete is
  ever visible under `versions/`. A crash mid-staging leaves a tree recovery deletes,
  not one it has to inspect file by file.
- **Every path component is checked, not just the text.** `SanitizeDst`
  (`internal/safepath`, fuzzed) judges the path string; `Stage` refuses to descend
  through a symlink while creating it. A clean-looking path plus a planted symlink is
  the traversal that text validation alone misses (T7).
- **The swap is a single rename of the pointer.** Rollback is the same rename in
  reverse. Locked Windows DLLs are irrelevant: the new files were written into a new
  directory.
- **The install state is written before the commit record**, so a crash between them
  leaves recovery a state that already agrees with the live pointer.
- **GC runs only after the commit.** A version directory that will not go (Windows
  sharing violation) yields `stage.ErrIncompleteGC`, which is reported through the
  Observer and retried next cycle — never a reason to undo a good update (§14.1).
- **The app lock is held until everything is finished, including the rollback.**
  `Migrator.Rollback` touches the same host state `Migrate` did; releasing earlier
  would hand the application back a database somebody is still undoing changes to.

### Failure handling

The rollback runs the same code as crash recovery (`txn.Rollback`), on purpose: a
failure path with its own implementation is one nobody exercises, and this one is
reached exactly when things are already going wrong. It runs under
`context.WithoutCancel` — undoing is not optional work a cancellation may skip.

If the rollback itself fails, its error is *joined* to the original rather than
replacing it: an operator needs to know both that the update failed and that undoing
it did too.

The reported result is `"rolled_back"` only when the failure happened after the
journal opened. A release refused in pre-flight was never applied, and reporting it
as rolled back would inflate exactly the number a publisher watches to decide whether
a release is bad.

## 5. Quiescence

Before the migration touches state outside the install root, no instance of the host
application may still be writing.

The **exclusive application lock** is the ground truth; `Coordinator.RequestShutdown`
is only how instances are *asked*. The lock is the host's, because only the host knows
where its data lives.

- Lock acquired ⇒ proceed.
- Not acquired ⇒ ask the Coordinator, then poll every 250ms until
  `QuiesceTimeout`.
- Still busy ⇒ `Policy.OnBusy` decides:
  - `BusyAbort` — `ErrBusy`, retry later.
  - `BusyDeferToRestart` — keeps the staged tree in a resting `DEFERRED` journal
    state and returns `ErrDeferred`; the launcher finishes it at the next start
    (IDN-06). Recommended for a host whose running application updates itself, but
    never the default: an unset `OnBusy` is `BusyAbort`, and `New` does not promote
    it (IDN-21).
  - `BusyForce` — proceed without the proof of quiescence. Terminating processes is
    the host's business; the updater's part of "force" is to continue anyway. Opt-in,
    documented as a data-loss risk.

**No lock offered** means quiescence cannot be proven. The updater proceeds — the
pre-existing behaviour of an updater with no coordination at all — and says so
through the Observer rather than pretending otherwise.

### Install and restart

The updater never restarts the application; the launcher does, when asked
(backlog IDN-29). After `Apply` returns — committed, or `ErrDeferred` because the
application itself holds its lock — the application releases what it holds and calls

```go
code, err := launch.Relaunch(launch.RelaunchOptions{
    Launcher: filepath.Join(root, "launcher"), // the host's own layout
    Root:     root,
    Args:     os.Args[1:],
})
if err == nil {
    os.Exit(code)
}
```

Under `cmd/launcher` on Windows that returns 42 and the launcher, still the parent,
finishes the deferred update and starts the application again. On POSIX the process
is replaced by the launcher. On Windows without a launcher in front, a new launcher
is started that waits for this process to exit before it touches anything. An
application that exits with 42 on its own gets the same treatment from a supervising
launcher; the code is reserved.

### Updating the launcher

The launcher sits above `versions/`, so an update never replaces it by itself
(backlog IDN-17). A host that ships its launcher in its releases says which file that
is and what it is called in the root:

```go
Launcher: stage.Launcher{
    Source: "bin/acme-launcher.exe", // the release's Dst of the launcher
    Name:   "acme.exe",              // the launcher's file name in the install root
},
```

Both are host knowledge and compiled in; no descriptor field can choose or move them.
Staging keeps the verified bytes of `Source` pending for the transaction, and only after
the commit record are they staged as `.updater/launcher.next/<Name>`. A rolled-back,
refused or deferred update stages nothing; a crash after the commit is finished by the
next recovery. The launcher (`core/launch`, `cmd/launcher`) swaps that file in at its
next start — it checks no hash; the install root's permissions protect the staged file
exactly as they protect the launcher.

On Windows the swap renames the running launcher aside and the new one in. A crash
between those two renames leaves no launcher under `Name` — a residual risk, because
Windows cannot atomically replace a running image. The repair runs at the next launcher
start and, since a missing launcher cannot start, also at the beginning of `Apply` and
`ApplyRequested`, in `launch.Relaunch`, and wherever the host calls
`Updater.RepairLauncher`. None of it can fail an update; failures are Observer events.

## 6. Crash recovery

The journal is rewritten atomically on every append (write, fsync, rename): a torn
append is exactly what a crash produces, and a journal that can itself be half-written
cannot certify that nothing else is. Transitions are validated against a table; a
history the recovery would have to interpret is never recorded in the first place.

On the next start, `txn.RecoverResult` reads the last record:

| Last state | Action | Why |
|---|---|---|
| `COMMITTED`, `ROLLED_BACK` | remove orphaned staging/abort dirs | terminal |
| `SWAPPED` | **complete** | the new version is already live and the migration ran |
| `MIGRATED` | ask the pointer, then complete or roll back | the swap is one rename — it happened or it did not; the filesystem is the authority, not the journal |
| `STAGED` | roll back, `Migrator.Rollback` | the migration may have been interrupted halfway; `Rollback` is contractually idempotent |
| `BEGIN` | roll back, no migrator | nothing beyond the journal write happened |
| anything else | error | an unknown state is refused, not guessed |

`txn.Rollback` differs from recovery in one deliberate way: it undoes a completed swap
too. Recovery finishes a post-swap transaction because after a crash the new version
is live; `Rollback` is called by a caller that is still running and has decided the
update is bad.

## 7. Elevation

With `Policy.Elevation != ElevationNone`, the root is one this process cannot write,
and it runs no part of a transaction there — not the journal, not staging, not the
time floor. What it does, with reads only: the clock floor check, the stale check,
the policy and walk decision, and the `Checker` and `Prompter` hooks. Then it asks
`elevate.Elevator`, and when the helper returns it reads the pointer back. A helper
that exits zero and did not install the requested version is `elevate.ErrHelper`,
never a success. Anything refused before the request never raises a prompt.

`CheckForUpdate` still enforces the time floor in this mode, but does not raise it:
the floor lives in the root, and the helper's own refresh raises it.

The helper side is `Updater.ApplyRequested(ctx, version)`, on an Updater configured
for `ElevationNone` (anything else is `ErrConfig`: a helper that elevates again
loops). It refreshes, resolves the channel head and runs every policy check itself;
the requested version only has to agree with the head, otherwise `ErrStale`. A
caller cannot pick a release the publisher has not made current, even one that
would still be an upgrade. A request for the installed head is a no-op success.
A host's helper verb validates its arguments with `elevate.ParseRequest` — the
same grammar the sender enforced — and keeps its TUF cache in
`elevate.PrivilegedCacheDir(root)`, inside the root, never in a directory the
invoking user can write (T23). `elevate.AcceptRequest` does the validation and also
refuses a root that anyone but an administrator could change (owner, ACL including
inheritable ACEs, reparse points, drive kind); a caller should run
`elevate.CheckPrivilegedRoot` before asking, so such a root never gets a prompt.

Download and staging therefore run elevated today, in the helper. The design's
unprivileged pre-download handed over by file descriptor needs the authenticated
IPC of the helper service (IDN-07); without it, a helper reading the user's cache
by path is exactly the TOCTOU §14.8 warns about, so the helper downloads again.

What crosses the boundary is three validated scalars — root, channel, version. No
file list, no hashes, no staged path, no URL. The privileged side runs its own TUF
refresh and verification: the descriptor is a *request*, not a verdict it may act on
(T16).

Available today: Windows `ElevationInteractive` (`ShellExecuteEx` verb `runas`,
`shell32.dll` loaded from `%SystemRoot%\System32` only, waits on the process handle).
`test/e2e/cmd/e2eapp` is a host wired this way (`apply` verb), and the `elevated`
e2e scenario installs and updates it into an administrators-only root through real
UAC prompts.

Linux `ElevationInteractive` runs the helper through `pkexec` with an argument
vector and an empty environment (`design.md` §14.2.2). pkexec is taken from
`/usr/bin` or `/bin` only, never `PATH`. The helper — `HelperPath`, or the running
executable — must resolve to a file that it and every directory above it are
root-owned and writable by nobody else; anything else is `elevate.ErrRequest` at
construction. pkexec status 126 (dialog dismissed) is `elevate.ErrDeclined`, 127
(no polkit agent, failed or refused authentication) and any other non-zero status
are `elevate.ErrHelper`; a helper must not exit 126 or 127 itself. An example
polkit action is `docs/examples/org.idunn.apply.policy`. The helper sees pkexec's
scrubbed environment, so proxy variables do not reach it.

macOS has no interactive elevation by decision: `NewInteractive` fails with
`elevate.ErrNotImplemented`, and a system-wide install there is the service mode
(`SMAppService`).

`ElevationService` on POSIX and Windows: `elevate.NewService(ServiceOptions{Endpoint})`
on the unprivileged side, and a daemon or service on the privileged side running
`elevate.NewHelper(HelperOptions{Endpoint, Applier, AllowedRoots, AllowedUIDs})` (POSIX,
a Unix socket path) or `elevate.NewHelper(HelperOptions{Endpoint, Applier,
AllowedRoots, AllowedSIDs})` (Windows, `\\.\pipe\<name>`) with
`updater.RequestApplier{Channel, Options}` as its applier. The helper authenticates the
caller from the kernel — `SO_PEERCRED`/`LOCAL_PEERCRED` on POSIX, the pipe client's
token user SID on Windows — allows only listed roots that also pass
`CheckPrivilegedRoot` (at start and per request), rate-limits, and answers with a class
only. An empty allow-list means root (POSIX) or SYSTEM (Windows) only, and the other
platform's allow-list is refused. On Windows the helper builds the pipe's DACL itself
(SYSTEM and Administrators full; the listed accounts read/write only), refuses to start
if the pipe name is already taken, and refuses remote (SMB) clients (backlog IDN-07).

On macOS that daemon is an `SMAppService` LaunchDaemon of the host's bundle (IDN-08).
The host ships `elevate.DaemonPlist(DaemonConfig{Label, BundleProgram,
AssociatedBundleIdentifiers, Arguments})` at
`Contents/Library/LaunchDaemons/<Label>.plist`, calls `elevate.RegisterDaemon("<Label>.plist")`
and then `elevate.DaemonStatus`; on `DaemonRequiresApproval` it tells the user why and
offers `elevate.OpenLoginItemsSettings()`. Until the status is `DaemonEnabled` there
is no helper to ask. Give the socket a directory the daemon creates as root, mode
0755, e.g. `/Library/Application Support/<Label>/helper.sock` — `/var/run` fails the
socket-directory check. Set `HelperOptions.PeerRequirement` (for example
`anchor apple generic and identifier "com.acme.app" and certificate leaf[subject.OU] = "TEAMID"`)
to require the caller's code signature as well as its uid. All of this needs a darwin
build with cgo and macOS 13; elsewhere the calls return `ErrNotImplemented` and a
non-empty `PeerRequirement` stops `NewHelper`.

Cancelling the context stops the *wait*, never the apply: the elevated process owns
the swap once it starts, and killing it mid-write is the half-installed state the
journal exists to prevent.

`elevate.NeedsElevation(root)` answers by creating and deleting a probe file in the
deepest existing directory of the root — the same operation the apply performs.
Predicting the kernel's access check from an ACL is a second implementation of it.
Ambiguity is an error *and* `true`.

## 8. Hooks

All optional; nil is a no-op and headless is the default.

| Hook | When | Failure |
|---|---|---|
| `Checker` | pre-flight, before the journal opens | `ErrCheck`, zero changes on disk |
| `Prompter` | after the check | `false` ⇒ `ErrDeclined` |
| `Coordinator` | quiesce, if the lock is held by someone | `ErrBusy` |
| `Migrator` | after staging, before the swap | `ErrMigrate` ⇒ rollback, `Rollback` runs |
| `Observer` | throughout | none — it is the host's own compiled code |
| `Reporter` | terminal outcome | logged to the Observer and dropped |

An Observer that panics is the host's problem, not something guarded against here: it
runs in the host's process, as the host's code. That is the same rule that makes
hooks safe at all — they are compiled host code, never fetched (§7).

## 9. Telemetry

`Outcome` is deliberately coarse: versions, OS/arch, result
(`committed`/`rolled_back`/`aborted`), the phase that failed, and an error class from
a closed vocabulary — `verify`, `network`, `migrate`, `disk`, `permission`,
`clock_skew`, `policy`, `busy`, `declined`, `check`, `cancelled`, `config`,
`resolve`, `unknown`. No paths, no raw error strings, no identifiers.

Reporting is best-effort and runs under `context.WithoutCancel`; a Reporter error
reaches the Observer and is then dropped. It never affects the update result, and the
telemetry backend has no authority over updates.

`clock_skew` is worth wiring into UI: it means metadata was rejected as expired, and
the actionable message is "the system clock looks wrong", not "update failed". The
check is never weakened — the fix is guidance (§14.7).

## 10. Testing an integration

Everything is injected, so a full update runs in memory with no network and no real
clock: `FS: fsx.NewMem()`, a `Resolver` returning fixture descriptors and bytes, `Now`
a fake clock, `OS`/`Arch` set explicitly. `core/updater`'s own tests do exactly this,
including crash injection at every journal boundary. For end-to-end runs against
genuinely signed, deliberately tampered repositories, see `test/redteam`
(`make redteam-corpus`).
