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
unknown `OnBusy` or elevation mode, or an elevated mode with no `Elevator`.

There is no switch for metadata expiry, and there is not going to be one. It is
checked inside go-tuf during `Refresh`, which runs before this package decides
anything, and the freeze defence *is* that check — a flag that could relax it would
be a way to ask for the attack. An earlier `EnforceExpiry` existed and was always
forced to `true`; it was removed rather than kept as decoration, because a knob that
cannot be turned is a knob somebody will eventually believe in (IDN-15).

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
  - `BusyDeferToRestart` — **today**: rolls back cleanly and returns `ErrDeferred`.
    The design wants the staged tree kept and finished by the launcher at next start;
    that needs a launcher and a resting journal state (backlog IDN-05, IDN-06).
  - `BusyForce` — proceed without the proof of quiescence. Terminating processes is
    the host's business; the updater's part of "force" is to continue anyway. Opt-in,
    documented as a data-loss risk.

**No lock offered** means quiescence cannot be proven. The updater proceeds — the
pre-existing behaviour of an updater with no coordination at all — and says so
through the Observer rather than pretending otherwise.

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

With `Policy.Elevation != ElevationNone`, the swap goes through `elevate.Elevator`
instead of the in-process stager. Download and staging stay unprivileged; only the
re-verify and swap run elevated.

What crosses the boundary is three validated scalars — root, channel, version. No
file list, no hashes, no staged path, no URL. The privileged side runs its own TUF
refresh and verification: the descriptor is a *request*, not a verdict it may act on
(T16).

Available today: Windows `ElevationInteractive` (`ShellExecuteEx` verb `runas`,
`shell32.dll` loaded from `%SystemRoot%\System32` only, waits on the process handle).
`ElevationService` and POSIX interactive elevation fail closed with
`elevate.ErrNotImplemented` — see `design.md` §14.2.1 and backlog IDN-07/IDN-08.

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
