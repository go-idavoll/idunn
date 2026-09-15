# IDN-17 — Launcher self-replacement (§13) — **done**

**Priority:** P2 — hardening and reach

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
