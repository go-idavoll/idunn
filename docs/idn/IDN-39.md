# IDN-39 — Probation: a new version confirms it is healthy, or is rolled back (§6.1, §6.2, §14.3, §14.5)

**Priority:** P1 — blocks a trustworthy release

Today an update is final once its transaction commits. `txn.Rollback` undoes a
completed swap, but only for a caller that is still inside `Apply` and has decided the
update is bad (`updater.md` §6). A release that commits and then crashes on every start,
hangs, or fails its own data migration stays live, although the previous version is
still under `versions/` (`stage.MinRetain`). The launcher cannot see it either: on POSIX
it `exec`s into the application and is gone, and on Windows it only passes the exit code
through, with `launch.RelaunchExitCode` as the one code it acts on (IDN-29).

"No non-zero exit within n seconds" is not the answer: an application that hangs or
shows an empty window passes, one that fails at n+1 seconds does not, the reason is
reduced to an exit code, and it needs a supervising parent the launcher does not have
on POSIX. The application knows when it is healthy, so it says so.

Wanted:

- **A committed update starts in probation.** The install state records the new
  version as `PROBATION` with an attempt counter and the version it replaced. Opt-in:
  without a probation setting, a commit is confirmed at once, so an application that
  never calls the API is never rolled back.
- **The publisher sets `K` per release, signed.** `pack.yaml` takes
  `probation: { attempts: K }`; each release carries its own value, so a release whose
  migration needs several starts raises it, and the next one lowers it again. The value
  that governs a probation is the one of the release *in* probation, read from signed
  metadata and copied into the install state at commit — the launcher never fetches
  anything to decide. **Not a descriptor field:** `release.ParseDescriptor` refuses
  unknown fields and schema versions, so either would make every deployed client
  refuse every new release. It travels like release notes (IDN-38): a TUF target
  discovered by name, e.g. `policy/v<major>/<version>.json`, with a strict parser; a
  client that knows nothing about probation never asks for it. The client clamps `K`
  to a ceiling, so a typo cannot turn probation into "never roll back". A host policy
  may override it locally (lower for a fleet canary, off for a kiosk), the same
  precedence as other policy.
- **The launcher counts starts, not seconds.** Before it starts a version in probation
  it increments the counter, durably, the way a boot counter works (A/B updates on
  Android and ChromeOS, GRUB `boot_counter`). No timer, no waiting process, the same
  on every platform. The code stays in `core/launch` and `core/txn`; `cmd/launcher`
  gains a call, not logic.
- **The application reports, through `core/launch`:**
  - `MarkHealthy(ctx)` — atomic write, idempotent, cheap enough to call on every start;
    ends probation. The application calls it once it is actually ready, after its own
    migrations, not at `main`.
  - `MarkUnhealthy(ctx, reason)` — records a bounded, sanitized reason; the application
    then exits. The next launcher start rolls back without spending further attempts.
- **Rollback on the next start** when the version is reported unhealthy, or when the
  counter exceeds `K` without a confirmation. It runs `txn.Rollback` with
  `Migrator.Rollback`, under the app lock, journaled and crash-safe like every other
  rollback, and then starts the previous version. The packer default for `K` is at
  least 2–3: users close an application before it confirms, and machines lose power.
- **A restart the application asks for is not a failed attempt.** A migration that
  needs several starts goes through `launch.Relaunch` (IDN-29). Before the application
  leaves, `Relaunch` atomically increments `requested_restarts` in the probation state;
  the launcher consumes the marker on its next start and does not count that start as
  an attempt. The three paths `Relaunch` has today:
  - **POSIX:** the application `execve`s the launcher. The launcher saw nothing of the
    run, so the marker is the only way it can know; the process id a service manager
    watches does not change.
  - **Windows, under the launcher:** the launcher never exits while the application
    runs — it is the parent for the application's lifetime (`exec_windows.go`), keeps
    the process id its starter sees and sees exit code `RelaunchExitCode` itself. The
    marker is redundant here and written anyway, so the launcher has one rule instead
    of a per-platform one.
  - **Windows, started without the launcher:** `Relaunch` starts a new launcher with
    `--after-pid` and the application exits. The process id does change on this path,
    as it already does for IDN-29; the marker covers it like the others.

  `requested_restarts` has its own ceiling, reset by `MarkHealthy`, so a loop of
  requested restarts ends in a rollback too — on POSIX, where no supervising launcher
  enforces the IDN-29 relaunch limits, this ceiling is the bound. An application that
  just exits and relies on being started again spends attempts, and its publisher
  sizes `K` for that.
- **No fork-and-hand-over supervisor on POSIX.** A launcher that starts the application
  as a child and exits once it is healthy changes the process id (systemd kills the
  control group, launchd with `KeepAlive` starts a second instance), returns a shell
  prompt while a CLI application still owns the terminal (`SIGTTIN`), loses the exit
  code, and must forward signals until it leaves. It would be neither the Windows
  model (a parent for the whole lifetime) nor the POSIX one (`exec`, same process id),
  and would carry the costs of both. Counting starts needs none of that.
- **The rolled-back version is blocked** in the install state until the channel offers
  a newer one; otherwise the next update check installs it again and the loop repeats.
  This is a local decision about an already verified target, not a TUF downgrade, and
  the security concept (§11) says so.
- **The reason is reported, not only stored:** a hook event (§7) and telemetry (§14.5)
  carry version, attempts and reason, so a publisher learns *why* a release failed, and
  a UI sidecar (IDN-19) can tell the user. The same record is what a later crash
  reporter reads; a reporter itself stays out of the launcher.

Open: how a `Migrator.Rollback` that runs days after `Migrate` handles data the new
version has written since — whether probation should forbid irreversible migrations,
or `Migrate` runs on confirmation rather than before the swap; whether services and
headless hosts count attempts per launcher start or need a supervisor's restart count
(systemd `Restart=`, the Windows service recovery actions); how probation interacts
with a system-wide install where neither the launcher nor the application can write
the install state — the counter, the restart marker and `MarkHealthy` all write there
(IDN-23); whether GC must pin the previous version while probation lasts, beyond
`MinRetain`; the default ceiling of `requested_restarts`, and whether the publisher
sets it next to `K`; and whether the policy target carries more than `K` later (a
probation deadline in wall-clock time, subject to the time floor of IDN-09).
