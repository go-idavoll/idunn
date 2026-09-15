# IDN-29 — Install and restart (§6.1, §14.3) — **done (Windows, Linux)**

**Priority:** P1 — blocks a trustworthy release

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
