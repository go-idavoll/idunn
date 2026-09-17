# IDN-40 — Windows: the launcher as the application's parent — job object and console control events (§6.1, §13, §14.3)

**Priority:** P1 — blocks a trustworthy release

On Windows the launcher cannot `exec`; it runs the application as a child and waits for
it for its whole lifetime, forwarding the standard streams and passing the exit code
through (`cmd/launcher/exec_windows.go`, IDN-29). That contract — whoever started the
launcher sees what it would have seen had it started the application — holds only while
the launcher and the application live and die together. Before this item they did not:

- **The launcher could die first, and the application ran on as an orphan.** Nothing
  tied the child to the launcher: a launcher ended with `TerminateProcess` (Task
  Manager, `taskkill /F`, a supervisor stopping what it started) left the application
  running, with nobody left to pass its exit code on or act on `RelaunchExitCode`.
- **Ctrl+C ended the launcher before the application.** The launcher installed no
  console control handler while the application ran. A Ctrl+C or Ctrl+Break reaches
  every process on the console, and Go's default for an unhandled one is to exit: the
  launcher exited at once with `STATUS_CONTROL_C_EXIT`, the shell prompt returned, and
  an application still shutting down cleanly lost its exit code.

Signals are **not** forwarded on Windows, and need not be: there is no general way to
send one (`GenerateConsoleCtrlEvent` reaches whole process groups on the launcher's own
console, and Ctrl+C not even that selectively), and the ones that exist already reach
the child directly, because it shares the launcher's console. What the launcher must do
is not act on them itself, and outlive the child.

## As built

- **A kill-on-close job the launcher joins itself** (`cmd/launcher/job_windows.go`).
  Before it starts the application the launcher creates a job object with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, moves *itself* into it and keeps the only
  handle. Everything it starts from then on — the application and whatever that
  starts — is in the job, so a launcher that dies for any reason takes the tree along.
  Joining rather than assigning the child avoids the moment a child runs unassigned
  between its creation and the assignment; closing that gap otherwise needs a
  suspended start, whose main thread `os/exec` does not expose. Nested jobs (Windows 8
  and later) keep it working when the launcher already runs inside a job.
- **The job lets go after a normal exit.** Once the application has exited on its own,
  the launcher clears kill-on-close before it exits, so a process the application left
  running on purpose — a browser it opened, a detached helper — is not killed by the
  launcher's exit. The limit is restored before a relaunch (IDN-29) starts the
  application again. `JOB_OBJECT_LIMIT_BREAKAWAY_OK` is set, so an application can
  also start a process with `CREATE_BREAKAWAY_FROM_JOB` that is never in the job.
- **Console control events are the application's.** While the application runs the
  launcher is notified of `os.Interrupt` (Ctrl+C, Ctrl+Break) and `syscall.SIGTERM`
  (close, logoff, shutdown) and does nothing with them. Being notified is what keeps Go
  from exiting on Ctrl+C; for the close events Go also holds the handler open, so the
  launcher stays up while the application uses the grace period — without that, the
  job would end the application in the middle of its clean shutdown.
- **Fail open.** If the job cannot be created or joined, the launcher reports it and
  starts the application anyway, as it did before.
- **Tests with real processes** (`test/e2e/local/lifetime_windows_test.go`, Windows):
  a killed launcher takes the application and the process it started along; after a
  normal exit that process keeps running; Ctrl+Break sent to the launcher's process
  group is answered by the application, and the launcher exits after it with its code
  (it exited with `0xc000013a` before); a closed console window lets the application
  finish shutting down before the launcher exits. The first and third failed before
  this change; the normal-exit test fails when the job is not released.

## Still open

Unverified: whether a windowless launcher is terminated at session end before the
application has handled `WM_ENDSESSION`, which the job would then cut short; how
`taskkill /PID <launcher>` without `/F` should behave, which fails because the launcher
has no window to send `WM_CLOSE` to; whether the launcher is built for the console
subsystem, and a GUI application started through it therefore opens a console window;
whether an application that runs as a Windows service can sit behind the launcher at
all, since the service control manager expects the process it starts to call
`StartServiceCtrlDispatcher` itself; and the close-window test skips when Windows
Terminal is the default terminal, where `WM_CLOSE` to the console handle closes nothing.
