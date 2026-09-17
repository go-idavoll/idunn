# IDN-40 — Windows: the launcher as the application's parent — job object and console control events (§6.1, §13, §14.3)

**Priority:** P1 — blocks a trustworthy release

On Windows the launcher cannot `exec`; it runs the application as a child and waits for
it for its whole lifetime, forwarding the standard streams and passing the exit code
through (`cmd/launcher/exec_windows.go`, IDN-29). That contract — whoever started the
launcher sees what it would have seen had it started the application — holds only while
the launcher and the application live and die together. Today they do not:

- **The launcher can die first, and the application runs on as an orphan.** Nothing
  ties the child to the launcher: a launcher ended with `TerminateProcess` (Task
  Manager, `taskkill /F`, a supervisor stopping what it started) leaves the application
  running, with nobody left to pass its exit code on or act on `RelaunchExitCode`.
  Stopping the launcher no longer stops the application.
- **Ctrl+C ends the launcher before the application.** The launcher installs no console
  control handler while the application runs (`signal.NotifyContext` is used only for
  `--uninstall`). A Ctrl+C or Ctrl+Break reaches every process on the console; Go's
  default for an unhandled one is to exit. The launcher exits at once, the shell prompt
  returns, and an application that handles Ctrl+C gracefully — saving, finishing a
  write — keeps writing to the console, and its exit code is lost.

Signals are **not** forwarded on Windows, and need not be: there is no general way to
send one (`GenerateConsoleCtrlEvent` reaches whole process groups on the launcher's own
console, and Ctrl+C not even that selectively), and the ones that exist already reach
the child directly, because it shares the launcher's console. What the launcher must do
is not act on them itself, and outlive the child.

Wanted:

- **A job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.** The launcher creates the
  job, starts the application suspended, assigns it and resumes it (or starts it with
  the job as a `PROC_THREAD_ATTRIBUTE_JOB_LIST` attribute), and holds the only handle.
  When the launcher dies for any reason, the handle closes and the application — with
  every process it started — ends with it. Nested jobs (Windows 8+) keep this working
  when the launcher itself runs inside a job (a CI runner, a terminal, a service host);
  `JOB_OBJECT_LIMIT_BREAKAWAY_OK` is not set, so a child cannot leave by accident.
- **Console control events are absorbed, not acted on.** While the application runs,
  the launcher handles `os.Interrupt` (Ctrl+C, Ctrl+Break) by ignoring it and keeps
  waiting; the application decides what Ctrl+C means and exits with its own code, which
  the launcher passes on.
- **Close, logoff and shutdown events wait for the child.** For `CTRL_CLOSE_EVENT`,
  `CTRL_LOGOFF_EVENT` and `CTRL_SHUTDOWN_EVENT` Go reports `syscall.SIGTERM` when it is
  notified, and blocks the handler, so the launcher stays up while the application uses
  the grace period Windows gives both. This matters because of the job: a launcher that
  died first would kill the application in the middle of its own clean shutdown.
- **Tests with real processes** (`test/e2e/local`): the launcher killed hard takes the
  application and its children with it; Ctrl+C sent to the console group ends a host
  application that exits on its own terms with its own code, and the launcher reports
  that code; a close event lets the application finish a write before both end.

Open, unverified: whether a windowless launcher is terminated at session end before the
application has handled `WM_ENDSESSION`, which the job would then cut short; how
`taskkill /PID <launcher>` without `/F` should behave, which fails today because the
launcher has no window to send `WM_CLOSE` to; whether the launcher is built for the
console subsystem, and a GUI application started through it therefore opens a console
window; and whether an application that runs as a Windows service can sit behind the
launcher at all, since the service control manager expects the process it starts to call
`StartServiceCtrlDispatcher` itself.
