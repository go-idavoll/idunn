# IDN-41 — Crash reports: detected at the launcher, collected by the application or the OS, sent by someone else (§8, §14.5, IDN-39)

**Priority:** P2 — hardening and reach

A publisher learns today that an update committed, rolled back or was aborted
(`hook.Outcome`, §14.5), and — with probation — that a version was rolled back on a
machine and why (IDN-39). What it does not learn is that the application itself
crashed, where, and on which version. Hosts bolt a crash reporter on themselves, and
the obvious place to hang one is the launcher, because every start goes through it.

That is exactly the place it must not go into whole. The launcher runs on every start,
it is what repairs a broken update, and on POSIX it is gone once it `exec`s: a crash
reporter's network code, endpoints, retries, consent, symbolication and SDKs in there
would make the smallest component the one with the most reasons to fail. The work
splits into three parts with three owners.

| Part | Cost | Owner |
|---|---|---|
| **Detect**: the application ended abnormally | trivial, no dependencies | launcher, where it can see it; probation (IDN-39) already does, by counting |
| **Collect**: stack trace, dump, version, recent log | moderate | the application itself, or the OS |
| **Send**: consent, filtering, transport, retry | large, changes often | a separate process, or the application at its next start |

Wanted:

- **A crash record, not a crash reporter, in core.** `.updater/crashes/`, one small
  bounded file per event, written atomically: version, platform, time from the injected
  clock, how the process ended (exit code, NTSTATUS on Windows, signal on POSIX where
  it is known), and the path of anything collected — never the contents. A ceiling on
  count and age; the oldest go first. A strict parser like every other record under
  `.updater/`, so the files are data a reporter reads, never instructions.
- **Detection where it is cheap and certain.**
  - **Windows:** the launcher is the parent for the application's lifetime (IDN-40)
    and sees its exit code. An exception code (`0xC0000005`, `0xC0000409`, …) or the
    Go runtime's exit code 2 after a fatal error becomes a record. Ctrl+C
    (`0xC000013A`) and a clean non-zero exit do not.
  - **POSIX:** the launcher has `exec`ed and sees nothing, and stays that way — no
    supervising parent for this (see IDN-39 on fork-and-hand-over). The application
    records its own fatal errors (below), and a start that finds a version on probation
    whose previous start never confirmed already has the signal it needs.
  - **Probation (IDN-39)** already writes the reason for a rollback; the record for it
    points there instead of duplicating it.
- **Collection by the application, through a small helper in `core/launch`.** Go's
  `debug.SetCrashOutput` (Go 1.23+) writes the runtime's fatal error and every
  goroutine's stack to a file on panics and fatal errors, including those in goroutines
  the application does not own. A helper opens that file under the crash directory at
  start-up and names it in the record the next start writes; the application calls one
  function first thing in `main`. Nothing is read or sent here.
- **Native crashes are the OS's.** Windows Error Reporting `LocalDumps` (a registry
  value per executable, recorded in the integrations manifest, IDN-36, so an uninstall
  removes it); systemd-coredump / `core_pattern` on Linux; macOS writes `.ips` reports
  itself. The record names where to look; idunn writes no dumps.
- **No stderr capture by the launcher.** Tailing the application's stderr needs a pipe
  in place of the inherited handle, which changes what the application sees (a console
  becomes a pipe, `isatty` answers differently, colours and prompts break) and puts a
  copying goroutine into the path of every byte. `SetCrashOutput` gets the part that
  matters without it.
- **Sending stays outside core.** A `CrashReporter` hook, or simply the records on disk
  and a documented format: the host's reporter — its own process, or the application at
  the next start — reads them, asks for consent, strips what it must and sends. It
  deletes a record once it has handled it. §14.5 holds: `hook.Outcome` stays coarse and
  PII-free; a stack trace is not an `Outcome` field and never becomes one.
- **Tests:** a Windows e2e scenario with a host application that dereferences nil and
  one that exits 2 after a Go fatal error, each producing one record; Ctrl+C and a
  clean `exit 1` producing none; `SetCrashOutput` wiring checked on every platform with
  a panic in a goroutine; the ceiling on records; a record the parser refuses.

Open: whether the launcher should also record an application that is killed from
outside (`TerminateProcess` of the application alone), which is not a crash of the
application but looks like one to a user; whether a crash within seconds of start
should count as a failed probation attempt immediately rather than at the next start,
which would make probation react to a crash loop without waiting for the user to try
again; how records and dumps are handled in a system-wide install, where the
application cannot write the root (IDN-23) and a per-user crash directory would be
needed; and how long dumps may be kept, which is the host's data-protection decision
rather than a default idunn should pick.
