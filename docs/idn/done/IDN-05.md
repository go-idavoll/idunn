# IDN-05 — Launcher shim (§6.1, §13, §14.3) — **done**

**Priority:** P0 — blocks a first end-to-end release

`cmd/launcher` is the shim; everything it does beyond flag parsing lives in
`core/launch`, so a host may write its own. It settles an interrupted transaction,
applies a deferred update while no lock is held, and hands over: `execve` on POSIX so
nothing of it survives into the running process, a parent that passes the exit code
through on Windows. No network, no keys, no TUF client — every byte it moves was
verified when it was staged.
