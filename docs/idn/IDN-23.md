# IDN-23 — Recovery and deferral for system-wide installs (§14.2, §14.3)

**Priority:** P2 — hardening and reach

An interrupted transaction in a root the launcher cannot write can only be recovered
by the elevated helper, and today nothing starts one for that: the launcher reports
the failed recovery and starts the application. Likewise `BusyDeferToRestart` in the
helper leaves a staged update the unprivileged launcher cannot finish. The same holds
for a new launcher the helper staged (IDN-17): the unprivileged launcher reports
`ErrSelfNotWritable` and keeps running the old one. All three need either a launcher
that elevates for this (a prompt at start) or the service mode (IDN-07).
