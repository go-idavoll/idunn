# IDN-30 — Replacing the privileged helper itself (§14.2)

**Priority:** P1 — blocks a trustworthy release

The helper (`cmd/helper`) is installed once, with administrator rights, and today
replaced only by uninstalling it and installing the new build: `install.sh` and
`install-service.ps1` refuse an existing installation, and an application update never
touches the helper that performs it. A publisher whose helper has a bug, or whose
trust anchor or allowed roots change, has no in-place path.

Needed: a way for a new helper to arrive with a release and be put in place — a
separate elevation during or after the update (a UAC/pkexec prompt, or the service
replacing itself through a staged binary it verified), with the same guarantees as the
application's own update: the new helper's bytes verified against TUF before they run
as root, the old helper kept as a rollback target, the service/daemon registration
(SCM, systemd unit, `SMAppService` — re-registration and approval behaviour on macOS
are unverified, see `scripts/macos/README.md`) updated atomically, and the caller list
and state directory carried over. Interacts with IDN-17 (launcher self-replacement)
and IDN-23 (recovery and deferral for system-wide installs).
