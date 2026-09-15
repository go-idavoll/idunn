# IDN-35 — Uninstall (§5, §6.1)

**Priority:** P1 — blocks a trustworthy release

Nothing removes an installation today; only the helper has uninstall scripts. Decided:
uninstall is a **verb of the launcher** (`launcher uninstall [--quiet] [--purge]`), not
a separate binary — the launcher is the one file that stays on disk above `versions/`,
replaces itself (IDN-17) and needs no network and no keys, and one binary less is one
binary less to sign and ship. The logic lives in a `core/uninstall` package, so a host
that writes its own launcher gets the same behaviour.

Wanted:
- **Offline.** No TUF client, no fetch; it works with the server gone and the metadata
  expired.
- **Only what idunn owns.** The root is accepted only if it holds a valid idunn state
  file whose application ID matches the one compiled in; otherwise refuse with no
  change. Only layout names are removed (`current`, `versions/`, the meta directory,
  the launcher); the root itself only if it is empty afterwards. The walk never follows
  a symlink, junction or other reparse point — `os.RemoveAll` is not relied on for that.
- **Crash-safe.** An `uninstalling` record in the journal, then: pointer removed (the
  application can no longer start), integrations removed (IDN-36), `versions/` deleted,
  meta directory last. A launcher that finds the record completes the uninstall instead
  of starting the application. Every step is idempotent.
- **Running instances** are handled as for an update: the lock and `hook.Coordinator`;
  refuse or ask, never delete under a live process.
- **Host hooks**, compiled in (AGENTS.md §1.3): `BeforeUninstall` may veto,
  `PurgeData` removes the application's own data under `--purge`. The TUF cache and the
  time floor belong to idunn and are always removed.
- **System-wide installs** require administrator rights directly (UAC, pkexec,
  authorization on macOS): the service or daemon is stopped and unregistered (the logic
  of `uninstall-service.ps1` and `uninstall.sh`, in Go). The privileged helper gets
  **no** uninstall verb — an allowed caller must not be able to remove a system-wide
  application without administrator rights.

Open: how the launcher removes itself on Windows, where a running image and its
directory cannot be deleted. A copy started from `%TEMP%` (NSIS, Inno Setup) collides
with Defender ASR rules for unknown executables; `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`
needs administrator rights and leaves files until a reboot; a delayed `cmd /c` removal
looks like malware to EDR. Leaning: remove everything but the launcher, then schedule
the launcher and the empty root for removal.

Negative tests: a root without a valid state file or with another application ID; a
junction or symlink below the root pointing outside, whose target must survive; crash
injection at every journal boundary; a running instance; a system-wide uninstall
without administrator rights; a helper caller asking to uninstall.
