# IDN-35 — Uninstall (§5, §6.1) — **done (user scope; system scope via an already-elevated process)**

**Priority:** P1 — blocks a trustworthy release

Uninstall is a **verb of the launcher** — `launcher --uninstall [--quiet] [--purge]` —
not a separate binary: the launcher is the one file that stays on disk above
`versions/`, replaces itself (IDN-17) and needs no network and no keys, and one binary
fewer is one binary fewer to sign and ship. The logic lives in `core/uninstall`, so a
host that writes its own launcher gets the same behaviour. `--modify`/repair is the
sidecar's, over an API (IDN-36); uninstall needs no UI.

As built:

- **Offline.** No TUF client and no fetch. `core/uninstall` imports neither; it works
  with the server gone and the metadata expired.
- **Only what idunn owns.** The root is accepted only if it holds a readable idunn
  install state or journal, and — when the launcher is built with `-X
  main.releaseName` — one that names this application; otherwise `ErrNotInstalled`
  with nothing changed. An unreadable state or journal is an error, never taken for
  "nothing installed". Only layout names go (`current`, `versions/`, the meta
  directory, the launcher, idunn's scratch and old-launcher leftovers) plus the caller's
  named caches; anything else in the root is kept and the root with it. The walk
  (`removeTree`) never follows a symlink, junction or other reparse point — it
  `Lstat`s every entry and `Remove`s a non-plain-directory as itself, so
  `os.RemoveAll` is never relied on to not cross a link. A junction planted below the
  root is removed as a link; its target survives (verified on the real filesystem,
  where a Windows junction reports as irregular, not as a directory).
- **Crash-safe.** A terminal `UNINSTALLING` record (`core/txn`) is written before
  anything is removed, then: pointer removed (the application can no longer start),
  `versions/` and the caches deleted, the meta directory last with the journal the
  final file to go. Recovery, rollback and `ResumeDeferred` all refuse a root whose
  last record is `UNINSTALLING` (`txn.ErrUninstalling`), so neither the launcher nor
  the updater rebuilds a tree an interrupted uninstall began to take apart; the
  launcher reports it and points at `--uninstall` to finish. Every step is idempotent,
  and a fault injected at each mutating operation of a clean run leaves either the
  installation intact or one finished by running the uninstall again.
- **Running instances** are handled as for an update: the exclusive application lock
  (optional `Lock`), refused (`ErrBusy`) rather than deleted under a live process. An
  interrupted *update* is settled first (the same `RecoverResult` a start runs); a
  *deferred* update is dropped with the installation it was waiting to change.
- **Host hooks**, compiled in (AGENTS.md §1.3): `hook.Uninstaller.BeforeUninstall` may
  veto (before any change), `PurgeData` removes the application's own data under
  `--purge` and is retried when a run is resumed. The TUF caches named by the caller
  are always removed; `cmd/launcher` passes the installer's cache
  (`layout.InstallerCache`).
- **Windows self-removal.** A running image cannot be deleted, so the launcher's last
  act hands its own removal to a copy of itself opened with `FILE_FLAG_DELETE_ON_CLOSE`
  through an inherited handle (the rustup/uv self-replace shape): the copy waits on the
  launcher's process handle, deletes the launcher and the empty root, then starts
  `cmd.exe /d /c exit` holding the copy's handle so the copy is deleted once it exits.
  Not `%TEMP%` (Defender ASR), no administrator rights, no `MoveFileEx` reboot delay.
  A process handle, not a pid, so a reused pid cannot make the copy wait on the wrong
  process. POSIX unlinks the running launcher directly.

Tests: `core/uninstall` unit tests on the in-memory FS (refusals, links never
followed, kept files, veto, lock, purge and its retry, settling an interrupted update,
dropping a deferred one, fault injection at every boundary, the leftovers-only resume,
option checks); real-filesystem tests for the platform link semantics and the root
check; `core/txn` tests for the `UNINSTALLING` transitions and the recovery refusals;
and `test/e2e/local` `TestUninstall` drives `cmd/launcher --uninstall` as real
processes — removal (including the Windows self-delete copy), a kept user file, an
interrupted uninstall refused a start and finished by a second run, and a refusal to
remove another application. It skips when the test process is elevated (root, or an
elevated Windows token): a user-owned install root is then refused by the
privileged-root check by design, so the per-user path — and, on the elevated GitHub
Windows runner, the self-delete copy with it — is exercised only unelevated. The unit
tests cover the same logic with the root check stubbed.

Still open, tracked elsewhere:

- **System-wide installs** are removed by a process that is already elevated: the root
  check refuses a non-administrators-only root when run with administrator rights
  (`CheckPrivilegedRoot`, the junction defence of §14.8), and refuses a root this
  unprivileged process cannot write (`ErrNotWritable`) rather than half-removing it.
  Raising the prompt itself (UAC/pkexec/authorization) and unregistering the
  service/daemon is [IDN-37](../IDN-37.md) on macOS/Linux and rides on the elevation
  work of [IDN-23](../IDN-23.md). The privileged helper deliberately gets **no**
  uninstall verb — an allowed caller must not remove a system-wide application without
  administrator rights.
- **OS integrations** (the Windows "Installed apps" entry, shortcuts) are removed from
  a recorded manifest by [IDN-36](../IDN-36.md); uninstall already removes what is
  inside the root.
