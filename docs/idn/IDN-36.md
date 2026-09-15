# IDN-36 — OS integrations as a recorded manifest; Windows "Installed apps" (§5, §13)

**Priority:** P1 — blocks a trustworthy release

The installer registers things outside the root — the Windows uninstall entry, Start
menu shortcuts, file associations, URL protocols, autostart, a scheduled task, the
helper service. Uninstall (IDN-35) must remove exactly those and guess nothing, so what
was registered is recorded, as MSI does: `<meta>/integrations.json`, written before each
registration takes effect, reversed by `Unregister`. A `core/integrate` package with a
per-OS implementation provides `Register`, `Refresh` and `Unregister`.

Windows uninstall entry, `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\<id>`
(user) or the same key in the 64-bit view of `HKLM` (machine): `DisplayName`,
`Publisher`, `DisplayIcon`, `DisplayVersion`, `InstallLocation`, `InstallDate`,
`EstimatedSize`, `UninstallString` and `QuietUninstallString` naming the launcher verb.
When an MSI installed the application (IDN-34), Windows Installer owns the entry and
idunn writes none of its own.

- **`DisplayVersion` is derived state, never a source of truth.** winget, Intune and
  SCCM detect the installed version through it, so a stale value makes them "upgrade"
  forever. It is refreshed after a commit and reconciled against the pointer by the
  launcher at start; a failed write is reported and never rolls back a committed
  update (the swap is the transaction, the registry is not part of it). In a
  system-wide install the refresh is the helper's, which can write `HKLM`.
- **Modify and repair belong to the sidecar.** Decided: idunn exposes the API to set
  and manage the entry — including `ModifyPath`, `NoModify` and `NoRepair` — and the
  actions behind it (update now, repair, uninstall), but core registers no modify
  command itself: without a UI there is nothing sensible for "Modify" to open, so the
  default is `NoModify=1`, `NoRepair=1`. A sidecar (`idunn-fyne`, `idunn-web`, …)
  calls the API to register its own entry point and presents the dialog. Settings has
  no "update" button for Win32 applications; "Modify" is the only hook.
- **Repair** is a core operation the sidecar calls: re-verify every installed file of
  the current version against its TUF target hash and re-materialize what differs
  (the verification already exists for reuse, IDN-10). Unlike uninstall it needs the
  network when a file has to be fetched.

macOS and Linux integrations (`.desktop` entries, icons, `~/.local/bin` links, systemd
user units, `SMAppService` registration) use the same manifest; their specifics are
IDN-37.
