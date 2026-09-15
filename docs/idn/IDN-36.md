# IDN-36 — OS integrations as a recorded manifest; Windows "Installed apps" (§5, §13) — **partly done (manifest, Windows uninstall entry; repair and the other integrations open)**

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

## As built

- **`core/integrate`.** An `Integrator` over an install root, with the operating
  system behind an injected `Registry` interface (`OSRegistry()` on Windows, nil
  elsewhere; `MemRegistry` for tests), so every path runs on every platform.
  `RegisterUninstallEntry`, `Refresh`, `Unregister`, and `Recorded` for a caller that
  must know before it removes anything.
- **The manifest** is `.updater/integrations.json` (`layout.Integrations`), strict JSON
  with a schema version, a closed set of kinds (today `windows-uninstall`), at most 64
  records, no duplicates, and every field validated on read — an unreadable or invalid
  manifest is an error, never "nothing registered". A record keeps only what finds,
  refreshes and removes the entry (kind, scope, id, launcher name, icon path), not the
  host's values. Register writes the record **before** the key; Unregister removes
  entries newest first and drops each record only once its entry is gone, so an
  interrupted run leaves on record exactly what is still registered.
- **Nothing is written or removed that is not this root's.** The entry id may hold
  only letters, digits, `.`, `_`, `-`, `{`, `}` — one key name below `Uninstall`, never
  a separator. Every entry carries `IdunnInstallRoot`. Register refuses (`ErrConflict`,
  nothing changed) an existing key without it, or one naming another root that still
  holds idunn state; it takes over one whose root is gone. Unregister deletes only a key
  naming this root (compared as Windows compares paths) and leaves any other alone.
- **Derived values** — `DisplayVersion`, `DisplayIcon` (the launcher, or an
  install-relative file in the live version directory), `EstimatedSize` (the live
  version directory plus the launcher, links never followed), `InstallLocation`, the
  quoted `"<root>\<launcher>" --uninstall [--quiet]` commands — come from the root and
  the pointer, never from the caller. `InstallDate` is kept from the first
  registration.
- **Modify and repair.** `UninstallEntry.ModifyPath` and `Repair` set `ModifyPath`,
  `NoModify` and `NoRepair`; left empty they hide both buttons. A sidecar registers the
  entry again with them set; the installer run again resets them.
- **Refresh** writes only what differs, so a start that finds the entry current changes
  nothing — which lets an unprivileged start of a system-wide installation succeed. It
  runs at the end of every `updater.Apply` (`Options.Registry`, on a context that
  outlives a cancellation after the commit), reports failures as Observer events, and
  never fails the update; `launch.Start` reconciles at every start (`Options.Registry`,
  `Result.IntegrateErr`), which covers recovery, deferred updates and hosts that set no
  registry on their updater. `cmd/helper` sets it for the updates it applies.
- **Uninstall** (`uninstall.Options.Registry`) refuses before changing anything when
  integrations are recorded and it has no registry, or the manifest does not read.
  Otherwise it unregisters right after the `UNINSTALLING` record and before the pointer
  goes; a failure is `ErrIncomplete`, and the next run continues.
- **Wiring.** `cmd/installer` registers after a successful install — also when the
  version was already installed, so running it again repairs a failed or removed entry
  — when built with `-X main.launcherName=...` (and optionally `main.publisher`); the
  entry is keyed by the release name and shows `appName`. Its scope follows the root:
  machine for an administrators-only root, user otherwise. An install performed by the
  elevated `apply` verb registers there; the unprivileged side that asked registers
  nothing. A failed registration exits 1 with the installation in place.
  `cmd/launcher` reconciles at start and unregisters with `--uninstall`.

Tests: `core/integrate` on the in-memory registry (values, scopes, re-registration,
validation, ownership refusals and takeover, write-ahead order, links not followed by
the size, refresh and its failures, resumable unregister, manifest validation, file
system failures) and on the real registry below `HKCU` (the backend, and the whole
lifecycle against a real root); `core/uninstall` (removal, refusals before anything
changes, a failed delete finished by the next run, another root's entry left alone,
fault injection at every filesystem operation with an entry registered); `core/updater`
(refresh after apply, a failed write that does not fail the update, a rolled-back update
that writes nothing, a canceled context); `core/launch` (reconcile after a deferred
update, an unrefreshed update and a skipped start; no failure over the entry);
`cmd/installer` (registration, a failure retried by running again, no launcher no
entry); and `test/e2e/local` `TestInstalledAppsEntry`, which drives the real binaries on
Windows: the installer registers, a start corrects a wrong `DisplayVersion`, a newer
install updates it, and `--uninstall` removes it.

Still open:

- **Repair** as a core operation (above).
- **The other Windows integrations**: Start menu shortcuts, file associations, URL
  protocols, autostart, the scheduled task, the helper service. Each becomes a kind in
  the manifest.
- **An MSI-owned entry** (IDN-34): an installer package that registers its own entry
  builds `cmd/installer` without `launcherName` today; refreshing an MSI's
  `DisplayVersion` belongs to that work.
- macOS and Linux integrations: [IDN-37](IDN-37.md).
