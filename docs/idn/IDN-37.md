# IDN-37 — Uninstall on macOS and Linux: leftovers and registrations (IDN-35, IDN-36)

**Priority:** P2 — hardening and reach

- **macOS, user scope:** a user drags the `.app` to the Trash, and nothing runs;
  `~/Library/Application Support/<bid>` with `versions/` and the TUF cache stay behind.
  The uninstall verb is reachable from the application (a menu item through the
  sidecar, or the helper in `Contents/Helpers`, IDN-28); the leftovers of a bundle that
  was only trashed are documented, not cleaned up — nothing starts again to do it.
- **macOS, system scope:** `SMAppService.unregister` for the daemon, removal of the
  bundle with administrator rights, `pkgutil --forget` for a `.pkg` install.
  **Unverified:** whether macOS 13+ Background Task Management disables the daemon on
  its own when the bundle is trashed.
- **Linux:** the verb removes the `.desktop` entry, icons, the `~/.local/bin` link and
  systemd user units from the manifest, and the helper unit for a system-wide install.
