# IDN-34 — Installer packages and the publishing pipeline (§5, §9)

**Priority:** P2 — hardening and reach

The signature of an installer package is checked when the package installs and never
again; an update bypasses the package and places files directly. So every file idunn
ships must carry its own OS signature, and a package is only the wrapper around the
first install. The order, to be documented: build, sign each file (inside out on
macOS), notarize and staple, `packer publish`, then package, sign the package, notarize
the package.

Wanted: scripts (not `core`) and documentation, generalising `scripts/macos` and
`scripts/windows` from the helper to the application:

| OS | fits idunn | does not |
|---|---|---|
| Windows | signed `cmd/installer`; an MSI (WiX) that installs only the launcher and the bootstrap | MSIX / Microsoft Store: read-only install location, updates only through the Store or App Installer |
| macOS | a notarized `.dmg` with the `.app` (user scope); a `.pkg` signed with a Developer ID Installer certificate (system scope with the helper daemon) | Mac App Store: self-updating is not permitted |
| Linux | a tarball or installer; a deb/rpm that installs only the launcher | Flatpak, Snap: read-only, their own update mechanism |

An MSI or deb/rpm must not list anything below `versions/` among its files, or a
Windows Installer repair or a package verification reverts or flags what idunn
updated. A deb/rpm's `prerm`/`postrm` calls the launcher's uninstall verb (IDN-35).
Worth evaluating: an offline installer — `cmd/installer` with a TUF snapshot of the
first release embedded, so the bytes are still TUF-verified and the package signature
stays a wrapper.

idunn sets no Mark-of-the-Web and no `com.apple.quarantine` on what it downloads, so
SmartScreen and Gatekeeper's first-launch assessment see only the first installer —
another reason for the gates in IDN-27 and IDN-31.
