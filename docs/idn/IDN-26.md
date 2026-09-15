# IDN-26 — macOS: the application bundle as the live pointer (§6.1, §13)

**Priority:** P1 — blocks a trustworthy release

On darwin `current` is a symlink in the root, but what a user starts, what the Dock,
Launch Services and TCC know, is `/Applications/<app>.app` (or `~/Applications`). A
bundle cannot be the blue/green layout inside itself: any change below `Contents/`
breaks its seal and, on Apple Silicon, gets the process killed at launch. Every
mature macOS updater therefore replaces the whole signed bundle — Sparkle 2 swaps it
with `renamex_np(old, new, RENAME_SWAP)` from a launchd job
(`Autoupdate/SUPlainInstaller.m`, `Sparkle/SUFileManager.m`).

Wanted, keeping the journal and the retained versions Sparkle does not have:
- `versions/<v>/<app>.app` holds complete bundles; staging assembles one there
  (reusing verified files through `clonefile`, which is also IDN-10's missing
  reflink half).
- The darwin `SetPointer` is a `RENAME_SWAP` between the staged bundle and the
  bundle at the install path; the previous bundle lands in `versions/<old>`, so a
  rollback is a second swap. Staging must be on the bundle's volume (compare
  `st_dev`; `RENAME_SWAP` does not cross volumes) — verify on the CI runner that
  `/Applications` (a firmlink into the Data volume) and `/Library/Application
  Support` qualify.
- Recovery cannot read a marker inside the bundle (writing one breaks the seal); it
  identifies which version sits at the install path by the signed digest of a file
  in it (`Contents/_CodeSignature/CodeResources`).
- Before the swap: owner and group matched to the bundle being replaced,
  `com.apple.quarantine` removed (clones copy it from the installed bundle),
  `futimes` on the bundle root so Launch Services notices, `gktool scan` where it
  exists (14.4+).
- Refuse up front, with a message that says what to do, when the bundle runs
  translocated (`/AppTranslocation/` in the path) or from a read-only volume
  (`statfs` `MNT_RDONLY`) — there is nothing an update could replace.

Depends on IDN-25; the default paths come from IDN-24.
