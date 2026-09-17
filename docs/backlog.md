# Backlog

Everything [`design.md`](design.md) describes that the code does not do yet, as
work items. The status map it derives from is [`status.md`](status.md).

Each item is one file under [`idn/`](idn/); an item that is implemented moves to
[`idn/done/`](idn/done/). IDs are stable — reference them in commits and PRs
(`feat(packer): IDN-01 …`). Priority is about unblocking: P0 items block a first
usable release, P1 items block a *trustworthy* one, P2 items are hardening and reach.
An item that is partly done stays open until what it still lists is done.

## Open

### P1 — blocks a trustworthy release

| ID | Item | Status |
|---|---|---|
| [IDN-07](idn/IDN-07.md) | Privileged helper service and its IPC (§14.2, §14.8, T16, T23) | POSIX and Windows done |
| [IDN-08](idn/IDN-08.md) | POSIX interactive elevation (§14.2) | Linux done; macOS service mode built |
| [IDN-10](idn/IDN-10.md) | Local reuse of already-installed files (§6.4 stage 1, second half) | partly done |
| [IDN-12](idn/IDN-12.md) | Streaming targets instead of whole-file buffers | done in this repository, one buffer left upstream |
| [IDN-25](idn/IDN-25.md) | Symlink entries in a release (§3.1, §3.2, §6.4) | open |
| [IDN-26](idn/IDN-26.md) | macOS: the application bundle as the live pointer (§6.1, §13) | open |
| [IDN-27](idn/IDN-27.md) | macOS: Apple code signing as a gate before the swap (§13, §14.2) | open |
| [IDN-28](idn/IDN-28.md) | macOS: install on quit and relaunch (§14.3) | open |
| [IDN-30](idn/IDN-30.md) | Replacing the privileged helper itself (§14.2) | open |
| [IDN-31](idn/IDN-31.md) | Windows: Authenticode as a gate before the swap (§13) | open |
| [IDN-36](idn/IDN-36.md) | OS integrations as a recorded manifest; Windows "Installed apps" (§5, §13) | manifest and uninstall entry done; repair and other integrations open |
| [IDN-39](idn/IDN-39.md) | Probation: a new version confirms it is healthy, or is rolled back (§6.1, §6.2, §14.3, §14.5) | mechanism and signed per-release allowance done; telemetry and launcher restore open |
| [IDN-40](idn/IDN-40.md) | Windows: the launcher as the application's parent — job object and console control events (§6.1, §13, §14.3) | job object and console control events done; session end and services open |

### P2 — hardening and reach

| ID | Item | Status |
|---|---|---|
| [IDN-13](idn/IDN-13.md) | Enterprise transport: PAC, resume, mTLS (§14.4, T18) | partial |
| [IDN-18](idn/IDN-18.md) | Reproducible builds and provenance in CI (§9, §15) | partly done |
| [IDN-19](idn/IDN-19.md) | UI sidecars (§8) | open |
| [IDN-23](idn/IDN-23.md) | Recovery and deferral for system-wide installs (§14.2, §14.3) | open |
| [IDN-32](idn/IDN-32.md) | Packer: require platform signatures at publish time (§9, T13) | open |
| [IDN-33](idn/IDN-33.md) | Signing without losing dedup and reproducibility (§4.1, §9, IDN-18) | open |
| [IDN-34](idn/IDN-34.md) | Installer packages and the publishing pipeline (§5, §9) | open |
| [IDN-37](idn/IDN-37.md) | Uninstall on macOS and Linux: leftovers and registrations ([IDN-35](idn/done/IDN-35.md), IDN-36) | open |
| [IDN-38](idn/IDN-38.md) | Release notes, signed and delivered with the release (§3, §8, §9) | open |
| [IDN-41](idn/IDN-41.md) | Crash reports: detected at the launcher, collected by the application or the OS, sent by someone else (§8, §14.5, IDN-39) | open |

## Done

| ID | Item | Priority |
|---|---|---|
| [IDN-01](idn/done/IDN-01.md) | Packer: publish a TUF repository (§9) | P0 |
| [IDN-02](idn/done/IDN-02.md) | Packer: delegations from day 1 (§4.1) | P0 |
| [IDN-03](idn/done/IDN-03.md) | Packer: retention (§4.1, §9 step 4) | P0 |
| [IDN-04](idn/done/IDN-04.md) | `cmd/installer`: the actual binary (§5) | P0 |
| [IDN-05](idn/done/IDN-05.md) | Launcher shim (§6.1, §13, §14.3) | P0 |
| [IDN-06](idn/done/IDN-06.md) | `BusyDeferToRestart` actually defers (§14.3) | P1 |
| [IDN-09](idn/done/IDN-09.md) | Monotonic known-good time floor (§14.7, T22) | P1 |
| [IDN-11](idn/done/IDN-11.md) | Test coverage for `core/trust` and `core/fetch` | P1 |
| [IDN-14](idn/done/IDN-14.md) | Delta stage 2: intra-file binary patches (§6.4) | P2 |
| [IDN-15](idn/done/IDN-15.md) | Descriptor-level validity window (§6.3 `EnforceExpiry`) | P2 |
| [IDN-16](idn/done/IDN-16.md) | Mutation testing (§12, AGENTS.md §4) | P2 |
| [IDN-17](idn/done/IDN-17.md) | Launcher self-replacement (§13) | P2 |
| [IDN-20](idn/done/IDN-20.md) | Decide the mythology naming question (§2.1) | P2 |
| [IDN-21](idn/done/IDN-21.md) | Reconcile the `OnBusy` default with the design (§6.3, §14.3) | P2 |
| [IDN-22](idn/done/IDN-22.md) | The elevated helper vets the install root it is asked to write (§14.2, T16) | P2 |
| [IDN-24](idn/done/IDN-24.md) | A default install root that follows the platform's conventions (§5, §6.1, §14.2) | P1 |
| [IDN-29](idn/done/IDN-29.md) | Install and restart (§6.1, §14.3) | P1 |
| [IDN-35](idn/done/IDN-35.md) | Uninstall (§5, §6.1) | P1 |

When an item is implemented, `git mv` its file to `idn/done/`, mark its heading
**done**, and move its row to the table above.
