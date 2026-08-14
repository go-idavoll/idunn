# Architecture

A one-page map of idunn for newcomers. It points into the full design at
[`docs/design.md`](docs/design.md); read this first, then dive there for detail.

## The one idea

idunn splits cleanly into two layers, and every decision follows from that split:

- **Trust layer — go-tuf v2.** Answers *"which bytes may I trust and fetch?"* Signatures,
  key management/rotation, freshness, and freeze/rollback/mix-and-match defense. We do
  **not** re-implement this; go-tuf is the audited trust core.
- **Lifecycle layer — idunn.** Answers *"how do I apply verified bytes safely?"* Atomic
  swap, migrations, elevation, garbage collection, crash recovery, UI.

Everything under `core/` sits on one side of that line. Keep new code on the correct side.

## Component map

| Package | Responsibility | Design |
|---|---|---|
| `core/trust` | go-tuf wrapper: embedded `root.json`, `Refresh`, resolve + materialize verified targets | §3, §4 |
| `core/release` | Release descriptor + channel pointer (both TUF targets) | §3.2 |
| `core/fetch` | Enterprise-aware go-tuf `Fetcher`: OS proxy/PAC, system trust store, ranged/resumable | §14.4 |
| `core/stage` | Verified staging, atomic apply, delta relink | §6.1, §6.4 |
| `core/txn` | Transaction journal, crash recovery, rollback | §6.2 |
| `core/hook` | Optional extension points: `Checker`, `Migrator`, `Observer`, `Prompter`, `Coordinator`, `Reporter` | §7 |
| `core/updater` | Orchestration: `CheckForUpdate`, `Apply` | §6.3 |
| `core/installer` | First-time install bootstrap (+ downgrade preflight) | §5, §14.6 |
| `core/elevate` | Privileged apply for system-wide installs (per-OS) | §14.2, §14.8 |
| `cmd/installer` | Thin installer binary | §5 |
| `cmd/packer` | `go:generate` tool: build artifacts + maintain the TUF repo | §9 |

UI is out-of-tree: `idunn-fyne`, `idunn-bubbletea`, `idunn-web` implement `hook.Observer`
/ `hook.Prompter` and are chosen at compile time. `core` has no UI dependency (§8).

## Data flow (happy path)

```
CheckForUpdate ─► trust.Refresh (TUF) ─► resolve channel pointer ─► descriptor
      │
Apply ─► materialize targets (verified, cached/relinked) ─► stage
      ─► quiesce (exclusive app lock) ─► journal:BEGIN
      ─► Migrate ─► swap `current` ─► journal:COMMIT ─► GC
                    │
        on error ───┴─► restore pointer + Rollback ─► journal:ROLLED_BACK
```

## Install layout

A tiny stable **launcher** execs `current/`, a symlink/junction to a versioned dir.
Update = write a new `versions/<v>/`, then a single atomic `rename()` of `current`.
Rollback = repoint `current`. Old versions are kept per `RetainVersions` and GC'd. (§6.1)

## Boundaries & invariants (do not cross)

- **Fail closed.** Any ambiguity aborts with no on-disk change.
- **No parallel trust path.** Verification lives in go-tuf, never hand-written beside it.
- **Packages carry data, not executable update logic.** Migrations are host code (hooks).
- **Every byte** — reused, downloaded, or patched — is checked against its TUF-signed
  target hash before commit.
- **Privilege boundary == trust boundary.** The elevated helper re-verifies via TUF and
  never trusts a caller-supplied path or verdict (§14.2).
- **`core` has no UI and no direct network** — only injected interfaces (`trust.Client`,
  `fetch.Fetcher`, `fsx.FS`), which also makes every path testable (§12).

## Where to look next

- Full design, rationale, and the T1–T23 threat model: [`docs/design.md`](docs/design.md)
- Security policy and reporting: [`SECURITY.md`](SECURITY.md)
- Contributor & agent contract, red-team requirements: [`AGENTS.md`](AGENTS.md)