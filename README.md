<div align="center">

<img src="docs/assets/idunn.png" alt="idunn — the Go gopher as Iðunn, holding a basket of apples of renewal" width="200"/>

# idunn

**Secure, headless-first software updates for Go.**
_Guarded by Algiz, renewed by Iðunn — built on Iðavöllr, the field where the gods rebuild._

[![Go Reference](https://pkg.go.dev/badge/github.com/go-idavoll/idunn.svg)](https://pkg.go.dev/github.com/go-idavoll/idunn)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-idavoll/idunn)](https://goreportcard.com/report/github.com/go-idavoll/idunn)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-design--stage-orange.svg)](#status)

</div>

---

## What is idunn?

**idunn** is a cryptographically secure installer and updater for Go applications.
It keeps software *forever fresh*: it pulls new releases from a remote repository,
verifies them end to end, and applies them atomically — with instant rollback if
anything goes wrong. It runs fully **headless** by default, with optional UI
sidecars per framework.

The trust core is not home-grown. idunn builds on **[The Update Framework
(TUF)](https://theupdateframework.io/)** via
**[go-tuf v2](https://github.com/theupdateframework/go-tuf)** for everything that is
easy to get subtly wrong — signatures, key management and rotation, freshness, and
rollback/freeze/mix-and-match defense. idunn owns the layer TUF deliberately leaves
open: **how to apply verified bytes** — atomic swap, migrations, elevation,
garbage collection, crash recovery, and UI.

> **Responsibility split:** go-tuf answers *"which bytes may I trust and fetch?"* —
> idunn answers *"how do I apply them safely?"*

## Features

- **TUF-backed trust** (go-tuf v2): role separation, thresholds, key rotation
  without client redeploy, freeze/rollback/mix-and-match defense.
- **Headless-first**: no UI dependency in `core`; UI is opt-in via sidecars.
- **Atomic blue/green apply** with a launcher shim and versioned install dirs —
  **instant rollback** by repointing `current`.
- **Crash-safe transactions**: an `fsync` journal completes or rolls back an
  interrupted update on next start.
- **Migration hooks with rollback**: two host-provided hooks (`Migrate` +
  `Rollback`); migration logic never travels in a package.
- **Content-addressed delta updates**: unchanged assets are reused from the TUF
  cache or retained versions — only changed files cross the wire.
- **Privilege model**: per-user in-process, or a privileged system helper over
  authenticated IPC (privilege boundary == trust boundary).
- **Garbage collection** of old versions with a configurable retention window.
- **Reproducible, signed releases** maintained via `go:generate` and a TUF repo.
- **Auditable by design**: a written security concept (threat model + mitigations)
  and a 100% coverage goal for the lifecycle code.

## How it works

```
CheckForUpdate ─► TUF Refresh ─► MaterializeTargets (verified) ─► Stage
      │                                                             │
      └────────────── on error: abort, no changes ◄────────────────┘
                                                                    ▼
                                    Quiesce ─► Migrate ─► swap `current` ─► Commit
                                                     │           │
                                          on error ─┴─► Rollback + restore pointer
```

Every byte that lands on disk — reused, downloaded, or patched — is verified against
its TUF-signed target hash before commit. Trust is never weakened; delta only changes
*how* bytes are obtained, not *what* is trusted.

## Module layout

```
github.com/go-idavoll/idunn          # core library (this repo)
  core/trust      # go-tuf v2 wrapper: embedded root, Refresh, target resolve
  core/release    # release descriptor + channel pointer (TUF targets)
  core/fetch      # enterprise-aware go-tuf Fetcher (proxy/PAC, system CAs)
  core/stage      # verified staging + atomic apply + delta relink
  core/txn        # transaction journal, crash recovery, rollback
  core/hook       # Checker, Migrator, Observer, Prompter, Coordinator, Reporter
  core/updater    # Updater orchestration API
  core/installer  # first-time install orchestration
  core/elevate    # privileged apply (per-OS)
  cmd/installer   # thin installer binary
  cmd/packer      # go:generate TUF repo maintenance + build tool
```

### UI sidecars

The `core` engine is UI-agnostic. UI lives in separate modules that implement the
optional `hook.Observer` / `hook.Prompter` interfaces — pick one at compile time:

- [`idunn-fyne`](https://github.com/go-idavoll/idunn-fyne) — Fyne GUI
- [`idunn-bubbletea`](https://github.com/go-idavoll/idunn-bubbletea) — terminal UI
- [`idunn-web`](https://github.com/go-idavoll/idunn-web) — WebView

## Usage (planned API)

> The API is not yet stable — see [Status](#status).

```go
u, err := updater.New(updater.Options{
    Trust:   trustClient,        // go-tuf wrapper with an embedded root.json
    Fetcher: fetch.OSDefault(),  // honours OS proxy/PAC and the system trust store
    Root:    "/opt/acme",
    Channel: "stable",
    Migrate: myMigrator,         // optional: Migrate + Rollback
    Observe: nil,                // headless; or wire a UI sidecar here
})
if err != nil { /* ... */ }

rel, err := u.CheckForUpdate(ctx)
if err == nil && rel != nil {
    err = u.Apply(ctx, rel)      // verify → stage → migrate → atomic swap → GC
}
```

## Security

idunn is **fail-closed**: any ambiguity aborts rather than proceeding "best effort".
The full threat model (T1–T23), design invariants, and residual risks live in
[`SECURITY.md`](SECURITY.md). Highlights:

- Trust anchor is an **embedded `root.json`**, never the update server.
- Packages carry **data only** — never executable update logic.
- The privileged helper **re-verifies** everything it installs; it never trusts a
  caller-supplied path or verdict.
- TLS-terminating corporate proxies (DPI) are tolerated **by design** — authenticity
  rests on TUF signatures, not on TLS.

> idunn is a design/trust *foundation*, not a proof of safety. The guarantee rests on
> the implementation, negative tests against tampered repositories, reproducible
> builds, and ideally an external audit.

## Naming & symbolism

<img src="docs/assets/go-idavoll.png" alt="go-idavoll org emblem" width="120" align="right"/>

Our mascot is the Go gopher as **Iðunn**, the Norse goddess who keeps the apples of
renewal — the same apples that keep your software fresh. The imagery is deliberate:

- **Apples of renewal** → the update itself (staying current).
- **Algiz (ᛉ)** — the protection rune on the headband and brooch → the **fail-closed
  trust** at the core.
- **Iðavöllr** — the field where the gods return to **rebuild** after Ragnarök →
  the org namespace `go-idavoll` (recovery & renewal).
- **The bridge & hall / the ravens** → the delivery channel and the recurring
  update check that flies out and reports back.

Guardian's shield plus the bridge between worlds — protection and delivery, in one
mark.

## Status

**Design stage.** The architecture and security concept are complete and
implementation-ready; the code and public API are still taking shape and **may
change without notice**. Not yet suitable for production. Follow along or open an
issue if you want to help shape it.

## Contributing

Issues and discussion are welcome. Please read `SECURITY.md` and `CONTRIBUTING.md`
(coming soon) before opening a pull request.

## License

Apache-2.0 (placeholder — confirm before first tag). See [`LICENSE`](LICENSE).