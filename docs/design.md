# idunn — Secure Installer & Updater — Concept (Go)

Status: Design/concept document. Prose: English. Code & comments: English.
**idunn** (Old Norse *Iðunn*, goddess of renewal who keeps the gods young with her
apples) is a headless-capable, cryptographically secured installer/updater system with
optional UI sidecars, a reproducible packer, and an auditable security concept — it
keeps software "forever fresh".

---

## 1. Goal

An ecosystem of a few clearly separated building blocks:

- **`core`** — reusable library: release resolution, staging, atomic apply,
  transaction/rollback journal, hook engine. The **trust/metadata core is go-tuf v2**
  (The Update Framework), not home-grown. Contains no UI and no network side effects
  except through injected interfaces.
- **`installer`** — small binary. Downloads the latest release, verifies it via TUF,
  and installs it for the first time. Uses only `core`.
- **`updater`** — library (and optional binary). In-place updates of existing
  installations. Uses only `core`.
- **`packer`** — CLI tool invoked via `go:generate`. Builds artifacts and **maintains
  the TUF repository** (adds targets, re-signs the roles). Never contains key material
  in the repo.
- **UI sidecars** (one repo per framework) — e.g. `idunn-fyne`, `idunn-bubbletea`
  (TUI), `idunn-webview`. Implement only the optional `Observer`/`Prompter` interface
  from `core`. No UI framework is a dependency of `core`.

**Responsibility split (central).** go-tuf answers "*which* bytes may I trust and which
do I download?" — key management, rotation, freeze/rollback/mix-and-match defense,
verification. Our code answers "*how* do I apply the verified bytes?" — atomic swap,
migration+rollback, quiesce, elevation, GC, crash recovery, UI. We deliberately do
**not** re-implement the trust core; that is the class of code that breaks silently when
self-built, and for which TUF exists — formally analyzed, audited, and battle-tested.

Guiding principle: **packages transport data and binary artifacts — never executable
update logic.** Migrations, checks, and UI are compiled code of the host program, not
content of the downloaded packages. That is the central security boundary.

---

## 2. Module & repo structure

```
idunn/                          (module: github.com/go-idavoll/idunn)
  core/
    trust/           # go-tuf v2 wrapper: embedded root, Refresh, target resolve
    release/         # release descriptor + channel pointer (TUF targets)
    fetch/           # enterprise-aware go-tuf Fetcher (proxy/PAC, system CAs)
    fsx/             # filesystem abstraction (interface + OS + in-memory)
    stage/           # verified staging + atomic apply + delta relink
    txn/             # transaction journal, crash recovery, rollback
    hook/            # Checker, Migrator, Observer, Prompter, Coordinator, Reporter
    updater/         # Updater orchestration API
    installer/       # first-time install orchestration
    elevate/         # privileged apply (per-OS)
  cmd/
    installer/       # thin installer binary
    packer/          # go:generate TUF repo maintenance + build tool
  SECURITY.md        # the written security concept (Sec. 11)

idunn-fyne/          (separate module, depends on idunn/core)
idunn-bubbletea/     (separate module, depends on idunn/core)
```

`core/trust` and `core/fetch` encapsulate go-tuf; the rest of `core` sees only a narrow
interface (`Refresh`, `LatestRelease`, `MaterializeTarget`) and stays independent of TUF
details — replaceable and testable.

### 2.1 Naming scheme (optional): mythology vs. function

The umbrella name is **idunn**. For the internal packages there is a coherent Norse
naming scheme — charming, but deliberately left as an **open decision**:

| Function (package) | Mytho codename | Why it fits |
|---|---|---|
| Project / umbrella | **idunn** | Goddess of renewal — keeps software fresh |
| `trust` (go-tuf, trust decision) | **heimdall** | Watchman; decides what may cross the bridge |
| `fetch` (transport, server→client) | **bifrost** | The rainbow bridge = delivery channel |
| `release` (descriptor/pointer, proclamation) | **bragi** | Herald/skald; mythically Iðunn's husband |
| `packer` (builds + signs the repo) | **brokkr** | Dwarven smith — forges the artifacts |
| `txn` / rollback / recovery | **eir** | Goddess of healing — heals a broken install |
| `hook` / observer / telemetry | **huginn** | Odin's raven "Thought" — flies out, reports back |
| `elevate` (privileged helper) | **tyr** | God of authority — the privileged instance |

The internal coherence is nice: **heimdall guards bifrost** = the trust layer decides
what the transport lets through — mythologically correct and exactly the data flow.

**Trade-off (left open):**
- *For:* memorable, coherent identity, fun, strengthens project culture and branding.
- *Against:* not self-documenting — `bragi` tells a new developer or auditor nothing;
  hampers onboarding/grep; can read as playful in enterprise/audit contexts; insider
  knowledge = bus factor.
- *Recommended middle path:* **functional names stay canonical in code**
  (self-documenting, audit-friendly) — the rest of this document uses them throughout.
  The mythological names serve **optionally** as product/module branding or internal
  codenames (at minimum the umbrella `idunn`, possibly the two most prominent public
  sub-names `heimdall`/`bifrost`). That gets you the charm without losing readability.
  How far to go is a deliberately open decision.

---

## 3. Package model & TUF trust core

**The trust anchor is the TUF role chain**, no longer a single self-signed manifest.
go-tuf v2 implements the TUF client workflow: starting from locally trusted `root`
metadata, the client loads the chain `timestamp → snapshot → targets` and verifies every
downloaded file against signed target metadata (hash + length). We do not reinvent
signatures, freshness, and rollback protection — TUF provides that.

### 3.1 Payload files = TUF targets

Every payload file (exe, dll, so, data) is a single **TUF target**. Benefits that fall
out of TUF directly:
- Integrity/authenticity per file via signed target hashes.
- **Content-addressed caching** (go-tuf `FindCachedTarget`) ⇒ file-level delta (Sec.
  6.4) is essentially free: unchanged files are never re-downloaded.
- Consistent snapshots ⇒ consistent, atomically publishable repository states.

Application-specific file metadata (destination path, `Kind`, `Mode`) that TUF does not
model rides along in the target's **`custom` field** — go-tuf v2 preserves and signs
unknown fields, so they are TUF-covered.

### 3.2 Release descriptor & channel pointer (also targets)

What belongs to release *X*, and which is the *newest* release? Two small JSON objects
that are themselves TUF targets (thus co-signed):

- **Release descriptor** `releases/<os>-<arch>/<version>.json`: lists the payload target
  paths belonging to the release and carries the former `Requirements`/hook/layout
  information.
- **Channel pointer** `channels/<channel>/<os>-<arch>/latest.json`: names the currently
  valid version → its descriptor. Its freshness is guaranteed by snapshot/timestamp
  (freeze defense), the version increment by TUF's rollback protection.

```go
// Package release defines the app-level descriptor carried as a TUF target.
// TUF secures WHAT to trust (hashes, signatures, freshness); this struct carries
// the app metadata TUF does not model, and is itself a signed TUF target.
package release

type Descriptor struct {
    // SchemaVersion guards the descriptor format; unknown -> reject (fail closed).
    SchemaVersion int `json:"schema_version"`

    Name    string `json:"name"`
    Version string `json:"version"` // SemVer. Monotonicity is enforced by TUF too.
    Channel string `json:"channel"`
    OS      string `json:"os"`
    Arch    string `json:"arch"`

    // Files maps each payload TUF target path to its install destination. The
    // hash/length live in TUF target metadata; here we keep only app attributes.
    Files []FileRef `json:"files"`

    Requirements Requirements `json:"requirements"`

    // Rollout in [0,1] drives staged/canary rollout (see 14.5). Optional.
    Rollout float64 `json:"rollout,omitempty"`

    // LayoutSchema pins the on-disk install layout the client must understand.
    LayoutSchema int `json:"layout_schema"`
}

type FileKind string

const (
    KindExe  FileKind = "exe"  // executable; may need self-replace handling.
    KindLib  FileKind = "lib"  // shared library (.dll/.so/.dylib).
    KindData FileKind = "data" // asset/config/data file.
)

type FileRef struct {
    // Target is the TUF target path; go-tuf resolves its verified hash/length.
    Target string `json:"target"`

    // Dst is the install-relative destination. MUST be clean, relative, and must
    // not escape the install root (validated on ingest to block traversal).
    Dst  string   `json:"dst"`
    Mode uint32   `json:"mode"` // POSIX mode; Windows honours only the exec bit.
    Kind FileKind `json:"kind"`
}

type Requirements struct {
    // MinFromVersion blocks downgrade/skip-migration; complements TUF rollback
    // protection with an app-level floor for migration validity.
    MinFromVersion string `json:"min_from_version"`
    // MinClientVersion stops an outdated client from mishandling a newer layout.
    MinClientVersion string `json:"min_client_version"`
}
```

**"Dependencies/DLLs/.so"** are simply further payload targets (`Kind: lib`), atomically
bound to the app via the descriptor. For real package DAGs, TUF additionally offers
TAP-4 multi-repository consensus (multiple roots) — deliberately optional.

### 3.3 Mapping concept → TUF

| Concept (before) | TUF equivalent |
|---|---|
| Manifest as trust root | `root`/`targets` role chain; descriptor is a signed target |
| Per-file digest in the manifest | Target hash/length in TUF target metadata |
| `FileEntry.Path/Mode/Kind` | TUF target `custom` / `Descriptor.FileRef` |
| `Requirements`, hook refs, `layout_schema` | `Descriptor` (itself a target) |
| Signed `index.json` + `expires_at` | `timestamp`+`snapshot`; channel pointer as a target |
| Embedded pubkey / keyset | Embedded `root.json` (trust bootstrap) |
| `crypto.Signer/Verifier`, `TrustStore` | go-tuf role keys + client verification |
| Blob endpoint `/blobs/sha256/...` | Content-addressed TUF `targets/` (consistent snapshot) |

---

## 4. Roles & key management (TUF)

Key management is the point where self-built updaters most often fail — and exactly
where TUF is strong. Instead of a single embedded pubkey we use the four TUF roles with
separate keys and thresholds:

- **`root`** — trust root. Signs (with m-of-n **offline**/HSM keys) which keys belong to
  the other roles, and **rotates every key** — including itself. Enables rotation
  **without client redeploy**.
- **`targets`** — signs the target metadata (hashes/lengths) incl. payload and
  descriptors. Can be kept **offline**; optionally delegations (e.g. per channel/team).
- **`snapshot`** — signs a consistent overall state of all target metadata
  (mix-and-match defense).
- **`timestamp`** — **online**, short-lived, frequently re-signed; proves the newest
  `snapshot` (freeze defense).

Only `timestamp` (and depending on operation `snapshot`) must be online; their
compromise permits **no** delivery of arbitrary, forged content as long as
`targets`/`root` are secured offline with thresholds. That is precisely the gain over the
old single-key model (where one key = single point of failure).

- **Signatures: Ed25519** (supported by TUF). **Hashes: SHA-256.** Both remain as
  before, only under TUF management.
- **Trust bootstrap:** client and installer embed an initial **`root.json`** (via
  `go:embed`) — that is the new trust anchor instead of a raw pubkey. go-tuf loads it as
  locally trusted root and updates the role keys afterward **data-driven** via signed
  root updates.

```go
// Package trust wraps go-tuf v2. The embedded root.json is the trust anchor;
// everything else (key rotation, freshness, target verification) is TUF's job.
package trust

//go:embed root.json
var embeddedRoot []byte

// Client wraps the go-tuf Updater. Refresh walks timestamp->snapshot->targets and
// updates trusted metadata; resolution and download go through go-tuf so that no
// custom signature/verification code exists in our trust path.
type Client struct{ /* *tufupdater.Updater, cfg */ }

// Refresh updates trusted TUF metadata (rollback/freeze/expiry checked by go-tuf).
func (c *Client) Refresh(ctx context.Context) error

// LatestRelease resolves the channel pointer target for os/arch to a verified
// release Descriptor (itself a verified target).
func (c *Client) LatestRelease(ctx context.Context, channel, os, arch string) (*release.Descriptor, error)

// MaterializeTarget returns a verified local path for a target, reusing the
// go-tuf cache when the content hash already matches (delta stage 1).
func (c *Client) MaterializeTarget(ctx context.Context, targetPath string) (localPath string, err error)
```

**Rotation (now data-driven):** new role keys are published via a signed `root` update;
clients adopt them automatically at the next `Refresh` — no new binary rollout needed.
Only on compromise of the **root threshold itself** is a new client with a fresh embedded
`root.json` required (rarer, deliberately hard).

Operations/key storage: `root`/`targets` offline or HSM; `timestamp`/`snapshot`
automated in CI (e.g. `tuf-on-ci`). No private key ever lives in the application repo.

### 4.1 Bounding metadata growth (delegations, dedup, retention)

Every payload file is a target; without countermeasures `targets.json` would grow over
many releases into a flat giant list that the client must fetch and parse on every
`Refresh`. Three combined measures keep it small:

- **Content addressing deduplicates.** Identical files across releases are the **same**
  target (same hash). Only *changed* files grow it, not `releases × files`. This bounds
  growth structurally.
- **Delegated targets roles** (TUF `delegated roles`) split the metadata: the top-level
  `targets.json` stays tiny and only delegates to smaller, separately signed roles —
  **per channel and major version** (e.g. `stable-v2`, `beta`). A client loads only the
  delegated file relevant to it, not the history of all channels/majors. We use
  delegations **from day 1** so no migration pain arises.
- **Retention in the packer.** The packer removes targets of retired releases beyond a
  keep window (respecting delta patch sources, Sec. 6.4). An entire major delegation can
  be retired/removed at end-of-life.

> **As built:** the packer delegates per channel (`stable`) *and* per release line
> (`v2`) rather than one role per `(channel, major)` pair, because a descriptor's
> target path deliberately carries no channel and the two pattern sets would
> otherwise overlap. Payload targets are content-addressed, which is what makes the
> dedup above literal. Both are argued in [`packer.md`](packer.md) §3 and §5.

**Escalation path for extreme target counts:** TUF's **hash-bin delegations** (succinct
delegations) distribute targets deterministically over N bounded bins — the approach with
which PyPI (PEP 458) scales millions of targets. For an app with dozens of files ×
hundreds of releases, the channel/major split usually suffices; hash bins are the reserve
path.

---

## 5. Flow: installer

The installer is a small binary; its only job is bootstrap:

0. **Preflight (downgrade protection).** Read the local install state
   (`.updater/state.json`: `name`, `version`, `layout_schema`). If an installation
   already exists, the installer behaves as a pure first-install bootstrapper: it
   **refuses** and points to the updater if (a) the installed version is `>=` the one to
   be installed, or (b) `layout_schema` is newer than this installer understands. This
   prevents an old, still-validly-signed installer binary from destroying the newer
   `versions/` layout or overwriting the launcher (fail-closed, analogous to
   `SchemaVersion`; see Sec. 14.6).
1. Determine `GOOS`/`GOARCH` and target channel.
2. **TUF `Refresh`** (`timestamp → snapshot → targets`) against the embedded `root.json`;
   go-tuf checks signatures, expiry, rollback, and freshness.
3. Resolve channel pointer → release descriptor (`LatestRelease`).
4. For each referenced payload file `MaterializeTarget`: go-tuf downloads on demand and
   **verifies against the signed target hash** (cache hits are reused).
5. Write into verified staging (sanitize destination paths, block path traversal).
6. `Checker` hooks (if registered), then atomic apply into the target location.
7. `Migrator.Migrate` (usually a no-op on first install), `Observer` events.
8. Optionally place the `updater` into the installation as a self-update mechanism (or
   the host ships it as a library).

Installer and updater share the same `core` code — TUF `Refresh`/resolve and the apply
paths exist only once.

---

## 6. Flow: updater — transaction, atomic swap, rollback

### 6.1 Install layout (blue/green + launcher shim)

```
<root>/
  launcher(.exe)          # tiny, stable; execs current/app. Rarely changes.
  current  ->  versions/1.3.0     # symlink (POSIX) / junction or pointer (Win)
  versions/
    1.2.0/                # previous, kept for instant rollback
    1.3.0/                # active
  .updater/
    journal.json          # in-progress transaction record (crash recovery)
    staging/              # verified new files, pre-swap
```

Advantages: the **atomic swap** is a single `rename()` of the `current` pointer.
**Rollback** is resetting the pointer to the previous version directory — plus
`Migrator.Rollback` for state changes. Locked files (Windows DLLs) are irrelevant because
new files are written into a *new* directory.

### 6.2 Transaction flow

```
Check(env) ─► TUF Refresh ─► MaterializeTargets (verified) ─► Stage(sanitize+relink)
      │                                                  │
      └──────────── on error: abort, no changes ◄────────┘
                                                         ▼
                                   Quiesce: acquire exclusive app lock
                                   (Coordinator.RequestShutdown + wait)
                                                         │
                    ┌──── lock not obtained in time ─────┤
                    ▼                                     ▼
        OnBusy: Abort / DeferToRestart          journal:BEGIN
        / Force                                       │
                                        Migrator.Migrate ► swap `current`
                                              │              │
                                              │              ▼
                                              │        journal:COMMIT
                                              │              │
                                              │              ▼
                                              │     GC old version dirs
                                              │     (keep RetainVersions)
                                              │
                                on error ─────┴─► restore pointer +
                                                  Migrator.Rollback ►
                                                  journal:ROLLED_BACK
                                                         │
                                                         ▼
                                    Reporter.Report(outcome)  [opt-in]
```

- Before every state-changing step a **journal entry** is persisted (`fsync`). If the
  process dies mid-apply, the updater detects an incomplete transaction on the next start
  and **completes or rolls back** (crash safety, "transaction log" thinking).
- `Migrate` runs *after* staging but is committed only with the swap.
- `Rollback` must be **idempotent** and safe even if `Migrate` ran only partially.

### 6.3 Core API

```go
// Package updater orchestrates verified, transactional in-place updates.
package updater

type Options struct {
    Trust   *trust.Client // go-tuf wrapper: Refresh, LatestRelease, Materialize.
    Fetcher fetch.Fetcher // enterprise-aware go-tuf Fetcher (proxy/PAC, system CAs).
    FS      fsx.FS        // filesystem abstraction (OS or in-memory).
    Now     func() time.Time // injected clock; go-tuf exposes UnsafeSetRefTime for tests.
    Root    string
    Channel string

    // Hooks — all optional; a nil hook is a no-op.
    Check       hook.Checker
    Migrate     hook.Migrator
    Observe     hook.Observer
    Prompt      hook.Prompter
    Coordinate  hook.Coordinator // signal running instances to quiesce (14.3).
    Report      hook.Reporter    // opt-in, privacy-first outcome telemetry (14.5).

    // Elevator performs the privileged apply for system-wide installs; nil for
    // per-user installs (Policy.Elevation == ElevationNone). See Sec. 14.2.
    Elevator elevate.Elevator

    Policy Policy
}

type Policy struct {
    AllowDowngrade   bool // default false (blocks rollback attacks).
    EnforceExpiry    bool // default true; enforce descriptor validity on top of TUF metadata expiry.
    VerifyAfterApply bool // re-hash installed files post-swap (belt & braces).

    // RetainVersions is how many version dirs to keep after a successful commit,
    // including `current`. Must be >= 2 so an instant rollback target survives.
    // Older dirs are garbage-collected at the end of Apply (see Sec. 14.1).
    RetainVersions int // default 2 => current + one previous.

    // Elevation selects how a privileged apply is performed when the install root
    // is not writable by the current process (system-wide installs; see 14.2).
    Elevation ElevationMode // default ElevationNone (per-user install).

    // QuiesceTimeout bounds how long Apply waits for running app instances to
    // release the exclusive lock before aborting or deferring (see 14.3).
    QuiesceTimeout time.Duration // default 30s.

    // OnBusy decides what happens if the target app cannot be quiesced in time.
    OnBusy BusyPolicy // default BusyDeferToRestart.
}

type ElevationMode int

const (
    ElevationNone      ElevationMode = iota // in-process; per-user install.
    ElevationInteractive                    // request UAC/polkit prompt on demand.
    ElevationService                         // hand off to a privileged helper via IPC.
)

type BusyPolicy int

const (
    BusyAbort          BusyPolicy = iota // fail the update, retry later.
    BusyDeferToRestart                   // stage now, apply+migrate at next launch.
    BusyForce                            // force-terminate after grace (last resort).
)

type Updater struct{ /* immutable config + injected deps */ }

// CheckForUpdate runs trust.Refresh (TUF), resolves the channel pointer to the
// newest applicable release Descriptor, and returns it or nil if already up to
// date. All metadata trust (signatures, rollback, freeze, expiry) is go-tuf's.
func (u *Updater) CheckForUpdate(ctx context.Context) (*Release, error)

// Apply downloads, verifies, quiesces running instances, stages, migrates, and
// atomically installs r, then garbage-collects old versions per Policy. It emits
// Observer events and an opt-in Reporter Outcome. For system-wide installs it
// routes the privileged apply through the configured Elevator. On any failure it
// rolls back files and calls Migrator.Rollback. Safe to call again after a crash.
func (u *Updater) Apply(ctx context.Context, r *Release) error
```

### 6.4 Delta / differential updates (content-addressed)

If only individual resources change, the whole release with all its assets should
**not** be transferred. With the TUF core this comes almost for free, because payload
files are individual, content-addressed targets. Two stages:

**Stage 1 — file-level (default, practically free):**
- Call `MaterializeTarget` for each file referenced by the descriptor. go-tuf checks via
  `FindCachedTarget` whether the verified content hash is already present locally (e.g.
  from the TUF cache) — only **missing** targets are fetched via `DownloadTarget` and
  verified against their signed hash.
- Beyond the TUF cache, we also reuse **already-installed files** of the same hash from
  `current/` or retained versions (reflink/CoW, else hardlink, else copy). Unchanged
  assets ⇒ **zero** network traffic.
- The new `versions/x/` is nonetheless complete and self-contained (a prerequisite for
  blue/green + instant rollback).

**Stage 2 — intra-file binary delta (optional, large binaries):**
- For a changed file, instead of the full target, fetch a **patch target**
  `oldHash → newHash` (`zstd --patch-from` / bsdiff) and apply it locally.
- The patch needs no separate trust handling: the *result* is checked against the signed
  target hash. A tampered/broken patch only produces a hash mismatch ⇒ fallback to the
  full target. Minimal attack surface.
- Worthwhile only for large binaries that change slightly.

**The security invariant is untouched:** every byte on disk — reused from the TUF cache,
downloaded as a target, or patched — is checked against the **TUF-signed target hash**.
Delta only changes *how* bytes are obtained, never *what* is trusted. Local files reused
beyond the TUF cache are also (re-)hashed rather than blindly adopted (protection against
disk rot / local tampering); as a performance trade-off one may rely on the verification
recorded at install time and re-hash fully only on `VerifyAfterApply`/periodic scrub.

**Synergy with GC:** retained previous versions (14.1) double as a relink and patch
source — so `RetainVersions` also affects delta efficiency.

**Packer/repo:** stage 1 requires **no** extra metadata (target hashes already exist).
For stage 2 the packer optionally adds patch targets against the last N versions; the
descriptor references them in its `custom` field. Discovery by convention, no signature
needed.

```go
// plan computes the minimal fetch set for a release Descriptor given what is
// already present locally. A target whose verified hash is in the go-tuf cache or
// in a retained version dir is reused (relink); only missing targets are fetched —
// as a full target, or via a patch target when offered. Every assembled file is
// verified against its TUF-signed target hash before commit, so reuse, download and
// patch application share one trust check.
func plan(d *release.Descriptor, cache trust.Cache) (reuse, fetch []release.FileRef)
```

---

## 7. Hook system

All hooks are **optional** and run **in-process** as compiled host code. For migrations
these are the required **two hooks** (`Migrate` + `Rollback`); the migration itself is
not part of the packer.

```go
// Package hook defines the host's optional extension points. Hooks are the host
// application's own compiled Go code — never code fetched from the network.
package hook

type Context struct {
    Ctx         context.Context // cancellation / deadline.
    FromVersion string          // installed version ("" for a fresh install).
    ToVersion   string          // version being installed.
    Root        string          // verified install root.
    StageDir    string          // verified staged files (read-only view).
}

// Checker runs pre-flight validation before anything is applied. A non-nil error
// aborts cleanly with zero changes on disk.
type Checker interface {
    Check(Context) error
}

// Migrator performs a stateful migration together with its exact inverse.
// The packer never contains migration logic; it lives here in the host.
type Migrator interface {
    Migrate(Context) error  // committed only if the whole transaction succeeds.
    Rollback(Context) error // idempotent; safe even if Migrate partially ran.
}

// Observer receives lifecycle events. UI sidecars implement this to render
// progress. Headless operation simply registers no Observer.
type Observer interface {
    OnEvent(Event)
}

// Prompter is an optional interactive gate (e.g. "Install now?"). Headless
// deployments leave it nil, in which case the configured default decision wins.
type Prompter interface {
    Confirm(ctx context.Context, question string) (bool, error)
}

// Coordinator lets the updater bring running instances of the host app to a
// consistent, non-writing state before StageMigrate touches shared resources
// outside the install root (e.g. a SQLite DB in AppData). The host implements
// RequestShutdown to signal its own running instances (via IPC/mutex/signal).
// The updater additionally uses the exclusive app lock as ground truth that no
// writer remains (see Sec. 14.3). All methods are optional (nil => no-op, and
// the updater falls back to lock-only coordination or BusyDeferToRestart).
type Coordinator interface {
    // RequestShutdown asks all running instances to quit or stop writing. It
    // returns once the request has been delivered, not once they have exited.
    RequestShutdown(Context) error
}

// Reporter receives the terminal outcome of an update transaction so a publisher
// is not blind to a bad release. It is opt-in and privacy-first: core produces
// only coarse, categorized data (no paths, no raw error strings, no PII); the
// host decides whether and where to send it. Reporting is best-effort and MUST
// NOT affect the update result (see Sec. 14.5).
type Reporter interface {
    Report(ctx context.Context, o Outcome) error
}

type Outcome struct {
    FromVersion string
    ToVersion   string
    OS, Arch    string
    Result      string    // "committed" | "rolled_back" | "aborted".
    FailedPhase Phase     // last phase reached on failure (empty on success).
    ErrorClass  string    // taxonomy, e.g. "verify", "migrate", "disk", "network", "clock_skew".
    At          time.Time
}

type Phase string

const (
    PhaseCheck    Phase = "check"
    PhaseDownload Phase = "download"
    PhaseVerify   Phase = "verify"
    PhaseQuiesce  Phase = "quiesce" // wait for running instances to release the lock.
    PhaseStage    Phase = "stage"
    PhaseMigrate  Phase = "migrate"
    PhaseApply    Phase = "apply"
    PhaseCommit   Phase = "commit"
    PhaseGC       Phase = "gc" // prune old version dirs after a successful commit.
    PhaseRollback Phase = "rollback"
)

type Event struct {
    Phase    Phase
    Message  string
    Progress float64 // in [0,1], or -1 if indeterminate.
    Err      error   // set on failure events.
}
```

---

## 8. Headless & optional UI sidecars

- **Headless** is the default: no hooks registered ⇒ silent, non-interactive,
  policy-driven. `core` has **no** UI-framework dependency.
- A **UI sidecar** is a separate repo/module that implements only `Observer` (and
  optionally `Prompter`) and passes it to `Options`:

```go
// idunn-fyne (separate module) — a thin adapter, not a fork of core.
package fyneui

// ProgressWindow implements hook.Observer by rendering Events into a Fyne widget.
type ProgressWindow struct{ /* fyne widgets */ }

func (w *ProgressWindow) OnEvent(e hook.Event) { /* update the progress bar */ }
func (w *ProgressWindow) Confirm(ctx context.Context, q string) (bool, error) { /* dialog */ }
```

The host selects its UI at compile time by importing the matching sidecar. Thus each
framework stays in its own dependency graph (Fyne, Bubble Tea, WebView, Qt binding, …)
without burdening headless builds.

---

## 9. Packer & `go:generate`

The packer builds artifacts and **maintains the TUF repository** (adds targets, writes
descriptor + channel pointer, re-signs roles). Invoked via a `generate` directive in the
host project's build directory:

```go
//go:generate go run github.com/go-idavoll/idunn/cmd/packer publish \
//   --config pack.yaml --repo ./tuf-repo
```

Input (`pack.yaml`) contains **no secrets**:

```yaml
# pack.yaml — packer input. Role keys are supplied via env/HSM, never here.
name: acme-app
version: 1.3.0
channel: stable
requirements:
  min_from_version: 1.0.0
  min_client_version: 1.2.0
rollout: 0.1                 # optional staged rollout (10%)
targets:
  - os: windows
    arch: amd64
    files:
      - { src: build/win-amd64/app.exe,     dst: app.exe,        kind: exe }
      - { src: build/win-amd64/plugin.dll,  dst: lib/plugin.dll, kind: lib }
  - os: linux
    arch: amd64
    files:
      - { src: build/linux-amd64/app,       dst: app,            kind: exe }
      - { src: build/linux-amd64/libx.so,   dst: lib/libx.so,    kind: lib }
```

Packer flow (uses the go-tuf repository API):
1. For each file: add it as a **TUF target** (go-tuf computes hash/length); write `dst`,
   `Mode`, `Kind` into the target `custom`. The target lands in the **delegated role** of
   the target channel/major (e.g. `stable-v2`), not in the top-level `targets.json`
   (Sec. 4.1).
2. Create the **release descriptor** (`releases/<os>-<arch>/<version>.json`) with
   `Requirements`/hook refs/`layout_schema`/`rollout` and add it as a target (into the
   same delegation).
3. Set the **channel pointer** (`channels/<channel>/<os>-<arch>/latest.json`) to the new
   version and add it as a target.
4. **Retention:** remove targets of retired releases beyond the keep window from the
   delegation (respect delta patch sources).
5. Re-sign the delegated role (offline/HSM key), then regenerate/re-sign `snapshot` and
   `timestamp` (CI keys). Consistent snapshot on.

```go
// The packer resolves TUF role keys from the environment (paths or KMS/HSM URIs),
// never from the repo. Missing keys -> hard failure, so an unsigned/incomplete
// repository state can never be published by accident.
targetsKey := os.Getenv("TUF_TARGETS_KEY")   // offline/HSM
snapshotKey := os.Getenv("TUF_SNAPSHOT_KEY") // CI
timestampKey := os.Getenv("TUF_TIMESTAMP_KEY")
if targetsKey == "" || snapshotKey == "" || timestampKey == "" {
    return errors.New("packer: TUF role keys missing; refusing to publish")
}
```

> **As built:** steps 1–3 and 5 exist in `internal/packer`; step 4 (retention) does
> not yet (IDN-03). Two details differ from the sketch above and are argued in
> [`packer.md`](packer.md): payload targets are named by content hash, and `custom`
> is not used — `dst`, `mode` and `kind` describe a release's *use* of a target, not
> the target, and the descriptor already carries them where the client validates
> them.

Root signatures (key rotation) deliberately run **outside** the normal publish — via a
separate, strictly controlled ceremony (offline, m-of-n), ideally with `tuf-on-ci`.
Reproducible builds of the artifacts remain a goal: bit-identical binaries allow
independent rebuilds and supply-chain verification.

---

## 10. TUF repository layout

Statically hostable (S3/CDN), no server-side logic — security sits in the client via the
TUF client workflow. Standard TUF layout with consistent snapshots:

```
/metadata/
  root.json            # (versioned) trust root, offline-signed
  timestamp.json       # online, short-lived -> freeze defense
  snapshot.json        # consistent overall state -> mix-and-match defense
  targets.json         # tiny: only delegates to the roles below
  stable-v2.json       # delegated role (channel/major), contains the targets
  beta.json            # further delegation
/targets/
  <hash>.<name>        # content-addressed targets (consistent snapshot):
                       #   payload files, release descriptors, channel pointers,
                       #   optional patch targets (delta stage 2)
```

The top-level `targets.json` stays small via delegations (Sec. 4.1); a client loads only
the delegated role of its channel/major. The content-addressed `targets/` replace the
former `/blobs/` endpoint; they are self-verifying via their hash. Patch targets are
output-verified against the signed target hash — no additional trust anchor. Freeze,
rollback, and mix-and-match defense come from `timestamp`/`snapshot`/`targets`; the
**rollout quota** lives in the descriptor (`rollout`, Sec. 14.5). TLS remains
defense-in-depth, but is **not** the basis of trust — the TUF roles are.

---

## 11. Security concept (written, auditable)

This chapter is the auditable `SECURITY.md`. Structure: assets, attackers, threats →
mitigations, residual risks.

### 11.1 Assets
- Integrity and authenticity of the delivered binary artifacts.
- The TUF role private keys, above all the **`root`** threshold (highest asset).
- The state of the host system during migrations (consistency).

### 11.2 Attacker model
- **Network attacker (MITM):** can read/modify/redirect traffic.
- **Malicious/compromised update server or mirror:** serves arbitrary, even
  validly-signed-old content.
- **Attacker with an online role key** (`timestamp`/`snapshot`): now **within** the
  model — TUF limits the damage to freeze/DoS, not content forgery, as long as
  `targets`/`root` are offline with thresholds and intact.
- **Local, unprivileged attacker:** tampers with files in the target path.
- **Explicitly out of scope:** an attacker with the `root`/`targets` threshold or with
  root/admin on the target system (see residual risks).

### 11.3 Threats → mitigations

| # | Threat | Mitigation |
|---|--------|------------|
| T1 | MITM alters delivery | TUF-signed metadata; TLS in addition. Tampering ⇒ TUF verification fails. |
| T2 | Bad server/mirror serves tampered content | Trust anchor is the **embedded `root.json`**, not the server. Invalid signature/hash ⇒ abort. |
| T3 | Downgrade to an old, vulnerable but valid version | TUF rollback protection (monotonic metadata versions); plus app floor `MinFromVersion` + `Policy.AllowDowngrade=false`. |
| T4 | Replay of old metadata | TUF version monotonicity + metadata expiry; expired/older metadata is discarded. |
| T5 | Freeze attack (server keeps client old) | Short-lived **`timestamp`** role; expired timestamp ⇒ abort instead of silent stall. |
| T5b | Mix-and-match of inconsistent metadata | **`snapshot`** role guarantees a consistent overall state. |
| T6 | Partial/corrupt download | TUF checks target hash + length; mismatch ⇒ discard. |
| T7 | Path traversal / Zip-Slip on materialization | Strict `Dst` validation: only relative, clean paths; rejection of `..`, absolute paths, symlinks escaping the root. Fuzzed. |
| T8 | Executable malicious logic in the package | Targets are data; **no** executable update logic. Hooks are host code. |
| T9 | TOCTOU between verify and install | Materialize from the *verified* go-tuf cache into staging; optionally `VerifyAfterApply`. |
| T10 | Crash mid-update | Transaction journal (`fsync`) + crash recovery: complete or roll back. |
| T11 | Failed migration | `Migrator.Rollback` + pointer restore to the old version; idempotent. |
| T12 | Compromise of a role key | Role separation + thresholds: loss of `timestamp`/`snapshot` (online) permits **no** forged content while `targets`/`root` (offline, m-of-n) are intact. Rotation via signed `root` update without client redeploy. |
| T13 | Incompletely signed repo via publisher error | Packer hard-aborts without the TUF role keys; no unsigned/inconsistent state is publishable. |
| T14 | Unknown/future descriptor format | `SchemaVersion`/`MinClientVersion` in the descriptor → client rejects fail-closed. |
| T15 | Disk exhaustion via unbounded `versions/` dirs | GC after `COMMIT` with `RetainVersions` (≥2); also removes orphaned staging/abort dirs; crash-safe (14.1). |
| T16 | Local privilege escalation via the privileged helper (unpriv. process makes the helper install a malicious package) | Privilege boundary = trust boundary: the helper runs a full TUF `Refresh`+verification itself, accepts only "channel→target version", authenticates the caller (peer credentials) (14.2). |
| T17 | Concurrent writes corrupt shared state during migration | Exclusive app lock as ground truth + `Coordinator.RequestShutdown`; on timeout `BusyDeferToRestart` (apply at restart) (14.3). |
| T18 | Enterprise TLS DPI/proxy breaks the download | go-tuf Fetcher honours OS proxy/PAC + system trust store; TUF signature independence tolerates DPI interception by design (14.4). |
| T19 | Old `installer` binary overwrites a newer installation | Installer preflight: reads install state, refuses if installed version ≥ target or `layout_schema` is newer (14.6). |
| T20 | Telemetry leaks PII / telemetry backend as attack vector | Data minimization, opt-in, only categorized error classes; reporting best-effort and **without** any authority over updates (14.5). |
| T21 | Tampered delta/patch target or corrupted local reuse | Every assembled file is checked against the TUF-signed target hash; mismatch ⇒ fallback to the full target, no compromise (6.4). |
| T22 | Clock rollback (turn the clock back to revive expired metadata) | Monotonic known-good time floor `max(build time, last valid metadata)`; an older clock is rejected (14.7). |
| T23 | Symlink/TOCTOU tampering of the shared TUF cache in elevated mode | Helper re-verifies every target hash (no forgery); hand-off via read-only fd instead of a path; `openat2`/`O_NOFOLLOW` fallback (14.8). |

### 11.4 Design invariants (fail closed)
- The trust path runs solely through go-tuf; **no** self-built verification code.
- Metadata/targets are verified by go-tuf **before** any use.
- Unknown `SchemaVersion`/`layout_schema` ⇒ abort.
- Any ambiguity ⇒ abort, not "best effort".

### 11.5 Residual risks (documented, accepted)
- Compromised **`root`/`targets` threshold** ⇒ break. Much harder than in the old
  single-key model (m-of-n, offline); not eliminable. Recovery via root rotation + a new
  client with a fresh `root.json`.
- Operational surface of the TUF repo: `timestamp` (and possibly `snapshot`) must be
  re-signed online in an automated way — needs reliable CI (e.g. `tuf-on-ci`); if it
  fails, timestamps expire and clients pause (fail-closed, no security break, but an
  availability concern).
- Root/admin on the target system ⇒ can replace the installation. Out of scope.
- OS-native code signing (Authenticode/notarization) is recommended **in addition**, but
  orthogonal to this system.
- The privileged update helper (14.2) is itself attack surface. Mitigation: minimal code
  as root (only TUF verify + swap), IPC caller authentication, no unchecked
  caller-supplied paths/URLs, rate limiting.
- `BusyForce` (14.3) can cause data loss if an instance is terminated mid-write. Hence
  **not** the default; opt-in only.
- The local install state (14.6) is tamperable by a local attacker; the installer's
  downgrade protection defends against mistakes and stale binaries, not against an
  already-privileged local attacker.
- **Clock skew** (14.7): a grossly wrong local clock pauses updates fail-closed. Without
  authenticated time (Roughtime/NTS) the only recourse is user guidance; the app keeps
  running but is cut off from updates until the clock is fixed. Availability, not a
  security risk.
- **Metadata growth** (4.1): without consistent delegations + retention, the client-side
  metadata load could rise over years. Delegations from day 1 and an active retention
  policy in the packer are therefore mandatory, not optional.

---

## 12. Test concept — 100% coverage + hardening

100% line coverage is the goal for our **lifecycle code** (Apply, journal, hooks, GC,
elevation, quiesce) — go-tuf is tested upstream and is not re-tested. Achievable via:

- **Dependency injection everywhere:** `trust.Client`, `fetch.Fetcher`, `fsx.FS`,
  `Now func()` are interfaces. No global state ⇒ every path deterministically testable.
  go-tuf offers `UnsafeSetRefTime` for time-dependent cases (expiry/freeze).
- **Local TUF test repo** (created via the go-tuf repository API) + **`httptest`** for
  real end-to-end runs with genuinely signed roles; **in-memory FS** for the apply.
- **Table-driven tests** for descriptor resolution, version comparison, policy.
- **Fuzzing** (Go native `testing.F`) on **our** attack surface:
    - descriptor parser (`release.Descriptor`),
    - `Dst` path sanitizer (traversal),
    - patch apply (delta stage 2).
- **Negative tests against tampered repos:** swapped/expired/rolled-back metadata must be
  rejected by go-tuf (integration proof of the binding).
- **Golden tests** on packer/artifact output ⇒ reproducible, bit-identical builds.
- **Property/invariant tests:** "Apply is atomic" (crash injection at every journal
  boundary yields a valid state: old **or** new, never half).
- **Mutation testing** (e.g. `go-mutesting`) as a quality measure of assertions —
  coverage percentage alone says nothing about the strength of the tests.

Honest note for the audit: 100% coverage ≠ security. The security guarantee rests on (a)
this threat model, (b) fuzzing of the parsers, (c) reproducible builds, and (d) ideally
an external audit — not on the coverage number.

---

## 13. Cross-platform specifics

- **Windows:** locked DLLs are defused by the blue/green layout (new files in a new
  directory). The `current` pointer as a directory junction or a pointer file read by the
  launcher. If the launcher itself must be updated: rename-self +
  `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` or restart. Authenticode recommended in
  addition.
- **Linux:** running binaries may be replaced (the inode remains for the running
  process). A symlink swap of `current` is atomic via `rename()`. System- vs. per-user
  install (permissions) via policy/root.
- **macOS:** `.dylib`, notarization/quarantine to consider; this system's signature is
  orthogonal to Apple code signing.

idunn's own signature is OS-independent and **in addition** to native code signing.

---

## 14. Operational hardening & deployment

This chapter closes the gaps identified in review. Each section maps 1:1 to a point.

### 14.1 Garbage collection / disk exhaustion

Without cleanup, `versions/` fills up with every update. Rule:

- GC runs in `PhaseGC` **only after** `journal:COMMIT` — the rollback fallback is never
  deleted before a successful commit.
- **Kept:** `current`, the `RetainVersions-1` newest predecessors (by version order),
  plus any *pinned* baseline and any directory still in use by a **running process**.
- Deletion failures on busy directories (Windows sharing violation) are **non-fatal**:
  retried next cycle or `MoveFileEx(DELAY_UNTIL_REBOOT)`.
- On startup recovery, orphaned staging/abort dirs are additionally cleaned up.

```go
// gc prunes version directories beyond the retention window. It runs only after
// a successful COMMIT, so the rollback target is never deleted prematurely.
// A pinned or in-use directory is skipped; a locked directory fails softly and
// is retried next run (Windows may schedule delete-on-reboot). keep must be >= 2.
func (u *Updater) gc(keep int) error
```

### 14.2 Privileges, elevation & UAC

Two deployment modes, controlled by `Policy.Elevation`:

- **Per-user install (`ElevationNone`, default):** the target directory is writable by
  the user; the updater runs in-process. Simplest, safest case.
- **System-wide install (`C:\Program Files`, `/opt`):** the triggering user process has
  no write permission. Two strategies:
    - **`ElevationInteractive`:** an elevated apply helper is launched on demand —
      Windows: `ShellExecute` verb `runas` (UAC); Linux: `pkexec` (polkit); macOS:
      Authorization Services / `SMAppService` helper. Good for user-initiated updates.
    - **`ElevationService`:** a **privileged system service/daemon** owns the install
      directory and performs applies; the unprivileged user process only triggers checks
      and shows UI, communicating via **IPC** (Windows: named pipe; Linux: systemd service
        + D-Bus/polkit or Unix socket; macOS: launchd helper). The standard for silent
          background updates.

**Central security invariant — privilege boundary = trust boundary:** the privileged side
**re-verifies itself** signature, digests, and version policy on exactly the bytes it
installs. It never trusts the unprivileged side's verdict and never installs a
caller-supplied path/URL unchecked. The client may only *request* "update channel X to
target version"; fetch/verify/policy the helper does independently. Otherwise a local
unprivileged attacker escalates via the helper.

IPC hardening: authenticate the caller via peer credentials (Linux `SO_PEERCRED`, Windows
named-pipe client token, macOS audit token), authorize only permitted users, validate the
request shape, rate-limit, no shell.

**Least privilege:** download+verify run unprivileged into staging; only the minimal
re-verify+swap runs elevated.

```go
// Package elevate abstracts how the privileged apply runs. core stays OS-agnostic.
package elevate

type Elevator interface {
    // ApplyElevated runs the file-mutating apply for r under elevation. The
    // unprivileged side may hand pre-fetched bytes to the helper as read-only file
    // descriptors over the authenticated IPC channel (Unix: SCM_RIGHTS; Windows: the
    // helper pulls the client handle via GetNamedPipeClientProcessId + OpenProcess +
    // DuplicateHandle), avoiding both a re-download and path-based symlink/TOCTOU
    // attacks (14.8). The helper runs a full TUF Refresh + target verification in the
    // privileged context (privilege boundary == trust boundary) and never trusts a
    // caller-supplied path.
    ApplyElevated(ctx context.Context, r *Release) error
}
```

#### 14.2.1 Windows `ElevationInteractive` (implemented)

`elevate.NewInteractive` launches the configured apply helper through
`ShellExecuteEx` with the verb `runas` — the only documented way to obtain the UAC
consent dialog — and waits on the returned process handle
(`SEE_MASK_NOCLOSEPROCESS`). `shell32.dll` is loaded from `%SystemRoot%\System32`
only, so a planted DLL on the search path is not what elevates.

The request that crosses the boundary is the whole contract:

```text
<helper> apply --root <install root> --channel <channel> --version <version>
```

Three validated scalars, quoted with `EscapeArg` so the helper's own
`CommandLineToArgvW` reproduces them exactly. No file list, no hashes, no staged
path, no URL: everything else the helper obtains and verifies itself (T16). Values
that cannot be expressed in that grammar — a relative or dot-laden root, a channel
or version outside a narrow charset, anything with a quote, a control character,
or a NUL — are refused before a privileged process exists, rather than escaped and
forwarded.

Outcomes map to `ErrDeclined` (prompt dismissed, or helper exit code
`ERROR_CANCELLED`), `ErrHelper` (launch failure or non-zero exit), and `ErrRequest`
(refused before launch). Cancelling the context stops the *wait*, never the apply:
the elevated process owns the swap once it starts, and killing it mid-write is the
half-installed state the journal exists to prevent.

`elevate.NeedsElevation` answers by creating and deleting a probe file in the
deepest existing directory of the root — the same operation the apply performs —
because predicting the kernel's access check from an ACL is a second
implementation of it. Access denied means "needs elevation"; anything ambiguous is
an error *and* `true`.

Residual risk: the helper binary runs with full administrator rights, so it must
live where only administrators can write. That is an install-time property; it
cannot be established at update time without a TOCTOU of its own. What is enforced
here is that the path is absolute, local (never UNC), existing, and a regular file.

`ElevationService` (the privileged helper and its authenticated IPC, 14.8) is not
built yet and fails closed.

### 14.3 Graceful shutdown & external file locks

The `Migrator` touches shared state **outside** the install directory (e.g. a SQLite DB
in `AppData`). Before `PhaseMigrate` it must be guaranteed that no running app instance is
writing concurrently.

- **Ground truth is an exclusive app lock:** while running, the host app holds a lock on
  `<data>/.app.lock` (Unix `flock`, Windows `LockFileEx` / named mutex — many
  single-instance apps do this anyway).
- Before migration the updater tries to acquire the lock **exclusively**. Success proves
  no writer is active anymore.
- If it cannot, it calls `Coordinator.RequestShutdown` (host-implemented IPC: "please
  quit, update pending") and waits up to `QuiesceTimeout`.
- On timeout `Policy.OnBusy` decides:
    - `BusyAbort` — abort cleanly, retry later.
    - `BusyDeferToRestart` (**recommended default** when the running app updates itself):
      the package stays staged, a "pending update" marker is set; the **launcher** performs
      swap+migrate at the next start — *before* the app opens the DB, when no lock is held.
      Sidesteps the concurrency problem entirely.
    - `BusyForce` — terminate after grace (risky, opt-in only).

At start the launcher checks for a staged pending update and applies it with a free lock
before it execs `current/app` (the classic "update on next start"). The paths of the
shared state are host knowledge and are configured.

### 14.4 Enterprise networks: proxy, PAC & custom CA

The **Fetcher we hand to go-tuf** (`fetch.Fetcher`) must account for enterprise reality —
plain `http.ProxyFromEnvironment` fails there. go-tuf loads all metadata and targets via
this Fetcher, so the hardening sits in *one* place:

- **OS-native proxy resolution incl. PAC:** Windows WinHTTP/WinINET settings, macOS
  `SCDynamicStore`, Linux env/GSettings. (Go's default reads only ENV variables and
  misses the system proxy + PAC.) Wrapped by a `ProxyResolver`.
- **OS system trust store** (`x509.SystemCertPool`) as default, so a corporate root CA
  installed by IT is accepted automatically; plus a configurable CA bundle and mTLS
  client certificates.
- **Resumable ranged downloads** (HTTP Range) + exponential backoff for flaky corporate
  links; proxy-auth support.

**Signature independence as a feature:** because authenticity rests on the TUF roles,
**TLS-terminating DPI proxies are tolerable by design** — even if the corporate proxy
breaks TLS, TUF guarantees the content. We never *disable* verification; we leave TLS
trust to the OS store the admin controls. A common failure mode becomes a non-issue.

### 14.5 Error telemetry / observability

So a publisher does not roll out a broken release blindly:

- **`Reporter` hook (opt-in, privacy-first):** `core` produces only coarse, categorized
  `Outcome` data (version transition, os/arch, result, `FailedPhase`, `ErrorClass` — **no**
  paths, **no** raw error strings, **no** PII). The host decides whether and where to
  send.
- Reporting is **best-effort**: batched, rate-limited, offline-tolerant, and **never
  affects** the update result. Consent/data minimization/retention GDPR-compliant.
- **Operational counterpart — staged/canary rollout:** the signed index carries a rollout
  quota per release; clients self-select deterministically (`hash(clientID) < pct`).
  Together with telemetry, the publisher watches the `rolled_back` rate and **halts** the
  rollout by publishing a new index with a lowered quota — *before* the bad release
  reaches everyone. That is exactly what prevents the "80% fail, we notice nothing"
  scenario.
- The telemetry backend is just a URL without any authority over updates; its compromise
  cannot force updates.

### 14.6 Downgrade protection in the installer

An old, still-validly-signed `installer` binary must not overwrite a newer installation or
destroy the `versions/` layout. The installer is a pure **first-install bootstrapper** and
runs a preflight before any action (see Sec. 5, step 0):

- Read install state `.updater/state.json` (`name`, `version`, `layout_schema`).
- **Refuse** if an installation exists and its `version >= target`, or if `layout_schema`
  is newer than this installer understands — with a clear hint to use the updater
  (fail-closed).
- State is written atomically by the updater. Residual risk: an already-privileged local
  attacker can tamper with the state — the protection targets mistakes and stale binaries,
  not this attacker (see 11.5).

### 14.7 Time dependency & clock skew

TUF checks metadata expiry against the local clock. A grossly wrong system clock (empty
CMOS battery, blocked NTP) makes valid metadata appear expired ⇒ go-tuf aborts `Refresh`
fail-closed. The behavior is **correct** — the fix is observability + user guidance,
**never** weakening the check.

- **Classify the error:** the wrapper distinguishes expiry errors from others and emits a
  dedicated error class `clock_skew` (Observer/Reporter). Instead of "update failed" the
  UI shows: *"System clock appears wrong (local X, expected ≳ Y). Updates paused, please
  correct the date/time."* — resolvable by the user.
- **Monotonic known-good time floor:** the client remembers `max(binary build time,
  timestamp of the last validly seen metadata)`. If the local clock is **below** it, it is
  certainly wrong (too far back). This is harmless — it helps no attacker, it only rejects
  impossible-past clocks — and simultaneously defends **clock rollback attacks** (turning
  the clock back to reactivate expired metadata).
- **Server `Date` header only as a hint:** may serve to *diagnose/display* the deviation,
  **never** to override TUF expiry (MITM-controllable, would reopen the freeze defense).
- **App keeps running:** with updates paused the installed version stays runnable; retry
  at the next start / after the clock is fixed.
- **Optional hardening for controlled fleets:** authenticated time (Roughtime/NTS) as a
  trustworthy source to detect skew *actively* — deliberately opt-in, as it is an extra
  dependency.

### 14.8 Shared TUF cache in elevated mode

For a system-wide update the unprivileged process pre-downloads, yet the privileged helper
must run `Refresh` + target verification itself (14.2). This creates a dilemma: its own
empty cache ⇒ **double download**; reading from the user cache ⇒ **symlink/TOCTOU danger**,
because an unprivileged user can tamper with the cache while the helper reads it.

- **Backstop first:** the helper verifies **every** target against the TUF-signed hash and
  all metadata signatures. A poisoned cache entry fails the hash check ⇒ re-download.
  **Content forgery is thereby excluded**; the real danger is symlink following
  (reading/writing privileged paths) and DoS, not forgery.
- **Primary solution — hand-off via file descriptor, not path:** the unprivileged process
  passes the pre-fetched bytes as a **read-only fd** over the already-authenticated IPC
  channel to the helper (Unix: `SCM_RIGHTS`; Windows: `DuplicateHandle`). The fd points to
  the inode — after opening, the user can **no longer** redirect it via a symlink. The
  helper reads from the fd, verifies the hash, and thus saves the double download
  **without** path-based attack surface. If verification fails, the helper downloads it
  itself.
- **Windows practice (`DuplicateHandle`):** unlike `SCM_RIGHTS`, the handle does not travel
  implicitly over the pipe. The viable direction is **pull by the helper**: an unprivileged
  process usually **cannot** obtain `PROCESS_DUP_HANDLE` on the privileged (SYSTEM) helper
  — a "push" fails the access check. The privileged helper may open the lesser-privileged
  client instead: get the client PID via `GetNamedPipeClientProcessId` from the pipe
  (which serves peer authentication anyway), `OpenProcess(PROCESS_DUP_HANDLE, clientPid)`,
  then duplicate the raw handle the client sent over the pipe into the helper with
  `DuplicateHandle(clientProc, h, GetCurrentProcess(), …)`. Safely doable because the
  helper already authenticates the caller — but it needs clean Win32 work.
- **Fallback for path-based reads:** `openat2` with `RESOLVE_NO_SYMLINKS` (Linux) or
  `O_NOFOLLOW`, inode/owner checks, copy into a root-owned private temp *before*
  verification (closes TOCTOU).
- **Cache ownership model:** separate caches — the user cache (best-effort, for the
  user-mode check/pre-download) and a **root-owned** helper cache (authoritative for the
  elevated apply); bridged via the fd hand-off so the pre-download is not wasted.

---

## 15. Open decisions & recommendations

- **TUF is now the trust core** (go-tuf v2, Sec. 3/4/9/10), no longer an outlook. Key
  rotation, freeze/rollback/mix-and-match defense, and role separation are in from day 1.
- **Signing ceremony & operations:** `root`/`targets` offline (m-of-n),
  `timestamp`/`snapshot` automated. Recommendation: `tuf-on-ci` for the signing workflows
  instead of hand-built CI scripts.
- **Delegations from day 1** (Sec. 4.1): split targets per channel/major so `targets.json`
  stays small; retention in the packer; hash-bin delegations as a reserve for extreme
  target counts. **TAP-4 multi-repository consensus** for real package DAGs / multiple
  roots.
- **Provenance/SLSA + reproducible builds** in CI as an additional supply-chain proof
  (complements TUF, does not replace it).
- **Time hardening** (Sec. 14.7): `clock_skew` classification + user guidance as a minimum;
  authenticated time (Roughtime/NTS) as opt-in for controlled fleets.
- **Delta updates:** file-level delta (content-addressed) falls out of the TUF targets
  model + go-tuf cache (Sec. 6.4). Only optional stage 2 (intra-file binary diffs) remains
  open, for large binaries that change slightly.
- **Uptane** as a reference should the system ever move toward embedded/automotive (a TUF
  extension for exactly that case).
- **When *without* TUF after all?** Only for single-vendor + single-HSM-key + tolerable
  compromise consequences + a hard minimalism constraint; then a tiny, externally audited
  own core. Conscious price: no online rotation, full break on key loss. For "Fort Knox",
  TUF is the right choice.

---

## 16. Next step

From this concept the `core` module can be scaffolded with the interfaces above
(including in-memory FS + `httptest` fixtures for 100% coverage) and then `installer`,
`packer`, the privileged helper (14.2), and a first UI sidecar. On request I will build
the runnable `core` skeleton with tests as a starting point.