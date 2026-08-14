# Security Policy

idunn is update infrastructure: its purpose is to stay trustworthy when the network,
the update server, and the operator's environment are not. We take security reports
seriously and design the project to be **fail-closed** and auditable.

This is a condensed, repo-facing summary. The full threat model (T1–T23), design
invariants, and residual risks live in the architecture concept document.

---

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Use private disclosure:

1. **Preferred:** open a private report via GitHub → *Security* →
   *Report a vulnerability* (private security advisory) on this repository.
2. **Fallback:** email `leise.lehmig.9o@icloud.com` _(maintainers: set this address and,
   ideally, publish a PGP key / `security.txt` before the first release)_.

Please include: affected version/commit, a description of the issue and its impact, and
a minimal reproduction (a tampered TUF repository, package, or input, plus the observed
vs. expected behavior). If you have a candidate fix or a corpus case, even better.

**What to expect:** we aim to acknowledge within a few working days, agree a
coordinated-disclosure timeline with you, and credit you (if you wish) once a fix is
available. We support good-faith security research and will not pursue action against
researchers who act in good faith, avoid privacy violations and data destruction, and
give us reasonable time to remediate before public disclosure.

## Supported versions

idunn is currently at **design/pre-release stage**. No version is yet supported for
production use, and the API may change without notice. Report vulnerabilities anyway —
finding weaknesses now is exactly the point. A support matrix will appear here at the
first stable release.

---

## Security model (summary)

**Trust foundation.** idunn does not roll its own trust. Signature verification, key
management/rotation, and freshness are delegated to **The Update Framework (TUF)** via
**go-tuf v2**. The trust anchor is an **embedded `root.json`**, not the update server.

**Responsibility split.** go-tuf answers *"which bytes may I trust and fetch?"*; idunn
owns *"how do I apply them safely?"* — atomic swap, migrations, elevation, garbage
collection, crash recovery.

**Design invariants (fail-closed).**
- Any ambiguity, unknown, or partial state **aborts** with no on-disk change.
- The trust path runs **only** through go-tuf — no hand-written parallel verification.
- Metadata and targets are **verified before use**; unknown schema/layout is rejected.
- Packages carry **data only** — never executable update logic.
- Privilege boundary **==** trust boundary: the privileged step re-verifies via TUF the
  exact bytes it installs.

## Threat model (condensed)

The full table is T1–T23 in the concept document. Grouped by class:

- **Delivery integrity & authenticity** (MITM, malicious server/mirror, corrupt or
  tampered blobs/patches): TUF-signed metadata + per-target hashes; every assembled file
  — reused, downloaded, or patched — is checked against its signed hash before commit.
- **Downgrade / replay / freeze / mix-and-match / clock-rollback**: TUF rollback
  protection and version monotonicity; the short-lived `timestamp` role; the `snapshot`
  role for consistency; and a monotonic known-good time floor
  (`max(build time, last valid metadata)`) that rejects an impossibly old clock.
- **Package safety**: strict install-path sanitization (no `..`, absolute paths, or
  escaping symlinks); no download-and-execute path exists by design.
- **Apply integrity**: verified staging (no TOCTOU), an `fsync` transaction journal with
  crash recovery, and `Migrate`/`Rollback` hooks for stateful migrations.
- **Key compromise**: TUF role separation and thresholds; `root`/`targets` offline
  (m-of-n), only `timestamp`/`snapshot` online; the packer refuses to publish without
  the required role keys.
- **Local & operational**: version garbage collection (disk exhaustion); the privileged
  helper authenticates its caller and re-verifies (local privilege escalation); an
  exclusive app lock + graceful quiesce (concurrent writers during migration); an
  OS-proxy/PAC + system-trust-store fetcher (enterprise DPI); installer preflight
  (stale-installer downgrade); privacy-first, authority-less telemetry; and a read-only
  file-descriptor hand-off for the shared TUF cache in elevated mode (symlink/TOCTOU).

## Out of scope / residual risks

These are documented and accepted, not solved:

- **`root`/`targets` threshold compromise** — a break, but hard (m-of-n, offline);
  recovery via root rotation + a fresh embedded `root.json`.
- **Root/Admin on the target host** — can replace the installation; outside scope.
- **Clock skew** — a grossly wrong local clock pauses updates fail-closed; without
  authenticated time (Roughtime/NTS) the resolution is user guidance. Availability, not
  a compromise.
- **The privileged helper is itself attack surface** — mitigated by a minimal elevated
  code path, caller authentication, and no caller-supplied paths.
- **`BusyForce`** (forced shutdown) can cause data loss — off by default, opt-in only.
- **Local install-state tampering** — the installer's downgrade guard defends against
  mistakes and stale binaries, not an already-privileged local attacker.
- **Metadata growth** — mitigated by TUF delegations and packer retention; neglecting
  either degrades client-side performance over time.

OS-native code signing (Authenticode / notarization) is recommended **in addition** to
idunn's TUF verification, and is orthogonal to it.

---

_See `README.md` for an overview and `AGENTS.md` for the contributor/agent security
contract, including the adversarial (red-team) testing requirements._