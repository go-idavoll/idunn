# The packer

> **Status: not implemented.** `cmd/packer` prints `idunn packer: not implemented`
> and exits. This document is the contract it must fulfil — derived from
> [`design.md`](design.md) §9, from the target-path helpers that already exist in
> `core/release`, and from what `core/trust` demands of a repository in order to
> resolve it. Backlog items IDN-01 … IDN-03.
>
> The only thing in this repository that currently produces a TUF repository is the
> red-team harness (`test/redteam/harness`, `make baseline`). It builds a *test*
> repository with *test* keys and is not a packer: no `pack.yaml`, no delegations,
> no retention, no key hygiene. It is useful as a worked example of the wire format
> (§6 below), not as a starting point for publishing.

---

## 1. What it is for

The packer is the publisher-side half of idunn. It builds release artifacts and
maintains the TUF repository the client reads: it adds payload files as targets,
writes the release descriptor and the channel pointer, and re-signs the roles.

It is a **maintainer tool**, invoked from the host project's build directory:

```go
//go:generate go run github.com/go-idavoll/idunn/cmd/packer publish \
//   --config pack.yaml --repo ./tuf-repo
```

It is never shipped to clients, and it never travels in a release.

The asymmetry with the client is deliberate. The client is the side an attacker
controls the network of; the packer is the side that holds the keys. Its failure mode
is not "installs the wrong bytes" but "publishes a repository that is inconsistent,
unsigned, or unreproducible" — which is threat **T13** in the model.

## 2. Input: `pack.yaml`

Contains no secrets. Role keys come from the environment or an HSM, always.

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

`kind` is one of `exe`, `lib`, `data` (`release.FileKind`). `dst` is the
install-relative destination and must survive `internal/safepath.Clean` — the packer
runs the *same* validator the client runs on ingest, so a path that would be rejected
at install time is rejected at publish time instead of shipping and failing on every
client.

## 3. Output: what a publish must produce

Every artifact below is a TUF target, and therefore signed.

| Target path | Content | Written by |
|---|---|---|
| `payloads/<version>/<name>` | one payload file, verbatim | §4 step 1 |
| `releases/<os>-<arch>/<version>.json` | `release.Descriptor` | `release.DescriptorPath` |
| `channels/<channel>/<os>-<arch>/latest.json` | `release.Pointer` | `release.PointerPath` |

The two path helpers live in `core/release` precisely so that the packer and the
client cannot drift apart: there is one place that knows the layout, and both sides
import it.

The descriptor the packer emits must satisfy `release.ParseDescriptor` — which is
strict, key-checked, and fuzzed. In particular: `schema_version` = 1,
`layout_schema` = 1, SemVer `version`, no duplicate `dst`, no unknown keys, no
setuid/setgid bits in `mode`.

The pointer must name exactly `release.DescriptorPath(os, arch, version)`. The client
derives the expected path from the version the pointer claims and refuses a pointer
that names anything else — a pointer may not fetch a release it is not entitled to
name.

## 4. Publish flow

1. **Add each payload file as a TUF target.** go-tuf computes hash and length; `dst`,
   `mode` and `kind` ride along in the target's `custom` field, where go-tuf preserves
   and signs unknown fields. The target lands in the **delegated role** for the
   channel and major (e.g. `stable-v2`), not in the top-level `targets.json`.
2. **Write the release descriptor** and add it as a target in the same delegation.
3. **Set the channel pointer** to the new version and add it as a target.
4. **Retention:** remove targets of retired releases beyond the keep window,
   respecting any delta patch sources that still reference them (§6.4).
5. **Re-sign** the delegated role (offline/HSM key), then regenerate and re-sign
   `snapshot` and `timestamp` (CI keys). Consistent snapshots on.

`root` signatures — key rotation — deliberately run **outside** the normal publish, in
a separate controlled ceremony (offline, m-of-n; `tuf-on-ci` is the recommendation).
A publish that could touch `root` would put the highest asset in the model behind the
most frequently run command.

## 5. Hard rules

These are not style preferences; each one is a threat mitigation.

**Keys never live in the repository.** They are resolved from the environment or a
KMS/HSM URI. A missing key is a hard failure *before* anything is written:

```go
targetsKey := os.Getenv("TUF_TARGETS_KEY")   // offline/HSM
snapshotKey := os.Getenv("TUF_SNAPSHOT_KEY") // CI
timestampKey := os.Getenv("TUF_TIMESTAMP_KEY")
if targetsKey == "" || snapshotKey == "" || timestampKey == "" {
    return errors.New("packer: TUF role keys missing; refusing to publish")
}
```

An unsigned or half-signed repository state must not be publishable by accident
(T13). The packer never reads, writes, logs, or prints key material (AGENTS.md §5).

**Output is reproducible.** No wall-clock, no randomness, no environment leakage into
artifacts (AGENTS.md §1.7). Two runs over the same inputs produce byte-identical
metadata and targets — that is what makes an independent rebuild a supply-chain proof
rather than a guess. Metadata expiry timestamps are inputs, not `time.Now()`.

**Publishes are atomic from the client's perspective.** Consistent snapshots mean a
client never sees a `snapshot` that references metadata not yet uploaded. Upload
order matters: targets and delegated metadata first, `timestamp.json` last.

**Delegations from day 1.** Retrofitting them is a migration for every deployed
client, which is why the design calls them mandatory rather than optional. The
top-level `targets.json` stays tiny and delegates per channel and major; a client
loads only the delegation for the channel it follows. Hash-bin (succinct) delegations
stay in reserve for extreme target counts.

**Content addressing does the deduplication.** An unchanged file across releases is
the *same* target with the same hash, so metadata grows with *changed* files, not with
`releases × files`. This is also what makes file-level delta free on the client side.

## 6. Repository layout on the server

Statically hostable (S3, CDN); no server-side logic. Security lives in the client's
TUF workflow.

```
/metadata/
  1.root.json          # version-prefixed, offline-signed
  timestamp.json       # never version-prefixed — the freshness anchor
  1.snapshot.json      # consistent overall state
  1.targets.json       # tiny: delegates only
  1.stable-v2.json     # delegated role, holds the targets
/targets/
  payloads/1.3.0/<sha256>.app.exe
  releases/windows-amd64/<sha256>.1.3.0.json
  channels/stable/windows-amd64/<sha256>.latest.json
```

With consistent snapshots, a target file is stored at `<dir>/<sha256>.<basename>`.
`test/redteam/harness.HashPrefixedPath` is the working implementation of that naming
and can be read as the reference.

TLS is defence in depth here, not the basis of trust. The trust anchor is the client's
embedded `root.json`.

## 7. Operational split

| Role | Key location | Touched by |
|---|---|---|
| `root` | offline / HSM, m-of-n | signing ceremony only, never a publish |
| `targets` (and delegations) | offline / HSM | publish (step 5) |
| `snapshot` | CI | publish |
| `timestamp` | CI, short-lived, frequently re-signed | publish + a periodic re-sign job |

Only `timestamp` (and depending on operation `snapshot`) must be online. Their
compromise permits no delivery of forged content while `targets` and `root` are
offline with thresholds — that is the entire gain over a single embedded public key.

The counterpart is an availability duty: if the `timestamp` re-signing job fails,
timestamps expire and clients pause fail-closed. That is not a security break, but it
is an outage, and it is why the design recommends `tuf-on-ci` over hand-rolled CI
scripts.

## 8. Beyond a first version

- **Delta stage 2** (§6.4): optional patch targets against the last *N* versions,
  referenced from the descriptor's `custom` field. Discovery is by convention and
  needs no extra signature — the *result* is verified against the signed target hash,
  so a broken or tampered patch only causes a fallback to the full target (backlog
  IDN-14).
- **Provenance / SLSA** alongside reproducible builds, as an additional supply-chain
  proof beside TUF (IDN-18).
- **Golden tests** over the emitted metadata, which is the practical way
  reproducibility stays true rather than aspirational (part of IDN-01).
