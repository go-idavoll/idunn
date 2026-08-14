# The packer

> **Status: implemented, except retention.** `cmd/packer publish` reads a
> `pack.yaml`, emits payloads, descriptors and channel pointers as delegated TUF
> targets, and re-signs `targets`, the delegations, `snapshot` and `timestamp`
> (IDN-01, IDN-02). The engine lives in `internal/packer`; `cmd/packer` is flags,
> exit codes and nothing else. What is still open is **retention** (IDN-03, §4
> step 4): nothing is ever removed from a delegation yet.
>
> The other producer of a TUF repository in this repo is the red-team harness
> (`test/redteam/harness`, `make baseline`). It builds a *test* repository with
> *test* keys and is not a packer: no `pack.yaml`, no delegations, no key hygiene.
> It stays as the adversarial fixture; it is not the publishing path.

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
| `payloads/v<major>/<sha256>` | one payload file, verbatim | §4 step 1 |
| `releases/<os>-<arch>/<version>.json` | `release.Descriptor` | `release.DescriptorPath` |
| `channels/<channel>/<os>-<arch>/latest.json` | `release.Pointer` | `release.PointerPath` |

The two path helpers live in `core/release` precisely so that the packer and the
client cannot drift apart: there is one place that knows the layout, and both sides
import it.

**Payload targets are content-addressed**, and that is a deliberate change from the
`payloads/<version>/<name>` sketch this document used to carry. Naming a payload by
its content is what makes the dedup claim in design §4.1 *true* rather than
aspirational: an unchanged file across releases is literally the same target, so
metadata — and server storage — grow with changed files, not with `releases × files`.
It also makes every payload target immutable, so a republish can never change what an
already published path resolves to. The `v<major>` prefix is not addressing; it is
what lets the release-line delegation own the payload namespace by path (§5).

Two consequences worth knowing:

- Under consistent snapshots the on-disk name repeats the hash
  (`payloads/v1/<sha256>.<sha256>`), because go-tuf prefixes every target file with
  its hash. Harmless, and not worth an exception to the naming rule.
- One release cannot install *identical bytes* to two destinations: both files would
  be the same target, and a descriptor that names one target twice is refused by the
  client. The packer detects it and says so, rather than emitting a descriptor that
  fails on every machine.

**`custom` is not used.** The design sketched `dst`, `mode` and `kind` riding along in
the target's `custom` field. With content-addressed targets that is not merely
redundant, it is ill-defined — two platforms can share one payload target and install
it to different destinations, so there is no single `dst` to record. Those three
fields are properties of *using* a target in a release, not of the target, and they
already live in the descriptor's `FileRef`, which the client parses, validates and
fuzzes. Publishing a second, unverified copy of a security-relevant field (`mode`)
would create a source of truth nothing checks.

The descriptor the packer emits must satisfy `release.ParseDescriptor` — which is
strict, key-checked, and fuzzed. In particular: `schema_version` = 1,
`layout_schema` = 1, SemVer `version`, no duplicate `dst`, no unknown keys, no
setuid/setgid bits in `mode`.

The pointer must name exactly `release.DescriptorPath(os, arch, version)`. The client
derives the expected path from the version the pointer claims and refuses a pointer
that names anything else — a pointer may not fetch a release it is not entitled to
name.

## 4. Publish flow

0. **Resolve every role key, and load and verify the repository**, before a byte is
   read from the build tree or written. A publish that cannot be completed must not
   be started (T13).
1. **Add each payload file as a TUF target.** go-tuf computes hash and length. The
   target lands in the **release-line delegation** (`v2`), never in the top-level
   `targets.json`.
2. **Write the release descriptor** and add it as a target in the same delegation.
3. **Set the channel pointer** to the new version and add it as a target in the
   **channel delegation** (`stable`).
4. **Retention:** remove targets of retired releases beyond the keep window,
   respecting any delta patch sources that still reference them (§6.4).
   *Not implemented — IDN-03.*
5. **Re-sign** the roles this publish touched (the two delegations with the
   offline/HSM key, then `snapshot` and `timestamp` with the CI keys). Consistent
   snapshots on.

A role whose signed content is unchanged is not re-signed and its file is not
rewritten: its version stays put. That is what makes a repeated publish a no-op
instead of metadata churn every client has to re-fetch — and it is the same
mechanism that makes two runs over the same inputs byte-identical. Roles this
publish does not touch (another channel, an older release line) keep their bytes,
their version *and their key*; re-delegating them to the key at hand would be a
silent key rotation for a role the operator did not mean to publish.

`root` signatures — key rotation — deliberately run **outside** the normal publish, in
a separate controlled ceremony (offline, m-of-n; `tuf-on-ci` is the recommendation).
A publish that could touch `root` would put the highest asset in the model behind the
most frequently run command.

## 5. Hard rules

These are not style preferences; each one is a threat mitigation.

**Keys never live in the repository.** The environment carries a *reference* to a
key, never a key:

| Variable | Role | Form |
|---|---|---|
| `TUF_TARGETS_KEY` | `targets` and, by default, its delegations | path or `file:` URI |
| `TUF_SNAPSHOT_KEY` | `snapshot` | path or `file:` URI |
| `TUF_TIMESTAMP_KEY` | `timestamp` | path or `file:` URI |
| `TUF_DELEGATION_KEY_<ROLE>` | one delegation (`…_STABLE`, `…_V2`) | optional override |

The file is an unencrypted PKCS#8 Ed25519 key; any other scheme is refused with
"only `file:` is implemented", which is where a KMS/HSM resolver plugs in later. A
variable that contains key *material* rather than a reference is refused outright —
material in an environment variable leaks into process listings, crash dumps and CI
logs — and the refusal does not echo it. Nothing here reads, writes, logs or prints
key material (AGENTS.md §5), and no `root` key is ever resolved at all.

Every key is resolved **before** the repository is touched, so a missing key aborts a
publish rather than truncating one: an unsigned or half-signed repository state must
not be publishable by accident (T13).

The publish also refuses a repository it cannot publish into *correctly*: a root that
does not enable consistent snapshots, a root that has expired at the reference time, a
role whose threshold is above one (that needs the ceremony, not this tool), or a
configured key that root does not name for its role. Each of those would otherwise
"succeed" and produce something no client accepts.

**Output is reproducible.** No wall-clock, no randomness, no environment leakage into
artifacts (AGENTS.md §1.7). Two runs over the same inputs produce byte-identical
metadata and targets — that is what makes an independent rebuild a supply-chain proof
rather than a guess. Metadata expiry timestamps are inputs, not `time.Now()`: the
reference time comes from `--now` or `SOURCE_DATE_EPOCH`, and there is deliberately no
fallback to the clock. A publish without one is refused, because the alternative is
output that silently embeds when it ran.

**Publishes are atomic from the client's perspective.** Consistent snapshots mean a
client never sees a `snapshot` that references metadata not yet uploaded. Upload
order matters: targets and delegated metadata first, `timestamp.json` last.

**Delegations from day 1.** Retrofitting them is a migration for every deployed
client, which is why the design calls them mandatory rather than optional. The
top-level `targets.json` holds **no targets at all** — it only delegates:

| Role | Path patterns | Holds |
|---|---|---|
| `stable`, `beta`, … | `channels/<channel>/*/latest.json` | that channel's pointers |
| `v1`, `v2`, … | `releases/*/<major>.*.json`, `payloads/v<major>/*` | one release line's descriptors and payloads |

Every delegation is `terminating`, with **disjoint** patterns: each target path
matches exactly one role, so the role that owns a path is the only role that may
provide it — if it does not have the target, resolution stops rather than letting
another delegation answer. A client following `stable` loads its own pointer role and
the one release line it is installing; it never sees another channel's pointers or
another major's history. `internal/packer` asserts the disjointness against go-tuf's
own matcher, not a reimplementation of it.

The split is per channel **and** per release line, rather than one role per
`(channel, major)` pair as design §4.1 sketches with `stable-v2`. A descriptor's
target path deliberately carries no channel — `releases/<os>-<arch>/<version>.json` is
what the client derives from the version a pointer claims, and what `--version`
resolves *without* knowing a channel at all. A `stable-v2` role would therefore have
to claim `releases/*/2.*.json` in every channel at once, and the patterns of
`stable-v2` and `beta-v2` would overlap. Splitting the two dimensions keeps them
disjoint and gives the same property the design asks for. The cost is that one
release-line delegation covers every channel's descriptors for that major, which is
bounded by the same retention window as everything else.

A channel may not be named `v<digits>`: it would collide with a release-line role, and
one role cannot be trusted for two path sets without giving each the other's reach.

Hash-bin (succinct) delegations stay in reserve for extreme target counts.

**Content addressing does the deduplication.** An unchanged file across releases is
the *same* target with the same hash, so metadata grows with *changed* files, not with
`releases × files`. This is also what makes file-level delta free on the client side.

## 6. Repository layout on the server

Statically hostable (S3, CDN); no server-side logic. Security lives in the client's
TUF workflow.

```
/metadata/
  1.root.json          # version-prefixed, offline-signed; an input, never an output
  timestamp.json       # never version-prefixed — the freshness anchor
  1.snapshot.json      # consistent overall state
  1.targets.json       # tiny: delegates only, no targets
  1.stable.json        # channel delegation: the pointers
  1.v1.json            # release-line delegation: descriptors and payloads
/targets/
  payloads/v1/<sha256>.<sha256>
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
- **Retention** (§4 step 4, IDN-03): the one part of the flow above that is not
  built. A delegation grows for the lifetime of the product until it is.
- **Root bootstrapping** stays out: a repository must already contain a
  `<version>.root.json` from the ceremony. The packer refuses to create one, so the
  command that runs on every release can never mint a trust anchor.

Golden tests over the emitted metadata are already in place
(`internal/packer/testdata/golden`, refresh with `go test ./internal/packer -run
Golden -update`). They are the practical way reproducibility stays true rather than
aspirational: the test keys are deterministic, so signatures and key IDs are pinned
too, and a change in emitted bytes is a red build rather than a surprise months later.
