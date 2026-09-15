# IDN-18 — Reproducible builds and provenance in CI (§9, §15) — **partly done**

**Priority:** P2 — hardening and reach

`scripts/repro.sh` (`make repro`) builds `cmd/installer`, `cmd/launcher` and
`cmd/packer` for linux, windows and darwin on amd64 and arm64 twice and fails unless
every binary is byte-identical. The passes are made to differ in what must not matter —
pass b builds a copy of the tree in another directory, and each pass has its own empty
`GOCACHE`, without which the second build is a cache hit that compares equal by
construction — and the flags pin what would otherwise leak in: `-trimpath` (no build or
module-cache path), `-buildvcs=false` (the bytes depend on the source, not on `.git`),
`-ldflags=-buildid=`, `CGO_ENABLED=0`, and a scrubbed `GOFLAGS`/`GOAMD64`. Without
`-trimpath` the two directories do produce different bytes, so the check is not vacuous.
CI's `reproducible builds` job runs it on every pull request and push and writes the
digests and the exact `go version` into the job summary.

Two passes on one runner catch what breaks reproducibility in practice — an embedded
path, a wall-clock stamp, a map iterated into output. They cannot catch a difference
between two machines or toolchains; publishing the digests and the Go version is what
makes an independent rebuild possible, not a substitute for one.

Provenance: the `Release provenance` workflow runs on `v*` tags. Its build job runs the
same script with `contents: read`; a separate attest job, the only one holding
`id-token: write` and `attestations: write`, checks out nothing, verifies the binaries
it downloaded against the digests the build job handed over as a job output, and signs
them with `actions/attest-build-provenance` (SHA-pinned). Check a binary with
`gh attestation verify <file> --repo go-idavoll/idunn`.

Still open, and why this is *partly*:

- The workflow attests binaries and keeps them as a workflow artifact; it does not
  create a GitHub release. Where released binaries are published (and whether that
  job gets `contents: write`) is a maintainer decision.
- The release build stamps no `main.clientVersion` or `main.buildTime` into
  `cmd/installer`. A host's installer that sets them stays reproducible only if the
  values are derived from the commit (tag, `SOURCE_DATE_EPOCH`), never from `date`.
- No second, independent rebuild (another runner or OS) compares digests yet.

The packer's half — byte-identical repository output from the same inputs and
reference time — was closed by IDN-01 and is pinned by a golden test.
