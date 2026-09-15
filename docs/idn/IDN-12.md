# IDN-12 — Streaming targets instead of whole-file buffers — **done in this repository, one buffer left upstream**

**Priority:** P1 — blocks a trustworthy release

Every byte of a release used to exist in memory at least twice — the `[]byte` go-tuf
hands over and the buffer staging writes — and a delta added a base and an output beside
them, so a chain held two payloads plus a patch. For a release whose bulk is a browser
runtime that is gigabytes of resident memory for an operation whose working set is one
file at a time.

What is done:

- `trust.Materialize(targetPath, io.Writer)` streams a verified target, and
  `trust.VerifyStream(targetPath, io.Reader)` gives a verdict on bytes that are never
  all in memory. `MaterializeTarget` is built on the first and `stage.Materializer` is
  those two plus `TargetLength` — staging no longer has a way to ask for a payload as a
  `[]byte`.
- `core/stage` produces every file through `fsx.WriteStreamAtomic` with the verifier
  teed into the bytes that land, so what was checked is what a reader will see. Reuse
  copies and verifies in one pass; `ApplyPatchStream` reads its base and its patch
  through `io.ReaderAt` and writes the reconstruction sequentially; a chain spills its
  intermediate hops to `.updater/staging/.scratch`, which is removed either way.
  `ApplyPatch` remains as the buffered wrapper the packer's round-trip check and
  `FuzzPatchApply` use, implemented in terms of the streaming one so there is a single
  reader.
- `VerifyAfterApply` re-reads through `VerifyStream`, so the belt-and-braces check no
  longer costs as much memory as the install that just finished.
- `Materialize` probes the go-tuf cache without writing anywhere before it streams, so a
  planted cache entry cannot reach the caller half-way, and it reads that cache itself
  rather than through `Updater.FindCachedTarget`, whose unbounded `os.ReadFile` reads an
  oversized planted entry whole (**T23**). An entry that does not verify is removed and
  re-downloaded. `FindCachedTarget` is no longer called anywhere: `Target`, the small
  remaining whole-buffer door for the pointer and the descriptor this package parses
  itself, is `Materialize` into a buffer, so every cache read in the process is the
  bounded, verifying one.
- The ceiling is unchanged and still the guard on the one buffer that remains:
  `trust.Options.MaxTargetBytes` (default `trust.DefaultMaxTargetBytes`, 2 GiB; negative
  is refused by `trust.New`) refuses a target whose signed length is above it **before a
  byte of it is requested or read**, through `targetInfo`, which `Materialize`,
  `VerifyStream`, `TargetLength`, `Target` and so `LatestRelease`/`ReleaseVersion` all
  start at.

**The part that deserves a reviewer's attention.** Streaming needs a verdict on bytes
that are never all in memory, and go-tuf v2.4.2 has none: `metadata.TargetFiles` exposes
only `VerifyLengthHashes([]byte)`. `TargetFiles.Equal` is *not* a substitute — its
`Hashes.Equal` passes as soon as one algorithm in common matches and ignores the rest,
where `VerifyLengthHashes` requires every signed algorithm and refuses one it does not
know; building on it would have been a weakening dressed as reuse. So `core/trust`
computes the digest incrementally itself, which is a hand-written check beside go-tuf's
and is the thing AGENTS.md §1.2 is about. It is held to being *the same* check: it lives
in the one package that may see signed material, it takes the signed length and hashes
from go-tuf alone, it refuses in every case go-tuf refuses (plus a stream that runs past
the signed length, which the `[]byte` form cannot encounter), and the equivalence is
enforced rather than claimed — `FuzzVerifyStreamMatchesGoTUF` fails the build the moment
the two verdicts differ on any input, with the individual refusals pinned beside it.

What is left, and it is upstream: a go-tuf `Fetcher` that can hand back an
`io.ReadCloser` and a `DownloadTarget` that verifies incrementally, then `core/fetch`
implementing it (and `fetch.Options.Resume` with it, whose `partial.body` is the other
whole-file buffer). Until then one copy of the largest target exists during its first
download, inside go-tuf, and `core/trust/stream.go` is the file that would be deleted by
the fix.
