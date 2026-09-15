# IDN-19 — UI sidecars (§8)

**Priority:** P2 — hardening and reach

`idunn-bubbletea` and `idunn-web` are named in the README and do not exist. Out of
tree by design. [`idunn-fyne`](https://github.com/go-idavoll/idunn-fyne) is the
first one and shows the `Observer`/`Prompter` surface is sufficient: it drives a
real `updater.Apply` — staging, journal, atomic swap, GC — with no change to
`core`.

Two gaps it surfaced, both small and neither blocking:

- `updater.classify` is unexported, and it matches `layout.ErrLayout` and
  `safepath.ErrUnsafe`, which are under `internal/`. A sidecar cannot reproduce
  the taxonomy exactly, so those errors fall into its "unknown" class. An
  exported `updater.Classify(error) string` would close it.
- `hook.Event.Progress` used to be hardcoded to `-1` at both emitters, so a UI had no
  progress to show and had to derive one from the phase. Closed by IDN-12:
  `stage.Stager.Progress` reports bytes as a release is written, and the updater turns
  that into events carrying the file, its source (reuse / patch / download), and the
  release's byte progress against a total known before the first byte moves. Events
  outside staging still say `-1`, which is honest — a quiesce has no byte count.

A packing assistant lives in the same repository. It shells out to
`cmd/packer publish` because `internal/packer` is not importable from another
module; a public `packer.ValidateConfig([]byte) error` and a `--json` flag on
`publish` would let it stop mirroring unexported rules and parsing human-readable
output.
