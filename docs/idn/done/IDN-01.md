# IDN-01 — Packer: publish a TUF repository (§9) — **done**

**Priority:** P0 — blocks a first end-to-end release

`cmd/packer publish` reads `pack.yaml` and produces a repository `core/trust`
resolves end to end. Engine in `internal/packer`, contract in
[`packer.md`](../../packer.md). Two deviations from the sketch in the design, both argued
there: payload targets are content-addressed (which is what makes the §4.1 dedup
claim true), and `custom` is not used (`dst`/`mode`/`kind` are properties of a
release's *use* of a target and already live in the descriptor).
