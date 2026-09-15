# IDN-02 — Packer: delegations from day 1 (§4.1) — **done**

**Priority:** P0 — blocks a first end-to-end release

`targets.json` holds delegations and no targets. The split is per channel
(`stable`) and per release line (`v2`) rather than one role per `(channel, major)`
pair, because a descriptor's target path deliberately carries no channel and the
patterns would otherwise overlap; the property the design asks for — disjoint
patterns, a client loading only what it follows — holds and is tested against
go-tuf's own matcher. See [`packer.md`](../../packer.md) §5.
