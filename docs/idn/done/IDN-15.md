# IDN-15 — Descriptor-level validity window (§6.3 `EnforceExpiry`) — **done, by removal**

**Priority:** P2 — hardening and reach

Decided the second way: the flag is gone. This is a public API break —
`updater.Policy` no longer has an `EnforceExpiry` field, and a host that set it no
longer compiles; deleting the line is the whole migration, because the value was
ignored.

It governed nothing. Schema 1 descriptors carry no validity window, so the only expiry
in play was TUF's own — checked inside go-tuf during `Refresh`, before this package
decides anything, and not relaxable from above by design. Adding a second, app-level
window in schema 2 was the alternative and is worse: it is exactly the parallel check
AGENTS.md §1.2 warns about, and it buys nothing `timestamp.expires` does not already
give. Removing the field rather than leaving it forced to `true` is the point — a knob
that cannot be turned is one somebody will eventually believe in.

`TestExpiredMetadataIsRefusedThroughTheUpdater` (`core/updater`) is the proof that
nothing was lost: a real go-tuf client, a signed repository a month past its timestamp
window, the most permissive `Policy`, and a refusal classified as expiry with nothing
written — beside a control that the same setup inside the window offers the release.
