# IDN-14 — Delta stage 2: intra-file binary patches (§6.4) — **done**

**Priority:** P2 — hardening and reach

Done: the format and both halves of it. `stage.ApplyPatch` reads idunn's delta
container — the bsdiff arrangement of control runs, byte-wise differences and
literals, deflate-compressed — bounded by the signed target length, fuzzed by
`FuzzPatchApply`, standard library only so `core` gains no dependency.
`internal/delta` generates one: anchors on identical 64-byte blocks found through a
rolling hash, grows each run for as long as the two files keep roughly agreeing (which
is what absorbs a relink's scattered pointer changes), and emits the same container.

Measured on a 200 MiB stand-in for a browser runtime, rebuilt with 1% rewritten, 50k
scattered byte changes and a megabyte inserted: a 3.3 MiB patch (1.64%), six seconds
to generate, a quarter of a second to apply
(`IDUNN_SCALE=1 go test ./internal/delta -run ReleaseScale`). A raw-dictionary zstd
delta — the other candidate the design named — was measured first: usable below 32 MiB
of base, 43% of the target at 64 MiB and 63% at 96 MiB with the Go implementations
available, so it was dropped.

Also done: the walk. A full target is self-contained, so reaching the head is one step;
a patch turns one exact set of bytes into another, so a client that skipped releases
cannot jump and has to follow what it missed. `release.Chain` produces that walk and
refuses everything it cannot answer unambiguously, and `trust.Versions` says which
releases exist — read out of the signed targets metadata, where every descriptor's path
already states its version, so no new document is published or signed for it.

Also done: the client side of applying one. `release.PatchPath` derives the target path
of a patch from the two content hashes the descriptors already carry — so discovery
needs no descriptor field and no schema bump, and the signed metadata answers whether a
patch exists before a byte is fetched. `core/updater` collects the byte-level history of
the walk into a `stage.Route`; `core/stage` reconstructs each changed file from the
cheapest published set of hops (a shortest path by patch bytes, weights straight out of
the signed metadata, the full target as the upper bound), verifies every intermediate
against that release's signed hash, and answers every failure — no patch published, a
poisoned patch, a missing base, a route that costs more than the file — with the
download it was trying to avoid.

Also done: the publishing side. A publish emits a patch from each of the last N
releases of a platform to the file it now ships, under the path both sides derive from
the two content hashes, in the release line's own delegated role. It skips what is not
worth carrying — an unchanged file, a rewritten one, a patch above `max_ratio` of the
file it rebuilds — and it re-reads its base out of the repository and checks it against
the hash it is published under first, so a locally rotted payload cannot become a patch
that fails on every client. `delta:` in pack.yaml configures both bounds.

Also done: the migration case. A `MinFromVersion` floor is the one refusal a path can
answer — unlike a downgrade or a client too old for the layout, it says only that this
install is too far back to arrive in one step. Where the repository publishes releases
that bridge the gap, `CheckForUpdate` offers the release and `Apply` installs the
releases in between in order, each a complete update with its own transaction, its own
migration hooks and its own commit; the walk it takes is the shortest the floors allow,
never passes through another channel, and is planned with the same `applicable()` the
apply enforces, so the planner cannot pick a step the apply then refuses. A step that
fails leaves the install on the last release that committed — a published release, not a
half-state — and says so.

One thing a walk has to do first is see the releases it walks through. A repository
delegates per release line, and a client loads a delegated role only when it resolves a
target in it — so a client that has just resolved a 2.0.0 head knows the 2.x descriptors
and no others, and would conclude that the 1.5.0 it has to step through was never
published. `trust.OpenLine` makes a line's role load; the walk opens every line between
the installed release and the one it is going to, bounded, before it asks which releases
exist. `internal/packer` tests this against a real delegated repository, because a fake
history that knows every release cannot show it.

Also done: the corpus cases. The harness publishes a previous release and the patches
between it and the head — in the content-addressed layout the packer really produces —
and drives the whole story: a machine installed on the older release, updated to the
newer one against a repository whose patches are the attacker's. Three cases attack it:
a properly signed patch that reconstructs bytes of the attacker's choosing, a valid
patch published under the path of a different pair of payloads, and a patch whose
published bytes disagree with the signed target. None expects a refusal — a patch is not
trusted, so the client may try it and discard the result — and all three assert the
stricter thing instead: the update arrives, every installed byte is the signed one, and
nothing the attacker chose is anywhere on disk. `TestDeltaBaselineTakesThePatch` is the
control that keeps them from passing on a client that ignores patches altogether.

IDN-14 is **done**.
