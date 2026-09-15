# IDN-04 — `cmd/installer`: the actual binary (§5) — **done**

**Priority:** P0 — blocks a first end-to-end release

The binary carries its trust anchor and repository description in
`cmd/installer/anchor/` (`go:embed`), parses `--root`/`--channel`/`--version`, makes
the elevation decision via `elevate.NeedsElevation`, and distinguishes refusal (3),
a declined prompt (4) and "needs privileges it cannot get" (5) from a real failure
(1). It also implements the privileged `apply` verb, so a build that embeds an
anchor is its own elevation helper — the three-scalar request grammar of §14.2 with
nothing else crossing the boundary.
