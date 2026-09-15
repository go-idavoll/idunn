# IDN-09 — Monotonic known-good time floor (§14.7, T22) — **done**

**Priority:** P1 — blocks a trustworthy release

`core/timefloor` persists `max(build time, clock at the last successful refresh)` in
the install root and refuses a local clock below it — before the refresh whose expiry
check depends on that clock, and again before an apply, since Apply does not refresh.
The floor only ever rises, and it can only refuse: it makes nothing acceptable that
go-tuf would have rejected (AGENTS.md §1.2).

The design says "timestamp of the last validly seen metadata". TUF metadata carries
only `expires`, which lies in the future by construction and would refuse every honest
clock as a lower bound; what is recorded is the local clock at the moment metadata
verified, which is the evidence that actually exists.
