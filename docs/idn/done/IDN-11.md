# IDN-11 — Test coverage for `core/trust` and `core/fetch` — **done**

**Priority:** P1 — blocks a trustworthy release

Both had no unit test at all. `core/trust` now has direct tests of the layer the
corpus cannot reach: two authentic documents that disagree — pointer/descriptor
version and platform mismatch, a pointer naming a descriptor it is not entitled to,
a descriptor that contradicts its own path — plus `ReleaseVersion`, the cache path,
and materialization. `core/fetch` covers the trust store (`ExtraCAs` makes a private
authority verifiable, an unknown one stays refused), the user agent, the timeout,
and the refusals. Three corpus cases were added for the resolve mutators that were
registered but never exercised by a case.
