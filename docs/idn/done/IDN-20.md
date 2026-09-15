# IDN-20 — Decide the mythology naming question (§2.1) — **done**

**Priority:** P2 — hardening and reach

Functional names are canonical in code; mythological names are branding for the
umbrella `idunn` and nothing below it.

The first half is what the code has always done, so deciding it costs nothing. The
second half is the part that needed deciding: not `heimdall`, not `bifrost`, not as an
internal codename. A codename that lives in a README is charming; one that turns up in
a stack trace an auditor is reading is a question they have to stop and ask, and the
boundary is easier to hold at zero than at two.
