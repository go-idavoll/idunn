# IDN-33 — Signing without losing dedup and reproducibility (§4.1, §9, IDN-18)

**Priority:** P2 — hardening and reach

A signature carries a timestamp, so re-signing an unchanged DLL produces new bytes: a new
content-addressed payload target, no reuse on the client, a pointless patch. And signed
bytes are not reproducible, which IDN-18's comparison does not cover.

Wanted: a signing step keyed by the digest of the *unsigned* build — a file whose
unsigned digest equals the previous release's is not re-signed; the signed file is
taken from that release. Publish the unsigned digests next to the signed ones, so an
independent rebuild can be related to what shipped. For Authenticode the signed hash
excludes the checksum and the certificate table; whether the unsigned build's
Authenticode digest matches the signed file's (padding added when signing) is
**unverified**. For Mach-O, whether `codesign --remove-signature` restores the unsigned
bytes is **unverified**.
