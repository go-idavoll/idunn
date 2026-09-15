# IDN-31 — Windows: Authenticode as a gate before the swap (§13)

**Priority:** P1 — blocks a trustworthy release

The Windows counterpart of IDN-27, under the same AGENTS.md §1.2 carve-out: after TUF
accepted every byte, and only as an additional refusal. Smart App Control and
WDAC/AppLocker publisher rules refuse an unsigned or wrongly signed exe or DLL; without
a gate that surfaces only after the swap, as an application that does not start.

`WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`) is in `golang.org/x/sys/windows`
— no cgo, no new dependency. Every staged file of kind `exe` and `lib` is checked, and
the signer is pinned against a value built into the binary (leaf certificate subject or
the publisher's certificate thumbprints, with room for a rotation), not against the
signature of the installed version, so a tampered installation cannot lower the bar.

Open: revocation. A full chain check goes to the network; a gate that fails every
offline update is unusable, a gate that silently skips revocation is weaker than it
looks. Candidates: `WTD_REVOKE_WHOLECHAIN` with `WTD_CACHE_ONLY_URL_RETRIEVAL`, or
`WTD_REVOKE_NONE` with the reason written down.

**Unsigned applications stay supported.** Plenty of publishers have no certificate —
open source projects, internal line-of-business tools, test builds — and TUF, not
Authenticode, is what makes an idunn update trustworthy. Proposed, for IDN-27 and this
item alike:
- **No pinned publisher: no gate.** The zero value keeps today's behaviour; the updater
  applies unsigned files as it does now. Unlike the `OnBusy` case (IDN-21) this is not
  a forgotten line changing behaviour: leaving the pin out changes nothing. The
  launcher and installer say once, in their log, that the platform signature is not
  checked.
- **A pinned publisher makes the signature mandatory**, for every `exe` and `lib`
  file of every later release: unsigned, signed by someone else, or invalid is a
  refusal before the swap, classified as its own error (not `verify` — the bytes are
  the publisher's, the OS would not run them).
- **The pin travels with the binary that checks**, so transitions follow from which
  version is installed: an unsigned 1.0 updates to a signed 1.1 that introduces the
  pin (1.0 has no gate), and from then on every release must be signed. Dropping
  signing again takes a signed release whose binary no longer carries the pin; an
  unsigned release published straight after would be refused by every client still on
  a pinned version. The packer gate (IDN-32) is where that mistake is caught before it
  ships.
- A pin never lets through anything TUF refused, and an unsigned application never
  gains from a gate it does not have — the gate only narrows.
- Windows itself may still refuse an unsigned application (Smart App Control, WDAC);
  that is the host's deployment question, which the gate would only make visible
  earlier.
