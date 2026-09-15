# IDN-03 — Packer: retention (§4.1, §9 step 4) — **done**

**Priority:** P0 — blocks a first end-to-end release

`retention.keep` in `pack.yaml` keeps the newest N releases per platform of the
release line being published and removes the rest from its delegation. It is off
unless configured, refuses a window below two, and refuses — rather than widens — a
window that would drop a release a channel pointer names, the one being published
included. What else goes is a reference count over the retained descriptors: a
payload stays while any of them names it, a patch while its base or its result does,
which contains every patch a client walking from a retained release to the head can
use. Anything in the line it cannot classify, or a retained descriptor it cannot
read and verify, is a refusal. Metadata is re-signed through the normal flow; files
are deleted only after `timestamp.json` is written. Tested against `core/trust`, the
installer and the updater: a retained release still resolves and updates to the
head. Not handled: a `min_from_version` floor naming a release outside the window is
not protected — a client below it may be refused rather than walked, which fails closed
(see [`packer.md`](../../packer.md) §4).
