# IDN-10 — Local reuse of already-installed files (§6.4 stage 1, second half) — **partly done**

**Priority:** P1 — blocks a trustworthy release

`stage.stageFile` now looks for the file it is about to write in the live version and
then in the retained ones, newest first, and stages the local bytes when
`trust.VerifyTarget` says they are the signed content. Nothing is adopted on name
alone: the candidate is size-filtered against the signed length, read, and verified,
and every way of failing that — tampered, bit-rotted, unreadable, swapped between the
stat and the read — falls back to fetching the target, never to a weaker check. The
`Materializer` interface carries the two methods this needs (`TargetLength`,
`VerifyTarget`), so staging still never holds a signed hash of its own.

What is left of the design text: the reuse is a plain copy, not reflink/CoW or a
hardlink, which needs an fsx operation that does not exist; and the lookup is keyed on
the destination a file lands at rather than on a content-hash index over the installed
tree, so a file that moved between releases is fetched. Both are efficiency, not
correctness — and the verified-base half that IDN-14 depends on is in place.
