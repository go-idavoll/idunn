# IDN-25 — Symlink entries in a release (§3.1, §3.2, §6.4)

**Priority:** P1 — blocks a trustworthy release

A descriptor names regular files of kind exe/lib/data and nothing else; the packer
takes a file list and staging refuses a symlink anywhere below a version directory.
A macOS `.app` cannot be expressed that way: frameworks carry `Versions/Current` and
top-level links into it, and the code signature seals them as links. Linux shared
libraries (`libfoo.so -> libfoo.so.1`) have the same shape.

Wanted: a `symlink` entry with a relative target, validated by `safepath` so it can
never resolve outside the version directory (no absolute target, no `..` that climbs
past the root after resolution, no link through a link), created by staging after
the files it may point at, covered by the release digest like every other entry, and
refused by the packer when the source tree's link escapes. Staging's own "no symlink
on the way down" defence stays: it applies to the directories it walks while writing,
which a release link must not be allowed to become.
