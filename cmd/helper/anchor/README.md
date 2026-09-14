# Build-time configuration

This directory is what `cmd/helper` embeds with `go:embed`. It is empty on purpose in
idunn's own tree: a placeholder trust anchor is the one file that must never be
shippable by accident.

A publisher drops three files here before building their helper
(`docs/helper.md` §2):

- `root.json` — the TUF trust anchor from the signing ceremony (as for
  `cmd/installer/anchor/`).
- `repository.json` — `metadata_url`, optional `targets_url` and `channel`
  (as for `cmd/installer/anchor/`).
- `helper.json` — `label`, `allowed_roots`, optional `peer_requirement`,
  `min_interval_seconds` and `macos_bundle_identifier`.

A build missing any of them refuses to serve. None of them can be overridden on
the command line.
