# Build-time trust anchor

This directory is what `cmd/installer` embeds with `go:embed`. It is empty on
purpose in idunn's own tree: this repository has no update repository to point
at, and a placeholder `root.json` is the one file that must never be shippable
by accident.

A host project drops two files here before building its installer:

## `root.json` — required for a shipped installer

The TUF trust anchor: the initial, offline-signed `<n>.root.json` from the
signing ceremony, renamed to `root.json`. It is the client's only trust
decision (`docs/design.md` §4). Everything else — URLs, channel, version — is
configuration; a wrong value there fails verification, while a wrong `root.json`
would not fail, it would succeed against the wrong publisher.

A build that carries this file **cannot be redirected** to another anchor:
`--root-metadata` is refused. A build without it is a tool rather than a
product, and requires `--root-metadata` on every run.

Root keys rotate through signed root updates, so this file does not need to be
refreshed for a key rotation — only if the root threshold itself is lost.

## `repository.json` — required for a shipped installer

```json
{
  "metadata_url": "https://updates.example.com/metadata/",
  "targets_url": "https://updates.example.com/targets/",
  "channel": "stable"
}
```

`targets_url` may be omitted; it then defaults to the `targets/` sibling of the
metadata URL, which is the layout the packer publishes. `channel` may be
omitted; it then defaults to `stable`. Both URLs may be overridden at runtime
(`--metadata-url`, `--targets-url`) — a wrong URL cannot make the binary trust
anything new, and pointing an installer at a mirror or a staging repository is a
legitimate thing to do.

The privileged `apply` verb is the exception: it accepts only `--root`,
`--channel` and `--version`, and requires both files to be embedded. It may run
elevated, and anything it accepted from its caller would move a trust decision
to the unprivileged side (`docs/design.md` §14.2).

## Building

```sh
cp path/to/1.root.json cmd/installer/anchor/root.json
cp path/to/repository.json cmd/installer/anchor/
go build -ldflags "-X main.clientVersion=1.3.0" -o dist/acme-installer ./cmd/installer
```

`clientVersion` is what a descriptor's `min_client_version` floor is checked
against (`docs/design.md` §11.3 T14). It is a linker variable rather than a flag
on purpose: an operator who could claim any client version could talk an
installer past the floor that exists to stop it from mishandling a newer layout.
A build that leaves it unset refuses any release that demands a minimum.
