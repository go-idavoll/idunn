# IDN-32 — Packer: require platform signatures at publish time (§9, T13)

**Priority:** P2 — hardening and reach

The OS signature must be inside the bytes before the packer hashes them; a file signed
after `publish` fails its TUF hash on every client, and a file never signed fails only
on the machines that enforce signatures. Both are publish-time mistakes, and the packer
already refuses what would fail on every client (a `dst` `safepath` rejects).

Wanted: an optional `platform_signature` block in `pack.yaml` — required or not, and
per OS the expected identity (Windows: certificate subject or thumbprints; darwin: Team
ID and identifier) — checked for every `exe` and `lib` file and for bundles. The packer
**verifies only**; it never signs. OS signing keys live in HSMs, Azure Trusted Signing
or the keychain, and notarization is a network round trip to Apple; neither belongs in
the tool that holds the TUF keys.

Open: a full chain check is only possible on the target OS (`WinVerifyTrust`,
`codesign`); on another OS the packer can only check that a signature is present and
names the expected signer. Whether that weaker check is offered, or the gate requires
publishing from the target OS, is to decide.
