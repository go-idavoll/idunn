# The privileged helper

How a publisher ships the `ElevationService` side of a system-wide install: a small
daemon or Windows service that owns the install root and applies updates the
unprivileged application asks for. `cmd/helper` is a runnable reference; the
reasoning is in [`design.md`](design.md) §14.2 and §14.8.

## 1. Every publisher builds and signs their own

There is no shared helper binary, and there cannot be one:

- **The trust anchor is compiled in.** The helper runs as root or SYSTEM and
  verifies every release itself. A helper that took its `root.json` or repository
  URL at runtime would let whoever starts it choose whom root trusts (AGENTS.md
  §1.4). So the anchor is a build-time fact of each publisher's helper, exactly as it
  is for `cmd/installer`.
- **The operating system checks the publisher's signature.** macOS registers a
  LaunchDaemon only from a signed bundle, and the helper's `PeerRequirement` names
  the publisher's Team ID. Windows services and SmartScreen expect Authenticode.

So a publisher copies nothing but configuration into `cmd/helper/anchor/`, builds,
signs with their own identity, and ships the helper inside their product. The
scripts under `scripts/` do the signing and packaging steps; they read identities
and credentials from the environment or the keychain and never from the tree.

## 2. What is compiled in, and what is per machine

| Where | File | Decides | Written by |
|---|---|---|---|
| build | `cmd/helper/anchor/root.json` | whom to trust | publisher, from the signing ceremony |
| build | `cmd/helper/anchor/repository.json` | where releases come from, channel | publisher |
| build | `cmd/helper/anchor/helper.json` | label, install roots, caller code requirement | publisher |
| machine | `<state dir>/callers.json` | which local accounts may ask | an administrator, through `helper allow` |

Who may ask cannot be decided at build time — a publisher does not know the uids or
SIDs of its users' machines — and an empty allow-list means only root/SYSTEM, which
is useless to an application. So that one decision is per machine, in a directory
only administrators can change, and the helper refuses to start if that directory
could be changed by anyone else (the same judgement as an install root,
`elevate.CheckPrivilegedRoot`).

### `helper.json`

```json
{
  "label": "com.acme.app.helper",
  "allowed_roots": ["/Library/Application Support/Acme"],
  "peer_requirement": "anchor apple generic and identifier \"com.acme.app\" and certificate leaf[subject.OU] = \"TEAMID1234\"",
  "min_interval_seconds": 5,
  "macos_bundle_identifier": "com.acme.app"
}
```

- `label` — reverse-DNS, `[A-Za-z0-9.-]`, at most 62 bytes (so the macOS socket path stays within the kernel limit). It names the launchd job,
  the Windows service, the socket or pipe and the state directory.
- `allowed_roots` — absolute install roots this helper maintains, per platform
  (a build carries the ones for the platform it is built for).
- `peer_requirement` — macOS only, optional; set on another platform it is
  refused at start rather than ignored.
- `min_interval_seconds` — optional, 0 to 3600, default 5.
- `macos_bundle_identifier` — macOS only: the app's `CFBundleIdentifier`, which
  macOS shows as the daemon's owner under Login Items; required by `helper plist`.

Unknown keys are refused.

### `callers.json`

```json
{ "uids": [501] }
```
```json
{ "sids": ["S-1-5-21-1111111111-2222222222-3333333333-1001"] }
```

POSIX takes `uids`, Windows takes `sids` (account SIDs only; groups are refused).
Written with `helper allow`, never by hand in production. A missing file means no
caller but root or SYSTEM, and the helper restarts to pick up a change.

## 3. Paths

| | macOS | Linux | Windows |
|---|---|---|---|
| state dir | `/Library/Application Support/<label>/` | `/etc/<label>/` | `%ProgramFiles%\<label>\` |
| endpoint | `/Library/Application Support/<label>/helper.sock` | `/run/<label>/helper.sock` | `\\.\pipe\<label>` |
| helper binary | `<App>.app/Contents/Library/HelperTools/<label>` | `/usr/libexec/<label>` | `%ProgramFiles%\<Product>\<label>.exe` |
| registration | `<App>.app/Contents/Library/LaunchDaemons/<label>.plist` via `SMAppService` | systemd unit `<label>.service` | Windows service `<label>` |

`elevate.DefaultHelperPaths(label)` returns the state dir and endpoint for the
running platform, and `elevate.DefaultHelperEndpoint(label)` the endpoint alone, so
the application and the helper agree without repeating the table. On Windows the
Program Files folder comes from the shell's known-folder API, not from
`%ProgramFiles%`, which a caller could set.

The application side is then only:

```go
endpoint, err := elevate.DefaultHelperEndpoint("com.acme.app.helper")
el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint})
opts.Elevator = el
opts.Policy.Elevation = updater.ElevationService
```

## 4. The `helper` verbs

| Verb | Runs as | Does |
|---|---|---|
| `helper serve` | root / SYSTEM (launchd, systemd, SCM) | starts `elevate.NewHelper` with `updater.RequestApplier`; under the Windows SCM it speaks the service protocol |
| `helper allow --uid N` / `--sid S` | administrator | adds a caller to `callers.json`, creating the state dir with administrator-only permissions |
| `helper deny --uid N` / `--sid S` | administrator | removes a caller |
| `helper check` | anyone | validates the embedded configuration and the state dir, prints the effective configuration; exit 0 only if `serve` would start |
| `helper plist` | anyone | prints the LaunchDaemon plist for this build (`elevate.DaemonPlist`), for the bundle step |
| `helper version` | anyone | prints the version this helper was built as |

No verb accepts a trust anchor, a repository URL, an install root or a caller
code requirement on the command line.

## 5. Build, sign, ship

```sh
cp ceremony/1.root.json   cmd/helper/anchor/root.json
cp release/repository.json cmd/helper/anchor/
cp release/helper.json     cmd/helper/anchor/
go build -trimpath -ldflags "-X main.version=1.3.0 -X main.buildTime=$(git log -1 --format=%ct)" \
  -o dist/com.acme.app.helper ./cmd/helper
dist/com.acme.app.helper check   # on the target machine: exit 0 only if serve would start
```

Under the Windows service control manager `helper serve` speaks the service
protocol and logs to `<state dir>\helper.log`; under launchd and systemd it logs to
stderr, which both collect.

Then, per platform, `scripts/macos/`, `scripts/windows/` and `scripts/linux/` (see
their READMEs).
