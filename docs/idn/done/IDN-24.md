# IDN-24 — A default install root that follows the platform's conventions (§5, §6.1, §14.2) — **done**

**Priority:** P1 — blocks a trustworthy release

`cmd/installer` requires `--root` and only makes it absolute; nothing proposes a
location, so every host has to know where per-user and system-wide software lives on
every OS, and gets it wrong in a different way each time. The launcher defaults to
its own directory, which is only right once something put it in the right place. The
one path that does follow the platform today is the TUF cache (`os.UserCacheDir`).

Wanted: a `--scope user|machine` (default `user`, matching `ElevationNone`) that
derives the root from a build-time application name (`-ldflags -X`, like
`appBinary`), with `--root` still overriding:

| OS | user | machine |
|---|---|---|
| Windows | `FOLDERID_UserProgramFiles` (`%LocalAppData%\Programs\<app>`) | `FOLDERID_ProgramFiles\<app>` |
| Linux | `$XDG_DATA_HOME/<app>` (`~/.local/share/<app>`) | `/opt/<app>` |
| macOS | `~/Library/Application Support/<bid>` + `~/Applications/<app>.app` | `/Library/Application Support/<bid>` + `/Applications/<app>.app` |

Known folders on Windows come from `SHGetKnownFolderPath`, never from environment
variables a caller controls — the machine root is what the elevated helper vets
(IDN-22), and it must not be steerable. macOS has two paths, not one: where the
versions live and where the bundle a user starts lives; that split is IDN-26's.
Linux needs a decision on the launcher's discoverability (a `.desktop` entry, a
`~/.local/bin` link) or an explicit statement that it is the host's job.

**As built.** `installer.DefaultRoot(Scope, App)` derives the root by the table above
— the versions root only; the macOS bundle path stays IDN-26's. `cmd/installer` takes
`--scope user|machine` (default `user`) and the identity from the build
(`-X main.appName=…` for Windows and Linux, `-X main.bundleID=…` for macOS, not flags).
Decisions made on the way:
- `--root` and `--scope` together are a usage error, not a precedence rule: which of
  the two wins decides whether the install is elevated.
- A build without an identity keeps the old contract (`--root` required, exit 2); an
  identity no root can be derived from is the build's defect (exit 1).
- The application name is one plain component — ASCII letters, digits, space, `.`,
  `_`, `-`, no leading/trailing space or dot, no Windows device name — refused, never
  escaped. The bundle identifier is reverse-DNS.
- Machine roots consult nothing from the environment: known folders on Windows
  (`FOLDERID_UserProgramFiles` with `KF_FLAG_DONT_VERIFY`, since it does not exist
  before the first per-user install), constants elsewhere. User roots follow `$HOME`
  and an absolute `$XDG_DATA_HOME`; a relative one is ignored, as the XDG spec requires.
- Linux discoverability is the host's job: idunn creates no `.desktop` entry and no
  link on `$PATH`.
- The launcher is unchanged: it still defaults to its own directory, which is now the
  right place once the installer put it there.
