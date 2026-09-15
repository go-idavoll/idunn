# IDN-07 — Privileged helper service and its IPC (§14.2, §14.8, T16, T23) — **POSIX and Windows done**

**Priority:** P1 — blocks a trustworthy release

`elevate.NewHelper` (privileged side) and `elevate.NewService` (the `Elevator` for
`ElevationService`) speak a line protocol over a Unix socket that carries exactly the
three scalars of the request grammar. The helper, in this order: authenticates the
peer from the kernel (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS; an empty
`AllowedUIDs` means root only), rate-limits, parses (fixed keys and order, length
bounds, no CR, nothing buffered after the terminator; fuzzed), checks the root against
`AllowedRoots` **and** `CheckPrivilegedRoot` — at start and again per request — and
only then calls its `Applier`. The answer is a class, never an error text.
`updater.RequestApplier` is that applier: the helper's own channel, options built per
root with `PrivilegedCacheDir`, then `ApplyRequested`. The socket's directory must
belong to the helper's user and be writable by nobody else, and so must every
directory above it unless sticky; an overlong socket path (macOS: 103 bytes) is refused
by name. The exchange deadline bounds reading and answering, never the apply;
cancelling the caller stops its wait, not the apply.

On Windows the same helper listens on a named pipe (go-winio v0.6.2, used for
`ListenPipe` and `DialPipeAccessImpLevel` only). The endpoint is `\\.\pipe\<name>` with a
strict name grammar, checked by `NewHelper` and `NewService`. The helper builds the
pipe's security descriptor from SIDs — protected DACL, `FILE_ALL_ACCESS` for SYSTEM,
Administrators and its own account, read/write/read-attributes/synchronize only for
each `AllowedSIDs` account, nothing for anyone else — and creates the first instance
with `FILE_CREATE`, so a squatter on the name stops it from starting; remote clients are
rejected by the pipe and, again, by the helper when the pipe reports a client computer
(SMB, including `\\localhost`). Per connection the client is identified by its token:
`ImpersonateNamedPipeClient`, `OpenThreadToken` as self, `RevertToSelf` on a locked
thread that is discarded if reverting fails; the token's user SID is compared with
`AllowedSIDs` (canonical account SIDs; empty = SYSTEM only). The caller dials at
identification level; an anonymous-level client is refused. The pid is logged only.
`AllowedUIDs` on Windows and `AllowedSIDs` on POSIX are refused. Tests run real pipes:
the POSIX hostile-caller corpus plus squatter, second helper, DACL read back and judged,
SMB-loopback client (at open, and at `authorizeConn` on a pipe without the flag),
anonymous client, and the option and endpoint refusals.

Still open:

- **Server check on the client side** (Windows): `NewService` does not verify that the
  pipe it reached is served by SYSTEM (`GetNamedPipeServerProcessId` + token). A
  squatter while the helper is down cannot install anything — the helper is the one
  that re-verifies — but can answer `ok` for an apply that never happened (the updater
  reads the pointer back) and learn the caller's identity at identification level.
- ~~**macOS daemon registration**~~ — built under IDN-08: `SMAppService` registration,
  the LaunchDaemon plist, and the audit token (`LOCAL_PEERTOKEN`) with an optional
  code-signing `PeerRequirement` on top of the uid allow-list.
- **fd hand-off** (`SCM_RIGHTS` / `DuplicateHandle` pulled by the helper) to avoid the
  second download; today the helper downloads again, into its privileged cache.
