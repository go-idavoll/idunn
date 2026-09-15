# IDN-08 — POSIX interactive elevation (§14.2) — **Linux done; macOS service mode built**

**Priority:** P1 — blocks a trustworthy release

**Linux** (§14.2.2): `NewInteractive` runs `pkexec <helper> apply --root R --channel
C --version V` as an argument vector, with an empty environment, no controlling
terminal and `/dev/null` streams. pkexec is taken from `/usr/bin/pkexec` or
`/bin/pkexec` only, and must resolve to a root-owned setuid file nobody else can
replace; the helper, symlinks resolved, and every directory above it must be
root-owned and writable by nobody else, and the resolved path is what runs. pkexec
126 is `ErrDeclined`, 127 and any other non-zero status `ErrHelper`; cancelling stops
the wait, not the apply. The decisions are in `core/elevate/pkexec.go` behind an
injected system seam, so their negative tests run on every OS; the real launcher is
tested on Linux against a stand-in pkexec, and the real prompt behind
`IDUNN_TEST_PKEXEC=1`. Example polkit action: `docs/examples/org.idunn.apply.policy`
(`auth_admin`, not `auth_admin_keep`).

Open on Linux: no e2e scenario drives a real polkit agent (CI has none); the helper
runs with pkexec's scrubbed environment, so an environment-only proxy does not
reach its download (IDN-13).

**Decided (maintainer): macOS uses `SMAppService`, as service mode** — the IDN-07
helper registered as a LaunchDaemon — not a one-shot prompt. Sparkle's `SMJobSubmit`
and `AuthorizationExecuteWithPrivileges` are not options.

Done on macOS (design §14.2, "the macOS helper daemon"):
- `elevate.DaemonStatus` / `RegisterDaemon` / `UnregisterDaemon` /
  `OpenLoginItemsSettings` over `SMAppService`, with a strictly validated plist name
  and `SMAppServiceStatus` mapped to `DaemonState` (unknown values fail closed).
  `ErrNotImplemented` off darwin, in `CGO_ENABLED=0` builds, and below macOS 13.
- `elevate.DaemonPlist`: a deterministic LaunchDaemon plist from validated fields
  (`Label`, `BundleProgram` below `Contents/`, `ProgramArguments`,
  `AssociatedBundleIdentifiers`, `RunAtLoad`, `KeepAlive{SuccessfulExit:false}`),
  golden-tested; no environment, user, `Program` or extra keys can be expressed.
- `HelperOptions.PeerRequirement`: the peer's audit token (`LOCAL_PEERTOKEN`) judged
  with `SecCodeCopyGuestWithAttributes` + `SecCodeCheckValidity` against the
  requirement, in addition to the uid. Refused at start where it cannot be checked
  or does not compile. The decision (`admitPeer`) is pure Go and tested everywhere.
- Socket location guidance for the daemon (`/Library/Application Support/<label>/`;
  `/var/run` fails the unchanged ancestor rule), recorded by a darwin test.
- CI: the macOS job asserts cgo is on, runs the bridge's tests by name, and the
  `CGO_ENABLED=0` fail-closed tests.

Still open on macOS:
- The signed, notarized bundle that carries `Contents/Library/LaunchDaemons/<label>.plist`
  and the helper (IDN-26, IDN-27), and an end-to-end run of registration, approval
  and a real update through the daemon — which needs that bundle and a person to
  approve, so it cannot run unattended in CI.
- The host's approval UX: when to register, how to explain `DaemonRequiresApproval`,
  and what the updater does while approval is outstanding.
- Maintainer decisions: macOS 13 as the floor for system-wide installs; who signs the
  helper (same Team ID as the app is assumed by the example requirement); whether
  the shipped darwin commands, today `CGO_ENABLED=0` for reproducibility, need a cgo
  build to register the daemon or whether only the host application does.
- Unverified until the macOS runner reports: the positive real-peer test (the Go
  linker's ad-hoc signature passing `SecCodeCheckValidity`) and the socket-parent
  verdicts.
