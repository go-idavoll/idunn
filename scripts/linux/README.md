# Linux: install the privileged helper as a hardened systemd service

These scripts take a helper built from `cmd/helper` (the contract is
[`docs/helper.md`](../../docs/helper.md)) and run it as a systemd service owned by
root, listening on `/run/<label>/helper.sock` (design §14.2, "As built —
`ElevationService` on POSIX").

They need bash, coreutils and **systemd 247 or newer** (Debian 11, Ubuntu 22.04,
RHEL 9 and later): the unit's hardening uses keys an older systemd would skip with
a warning, and `install.sh` refuses rather than run the helper less confined than
the unit says. Every script takes `--help`.

## The flow

```sh
# 1. Build the helper with the publisher's compiled-in anchor (docs/helper.md §5).
cp ceremony/1.root.json    cmd/helper/anchor/root.json
cp release/repository.json cmd/helper/anchor/
cp release/helper.json     cmd/helper/anchor/      # label com.acme.app.helper,
                                                   # allowed_roots ["/opt/acme"]
go build -trimpath -ldflags "-X main.version=1.3.0" -o dist/com.acme.app.helper ./cmd/helper

# 2. Ship it with these scripts in the product's package (deb, rpm, tarball). There
#    is no Linux code-signing step the kernel checks; the package manager's own
#    signature covers the binary on its way to the machine.

# 3. On the target machine, as root, after the install root exists (root:root 0755):
install -d -o root -g root -m 0755 /opt/acme
/usr/share/acme/helper/install.sh --helper /usr/share/acme/helper/com.acme.app.helper \
  --label com.acme.app.helper --rw /opt/acme

# 4. Let a user ask, then restart so the helper reads the list:
/usr/libexec/com.acme.app.helper allow --uid "$(id -u alice)"
systemctl restart com.acme.app.helper.service

# Removal (the state directory is kept unless --remove-state):
/usr/share/acme/helper/uninstall.sh --label com.acme.app.helper
```

Run the scripts from a location only root can change (the package payload, not a
user's download directory): `install.sh` renders a unit that runs as root.

| Script | Does | Refuses |
|---|---|---|
| `install.sh --helper H --label L --rw R...` | copies `H` into `/usr/libexec` (root:root 0755) and runs that copy's `check --json`; moves it to `/usr/libexec/L`; renders `helper.service.in` to `/etc/systemd/system/L.service` (0644); `daemon-reload`; `/usr/libexec/L check --json`; `enable --now`; waits for the socket; prints how to `allow` | not root; neither `jq` nor `python3` (to read `check --json`); no systemd, or older than 247; a label outside docs/helper.md §2 (reverse-DNS, `[A-Za-z0-9.-]`, ≤ 62 bytes); `/usr/libexec` or a directory above it not owned by root, group-writable (other than group root) or other-writable, or a symlink; an `--rw` root that is not a clean absolute `[A-Za-z0-9._@+-]` path at least two deep, lies under `/proc /sys /dev /run /tmp /var/tmp /home /root /boot /etc /bin /sbin /lib*` or `/usr` (except `/usr/local/<product>`), does not exist, goes through a symlink, or fails the ownership rule along its path; `--rw` roots that are not exactly the helper's `allowed_roots`; a helper built for another label; a failing `check`; an existing unit or binary. A failure after the first change removes what was installed |
| `install.sh --render-unit --label L --rw R...` | prints the rendered unit; needs no root and changes nothing | the same label and path syntax rules |
| `uninstall.sh --label L [--remove-state]` | `disable --now`, removes the unit and `/usr/libexec/L`, `daemon-reload`; with `--remove-state` removes `/etc/L` | not root; a state directory that is a symlink or not a directory |

The ownership rule is `elevate.CheckPrivilegedRoot` on Linux: owned by root, writable
by nobody else (root's group excepted), and the sticky bit does not help. The helper
applies it again to its roots and state directory when it starts.

## Where things live

| | Path |
|---|---|
| helper | `/usr/libexec/<label>`, root:root 0755 |
| unit | `/etc/systemd/system/<label>.service` |
| endpoint | `/run/<label>/helper.sock` — `RuntimeDirectory=`, root:root 0755, removed on stop |
| state dir | `/etc/<label>/` — `callers.json`, created by `helper allow` |
| logs | the journal: `journalctl -u <label>.service` |

## How the application finds the helper

From the label alone, as the helper does:

```go
endpoint, err := elevate.DefaultHelperEndpoint("com.acme.app.helper") // /run/com.acme.app.helper/helper.sock
```

and `elevate.NewService` dials it. The socket is connectable by anyone; the helper
decides per connection on the peer's uid (`SO_PEERCRED`) against `callers.json`
(empty: root only), then rate-limits, parses, and checks the root against its
compiled-in `allowed_roots` before it does anything.

## The unit's hardening

`helper.service.in` explains each line; in short:

| Setting | Why it is safe for this helper |
|---|---|
| `User=root`, `Group=root`, `UMask=0022` | it replaces files under root-owned roots; nothing it creates is group- or world-writable |
| `RuntimeDirectory=<label>`, `RuntimeDirectoryMode=0755` | `/run/<label>` owned by root and writable by nobody else is exactly elevate's socket-directory rule; 0755 so callers reach the socket |
| `NoNewPrivileges=yes` | it executes nothing |
| `ProtectSystem=strict` + `ReadWritePaths=<roots>` | the whole file system is read-only to it except its runtime directory and its install roots (its TUF cache is inside each root). `/etc/<label>` stays read-only: `serve` only reads `callers.json` |
| `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes` | no user homes, no shared temp, no device nodes |
| `ProtectKernelTunables/Modules/Logs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible` | none of that state is its business |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | its socket, and HTTPS to the repository |
| `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality` | no namespaces, realtime scheduling, setuid/setgid files or personality changes |
| `MemoryDenyWriteExecute=yes` | Go is compiled ahead of time and never maps W+X memory |
| `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM` | the syscalls an ordinary service uses; anything else fails with EPERM instead of killing it |
| `CapabilityBoundingSet=CAP_DAC_OVERRIDE`, `AmbientCapabilities=` | root needs no capability to write root-owned 0755 trees; `CAP_DAC_OVERRIDE` is kept for packages that ship read-only (0444/0555) entries, which must still be replaced and collected. No `CAP_CHOWN`, `CAP_FOWNER`, `CAP_SETUID`, `CAP_SYS_ADMIN`, … |

`systemd-analyze security <label>.service` shows the resulting exposure.

## CI

`.github/workflows/helper-scripts.yml` runs shellcheck on these scripts,
`systemd-analyze verify` on a rendered unit (failing on any unknown key), and on an
ubuntu runner installs a real `cmd/helper` build with `--rw /usr/local/idunn-ci-root` (not `/opt`: GitHub's runners ship `/opt` as `0777`, which `install.sh` and the helper both refuse),
checks the service is active with its socket and `check` passes, allows a caller and
restarts, checks the refusals, and uninstalls. It does not perform an update through
the service: that needs a served repository and a client, and belongs to the e2e
suite.
