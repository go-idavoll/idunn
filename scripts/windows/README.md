# Windows: sign and register the privileged helper as a service

These scripts take a helper built from `cmd/helper` (the contract is
[`docs/helper.md`](../../docs/helper.md)) and make it what Windows runs as SYSTEM:
an Authenticode-signed executable under `%ProgramFiles%`, registered as the service
`<label>`, listening on `\\.\pipe\<label>` (design §14.2, IDN-07).

They are Windows PowerShell 5.1 compatible (and run on PowerShell 7), use
`Set-StrictMode -Version Latest` and stop on the first error. Every script has
comment-based help (`Get-Help .\install-service.ps1 -Full`) and the state-changing
ones take `-WhatIf`.

Nothing here reads a key, a certificate file or a password from the tree or the
command line. The signing certificate is selected by thumbprint from the Windows
certificate store; its key stays there, on a token or in an HSM.

## The flow

```powershell
# 1. Build the helper with the publisher's compiled-in anchor (docs/helper.md §5).
Copy-Item ceremony\1.root.json    cmd\helper\anchor\root.json
Copy-Item release\repository.json cmd\helper\anchor\
Copy-Item release\helper.json     cmd\helper\anchor\     # label com.acme.app.helper
go build -trimpath -ldflags "-X main.version=1.3.0" -o dist\com.acme.app.helper.exe .\cmd\helper

# 2. Sign and timestamp it, then verify.
.\scripts\windows\sign.ps1 -Path dist\com.acme.app.helper.exe `
    -CertificateThumbprint 0123456789ABCDEF0123456789ABCDEF01234567 `
    -TimestampUrl http://timestamp.digicert.com

# 3. Package it into the product installer (an MSI, say), installing it to
#    %ProgramFiles%\Acme\com.acme.app.helper.exe. Verify the
#    packaged copy again if the packaging step touched it:
.\scripts\windows\sign.ps1 -Path staging\Acme\com.acme.app.helper.exe `
    -CertificateThumbprint 0123456789ABCDEF0123456789ABCDEF01234567 -VerifyOnly

# 4. On the target machine, elevated (an MSI deferred custom action runs as SYSTEM):
.\install-service.ps1 -HelperPath 'C:\Program Files\Acme\com.acme.app.helper.exe' `
    -Label com.acme.app.helper

# 5. Let an account ask, elevated, then restart so the pipe's DACL names it:
& 'C:\Program Files\Acme\com.acme.app.helper.exe' allow --sid S-1-5-21-...-1001
Restart-Service com.acme.app.helper

# Removal (the state directory is kept unless -RemoveState):
.\uninstall-service.ps1 -Label com.acme.app.helper
```

| Script | Does | Refuses |
|---|---|---|
| `sign.ps1 -Path F... -CertificateThumbprint T [-TimestampUrl U] [-SignToolPath S] [-MachineStore] [-VerifyOnly] [-NoTimestampForCI]` | `signtool sign /sha1 T /fd sha256 /tr U /td sha256 /v`, then `signtool verify /pa /v` and `Get-AuthenticodeSignature`: status `Valid`, signer thumbprint `T`, timestamped | no `-TimestampUrl` (a signature without a timestamp dies with the certificate); a non-http(s) URL; a certificate not in the store, without a private key or without the code-signing EKU; any verification failure. There is no parameter for a PFX or its password |
| `install-service.ps1 -HelperPath P -Label L [-Account LocalSystem]` | `P check --json` (schema 1, label must match); `New-Service` with image path `"P" serve`, automatic start, LocalSystem; `sc.exe failure`/`failureflag`; `sc.exe sdset` (below); start; waits for `\\.\pipe\L`; prints how to `allow` | not elevated; 32-bit PowerShell on 64-bit Windows; a label outside docs/helper.md §2 (reverse-DNS, `[A-Za-z0-9.-]`, ≤ 62 bytes); `P` not a local, normalized, long path strictly inside a product directory under `%ProgramFiles%`, or not named `L.exe`; `P`, a directory above it or `%ProgramFiles%` owned by anyone but SYSTEM, Administrators or TrustedInstaller, or granting anyone else write, create, delete, rename or re-permission rights (inheritable ACEs included), or a reparse point; above `%ProgramFiles%`, anyone else able to delete, rename or re-permission; an existing service `L`; a failing `check`. A failure after `New-Service` deletes the service again |
| `uninstall-service.ps1 -Label L [-RemoveState]` | stops and deletes service `L`, waits until the SCM has removed it; with `-RemoveState` deletes `%ProgramFiles%\L\` | not elevated; a state directory that is, or contains, a junction or symbolic link |

The ACL rules are those of `elevate.CheckPrivilegedRoot` on Windows
(`core/elevate/rootcheck_windows.go`), applied to the helper binary: it runs as
SYSTEM at every boot, so whoever can replace it, plant a DLL next to it, or rename a
directory above it owns the machine.

## Where things live

| | Path |
|---|---|
| helper | `%ProgramFiles%\<Product>\<label>.exe` |
| service | `<label>`, LocalSystem, automatic |
| endpoint | `\\.\pipe\<label>` |
| state dir | `%ProgramFiles%\<label>\` — `callers.json`, and `helper.log` while it runs as a service |

"%ProgramFiles%" is the Program Files known folder (`FOLDERID_ProgramFiles`), never
the environment variable, on both sides: the scripts ask .NET for the special
folder, the helper asks the shell (`elevate.DefaultHelperPaths`).

**Why not `%ProgramData%`.** `C:\ProgramData` grants `BUILTIN\Users` the right to
create files and folders, and passes that on through inheritable ACEs: any user can
create `C:\ProgramData\<label>` before the installer does, own it, and decide what
`callers.json` says — or make the directory's inherited ACL give themselves write
access to what the helper later creates there. `%ProgramFiles%` lets only
administrators create children. The helper refuses a state directory anyone else
could change (`helper check` reports it), so a ProgramData location would not start.

## How the application finds the helper

The application does not configure a pipe name. It derives it from the same label
the helper was built with:

```go
endpoint, err := elevate.DefaultHelperEndpoint("com.acme.app.helper") // \\.\pipe\com.acme.app.helper
```

and dials it with `elevate.NewService`. The pipe exists only while the service runs,
is created by the helper with `FILE_CREATE` (a squatter holding the name makes the
helper refuse to start rather than share clients), and its DACL grants SYSTEM and
Administrators full access and each allowed SID read/write only. Every connection is
then judged on the client's token (§14.2 "As built"). The allow-list is read at
start, so `allow`/`deny` take effect on `Restart-Service`.

## The service security descriptor

`install-service.ps1` replaces the service object's default security descriptor:

```text
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;AU)
S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```

| Trustee | Rights | Meaning |
|---|---|---|
| `SY` LocalSystem | `CC LC SW RP WP DT LO CR RC` | query config and status, enumerate dependents, start, stop, pause, interrogate, user-defined control, read the SD (Windows' default for SYSTEM) |
| `BA` Administrators | all, incl. `DC SD WD WO` | also change the configuration, delete, change the SD, take ownership |
| `AU` Authenticated Users | `CC LC SW LO RC` | see whether the helper is installed and running; nothing else |
| anyone else | — | anonymous and network logons get no access |
| SACL `WD` | audit failures | the Windows default: failed attempts by anyone are audited |

Compared with the Windows default, interactive (`IU`) and service (`SU`) logons lose
user-defined control (`CR`), which the helper does not handle; and the grant moves to
`AU`, so an application running as a service account can query status too. No
non-administrator can stop, pause, reconfigure (for example point the image path
elsewhere) or delete the service. The script reads the DACL back with
`sc.exe sdshow` and fails if it did not take.

Failure recovery: restart after 5 s, 30 s, then every 5 minutes, count reset after a
day; `failureflag 1` so an exit with an error code (the helper refusing its
configuration) counts as a failure too.

## Signing without a password on the command line

`sign.ps1` has no `-PfxPath` or `-Password`, deliberately:

- **Hardware token / HSM (EV and, since 2023, all OV code signing):** install the
  vendor's CSP/KSP; the certificate appears in `CurrentUser\My` (or `LocalMachine\My`,
  use `-MachineStore`) with its key on the device. Pass the thumbprint.
- **A PFX you must use:** `Import-PfxCertificate -FilePath cert.pfx -CertStoreLocation
  Cert:\CurrentUser\My -Password (Read-Host -AsSecureString) -Exportable:$false` once,
  then pass the thumbprint. Delete the PFX from the build machine.
- **Azure Trusted Signing, a cloud HSM, a signing service:** use that service's own
  tooling (e.g. signtool with its dlib, or its CLI). `sign.ps1 -VerifyOnly` still
  checks the result.

## CI mode

`-NoTimestampForCI` exists so CI can run the whole flow with a throwaway self-signed
certificate from the runner's `CurrentUser\My`. It is refused unless `CI` or
`GITHUB_ACTIONS` is `true`. It signs without a timestamp, and because a self-signed
root is trusted by nothing, `signtool verify /pa` fails for it by design; in this
mode that failure is tolerated only if `Get-AuthenticodeSignature` reports
`UnknownError` or `NotTrusted` (an untrusted root) **and** the signer is exactly the
given thumbprint. `HashMismatch`, `NotSigned` and every other status are still
refused; CI checks that with a tampered copy. Such a binary is never shippable.

`.github/workflows/helper-scripts.yml` runs PSScriptAnalyzer over these scripts,
signs a real `cmd/helper` build in CI mode, checks the refusals, and installs,
exercises and removes the service on the (elevated) runner.
