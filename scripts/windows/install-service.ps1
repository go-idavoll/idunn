# Copyright 2026 The idunn Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

<#
.SYNOPSIS
    Register a publisher-built idunn helper as a Windows service and start it.

.DESCRIPTION
    For an installer (MSI custom action, or an administrator by hand) after the
    signed helper has been copied to %ProgramFiles%\<Product>\<label>.exe. See
    docs/helper.md and scripts/windows/README.md.

    Refuses, before registering anything, unless:

      * the process is elevated, 64-bit PowerShell;
      * the label is a valid helper label and no service of that name exists;
      * the helper is a regular file named <label>.exe strictly below
        %ProgramFiles%, reached through no junction or symbolic link;
      * the helper, every directory holding it up to %ProgramFiles%, and
        %ProgramFiles% itself are owned by SYSTEM, Administrators or
        TrustedInstaller and grant nobody else the right to write, create,
        delete, rename or re-permission them, including through inheritable
        ACEs; above %ProgramFiles% nobody else may delete, rename or
        re-permission. The service runs this file as LocalSystem at every boot,
        so whoever could replace it would own the machine;
      * "<helper> check" exits 0.

    Then it creates the service (LocalSystem, automatic start, image path
    "<helper>" serve), sets restart-on-failure, replaces the service's security
    descriptor with a restrictive one, and starts it. If any of those steps
    fails the service is stopped and deleted again, so nothing half-registered
    is left behind.

    The service security descriptor set with "sc.exe sdset":

      D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)
        (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
        (A;;CCLCSWLORC;;;AU)
      S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)

      SY  LocalSystem: query config/status, enumerate dependents, start, stop,
          pause/continue, interrogate, user-defined control, read the SD
          (the Windows default for SYSTEM).
      BA  Administrators: everything, including change config (DC), delete
          (SD), change the SD (WD) and take ownership (WO).
      AU  Authenticated Users: query config (CC) and status (LC), enumerate
          dependents (SW), interrogate (LO), read the SD (RC). So an
          application can see whether its helper is installed and running.
          No start (RP), stop (WP), pause (DT), user-defined control (CR),
          change config (DC), delete (SD), WRITE_DAC (WD) or WRITE_OWNER (WO).
          Windows' default additionally grants interactive and service logons
          user-defined control (CR); this one does not.
      No ACE for anyone else: anonymous and network logons get nothing.
      S:  the default audit ACE: failed access attempts by anyone are audited.

    The helper decides who may *ask it* per connection from callers.json; the
    service SD only decides who may stop or reconfigure it.

.PARAMETER HelperPath
    Full path of the signed helper, %ProgramFiles%\<Product>\<label>.exe.

.PARAMETER Label
    The helper label compiled into the helper (helper.json). Names the service,
    the pipe \\.\pipe\<label> and the state directory %ProgramFiles%\<label>\.

.PARAMETER Account
    The service account. Only LocalSystem: the helper must be able to write
    install roots only SYSTEM and administrators can write.

.EXAMPLE
    .\install-service.ps1 -HelperPath 'C:\Program Files\Acme\com.acme.app.helper.exe' -Label com.acme.app.helper
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$HelperPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Label,

    [ValidateSet('LocalSystem')]
    [string]$Account = 'LocalSystem'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'HelperCommon.ps1')

# See .DESCRIPTION for what each ACE grants.
$ServiceSddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;AU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'

function Write-Step {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)
    Write-Information "==> $Message" -InformationAction Continue
}

function Invoke-Native {
    <#
    .SYNOPSIS
        Runs a native command and throws on a non-zero exit code.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @()
    )
    # stderr merged as plain text under a local 'Continue': Windows PowerShell 5.1
    # would otherwise turn each stderr line into an error record and throw before
    # the exit code decides.
    $ErrorActionPreference = 'Continue'
    & $FilePath @ArgumentList 2>&1 | ForEach-Object { Write-Information "$_" -InformationAction Continue }
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -ne 0) {
        throw "'$FilePath $($ArgumentList -join ' ')' failed with exit code $code"
    }
}

function Get-DaclSummary {
    <#
    .SYNOPSIS
        A DACL as "type sid mask flags" entries in order, for comparing two
        descriptors independent of how their SDDL is spelled.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Sddl)
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    if ($null -eq $sd.DiscretionaryAcl) { return '<NULL DACL>' }
    $entries = foreach ($ace in $sd.DiscretionaryAcl) {
        if (-not ($ace -is [System.Security.AccessControl.CommonAce])) { "$($ace.AceType)"; continue }
        '{0} {1} 0x{2:x} {3}' -f $ace.AceQualifier, $ace.SecurityIdentifier.Value, $ace.AccessMask, [int]$ace.AceFlags
    }
    return ($entries -join '; ')
}

function Get-ServiceDacl {
    <#
    .SYNOPSIS
        The DACL of a service as Windows stores it, summarized by Get-DaclSummary.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Name)
    $shown = (& sc.exe sdshow $Name | Where-Object { $_.Trim() }) -join ''
    if ($LASTEXITCODE -ne 0) { throw "sc.exe sdshow $Name failed with exit code $LASTEXITCODE" }
    return Get-DaclSummary -Sddl $shown.Trim()
}

# --- checks: nothing below changes machine state until "register" -------------

Assert-HelperLabel -Label $Label
Assert-Administrator
$programFiles = Get-ProgramFilesDirectory

if ($HelperPath -match '^\\\\|^//') {
    throw "'$HelperPath' is a UNC or device path; the helper must be on a local disk below $programFiles"
}
if (-not [System.IO.Path]::IsPathRooted($HelperPath) -or $HelperPath -notmatch '^[A-Za-z]:\\') {
    throw "'$HelperPath' is not a full path (expected $programFiles\<Product>\$Label.exe)"
}
$helper = [System.IO.Path]::GetFullPath($HelperPath)
if ($helper -ne $HelperPath.TrimEnd()) {
    # "..", "." or doubled separators: say the path the way it will be registered.
    throw "'$HelperPath' is not in normalized form; pass '$helper'"
}
if ($helper.IndexOf('"') -ge 0) {
    throw "'$helper' contains a quote"
}
if (-not (Test-PathUnder -Path $helper -Parent $programFiles)) {
    throw "'$helper' is not below $programFiles; only a location administrators alone can write is acceptable for a LocalSystem service"
}
if ([System.IO.Path]::GetFileName($helper) -cne "$Label.exe") {
    throw "the helper must be named '$Label.exe' (docs/helper.md, section 3), not '$([System.IO.Path]::GetFileName($helper))'"
}
if ([System.IO.Path]::GetDirectoryName($helper) -ieq $programFiles) {
    throw "the helper must be in a product directory below $programFiles, not directly in it"
}
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
    throw "'$helper' does not exist or is not a file"
}
if ($helper.IndexOf('~') -ge 0) {
    # Most likely a short (8.3) name, which would slip past the prefix check above
    # and be registered as typed. Pass the long path.
    throw "'$helper' contains '~'; pass the long path name, not an 8.3 short name"
}

Write-Step "checking who can change $helper"
Assert-AdminOnlyPath -LiteralPath $helper -Boundary $programFiles

if (Get-Service -Name $Label -ErrorAction SilentlyContinue) {
    throw "a service named '$Label' already exists; run uninstall-service.ps1 -Label $Label first"
}

Write-Step "$helper check --json"
$ErrorActionPreference = 'Continue'
$checkJson = (& $helper check --json 2>$null | Out-String)
$checkExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
Write-Information $checkJson -InformationAction Continue
try {
    $check = $checkJson | ConvertFrom-Json
} catch {
    throw "'$helper check --json' did not print a report (exit code $checkExit); nothing was registered"
}
if ($check.schema -ne 1) {
    throw "'$helper check --json' reports schema $($check.schema); this script understands schema 1"
}
if ($checkExit -ne 0 -or -not $check.ok) {
    $why = @($check.error) + @($check.roots | Where-Object { -not $_.ok } | ForEach-Object { "$($_.path): $($_.error)" })
    if ($check.state -and -not $check.state.ok) { $why += "state dir: $($check.state.error)" }
    if ($check.callers -and $check.callers.error) { $why += "callers: $($check.callers.error)" }
    throw "'$helper check' refused (exit code $checkExit): $((@($why) | Where-Object { $_ }) -join '; '); nothing was registered"
}

# The helper derives its service name, pipe and state directory from the label it
# was built with; a service registered under another name would never start
# (the SCM dispatcher names the service) and the application would not find it.
$builtLabel = [string]$check.label
if ($builtLabel -cne $Label) {
    throw "the helper was built for label '$builtLabel', not '$Label'"
}
$builtState = [string]$check.state_dir
if ($builtState -ne (Join-Path $programFiles $Label)) {
    throw "the helper's state directory is '$builtState', expected '$(Join-Path $programFiles $Label)'"
}
$builtEndpoint = [string]$check.endpoint
if ($builtEndpoint -cne "\\.\pipe\$Label") {
    throw "the helper's endpoint is '$builtEndpoint', expected '\\.\pipe\$Label'"
}

# --- register -------------------------------------------------------------------

if (-not $PSCmdlet.ShouldProcess($Label, "Create and start the LocalSystem service running `"$helper`" serve")) {
    return
}

$created = $false
try {
    Write-Step "creating service $Label"
    # No -Credential: LocalSystem. The image path is quoted so a space in
    # "Program Files" cannot be read as the end of the executable's name.
    New-Service -Name $Label `
        -BinaryPathName ('"{0}" serve' -f $helper) `
        -DisplayName $Label `
        -Description "idunn privileged update helper ($Label)" `
        -StartupType Automatic | Out-Null
    $created = $true

    Write-Step 'setting failure recovery'
    # Restart after 5 s, 30 s, then every 5 min; the failure count resets after a day.
    Invoke-Native -FilePath sc.exe -ArgumentList @('failure', $Label, 'reset=', '86400', 'actions=', 'restart/5000/restart/30000/restart/300000')
    # Also count a stop with a non-zero exit code as a failure, not only a crash.
    Invoke-Native -FilePath sc.exe -ArgumentList @('failureflag', $Label, '1')

    Write-Step 'restricting the service security descriptor'
    Invoke-Native -FilePath sc.exe -ArgumentList @('sdset', $Label, $ServiceSddl)
    $want = Get-DaclSummary -Sddl $ServiceSddl
    $have = Get-ServiceDacl -Name $Label
    if ($have -ne $want) {
        throw "the service DACL did not take: have $have, want $want"
    }

    Write-Step "starting $Label"
    Start-Service -Name $Label
    $svc = Get-Service -Name $Label
    $svc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))

    # The service is only useful once its pipe exists. Listed rather than opened
    # where possible: opening it would be a connection the helper has to refuse.
    $pipe = $false
    for ($i = 0; $i -lt 20 -and -not $pipe; $i++) {
        try {
            $pipe = @([System.IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -ieq "\\.\pipe\$Label" }).Count -gt 0
        }
        catch {
            # .NET Framework refuses to list when some other pipe's name holds a
            # character it considers illegal in a path.
            $pipe = Test-Path -LiteralPath "\\.\pipe\$Label"
        }
        if (-not $pipe) { Start-Sleep -Milliseconds 500 }
    }
    if (-not $pipe) {
        throw "the service is running but \\.\pipe\$Label did not appear within 10 s; see the Application and System event logs"
    }
    if ((Get-Service -Name $Label).Status -ne 'Running') {
        throw "the service stopped after start; see the Application and System event logs"
    }
}
catch {
    if ($created) {
        Write-Warning "installation failed, removing the service again: $_"
        Stop-Service -Name $Label -Force -ErrorAction SilentlyContinue
        & sc.exe delete $Label | Out-Null
    }
    throw
}

$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Write-Output ''
Write-Output "Service '$Label' is running as $Account and listening on \\.\pipe\$Label."
Write-Output ''
Write-Output 'Nobody may ask it for an update yet (an empty allow-list means SYSTEM only).'
Write-Output 'To allow an account, run elevated, with that account''s SID, then restart the'
Write-Output 'service so the pipe''s DACL names it:'
Write-Output ''
Write-Output "    & '$helper' allow --sid $me"
Write-Output "    Restart-Service -Name $Label"
Write-Output ''
Write-Output "($me is the account running this script. Another account's SID:"
Write-Output "    (New-Object System.Security.Principal.NTAccount('DOMAIN\user')).Translate([System.Security.Principal.SecurityIdentifier]).Value )"

# Every failure above throws. The exit code of the last native command (signtool,
# sc.exe, the helper) must not become this script's: callers read $LASTEXITCODE.
exit 0
