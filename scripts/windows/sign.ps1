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
    Authenticode-sign the helper (or any PE file) with a certificate from the
    Windows certificate store, timestamp it, and verify the result.

.DESCRIPTION
    Runs, for each file:

        signtool sign   /sha1 <thumbprint> /fd sha256 /tr <timestamp url> /td sha256 /v <file>
        signtool verify /pa /v <file>

    and then checks with Get-AuthenticodeSignature that the file is signed by
    exactly the certificate named by -CertificateThumbprint.

    The certificate is selected by thumbprint from the store; its private key
    never passes through this script. There is deliberately no parameter for a
    PFX file or its password: a password on a command line lands in process
    listings, shell history and CI logs. Instead:

      * a certificate on a hardware token or HSM: import the certificate into
        CurrentUser\My (or LocalMachine\My with -MachineStore) through the
        vendor's CSP/KSP and pass its thumbprint; the key stays on the device.
      * a PFX you must use: import it once with Import-PfxCertificate, which
        prompts for the password as a SecureString, preferably with
        -Exportable:$false, and pass the thumbprint.
      * Azure Trusted Signing, a cloud HSM or a signing service: use that
        service's own tool or signtool dlib integration; this script is not
        a wrapper for them. -VerifyOnly still checks what they produced.

    Signing answers "will Windows run this and show the publisher", never
    "may the updater trust this": trust comes from TUF (AGENTS.md section 1.2).

    Without a timestamp a signature stops validating when the certificate
    expires, so a timestamp URL is required. -NoTimestampForCI drops that
    requirement and relaxes verification for a self-signed CI certificate; see
    that parameter. It is for CI only and refuses to run outside it.

.PARAMETER Path
    One or more files to sign. Taken literally (no wildcards).

.PARAMETER CertificateThumbprint
    SHA-1 thumbprint (40 hex digits) of a code-signing certificate with a
    private key in CurrentUser\My, or LocalMachine\My with -MachineStore.

.PARAMETER TimestampUrl
    RFC 3161 timestamp server, for example http://timestamp.digicert.com or
    your CA's. Required unless -NoTimestampForCI.

.PARAMETER SignToolPath
    signtool.exe to use. Default: the newest x64 signtool under
    "Windows Kits\10\bin".

.PARAMETER MachineStore
    Look the certificate up in LocalMachine\My instead of CurrentUser\My.

.PARAMETER VerifyOnly
    Do not sign; only verify, with the same rules, that each file carries a
    valid signature by the given certificate (for example after packaging).

.PARAMETER NoTimestampForCI
    CI only (refused unless the CI or GITHUB_ACTIONS environment variable is
    'true'). Signs without a timestamp, and accepts a signature whose chain ends
    in an untrusted root: a throwaway self-signed certificate in the runner's
    CurrentUser store cannot chain to a trusted root, so "signtool verify /pa"
    fails for it by design. In this mode the file must still carry a signature
    by exactly the given certificate whose hash matches the file; the only
    statuses accepted besides Valid are UnknownError and NotTrusted (the
    untrusted-root results). HashMismatch, NotSigned, NotSupportedFileFormat
    and every other status are refused as always. Never use it for a release.

.EXAMPLE
    .\sign.ps1 -Path dist\com.acme.app.helper.exe -CertificateThumbprint 0123456789ABCDEF0123456789ABCDEF01234567 -TimestampUrl http://timestamp.digicert.com

.EXAMPLE
    .\sign.ps1 -Path dist\com.acme.app.helper.exe -CertificateThumbprint $thumb -VerifyOnly
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Sign')]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'Sign')]
    [string]$TimestampUrl,

    [string]$SignToolPath,

    [switch]$MachineStore,

    [Parameter(Mandatory, ParameterSetName = 'Verify')]
    [switch]$VerifyOnly,

    [switch]$NoTimestampForCI
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-SignTool {
    <#
    .SYNOPSIS
        Runs signtool, shows its output, returns its exit code.
    .DESCRIPTION
        stderr is merged and turned into plain text under a local 'Continue'
        preference: otherwise Windows PowerShell 5.1 turns each stderr line into
        an error record, which under 'Stop' throws before the exit code is read,
        and whether it does depends on how the caller redirected this script.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][string]$SignTool,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )
    $ErrorActionPreference = 'Continue'
    & $SignTool @ArgumentList 2>&1 | ForEach-Object { Write-Information "$_" -InformationAction Continue }
    return $LASTEXITCODE
}

function Find-SignTool {
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Explicit)

    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit -PathType Leaf)) {
            throw "signtool not found at '$Explicit'"
        }
        return (Resolve-Path -LiteralPath $Explicit).ProviderPath
    }
    $kits = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)) 'Windows Kits\10\bin'
    if (-not (Test-Path -LiteralPath $kits -PathType Container)) {
        throw "no Windows SDK at '$kits'; install the Windows SDK signing tools or pass -SignToolPath"
    }
    $candidates = @(Get-ChildItem -LiteralPath $kits -Directory |
            Where-Object { $_.Name -match '^\d+(\.\d+){3}$' } |
            Sort-Object -Descending { [version]$_.Name } |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($candidates.Count -eq 0) {
        throw "no x64 signtool.exe under '$kits'; install the Windows SDK signing tools or pass -SignToolPath"
    }
    return $candidates[0]
}

function Test-FileSignature {
    <#
    .SYNOPSIS
        Throws unless File is validly signed by Thumbprint (relaxed chain rules in CI mode).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$SignTool,
        [switch]$CiMode
    )

    $verifyExit = Invoke-SignTool -SignTool $SignTool -ArgumentList @('verify', '/pa', '/v', $File)

    $sig = Get-AuthenticodeSignature -LiteralPath $File
    if ($null -eq $sig.SignerCertificate) {
        throw "'$File' carries no signature (status $($sig.Status))"
    }
    if ($sig.SignerCertificate.Thumbprint -ne $Thumbprint) {
        throw "'$File' is signed by $($sig.SignerCertificate.Thumbprint), not by $Thumbprint"
    }

    if (-not $CiMode) {
        if ($verifyExit -ne 0 -or $sig.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "'$File' did not verify: signtool verify exit code $verifyExit, Authenticode status $($sig.Status): $($sig.StatusMessage)"
        }
        if ($null -eq $sig.TimeStamperCertificate) {
            throw "'$File' is signed but not timestamped; it would stop validating when the certificate expires"
        }
        return
    }
    if ($verifyExit -eq 0 -and $sig.Status -eq [System.Management.Automation.SignatureStatus]::Valid) {
        return
    }
    # CI mode: the certificate is a throwaway self-signed one no trust store knows.
    # Accept only the statuses that mean "chain ends in an untrusted root".
    $untrustedRoot = @(
        [System.Management.Automation.SignatureStatus]::UnknownError,
        [System.Management.Automation.SignatureStatus]::NotTrusted
    )
    if ($untrustedRoot -notcontains $sig.Status) {
        throw "'$File' did not verify: Authenticode status $($sig.Status): $($sig.StatusMessage)"
    }
    Write-Warning ("'{0}': signature by {1} accepted with status {2} ({3}) because -NoTimestampForCI is set; this would be refused outside CI" -f
        $File, $Thumbprint, $sig.Status, $sig.StatusMessage)
}

$thumb = $CertificateThumbprint.ToUpperInvariant()

if ($NoTimestampForCI) {
    if ($env:CI -ne 'true' -and $env:GITHUB_ACTIONS -ne 'true') {
        throw '-NoTimestampForCI is only accepted in CI (CI or GITHUB_ACTIONS set to true)'
    }
    if ($TimestampUrl) {
        throw '-TimestampUrl and -NoTimestampForCI contradict each other'
    }
}
elseif (-not $VerifyOnly) {
    if (-not $TimestampUrl) {
        throw '-TimestampUrl is required: without an RFC 3161 timestamp the signature stops validating when the certificate expires'
    }
    $uri = $null
    if (-not [System.Uri]::TryCreate($TimestampUrl, [System.UriKind]::Absolute, [ref]$uri) -or
        ($uri.Scheme -ne 'http' -and $uri.Scheme -ne 'https') -or $TimestampUrl -match '\s') {
        throw "-TimestampUrl '$TimestampUrl' is not an absolute http or https URL"
    }
}

$files = foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        throw "'$p' does not exist or is not a file"
    }
    (Resolve-Path -LiteralPath $p).ProviderPath
}

$signtool = Find-SignTool -Explicit $SignToolPath
Write-Verbose "signtool: $signtool"

if (-not $VerifyOnly) {
    $store = if ($MachineStore) { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }
    $cert = Get-ChildItem -LiteralPath $store | Where-Object { $_.Thumbprint -eq $thumb }
    if ($null -eq $cert) {
        throw "no certificate with thumbprint $thumb in $store"
    }
    if (-not $cert.HasPrivateKey) {
        throw "the certificate $thumb in $store has no private key available to this user"
    }
    $codeSigning = '1.3.6.1.5.5.7.3.3'
    $ekus = @($cert.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId })
    if ($ekus -notcontains $codeSigning) {
        throw "the certificate $thumb is not valid for code signing (no EKU $codeSigning)"
    }
}

foreach ($file in $files) {
    if (-not $VerifyOnly -and $PSCmdlet.ShouldProcess($file, "Authenticode-sign with $thumb")) {
        $signArgs = @('sign', '/sha1', $thumb, '/fd', 'sha256')
        if ($MachineStore) { $signArgs += '/sm' }
        if (-not $NoTimestampForCI) { $signArgs += @('/tr', $TimestampUrl, '/td', 'sha256') }
        $signArgs += @('/v', $file)
        $signExit = Invoke-SignTool -SignTool $signtool -ArgumentList $signArgs
        if ($signExit -ne 0) {
            throw "signtool sign failed for '$file' (exit code $signExit)"
        }
    }
    if ($VerifyOnly -or -not $WhatIfPreference) {
        Test-FileSignature -File $file -Thumbprint $thumb -SignTool $signtool -CiMode:$NoTimestampForCI
        Write-Output "verified: $file (signer $thumb)"
    }
}
