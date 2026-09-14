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
    Stop and delete an idunn helper service registered by install-service.ps1.

.DESCRIPTION
    Stops the service <label>, deletes it and waits until the Service Control
    Manager has removed it. The helper binary belongs to the product's
    installer and is not touched.

    The state directory %ProgramFiles%\<label>\ (callers.json: which accounts
    may ask the helper) is kept, so a reinstall or upgrade keeps its callers,
    unless -RemoveState is given. It is removed only if it is a real directory,
    not a junction or symbolic link.

.PARAMETER Label
    The helper label, which is the service name.

.PARAMETER RemoveState
    Also delete %ProgramFiles%\<label>\.

.EXAMPLE
    .\uninstall-service.ps1 -Label com.acme.app.helper

.EXAMPLE
    .\uninstall-service.ps1 -Label com.acme.app.helper -RemoveState
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Label,

    [switch]$RemoveState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'HelperCommon.ps1')

Assert-HelperLabel -Label $Label
Assert-Administrator
$programFiles = Get-ProgramFilesDirectory

$svc = Get-Service -Name $Label -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Write-Warning "no service named '$Label'"
}
elseif ($PSCmdlet.ShouldProcess($Label, 'Stop and delete the service')) {
    if ($svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -Name $Label -Force
        $svc.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(60))
    }
    & sc.exe delete $Label
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe delete $Label failed with exit code $LASTEXITCODE"
    }
    # Deletion is deferred while any handle to the service is open.
    for ($i = 0; $i -lt 60 -and (Get-Service -Name $Label -ErrorAction SilentlyContinue); $i++) {
        Start-Sleep -Milliseconds 500
    }
    if (Get-Service -Name $Label -ErrorAction SilentlyContinue) {
        throw "service '$Label' is marked for deletion but still present; close Services.msc or other tools holding it open"
    }
    Write-Output "service '$Label' removed"
}

$state = Join-Path $programFiles $Label
if ($RemoveState) {
    if (-not (Test-Path -LiteralPath $state)) {
        Write-Output "no state directory at $state"
    }
    else {
        $item = Get-Item -LiteralPath $state -Force
        if (-not $item.PSIsContainer) {
            throw "'$state' is not a directory; not removing it"
        }
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            # Recursing into a junction would delete whatever it points at.
            throw "'$state' is a junction or symbolic link; not removing it"
        }
        $links = @(Get-ChildItem -LiteralPath $state -Recurse -Force |
                Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint })
        if ($links.Count -gt 0) {
            throw "'$state' contains a junction or symbolic link ($($links[0].FullName)); not removing it"
        }
        if ($PSCmdlet.ShouldProcess($state, 'Remove the helper state directory')) {
            Remove-Item -LiteralPath $state -Recurse -Force
            Write-Output "removed $state"
        }
    }
}
elseif (Test-Path -LiteralPath $state) {
    Write-Output "kept the state directory $state (pass -RemoveState to delete it)"
}
