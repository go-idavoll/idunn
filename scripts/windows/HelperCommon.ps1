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
    Shared checks for the helper service scripts. Dot-sourced; defines functions only.

.DESCRIPTION
    Nothing here changes machine state. The rules mirror the Go side so the
    scripts refuse, before anything is registered, what the helper would refuse
    at start:

      * Assert-HelperLabel     -- elevate.CheckHelperLabel (docs/helper.md, section 2)
      * Assert-AdminOnlyPath   -- elevate.CheckPrivilegedRoot on Windows
                                  (core/elevate/rootcheck_windows.go)

    Windows PowerShell 5.1 compatible.
#>

Set-StrictMode -Version Latest

# Well-known principals an install path may belong to and grant change rights to.
# Same set as isAdminPrincipal in core/elevate/rootcheck_windows.go.
$script:AdminSids = @(
    'S-1-5-18',                                                     # SYSTEM
    'S-1-5-32-544',                                                 # BUILTIN\Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # NT SERVICE\TrustedInstaller
)
$script:OwnerRightsSid = 'S-1-3-4'                  # OWNER RIGHTS: grants to the owner, checked on its own.
$script:CreatorSids = @('S-1-3-0', 'S-1-3-1')       # CREATOR OWNER / CREATOR GROUP, inheritable only.

# Access mask bits, as in rootcheck_windows.go.
#   moveRights   -- delete, rename or re-permission the object, or delete its children.
#   changeRights -- additionally create in a directory or write a file.
$script:MoveRights = 0x00010000 -bor 0x00040000 -bor 0x00080000 -bor 0x00000040 -bor 0x10000000
$script:ChangeRights = $script:MoveRights -bor 0x00000002 -bor 0x00000004 -bor 0x40000000

function Assert-HelperLabel {
    <#
    .SYNOPSIS
        Throws unless Label is a valid helper label.
    .DESCRIPTION
        Reverse-DNS: at least two dot-separated components of [A-Za-z0-9-], none
        empty, none starting or ending with '-', at most 62 bytes in total. The
        label names the Windows service, the pipe \\.\pipe\<label> and the state
        directory, so it must never carry a path separator, a quote or a space.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Label)

    # -cmatch with \z: '$' in .NET also matches before a trailing newline.
    $component = '[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?'
    if ($Label.Length -gt 62 -or $Label -cnotmatch "^$component(?:\.$component)+\z") {
        throw "invalid helper label '$Label': expected reverse-DNS such as com.acme.app.helper (components of A-Z a-z 0-9 '-', not starting or ending with '-', at least two, at most 62 bytes)"
    }
}

function Assert-Administrator {
    <#
    .SYNOPSIS
        Throws unless this process runs with an elevated administrator token.
    #>
    [CmdletBinding()]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'this script must run elevated (Run as administrator); refusing to continue'
    }
}

function Get-ProgramFilesDirectory {
    <#
    .SYNOPSIS
        Returns the native %ProgramFiles% directory, without a trailing separator.
    .DESCRIPTION
        Refuses a 32-bit PowerShell on 64-bit Windows, where the folder would be
        "Program Files (x86)", and does not read $env:ProgramFiles, which the
        invoking environment can set to anything.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        throw 'run this script from 64-bit PowerShell; a 32-bit process sees Program Files (x86)'
    }
    $dir = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrEmpty($dir) -or -not [System.IO.Path]::IsPathRooted($dir)) {
        throw 'cannot determine the Program Files directory'
    }
    return $dir.TrimEnd('\')
}

function Test-PathUnder {
    <#
    .SYNOPSIS
        True if Path is strictly below Parent (both full, normalized paths).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Parent
    )
    $prefix = $Parent.TrimEnd('\') + '\'
    return $Path.Length -gt $prefix.Length -and
        $Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-AdminOnlyObject {
    <#
    .SYNOPSIS
        Throws unless one file or directory can be changed by administrators only.
    .PARAMETER Rights
        'Change' for the helper and the directories that hold it (nobody else may
        create, write, delete, rename or re-permission), 'Move' for directories
        further up (nobody else may delete, rename or re-permission; creating a
        sibling, as Authenticated Users may in C:\, is harmless).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][ValidateSet('Change', 'Move')][string]$Rights
    )

    $item = Get-Item -LiteralPath $LiteralPath -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "'$LiteralPath' is a junction, symbolic link or other reparse point"
    }

    # The raw descriptor rather than FileSystemAccessRule objects: those hide ACE
    # types they do not model, and an ACE this check cannot read must refuse.
    $acl = Get-Acl -LiteralPath $LiteralPath
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor(
        $acl.GetSecurityDescriptorBinaryForm(), 0)

    if ($null -eq $sd.Owner -or $script:AdminSids -notcontains $sd.Owner.Value) {
        # An owner may always rewrite the DACL, whatever it says today.
        throw "'$LiteralPath' is owned by $($sd.Owner); the owner must be SYSTEM, Administrators or TrustedInstaller"
    }
    if ($null -eq $sd.DiscretionaryAcl) {
        throw "'$LiteralPath' has a NULL DACL, which grants everyone everything"
    }

    $isContainer = $item.PSIsContainer
    foreach ($ace in $sd.DiscretionaryAcl) {
        if (-not ($ace -is [System.Security.AccessControl.CommonAce])) {
            throw "'$LiteralPath' holds an ACE of type $($ace.AceType) this check does not read"
        }
        if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessDenied) {
            continue
        }
        if ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) {
            throw "'$LiteralPath' holds an ACE with qualifier $($ace.AceQualifier) this check does not read"
        }
        $sid = $ace.SecurityIdentifier.Value
        if ($script:AdminSids -contains $sid -or $sid -eq $script:OwnerRightsSid) {
            continue
        }

        # AceFlags is a byte-based enum, which -band will not combine; compare as int.
        $flags = [int]$ace.AceFlags
        $inheritOnly = ($flags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0
        $inherits = ($flags -band ([int][System.Security.AccessControl.AceFlags]::ObjectInherit -bor
                [int][System.Security.AccessControl.AceFlags]::ContainerInherit)) -ne 0
        $creator = $script:CreatorSids -contains $sid
        # Int32 in .NET; every bit tested here is below the sign bit.
        $mask = $ace.AccessMask

        $bad = 0
        if (-not $inheritOnly -and -not $creator) {
            if ($Rights -eq 'Change') { $bad = $bad -bor ($mask -band $script:ChangeRights) }
            else { $bad = $bad -bor ($mask -band $script:MoveRights) }
        }
        # What a directory hands down to what is created in it later: a new
        # helper version, or a planted DLL next to the executable.
        if ($isContainer -and $inherits -and -not $creator -and $Rights -eq 'Change') {
            $bad = $bad -bor ($mask -band $script:ChangeRights)
        }
        if ($bad -ne 0) {
            $name = $sid
            try { $name = '{0} ({1})' -f $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value, $sid } catch { $name = $sid }
            throw ("'{0}' grants {1} access 0x{2:x8}; only SYSTEM, Administrators and TrustedInstaller may change it" -f $LiteralPath, $name, $bad)
        }
    }
}

function Assert-AdminOnlyPath {
    <#
    .SYNOPSIS
        Throws unless a file, every directory holding it below Boundary, and every
        directory above that can be changed by administrators only.
    .DESCRIPTION
        From the file up to and including Boundary (normally %ProgramFiles%) the
        change rule applies; from Boundary's parent to the drive root the move
        rule does. The path must be a full, normalized path strictly below
        Boundary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$Boundary
    )

    if (-not (Test-PathUnder -Path $LiteralPath -Parent $Boundary)) {
        throw "'$LiteralPath' is not below '$Boundary'"
    }
    $p = $LiteralPath
    $rule = 'Change'
    while ($true) {
        Assert-AdminOnlyObject -LiteralPath $p -Rights $rule
        if ($p.TrimEnd('\') -ieq $Boundary.TrimEnd('\')) { $rule = 'Move' }
        $parent = [System.IO.Path]::GetDirectoryName($p)
        if ([string]::IsNullOrEmpty($parent)) { break }
        $p = $parent
    }
}
