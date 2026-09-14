# PSScriptAnalyzer settings for scripts/windows (used by CI; see
# .github/workflows/helper-scripts.yml). All default rules run; this adds a
# syntax compatibility check, because the scripts must run on the Windows
# PowerShell 5.1 every Windows ships as well as on PowerShell 7.
@{
    Severity = @('Error', 'Warning')
    Rules    = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}
