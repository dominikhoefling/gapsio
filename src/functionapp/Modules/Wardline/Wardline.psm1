#Requires -Version 7.2
# Wardline core module. Loads the parts (Core, Endpoint, Agents, Access).
$ErrorActionPreference = 'Stop'

foreach ($part in @('Core.ps1', 'License.ps1', 'Endpoint.ps1', 'Agents.ps1', 'Access.ps1')) {
    . (Join-Path $PSScriptRoot $part)
}

function Invoke-WlCollection {
    <#
    .SYNOPSIS
    Runs the data collection for a module ('endpoint', 'agents', 'access' or 'all').
    'all' covers the enabled modules only (app setting WL_MODULES).
    #>
    param([ValidateSet('endpoint', 'agents', 'access', 'all')][string]$Module = 'all')
    $enabled = Get-WlModules
    $todo = if ($Module -eq 'all') { $enabled } else { @($Module) }
    $results = @()
    foreach ($m in $todo) {
        if ($enabled -notcontains $m) { Write-Warning "Module '$m' is not enabled (WL_MODULES) – skipped."; continue }
        switch ($m) {
            'endpoint' { $results += Invoke-WlEndpointCollection }
            'agents' { $results += Invoke-WlAgentsCollection }
            'access' { $results += Invoke-WlAccessCollection }
        }
    }
    if ($todo -contains 'endpoint') { try { Update-WlReleaseInfo | Out-Null } catch { Write-Warning "Update check: $($_.Exception.Message)" } }
    $results
}
