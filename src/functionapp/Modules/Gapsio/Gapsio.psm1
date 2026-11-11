#Requires -Version 7.2
# Gapsio core module. Loads the parts (Core, Endpoint, Posture, Agents, Access, Licensing, previews, Assistant).
$ErrorActionPreference = 'Stop'

foreach ($part in @('Core.ps1', 'License.ps1', 'Endpoint.ps1', 'Posture.ps1', 'Agents.ps1', 'Access.ps1', 'Licensing.ps1', 'OfficeAntiPhish.ps1', 'OfficePolicy.ps1', 'OfficePreview.ps1', 'PurviewPreview.ps1', 'Assistant.ps1')) {
    . (Join-Path $PSScriptRoot $part)
}

function Invoke-GapsioCollection {
    <#
    .SYNOPSIS
    Runs the data collection for a module ('endpoint', 'agents', 'access', 'licensing', 'officepreview' or 'all').
    'all' covers the enabled modules only (app setting GAPSIO_MODULES).
    #>
    param([ValidateSet('endpoint', 'agents', 'access', 'licensing', 'officepreview', 'purviewpreview', 'all')][string]$Module = 'all')
    $enabled = Get-GapsioModules
    $todo = if ($Module -eq 'all') { $enabled } else { @($Module) }
    $results = @()
    foreach ($m in $todo) {
        if ($enabled -notcontains $m) { Write-Warning "Module '$m' is not enabled (GAPSIO_MODULES) – skipped."; continue }
        switch ($m) {
            'endpoint' { $results += Invoke-GapsioEndpointCollection }
            'agents' { $results += Invoke-GapsioAgentsCollection }
            'access' { $results += Invoke-GapsioAccessCollection }
            'licensing' { $results += Invoke-GapsioLicensingCollection }
            'officepreview' { $results += Invoke-GapsioOfficePreviewCollection }
            'purviewpreview' { $results += Invoke-GapsioPurviewPreviewCollection }
        }
    }
    if ($todo -contains 'endpoint') { try { Update-GapsioReleaseInfo | Out-Null } catch { Write-Warning "Update check: $($_.Exception.Message)" } }
    # Build the assistant's knowledge index with the run, so the first question does not have to wait for it
    if ($todo -contains 'endpoint' -and (Test-GapsioAssistant)) { try { Update-GapsioAssistantIndex | Out-Null } catch { Write-Warning "Assistant knowledge index: $($_.Exception.Message)" } }
    $results
}
