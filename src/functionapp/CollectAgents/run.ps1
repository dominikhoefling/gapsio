param($Timer)
Import-Module Gapsio
if (-not (Test-GapsioModuleEnabled -Name 'agents')) { Write-Information 'Module agents is not enabled – skipped.' -InformationAction Continue; return }
Invoke-GapsioAgentsCollection | Out-Null
