param($Timer)
Import-Module Wardline
if (-not (Test-WlModuleEnabled -Name 'agents')) { Write-Information 'Module agents is not enabled – skipped.' -InformationAction Continue; return }
Invoke-WlAgentsCollection | Out-Null
