param($Timer)
Import-Module Wardline
# The "access" module (PIM, roles, access packages) is optional – only run when enabled in WL_MODULES.
if (-not (Test-WlModuleEnabled -Name 'access')) { Write-Information 'Module access is not enabled – skipped.' -InformationAction Continue; return }
Invoke-WlAccessCollection | Out-Null
