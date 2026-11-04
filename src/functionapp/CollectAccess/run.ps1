param($Timer)
Import-Module Gapsio
# The "access" module (PIM, roles, access packages) is optional – only run when enabled in GAPSIO_MODULES.
if (-not (Test-GapsioModuleEnabled -Name 'access')) { Write-Information 'Module access is not enabled – skipped.' -InformationAction Continue; return }
Invoke-GapsioAccessCollection | Out-Null
