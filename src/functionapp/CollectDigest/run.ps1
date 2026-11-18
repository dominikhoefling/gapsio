param($Timer)
Import-Module Gapsio
# The change digest (message center posts about security products) is optional – only run when enabled in GAPSIO_MODULES.
if (-not (Test-GapsioModuleEnabled -Name 'digest')) { Write-Information 'Module digest is not enabled – skipped.' -InformationAction Continue; return }
Invoke-GapsioDigestCollection | Out-Null
