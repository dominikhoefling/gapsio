param($Timer)
Import-Module Gapsio
# Through Invoke-GapsioCollection like a manual run: it skips the module when it is not enabled in GAPSIO_MODULES and,
# after the endpoint run, does the daily update check and refreshes the assistant's knowledge index.
if (-not (Test-GapsioModuleEnabled -Name 'endpoint')) { Write-Information 'Module endpoint is not enabled – skipped.' -InformationAction Continue; return }
Invoke-GapsioCollection -Module 'endpoint' | Out-Null
