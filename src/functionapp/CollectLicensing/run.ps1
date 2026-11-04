param($Timer)
Import-Module Gapsio
# The "licensing" module (Defender for Endpoint licence indication) is optional – only run when enabled in WL_MODULES.
if (-not (Test-WlModuleEnabled -Name 'licensing')) { Write-Information 'Module licensing is not enabled – skipped.' -InformationAction Continue; return }
Invoke-WlLicensingCollection | Out-Null
