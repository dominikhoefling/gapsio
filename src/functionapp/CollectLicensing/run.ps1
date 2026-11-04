param($Timer)
Import-Module Gapsio
# The "licensing" module (Defender for Endpoint licence indication) is optional – only run when enabled in GAPSIO_MODULES.
if (-not (Test-GapsioModuleEnabled -Name 'licensing')) { Write-Information 'Module licensing is not enabled – skipped.' -InformationAction Continue; return }
Invoke-GapsioLicensingCollection | Out-Null
