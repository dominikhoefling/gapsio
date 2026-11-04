param($Timer)
Import-Module Gapsio
if (-not (Test-GapsioModuleEnabled -Name 'purviewpreview')) { return }
Invoke-GapsioPurviewPreviewCollection | Out-Null
