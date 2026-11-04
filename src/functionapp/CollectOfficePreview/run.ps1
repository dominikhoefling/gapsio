param($Timer)
Import-Module Gapsio
if (-not (Test-GapsioModuleEnabled -Name 'officepreview')) { return }
Invoke-GapsioOfficePreviewCollection | Out-Null
