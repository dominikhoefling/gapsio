param($Timer)
Import-Module Gapsio
if (-not (Test-WlModuleEnabled -Name 'officepreview')) { return }
Invoke-WlOfficePreviewCollection | Out-Null
