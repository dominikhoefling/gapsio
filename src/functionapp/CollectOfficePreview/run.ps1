param($Timer)
Import-Module Wardline
if (-not (Test-WlModuleEnabled -Name 'officepreview')) { return }
Invoke-WlOfficePreviewCollection | Out-Null
