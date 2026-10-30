#Requires -Version 7.2
<#
.SYNOPSIS
    Removes Wardline: the resource group (including the managed identity and all data) and the portal app registration.

.DESCRIPTION
    Warning: this also deletes all snapshots. If immutability (WORM) is enabled and locked, Azure only allows deleting
    the storage account after the retention period.
    App registrations that were created up front by the identity team (-PortalAppId / -DataAppId) are NOT deleted;
    remove them in Entra ID if they are no longer needed.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][string]$ResourceGroup)
$ErrorActionPreference = 'Stop'

$fn = (& az functionapp list -g $ResourceGroup --query "[?tags.\"wardline-component\"=='functionapp'].name | [0]" -o tsv --only-show-errors)
if ($fn) {
    $name = "Wardline Portal ($fn)"
    $apps = & az ad app list --display-name $name --query '[].id' -o tsv --only-show-errors
    foreach ($id in @($apps | Where-Object { $_ })) {
        if ($PSCmdlet.ShouldProcess($name, 'Delete app registration')) { & az ad app delete --id $id --only-show-errors; Write-Host "App registration deleted: $name" }
    }
}
Write-Host 'Note: if the device inventory was used, run ./setup/Install-Wardline.ps1 -ResourceGroup <rg> -RemoveDeviceInventory first, or delete the script "Wardline – local Defender exclusions" in Intune › Devices › Scripts and remediations.'
if ($PSCmdlet.ShouldProcess($ResourceGroup, 'Delete the resource group with all Wardline data')) {
    & az group delete -n $ResourceGroup --yes --no-wait --only-show-errors
    Write-Host "Deletion of resource group $ResourceGroup started."
}
