#Requires -Version 7.2
<#
.SYNOPSIS
    Grants Wardline's read-only application permissions for the selected features – and nothing more.

.DESCRIPTION
    For the identity team when the Azure team installed Wardline with -SkipPermissionGrant.
    The target is the managed identity of the Wardline Function App (id-<prefix>-runner) or a data-access app registration.
    -Prune removes Wardline permissions that the selected features no longer need (least privilege when features are switched off).
    Requires: Azure CLI signed in ("az login") as Privileged Role Administrator or Global Administrator.

.EXAMPLE
    ./setup/Grant-WardlinePermissions.ps1 -PrincipalId <objectId of the managed identity> -Features Hunting,Indicators,Coverage,Response,Agents

.EXAMPLE
    ./setup/Grant-WardlinePermissions.ps1 -Features Hunting,Agents -ShowOnly
#>
[CmdletBinding()]
param(
    [string]$PrincipalId,
    [string[]]$Features = @('Hunting', 'Indicators', 'Coverage', 'Response', 'Agents'),
    [switch]$Prune,
    [switch]$ShowOnly
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'WardlineSetup.ps1')

$featureList = Resolve-WardlineFeatures -Features $Features
Write-Host "`nWardline features: $($featureList -join ', ')" -ForegroundColor Cyan
Show-WardlinePermissions -Features $featureList
if ($ShowOnly) { return }
if (-not $PrincipalId) { throw 'Parameter -PrincipalId (object ID of the service principal / managed identity) is required.' }

Write-Step "Granting the permissions to $PrincipalId"
$sp = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId`?`$select=id,displayName"
Write-Ok "Target: $($sp.displayName)"
$r = Grant-WardlinePermissions -PrincipalId $PrincipalId -Features $featureList -Prune:$Prune
Write-Host ''
Write-Ok "$($r.granted) granted, $($r.present) already present$(if ($Prune) { ", $($r.removed) removed" })"
if ($r.missing.Count) { Write-Note "Not available in this tenant: $($r.missing -join ', ')" }
Write-Note 'New permissions take effect with the next token of the managed identity (usually within an hour, at most 24 hours).'
