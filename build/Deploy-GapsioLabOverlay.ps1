#Requires -Version 7.2
<#!
.SYNOPSIS
  Lab-only overlay deploy flow (kept local): deploys a branch/worktree package to an existing Function App
  without touching public/main.
.DESCRIPTION
  Default branch is private/office-preview. Use this after a normal public update to re-apply your private lab
  features (e.g. Office preview view/collector) to gapsio-cyberdom365.
.EXAMPLE
  ./build/Deploy-GapsioLabOverlay.ps1
.EXAMPLE
  ./build/Deploy-GapsioLabOverlay.ps1 -Branch private/office-preview -ResourceGroup rg-gapsio -FunctionApp gapsio-cyberdom365
#>
[CmdletBinding()]
param(
  [string]$Branch = 'private/office-preview',
  [string]$ResourceGroup = 'rg-gapsio',
  [string]$FunctionApp = 'gapsio-cyberdom365',
  [string]$WorktreePath = '/tmp/gapsio-lab-overlay',
  [switch]$KeepWorktree
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$src = Join-Path $WorktreePath 'src/functionapp'
$zip = Join-Path ([IO.Path]::GetTempPath()) "gapsio-lab-overlay-$([Guid]::NewGuid().ToString('n')).zip"

Write-Host "Preparing worktree from branch '$Branch'..."
if (Test-Path $WorktreePath) { git -C $root worktree remove $WorktreePath --force | Out-Null }
git -C $root worktree add $WorktreePath $Branch | Out-Null
if (-not (Test-Path $src)) { throw "Function app folder not found in $WorktreePath" }

Write-Host 'Packaging function app...'
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $src '*') -DestinationPath $zip -CompressionLevel Optimal

Write-Host "Deploying to $FunctionApp in $ResourceGroup..."
az functionapp deployment source config-zip -g $ResourceGroup -n $FunctionApp --src $zip --timeout 600 --output none | Out-Null
Start-Sleep -Seconds 15
$status = az rest -m get -u "https://$FunctionApp.scm.azurewebsites.net/api/deployments/latest" --resource https://management.azure.com/ --query '{status:status, complete:complete, end:end_time}' -o json | ConvertFrom-Json
Write-Host "Deployment status: $($status.status), complete=$($status.complete), end=$($status.end)"

if (-not $KeepWorktree) {
  git -C $root worktree remove $WorktreePath --force | Out-Null
}
if (Test-Path $zip) { Remove-Item $zip -Force }
Write-Host 'Done.'
