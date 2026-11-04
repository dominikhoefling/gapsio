#Requires -Version 7.2
<#
.SYNOPSIS
    Builds the release assets in dist/release – the same files the GitHub release workflow publishes.

.DESCRIPTION
    dist/release/
      gapsio.zip                 Installer bundle: setup/, deploy/, the function package, README, CHANGELOG, LICENSE
      gapsio-functionapp.zip     Function package only (used by Update-Gapsio.ps1 and the Deploy-to-Azure button)
      azuredeploy.json             ARM template (Deploy-to-Azure button, infrastructure change detection)
      permissions.json             Permission model of this release (Update-Gapsio.ps1 checks for new permissions)
      release.json                 Version metadata
      sbom.cdx.json                Software bill of materials (CycloneDX 1.5)
      SHA256SUMS                   Checksums of all assets (verified by Update-Gapsio.ps1)

    The asset names carry no version, so "releases/latest/download/gapsio.zip" always points to the newest release.

.EXAMPLE
    ./build/New-GapsioRelease.ps1
#>
[CmdletBinding()]
param([string]$OutDir)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $OutDir) { $OutDir = Join-Path $root 'dist/release' }
if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$version = (Import-PowerShellDataFile (Join-Path $root 'src/functionapp/Modules/Gapsio/Gapsio.psd1')).ModuleVersion
$pkg = & (Join-Path $PSScriptRoot 'New-GapsioPackage.ps1') -OutFile (Join-Path $OutDir 'gapsio-functionapp.zip') | Select-Object -Last 1

# Installer bundle (what a customer downloads and runs in Cloud Shell)
$stage = Join-Path ([IO.Path]::GetTempPath()) "gapsio-release-$([guid]::NewGuid().ToString('n'))"
$bundle = Join-Path $stage 'gapsio'
New-Item -ItemType Directory -Force -Path (Join-Path $bundle 'dist') | Out-Null
Copy-Item -Recurse -Path (Join-Path $root 'setup'), (Join-Path $root 'deploy') -Destination $bundle
Copy-Item -Path $pkg -Destination (Join-Path $bundle 'dist/gapsio-functionapp.zip')
foreach ($f in 'README.md', 'CHANGELOG.md', 'LICENSE', 'SECURITY.md', 'SUPPORT.md') { if (Test-Path (Join-Path $root $f)) { Copy-Item (Join-Path $root $f) $bundle } }
Compress-Archive -Path $bundle -DestinationPath (Join-Path $OutDir 'gapsio.zip') -CompressionLevel Optimal
Remove-Item $stage -Recurse -Force

Copy-Item (Join-Path $root 'deploy/azuredeploy.json') $OutDir
& (Join-Path $PSScriptRoot 'New-GapsioSbom.ps1') -PackagePath (Join-Path $OutDir 'gapsio-functionapp.zip') -OutFile (Join-Path $OutDir 'sbom.cdx.json') | Out-Null
Copy-Item (Join-Path $root 'setup/permissions.json') $OutDir
$templateHash = (Get-FileHash -Algorithm SHA256 (Join-Path $root 'deploy/azuredeploy.json')).Hash.ToLowerInvariant()
[ordered]@{ version = $version; templateSha256 = $templateHash; builtAt = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content -Path (Join-Path $OutDir 'release.json') -Encoding utf8

$sums = Get-ChildItem -Path $OutDir -File | Where-Object Name -ne 'SHA256SUMS' | Sort-Object Name | ForEach-Object { "$((Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant())  $($_.Name)" }
$sums | Set-Content -Path (Join-Path $OutDir 'SHA256SUMS') -Encoding ascii
Write-Host "Release $version built: $OutDir"
Get-ChildItem $OutDir | ForEach-Object { Write-Host ("  {0,-28} {1,8:N1} KB" -f $_.Name, ($_.Length / 1KB)) }
