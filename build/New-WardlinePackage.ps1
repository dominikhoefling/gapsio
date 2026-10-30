#Requires -Version 7.2
<#
.SYNOPSIS
    Creates the function package dist/wardline-functionapp.zip from src/functionapp.
    Install-Wardline.ps1 deploys this package; for the Deploy-to-Azure button it is published
    (e.g. as a GitHub release asset).
#>
[CmdletBinding()]
param([string]$OutFile)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$src = Join-Path $root 'src/functionapp'
if (-not $OutFile) { $OutFile = Join-Path $root 'dist/wardline-functionapp.zip' }
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile -Parent) | Out-Null
if (Test-Path $OutFile) { Remove-Item $OutFile -Force }

# Runtime files only – no tests, no local settings
$items = Get-ChildItem -Path $src -Force | Where-Object { $_.Name -notin 'local.settings.json', '.vscode', 'tests' }
Compress-Archive -Path $items.FullName -DestinationPath $OutFile -CompressionLevel Optimal
$size = [Math]::Round((Get-Item $OutFile).Length / 1KB, 1)
Write-Host "Package created: $OutFile ($size KB)"
$OutFile
