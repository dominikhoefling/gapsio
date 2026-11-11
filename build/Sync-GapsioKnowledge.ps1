<#
.SYNOPSIS
    Copies the documentation pages the portal assistant may cite into the Function App package source.

.DESCRIPTION
    The assistant searches src/functionapp/config/knowledge/*.md (shipped with the Function App). These files are
    copies of pages under docs/. Run this script after changing one of the pages; a test fails when a copy differs.

    -Check only reports differences (exit code 1 when there are any).
#>
[CmdletBinding()]
param([switch]$Check)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$target = Join-Path $root 'src/functionapp/config/knowledge'
# knowledge file name -> page under docs/
$pages = [ordered]@{
    'access.md'               = 'modules/access.md'
    'agents.md'               = 'modules/agents.md'
    'baseline.md'             = 'baseline.md'
    'compliance.md'           = 'compliance.md'
    'endpoint.md'             = 'modules/endpoint.md'
    'getting-started.md'      = 'getting-started.md'
    'installation.md'         = 'installation.md'
    'licence.md'              = 'licensing.md'
    'licensing.md'            = 'modules/licensing.md'
    'limitations.md'          = 'limitations.md'
    'office-preview.md'       = 'modules/office-preview.md'
    'operations.md'           = 'operations.md'
    'permissions.md'          = 'permissions.md'
    'portal.md'               = 'portal.md'
    'purview-preview.md'      = 'modules/purview-preview.md'
    'security.md'             = 'security.md'
    'separation-of-duties.md' = 'separation-of-duties.md'
    'updates.md'              = 'updates.md'
}
$different = @()
foreach ($name in $pages.Keys) {
    $source = Join-Path $root "docs/$($pages[$name])"
    $copy = Join-Path $target $name
    if (-not (Test-Path $source)) { throw "Missing page: docs/$($pages[$name])" }
    $same = (Test-Path $copy) -and ((Get-FileHash $source).Hash -eq (Get-FileHash $copy).Hash)
    if ($same) { continue }
    $different += $name
    if (-not $Check) { Copy-Item -Path $source -Destination $copy -Force }
}
$extra = @(Get-ChildItem -Path $target -Filter '*.md' -File | Where-Object { $_.Name -notin $pages.Keys } | ForEach-Object { $_.Name })
if (-not $Check) { foreach ($name in $extra) { Remove-Item -Path (Join-Path $target $name) -Force } }
if ($Check) {
    if ($different.Count -or $extra.Count) { Write-Host "Knowledge copies out of date: $(($different + $extra) -join ', '). Run ./build/Sync-GapsioKnowledge.ps1"; exit 1 }
    Write-Host "Knowledge copies are up to date ($($pages.Count) pages)."
}
else { Write-Host "Knowledge: $($pages.Count) pages, $($different.Count) updated, $($extra.Count) removed." }
