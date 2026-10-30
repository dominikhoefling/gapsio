#Requires -Version 7.2
<#
.SYNOPSIS
    Creates dist/demo: the portal offline with fictitious data from the tests (open index.html in a browser).
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$tmp = Join-Path ([IO.Path]::GetTempPath()) "wardline-demo-$([guid]::NewGuid().ToString('n'))"
& (Join-Path $root 'tests/Test-Wardline.ps1') -OutDir $tmp | Out-Null
$demo = Join-Path $root 'dist/demo'
New-Item -ItemType Directory -Force -Path $demo | Out-Null
Copy-Item -Path (Join-Path $root 'src/functionapp/www/*') -Destination $demo -Recurse -Force
$read = { param($n) $p = Join-Path $tmp $n; if (Test-Path $p) { Get-Content -Raw $p | ConvertFrom-Json -Depth 64 } else { $null } }
$data = [ordered]@{
    me       = [ordered]@{ oid = 'u-alice'; upn = 'alice@contoso.com'; displayName = 'Alice (Demo)'; isAdmin = $true; tenantId = 'contoso.onmicrosoft.com'; modules = @('endpoint', 'agents'); version = (Import-PowerShellDataFile (Join-Path $root 'src/functionapp/Modules/Wardline/Wardline.psd1')).ModuleVersion }
    endpoint = & $read 'endpoint-latest.json'
    agents   = & $read 'agents-latest.json'
    runs     = @(& $read 'runs.json')
    changes  = @(& $read 'endpoint-changes.json')
    acceptances = [ordered]@{ acceptances = @(& $read 'acceptances.json' | Where-Object { $_ } | ForEach-Object { $_ | Add-Member -NotePropertyName active -NotePropertyValue (-not $_.revokedAt) -Force -PassThru }) }
    'acceptances/log' = @(& $read 'acceptances-log.json')
}
# Demo: one active acceptance (hygiene finding) to show the accepted-risk workflow
$hyg = @($data.endpoint.findings | Where-Object { $_.category -eq 'Hygiene' })[0]
if ($hyg) {
    $data.acceptances.acceptances = @($data.acceptances.acceptances) + [pscustomobject]@{ key = $hyg.key; kind = 'finding'; module = 'endpoint'; title = $hyg.title.en; justification = 'Legacy line-of-business app, decommissioning planned for Q2.'; owner = 'Workplace team'; ticket = 'CHG-1042'; expires = [DateTime]::UtcNow.AddDays(60).ToString('yyyy-MM-dd'); acceptedBy = 'alice@contoso.com'; acceptedAt = [DateTime]::UtcNow.AddDays(-3).ToString('o'); active = $true }
}
"window.WARDLINE_DEMO = $($data | ConvertTo-Json -Depth 64 -Compress);" | Set-Content -Path (Join-Path $demo 'demo-data.js') -Encoding utf8
$html = Get-Content -Raw (Join-Path $demo 'index.html')
if ($html -notmatch 'demo-data\.js') { $html = $html -replace '<script src="app.js"', '<script src="demo-data.js"></script><script src="app.js"'; Set-Content -Path (Join-Path $demo 'index.html') -Value $html -Encoding utf8 }
Remove-Item $tmp -Recurse -Force
Write-Host "Demo created: $demo"
