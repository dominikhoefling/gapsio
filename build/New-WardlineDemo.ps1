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
# Demo: 30 days of history so the trend and drift charts have something to show
$rand = [Random]::new(42)
$now = [DateTime]::UtcNow
$latestEp = @($data.runs | Where-Object { $_.module -eq 'endpoint' -and $_.findings })[0]
$latestAg = @($data.runs | Where-Object { $_.module -eq 'agents' -and $_.findings })[0]
$hist = [System.Collections.Generic.List[object]]::new()
foreach ($d in 1..29) {
    $day = $now.Date.AddDays(-$d).AddHours(2).AddMinutes(17)
    foreach ($src in @($latestEp, $latestAg)) {
        if (-not $src) { continue }
        $f = [ordered]@{}
        foreach ($sev in 'Critical', 'High', 'Medium', 'Low') { $f[$sev] = [Math]::Max(0, [int]$src.findings.$sev + [int][Math]::Floor($d / 9) + $rand.Next(-1, 2)) }
        $drift = [ordered]@{ Added = $rand.Next(0, 4); Changed = $rand.Next(0, 6); Removed = $rand.Next(0, 3) }
        if ($rand.Next(0, 5) -eq 0) { $drift = [ordered]@{ Added = 0; Changed = 0; Removed = 0 } }
        $hist.Add([pscustomobject]@{ module = $src.module; at = $day.AddMinutes($(if ($src.module -eq 'agents') { 15 } else { 0 })).ToString('o'); durationSec = $rand.Next(40, 140)
                changes = $drift.Added + $drift.Changed + $drift.Removed; drift = $drift; findings = $f; protection = $src.protection; warnings = 0; snapshot = '' })
    }
}
$data.runs = @($data.runs) + @($hist)
$tmpl = @($data.changes | Where-Object { $_ })
if ($tmpl.Count) {
    $extra = foreach ($r in $hist | Where-Object { $_.module -eq 'endpoint' }) {
        foreach ($kind in 'Added', 'Changed', 'Removed') {
            $pool = @($tmpl | Where-Object { $_.change -eq $kind }); if (-not $pool.Count) { $pool = $tmpl }
            for ($i = 0; $i -lt [int]$r.drift.$kind; $i++) { $c = $pool[$rand.Next(0, $pool.Count)] | ConvertTo-Json -Depth 10 | ConvertFrom-Json; $c.at = $r.at; $c.change = $kind; $c }
        }
    }
    $data.changes = @($data.changes) + @($extra)
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
