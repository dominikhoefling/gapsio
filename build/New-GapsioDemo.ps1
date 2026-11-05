#Requires -Version 7.2
<#
.SYNOPSIS
    Creates dist/demo: the portal offline with demo data (open index.html in a browser or publish the folder).

.DESCRIPTION
    By default the data comes from the fictitious test tenant of tests/Test-Gapsio.ps1. With -StateDir the demo is
    built from real state files (endpoint-latest.json, agents-latest.json, runs.json, endpoint-changes.json, … from the
    "state" container) – for a richer demo.

    Either way every value that could identify a tenant is pseudonymised (build/Protect-GapsioDemoData.ps1) and the
    result is scanned for leaks. The build fails if anything is left: original names, deny terms, e-mail addresses
    outside contoso.example, IP addresses outside the documentation ranges, tenant domains.

    Deny terms (company names, people, tenant ID, …) come from -DenyTerms and from build/demo-denylist.txt (one term
    per line, git-ignored – keep it local).

.EXAMPLE
    ./build/New-GapsioDemo.ps1
.EXAMPLE
    ./build/New-GapsioDemo.ps1 -StateDir ~/Downloads/gapsio-state -DenyTerms 'Fabrikam', 'fabrikam.de'
#>
param(
    [string]$StateDir,
    [string[]]$DenyTerms = @(),
    [string]$DenyTermsFile = (Join-Path $PSScriptRoot 'demo-denylist.txt')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'Protect-GapsioDemoData.ps1')
. (Join-Path $PSScriptRoot 'Get-GapsioPreviewDemoData.ps1')
if (Test-Path $DenyTermsFile) { $DenyTerms += @(Get-Content $DenyTermsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }) }
$tmp = Join-Path ([IO.Path]::GetTempPath()) "gapsio-demo-$([guid]::NewGuid().ToString('n'))"
if ($StateDir) {
    New-Item -ItemType Directory -Path $tmp | Out-Null
    Copy-Item -Path (Join-Path $StateDir '*.json') -Destination $tmp
}
else {
    & (Join-Path $root 'tests/Test-Gapsio.ps1') -OutDir $tmp | Out-Null
}
$demo = Join-Path $root 'dist/demo'
New-Item -ItemType Directory -Force -Path $demo | Out-Null
Copy-Item -Path (Join-Path $root 'src/functionapp/www/*') -Destination $demo -Recurse -Force
$read = { param($n) $p = Join-Path $tmp $n; if (Test-Path $p) { Get-Content -Raw $p | ConvertFrom-Json -Depth 64 } else { $null } }
$data = [ordered]@{
    me       = [ordered]@{ oid = 'u-demo'; upn = 'demo@contoso.example'; displayName = 'Demo account (Contoso)'; isAdmin = $true; tenantId = 'contoso.example'; license = [ordered]@{ status = 'Valid'; plan = 'Annual'; customer = 'Contoso (Demo)'; expires = [DateTime]::UtcNow.AddMonths(10).ToString('yyyy-MM-dd'); daysLeft = 300 }; modules = @('endpoint', 'agents', 'access', 'licensing', 'officepreview', 'purviewpreview'); version = (Import-PowerShellDataFile (Join-Path $root 'src/functionapp/Modules/Gapsio/Gapsio.psd1')).ModuleVersion }
    endpoint = & $read 'endpoint-latest.json'
    agents   = & $read 'agents-latest.json'
    licensing = & $read 'licensing-latest.json'
    access   = & $read 'access-latest.json'
    runs     = @(& $read 'runs.json')
    changes  = @(& $read 'endpoint-changes.json')
    acceptances = [ordered]@{ acceptances = @(& $read 'acceptances.json' | Where-Object { $_ } | ForEach-Object { $_ | Add-Member -NotePropertyName active -NotePropertyValue (-not $_.revokedAt) -Force -PassThru }) }
    'acceptances/log' = @(& $read 'acceptances-log.json')
    assignments = [ordered]@{ assignments = @() }
    'directory/search' = [ordered]@{ results = @(
            [pscustomobject]@{ type = 'user'; id = '00000000-0000-0000-0000-00000000d001'; displayName = 'Bob (Demo)'; mail = 'bob.demo@contoso.example' },
            [pscustomobject]@{ type = 'group'; id = '00000000-0000-0000-0000-00000000d002'; displayName = 'SecOps (Demo)'; mail = $null },
            [pscustomobject]@{ type = 'distributionList'; id = '00000000-0000-0000-0000-00000000d003'; displayName = 'Workplace team (Demo)'; mail = 'workplace.demo@contoso.example' }); notices = @() }
}
# Demo: private-preview modules (Advanced Hunting only – not simulated by the test tenant); real state files win
$preview = Get-GapsioPreviewDemoData
$data.officepreview = $(if ($x = & $read 'office-preview-latest.json') { $x } else { $preview.officepreview })
$data.purviewpreview = $(if ($x = & $read 'purview-preview-latest.json') { $x } else { $preview.purviewpreview })
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
# Demo: one assignment (highest open finding) to show the assignment workflow
$top = @($data.endpoint.findings | Where-Object { $_.severity -in 'Critical', 'High' -and $_.key -ne $hyg.key })[0]
if ($top) {
    $data.assignments.assignments = @([pscustomobject]@{ key = $top.key; kind = 'finding'; module = 'endpoint'; title = $top.title.en; assignee = [pscustomobject]@{ type = 'distributionList'; id = '00000000-0000-0000-0000-00000000d003'; displayName = 'Workplace team (Demo)'; mail = 'workplace.demo@contoso.example' }; note = 'Please fix with the next maintenance window.'; assignedBy = 'alice@contoso.com'; assignedAt = [DateTime]::UtcNow.AddDays(-1).ToString('o') })
}
# Pseudonymise and scan – the demo is meant to be public
$keep = @(Get-ChildItem -Recurse -File -Path (Join-Path $root 'src/functionapp/Modules'), (Join-Path $root 'src/functionapp/config') -Include *.ps1, *.json |
    ForEach-Object { [regex]::Matches((Get-Content -Raw $_.FullName), $script:GuidRx) | ForEach-Object Value } | Sort-Object -Unique)
$tree = $data | ConvertTo-Json -Depth 64 -Compress | ConvertFrom-Json -AsHashtable -Depth 64
$mapper = Protect-GapsioDemoData -Data $tree -DenyTerms $DenyTerms -KeepGuids $keep
$tree.me.upn = 'demo@contoso.example'; $tree.me.displayName = 'Demo account (Contoso)'
$tree.license = [ordered]@{ status = 'Valid'; licenseId = 'GP-DEMO'; customer = 'Contoso (Demo)'; plan = 'Annual'; tenantId = $tree.me.tenantId; issued = [DateTime]::UtcNow.AddMonths(-2).ToString('yyyy-MM-dd'); expires = $tree.me.license.expires; daysLeft = 300; source = 'Portal'; setBy = 'demo@contoso.example'; setAt = [DateTime]::UtcNow.AddMonths(-2).ToString('o') }
$json = $tree | ConvertTo-Json -Depth 64 -Compress
$leaks = @(Test-GapsioDemoLeaks -Json $json -Mapper $mapper -DenyTerms $DenyTerms)
if ($leaks.Count) { Remove-Item $tmp -Recurse -Force; throw "Demo data not clean – nothing written:`n  $($leaks -join "`n  ")" }
Write-Host "Demo data pseudonymised: $(@($mapper.Map.Values).Count) values replaced, leak check passed."
"window.GAPSIO_DEMO = $json;" | Set-Content -Path (Join-Path $demo 'demo-data.js') -Encoding utf8
$html = Get-Content -Raw (Join-Path $demo 'index.html')
if ($html -notmatch 'demo-data\.js') { $html = $html -replace '<script src="app.js"', '<script src="demo-data.js"></script><script src="app.js"'; Set-Content -Path (Join-Path $demo 'index.html') -Value $html -Encoding utf8 }
Remove-Item $tmp -Recurse -Force
Write-Host "Demo created: $demo"
