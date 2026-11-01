#Requires -Version 7.2
<#
.SYNOPSIS
    News agent: collects new items about Microsoft Defender for Endpoint and Microsoft Agent 365 from documented
    public sources, remembers what has been seen and prints a Markdown digest. Nothing is changed in Wardline –
    a maintainer decides per item whether a check, a baseline setting or documentation follows.

    Sources (no authentication):
      - Microsoft Learn "What's new" pages (Windows, macOS, Linux, Defender XDR) – headings of the page
      - Tech Community blog "Microsoft Defender for Endpoint" (RSS)
      - Microsoft 365 roadmap API (public), filtered on "Defender for Endpoint" and "Agent 365"
      - Microsoft Learn "What's new" for Microsoft Agent 365 (if the page exists)

.EXAMPLE
    ./tools/Get-WardlineNews.ps1                         # digest of items not seen before, state in the temp folder
    ./tools/Get-WardlineNews.ps1 -Days 14 -NoState       # everything from the last 14 days, do not touch the state
    ./tools/Get-WardlineNews.ps1 -Output /tmp/news.md    # write the digest to a file (used by the workflow)
#>
param(
    [string]$StatePath = (Join-Path ([IO.Path]::GetTempPath()) 'wardline-news-state.json'),
    [string]$Output,
    [int]$Days = 45,
    [switch]$NoState
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ua = @{ 'User-Agent' = 'Mozilla/5.0 (Macintosh) Wardline-NewsAgent/1.0 (+https://github.com/dominikhoefling/wardline)' }
$since = [DateTime]::UtcNow.AddDays(-$Days)

function Get-Html { param([string]$Uri) try { (Invoke-WebRequest -Uri $Uri -Headers $ua -TimeoutSec 40).Content } catch { Write-Warning "Fetch failed: $Uri ($($_.Exception.Message))"; $null } }
function Strip { param([string]$s) [System.Net.WebUtility]::HtmlDecode(($s -replace '<[^>]+>', '')).Trim() -replace '\s+', ' ' }
function New-Item2 { param([string]$Source, [string]$Title, [string]$Url, [string]$Date, [string]$Summary, [string]$Topic)
    [pscustomobject]@{ id = ("$Source|$Title|$Url").ToLowerInvariant(); source = $Source; topic = $Topic; title = $Title; url = $Url; date = $Date; summary = $Summary } }

$items = [System.Collections.Generic.List[object]]::new()

# 1) Microsoft Learn "What's new": the page lists months/features as headings; we take h2/h3 headings with their first paragraph
$learn = @(
    @{ topic = 'MDE'; name = 'Learn: What''s new in Defender for Endpoint'; url = 'https://learn.microsoft.com/en-us/defender-endpoint/whats-new-in-microsoft-defender-endpoint' },
    @{ topic = 'MDE'; name = 'Learn: What''s new on macOS'; url = 'https://learn.microsoft.com/en-us/defender-endpoint/mac-whatsnew' },
    @{ topic = 'MDE'; name = 'Learn: What''s new on Linux'; url = 'https://learn.microsoft.com/en-us/defender-endpoint/linux-whatsnew' },
    @{ topic = 'MDE'; name = 'Learn: What''s new in Defender XDR'; url = 'https://learn.microsoft.com/en-us/defender-xdr/whats-new' },
    @{ topic = 'Agent365'; name = 'Learn: What''s new in Microsoft Agent 365'; url = 'https://learn.microsoft.com/en-us/microsoft-agent-365/whats-new'; optional = $true }
)
foreach ($p in $learn) {
    $html = $(if ($p.ContainsKey('optional')) { try { (Invoke-WebRequest -Uri $p.url -Headers $ua -TimeoutSec 40).Content } catch { $null } } else { Get-Html $p.url }); if (-not $html) { continue }
    $main = if ($html -match '(?s)<main[^>]*>(.*?)</main>') { $Matches[1] } else { $html }
    # Structure of the Learn pages: <h2 id="october-2026">October 2026</h2> followed by <ul><li>…</li></ul> and/or <h3> entries.
    $sections = [regex]::Matches($main, '(?s)<h2[^>]*?id="([^"]*)"[^>]*>(.*?)</h2>(.*?)(?=<h2[ >]|\z)')
    foreach ($s in $sections) {
        $month = Strip $s.Groups[2].Value; $body = $s.Groups[3].Value
        if ($month -notmatch '\b20\d\d\b') { continue }                       # only dated sections (e.g. "October 2026")
        try { $md = [DateTime]::ParseExact("01 $month", 'dd MMMM yyyy', [Globalization.CultureInfo]::InvariantCulture) } catch { $md = $null }
        if ($md -and $md -lt $since.AddDays(-31)) { continue }                 # months older than the window
        $entries = @()
        # a) table rows: Type | Feature | Preview/GA | Description (What's new in Defender for Endpoint)
        foreach ($tr in [regex]::Matches($body, '(?s)<tr[^>]*>(.*?)</tr>')) {
            $cells = @([regex]::Matches($tr.Groups[1].Value, '(?s)<td[^>]*>(.*?)</td>') | ForEach-Object { $_.Groups[1].Value })
            if ($cells.Count -lt 2) { continue }
            $feature = Strip $cells[1]; if (-not $feature) { continue }
            $stage = if ($cells.Count -ge 3) { Strip $cells[2] } else { '' }
            $desc = if ($cells.Count -ge 4) { Strip $cells[3] } else { Strip $cells[0] }
            $href = if ($cells[1] -match 'href="([^"]+)"') { $Matches[1] } else { $null }
            $link = if (-not $href) { $null } elseif ($href -match '^https?://') { $href } elseif ($href -match '^/') { "https://learn.microsoft.com$href" } else { "https://learn.microsoft.com/en-us/defender-endpoint/$href" }
            $title = $feature; if ($stage) { $title = "$feature ($stage)" }
            $entries += [pscustomobject]@{ title = $title; anchor = $s.Groups[1].Value; text = "$(Strip $cells[0]): $desc"; link = $link }
        }
        # b) h3 sub-headings with first paragraph (macOS/Linux/XDR pages)
        if (-not $entries.Count) {
            foreach ($h in [regex]::Matches($body, '(?s)<h3[^>]*?(?:id="([^"]*)")?[^>]*>(.*?)</h3>(.*?)(?=<h3[ >]|\z)')) {
                $para = ''; if ($h.Groups[3].Value -match '(?s)<(p|li)[^>]*>(.*?)</\1>') { $para = Strip $Matches[2] }
                $entries += [pscustomobject]@{ title = Strip $h.Groups[2].Value; anchor = $h.Groups[1].Value; text = $para; link = $null }
            }
        }
        # c) plain bullet list
        if (-not $entries.Count) {
            foreach ($li in [regex]::Matches($body, '(?s)<li[^>]*>(.*?)</li>')) {
                $t = Strip $li.Groups[1].Value; if (-not $t) { continue }
                $title = if ($li.Groups[1].Value -match '(?s)<(?:strong|b|a)[^>]*>(.*?)</(?:strong|b|a)>') { Strip $Matches[1] } else { $t }
                if ($title.Length -gt 140) { $title = $title.Substring(0, 137) + '…' }
                $entries += [pscustomobject]@{ title = $title; anchor = $s.Groups[1].Value; text = $t; link = $null }
            }
        }
        foreach ($e in $entries) {
            if (-not $e.title -or $e.title -match '^(Related|Next steps|Feedback|See also)') { continue }
            $txt = $e.text; if ($txt.Length -gt 320) { $txt = $txt.Substring(0, 317) + '…' }
            $url = if ($e.link) { $e.link } elseif ($e.anchor) { "$($p.url)#$($e.anchor)" } else { $p.url }
            $items.Add((New-Item2 -Source $p.name -Topic $p.topic -Title "$month – $($e.title)" -Url $url -Date $(if ($md) { $md.ToString('yyyy-MM') } else { '' }) -Summary $txt))
        }
    }
}

# 2) Tech Community blogs (RSS): Defender for Endpoint board, Microsoft 365 / Copilot blog filtered on Agent 365
$feeds = @(
    @{ topic = 'MDE'; name = 'Tech Community: Defender for Endpoint blog'; url = 'https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftDefenderATPBlog'; filter = $null },
    @{ topic = 'Agent365'; name = 'Tech Community: Microsoft 365 blog (Agent 365)'; url = 'https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoft_365blog'; filter = 'Agent 365' },
    @{ topic = 'Agent365'; name = 'Tech Community: Copilot blog (Agent 365)'; url = 'https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=Microsoft365CopilotBlog'; filter = 'Agent 365' }
)
foreach ($fd in $feeds) {
    $rss = Get-Html $fd.url; if (-not $rss) { continue }
    try {
        [xml]$x = $rss
        $list = @(); try { $list = @($x.rss.channel.item) } catch { $list = @() }
        foreach ($it in $list) {
            if ($null -eq $it -or -not ($it.PSObject.Properties.Name -contains 'title')) { continue }
            if ($fd.filter -and "$($it.title) $($it.description)" -notmatch [regex]::Escape($fd.filter)) { continue }
            $d = $null; try { $d = [DateTime]::Parse([string]$it.pubDate, [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime() } catch { }
            if ($d -and $d -lt $since) { continue }
            $desc = Strip ([string]$it.description); if ($desc.Length -gt 320) { $desc = $desc.Substring(0, 317) + '…' }
            $items.Add((New-Item2 -Source $fd.name -Topic $fd.topic -Title ([string]$it.title) -Url ([string]$it.link) -Date $(if ($d) { $d.ToString('yyyy-MM-dd') } else { '' }) -Summary $desc))
        }
    } catch { Write-Warning "RSS parse failed ($($fd.name)): $($_.Exception.Message)" }
}

# 3) Microsoft 365 roadmap (public JSON API)
$road = Get-Html 'https://www.microsoft.com/releasecommunications/api/v1/m365'
if ($road) {
    try {
        foreach ($r in @($road | ConvertFrom-Json)) {
            $text = "$($r.title) $($r.description) $(@($r.tagsContainer.products | ForEach-Object { $_.tagName }) -join ' ')"
            $topic = if ($text -match 'Agent 365') { 'Agent365' } elseif ($text -match 'Defender for Endpoint|Defender Vulnerability Management|Defender XDR') { 'MDE' } else { $null }
            if (-not $topic) { continue }
            $d = $null; try { $d = [DateTime]::Parse([string]$r.modified, [Globalization.CultureInfo]::InvariantCulture).ToUniversalTime() } catch { }
            if ($d -and $d -lt $since) { continue }
            $desc = Strip ([string]$r.description); if ($desc.Length -gt 320) { $desc = $desc.Substring(0, 317) + '…' }
            $items.Add((New-Item2 -Source "M365 roadmap" -Topic $topic -Title "[$($r.id)] $($r.title)" -Url "https://www.microsoft.com/microsoft-365/roadmap?id=$($r.id)" -Date $(if ($d) { $d.ToString('yyyy-MM-dd') } else { '' }) -Summary "($($r.status)) $desc"))
        }
    } catch { Write-Warning "Roadmap parse failed: $($_.Exception.Message)" }
}

# State: ids already reported. Identical entries that appear on several Learn pages (shared release tables) count once.
$dedup = @{}; $items = [System.Collections.Generic.List[object]]@($items | Where-Object { $k = "$($_.topic)|$($_.title)".ToLowerInvariant(); if ($dedup.ContainsKey($k)) { $false } else { $dedup[$k] = $true; $true } })
$seen = @{}
if (-not $NoState -and (Test-Path $StatePath)) { foreach ($k in @((Get-Content -Raw $StatePath | ConvertFrom-Json).seen)) { $seen[[string]$k] = $true } }
$new = @($items | Where-Object { -not $seen.ContainsKey($_.id) } | Sort-Object topic, source, { $_.date } -Descending)

# Digest
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# Defender for Endpoint / Agent 365 – news digest $([DateTime]::UtcNow.ToString('yyyy-MM-dd'))")
[void]$sb.AppendLine()
[void]$sb.AppendLine("$($new.Count) new item(s) from $($items.Count) collected. Nothing has been changed in Wardline – reply per item with **einbauen** / **implement** (what: check, baseline setting, docs) or **ignorieren** / **ignore**.")
foreach ($t in @('MDE', 'Agent365')) {
    $grp = @($new | Where-Object topic -eq $t); if (-not $grp.Count) { continue }
    [void]$sb.AppendLine(); [void]$sb.AppendLine("## $(if ($t -eq 'MDE') { 'Microsoft Defender for Endpoint / XDR' } else { 'Microsoft Agent 365' }) ($($grp.Count))")
    foreach ($s in @($grp | Group-Object source)) {
        [void]$sb.AppendLine(); [void]$sb.AppendLine("### $($s.Name)")
        foreach ($i in $s.Group) {
            [void]$sb.AppendLine("- [ ] **[$($i.title)]($($i.url))**$(if ($i.date) { " – $($i.date)" })")
            if ($i.summary) { [void]$sb.AppendLine("  $($i.summary)") }
        }
    }
}
[void]$sb.AppendLine(); [void]$sb.AppendLine('<sub>Generated by tools/Get-WardlineNews.ps1. Sources: Microsoft Learn, Tech Community RSS, Microsoft 365 roadmap API.</sub>')
$md = $sb.ToString()
if ($Output) { Set-Content -Path $Output -Value $md -Encoding utf8 } else { $md }

if (-not $NoState) {
    $all = @($seen.Keys) + @($items | ForEach-Object id) | Sort-Object -Unique
    New-Item -ItemType Directory -Force -Path (Split-Path $StatePath) | Out-Null
    [pscustomobject]@{ updated = [DateTime]::UtcNow.ToString('o'); seen = @($all) } | ConvertTo-Json -Depth 3 | Set-Content -Path $StatePath -Encoding utf8
}
if ($env:GITHUB_OUTPUT) { Add-Content $env:GITHUB_OUTPUT "count=$($new.Count)" }
