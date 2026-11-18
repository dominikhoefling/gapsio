#Requires -Version 7.2
<#
.SYNOPSIS
    News agent: collects new items about the Microsoft security products Gapsio audits – Defender for Endpoint and
    Defender XDR, Defender for Office 365, Intune, Entra, Purview and Agent 365 – from documented public sources,
    remembers what has been seen and prints a Markdown digest. Nothing is changed in Gapsio – a maintainer decides
    per item whether a check, a baseline setting or documentation follows.

    Sources (no authentication):
      - Microsoft Learn "What's new" pages: Defender for Endpoint (Windows, macOS, Linux), Defender XDR, Defender for
        Office 365, Intune (security-related areas), Purview (data security solutions), Entra, Agent 365
      - Tech Community blogs (RSS): Microsoft Defender, Intune, Entra, Agent 365, Security Community
      - Microsoft Security blog (RSS), filtered on the products above
      - Microsoft 365 roadmap API (public), by the product tags of an entry

    Each item carries a hint which Gapsio module it may concern. A source that returns nothing is named at the end
    of the digest – a feed Microsoft retires must not go unnoticed.

.EXAMPLE
    ./tools/Get-GapsioNews.ps1                         # digest of items not seen before, state in the temp folder
    ./tools/Get-GapsioNews.ps1 -Days 14 -NoState       # everything from the last 14 days, do not touch the state
    ./tools/Get-GapsioNews.ps1 -Output /tmp/news.md    # write the digest to a file (used by the workflow)
#>
param(
    [string]$StatePath = (Join-Path ([IO.Path]::GetTempPath()) 'gapsio-news-state.json'),
    [string]$Output,
    [int]$Days = 45,
    [int]$MaxPerSource = 12,   # newest items per source in one digest; the rest is counted and reported next time
    [switch]$NoState
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ua = @{ 'User-Agent' = 'Mozilla/5.0 (Macintosh) Gapsio-NewsAgent/1.0 (+https://github.com/dominikhoefling/gapsio)' }
$since = [DateTime]::UtcNow.AddDays(-$Days)

function Get-Html { param([string]$Uri) try { (Invoke-WebRequest -Uri $Uri -Headers $ua -TimeoutSec 40).Content } catch { Write-Warning "Fetch failed: $Uri ($($_.Exception.Message))"; $null } }
function Strip { param([string]$s) [System.Net.WebUtility]::HtmlDecode(($s -replace '<[^>]+>', '')).Trim() -replace '\s+', ' ' }
function New-Item2 { param([string]$Source, [string]$Title, [string]$Url, [string]$Date, [string]$Summary, [string]$Topic)
    [pscustomobject]@{ id = ("$Source|$Title|$Url").ToLowerInvariant(); source = $Source; topic = $Topic; title = $Title; url = $Url; date = $Date; summary = $Summary } }

$items = [System.Collections.Generic.List[object]]::new()
$empty = [System.Collections.Generic.List[string]]::new()   # sources that returned nothing (retired feed, changed page)
$topics = [ordered]@{ Defender = 'Microsoft Defender for Endpoint / XDR'; Office = 'Microsoft Defender for Office 365'; Intune = 'Microsoft Intune'; Entra = 'Microsoft Entra'
    Purview = 'Microsoft Purview'; Agent365 = 'Microsoft Agent 365'; Security = 'Microsoft Security (general)' }

function Get-SectionDate {
    # Date of a "What's new" section heading: "October 2026", "Aug 2025", "Week of November 16, 2026 (Service release 2611)"
    param([string]$Heading)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    if ($Heading -match '([A-Z][a-z]+) (\d{1,2}), (20\d\d)') { try { return [DateTime]::ParseExact("$($Matches[2]) $($Matches[1]) $($Matches[3])", 'd MMMM yyyy', $inv) } catch { } }
    if ($Heading -match '([A-Z][a-z]+)\.? (20\d\d)') {
        foreach ($f in 'MMMM yyyy', 'MMM yyyy') { try { return [DateTime]::ParseExact("$($Matches[1]) $($Matches[2])", $f, $inv) } catch { } }
    }
    $null
}

function Get-BulletTitle {
    # Title of a bullet: its bold lead – unless the lead is only a release stage ("General availability: Endpoint DLP
    # can now …"), then the first sentence of the text with the stage in brackets
    param([string]$Html, [string]$Text)
    $lead = if ($Html -match '(?s)<(?:strong|b)[^>]*>(.*?)</(?:strong|b)>') { (Strip $Matches[1]).TrimEnd(':').Trim() } elseif ($Html -match '(?s)<a[^>]*>(.*?)</a>') { Strip $Matches[1] } else { '' }
    $title = $lead
    if (-not $lead -or $lead -match '^(?i)(general(ly)? availab\w+|(public |private |in )?preview|new|rolling out|coming soon|updated?|ga)$') {
        $rest = $Text; if ($lead) { $rest = ($Text -replace "^(\(Preview\)\s*)?$([regex]::Escape($lead))\s*:?\s*", '') }
        $first = ($rest -split '(?<=[.!?])\s', 2)[0]
        $title = $first; if ($lead) { $title = "$first ($lead)" }
    }
    if ($title.Length -gt 140) { $title = $title.Substring(0, 137) + '…' }
    $title
}
# Event promotion and build numbers are not product changes
$promo = '(?i)(^|: )catch |your guide to|webinar|join (us|our)|register (now|today)|save the date|\bESPC\b|deep dives?:'
$builds = '^\S+ 20\d\d – Build \d'

function Get-GapsioHint {
    # Which Gapsio module an item may concern – a reading aid for the maintainer, not a decision
    param([string]$Text)
    $h = [System.Collections.Generic.List[string]]::new()
    if ($Text -match '(?i)exclusion|attack surface reduction|\bASR\b|tamper protection|antivirus|passive mode|device control|network protection|security settings management|onboarding|offboarding|sensor|attack disruption|custom detection|endpoint security polic') { $h.Add('Endpoint') }
    if ($Text -match '(?i)\bagents?\b|agent id|agent 365|\bMCP\b|copilot studio') { $h.Add('Agents') }
    if ($Text -match '(?i)unified RBAC|\bPIM\b|privileged identity|access review|access package|role assignment|built-in role|custom role') { $h.Add('Access') }
    if ($Text -match '(?i)conditional access') { $h.Add('Agents / Access (Conditional Access)') }
    if ($Text -match '(?i)anti-?phish|quarantine|safe links|safe attachments|tenant allow/block|zero-hour|\bZAP\b|defender for office|teams (message|protection)') { $h.Add('Office') }
    if ($Text -match '(?i)data loss prevention|\bDLP\b|sensitivity label|data security posture') { $h.Add('Purview') }
    if ($Text -match '(?i)licen[cs]|\bplan [12]\b|\bE7\b') { $h.Add('Licensing') }
    if ($Text -match '(?i)retire|deprecat|end of support|breaking change|action required') { $h.Add('Change digest (retirement or deadline)') }
    @($h | Select-Object -Unique) -join ', '
}

# 1) Microsoft Learn "What's new": the page lists months/features as headings; we take h2/h3 headings with their first paragraph
$learn = @(
    @{ topic = 'Defender'; name = 'Learn: What''s new in Defender for Endpoint'; url = 'https://learn.microsoft.com/en-us/defender-endpoint/whats-new-in-microsoft-defender-endpoint'; table = $true },
    @{ topic = 'Defender'; name = 'Learn: What''s new on macOS'; url = 'https://learn.microsoft.com/en-us/defender-endpoint/mac-whatsnew' },
    @{ topic = 'Defender'; name = 'Learn: What''s new on Linux'; url = 'https://learn.microsoft.com/en-us/defender-endpoint/linux-whatsnew' },
    @{ topic = 'Defender'; name = 'Learn: What''s new in Defender XDR'; url = 'https://learn.microsoft.com/en-us/defender-xdr/whats-new' },
    @{ topic = 'Office'; name = 'Learn: What''s new in Defender for Office 365'; url = 'https://learn.microsoft.com/en-us/defender-office-365/defender-for-office-365-whats-new' },
    # Intune: week -> area (h3) -> feature (h4); only the areas that concern device security and policy
    @{ topic = 'Intune'; name = 'Learn: What''s new in Intune'; url = 'https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/whats-new'; mode = 'areas'; areas = 'security|compliance|device configuration|tenant administration|role-based' },
    # Purview: month -> solution (h3) -> bullets; only the data security solutions
    @{ topic = 'Purview'; name = 'Learn: What''s new in Purview'; url = 'https://learn.microsoft.com/en-us/purview/whats-new'; mode = 'solutions'; areas = 'data loss prevention|data security posture|sensitivity label|information protection|insider risk|audit|data security' },
    @{ topic = 'Entra'; name = 'Learn: What''s new in Entra'; url = 'https://learn.microsoft.com/en-us/entra/fundamentals/whats-new' },
    @{ topic = 'Agent365'; name = 'Learn: What''s new in Microsoft Agent 365'; url = 'https://learn.microsoft.com/en-us/microsoft-agent-365/whats-new'; optional = $true }
)
foreach ($p in $learn) {
    $html = $(if ($p.ContainsKey('optional')) { try { (Invoke-WebRequest -Uri $p.url -Headers $ua -TimeoutSec 40).Content } catch { $null } } else { Get-Html $p.url })
    if (-not $html) { if (-not $p.ContainsKey('optional')) { $empty.Add("$($p.name) (page could not be read)") }; continue }
    $before = $items.Count; $dated = 0
    $main = if ($html -match '(?s)<main[^>]*>(.*?)</main>') { $Matches[1] } else { $html }
    # Structure of the Learn pages: <h2 id="october-2026">October 2026</h2> followed by <ul><li>…</li></ul> and/or <h3> entries.
    $sections = [regex]::Matches($main, '(?s)<h2[^>]*?id="([^"]*)"[^>]*>(.*?)</h2>(.*?)(?=<h2[ >]|\z)')
    foreach ($s in $sections) {
        $month = Strip $s.Groups[2].Value; $body = $s.Groups[3].Value
        if ($month -notmatch '\b20\d\d\b') { continue }                       # only dated sections (e.g. "October 2026")
        $md = Get-SectionDate $month
        if (-not $md) { continue }                                             # a heading with a year that is not a date ("What's planned for 2027")
        $dated++
        $isWeek = $month -match '\d{1,2}, 20\d\d'
        if ($md -lt $(if ($isWeek) { $since.AddDays(-7) } else { $since.AddDays(-31) })) { continue }   # sections older than the window
        $entries = @()
        $mode = if ($p.ContainsKey('mode')) { $p.mode } else { '' }
        if ($mode -in 'areas', 'solutions') {
            # h3 = area or solution; keep the ones that match, then h4 features (Intune) or bullets (Purview)
            foreach ($a in [regex]::Matches($body, '(?s)<h3[^>]*>(.*?)</h3>(.*?)(?=<h3[ >]|\z)')) {
                $area = Strip $a.Groups[1].Value
                if ($area -notmatch "(?i)$($p.areas)") { continue }
                if ($mode -eq 'areas') {
                    foreach ($h in [regex]::Matches($a.Groups[2].Value, '(?s)<h4[^>]*?(?:id="([^"]*)")?[^>]*>(.*?)</h4>(.*?)(?=<h4[ >]|\z)')) {
                        $para = ''; if ($h.Groups[3].Value -match '(?s)<p[^>]*>(.*?)</p>') { $para = Strip $Matches[1] }
                        $entries += [pscustomobject]@{ title = "$area`: $(Strip $h.Groups[2].Value)"; anchor = $h.Groups[1].Value; text = $para; link = $null }
                    }
                }
                else {
                    foreach ($li in [regex]::Matches($a.Groups[2].Value, '(?s)<li[^>]*>(.*?)</li>')) {
                        $t = Strip $li.Groups[1].Value; if (-not $t) { continue }
                        $entries += [pscustomobject]@{ title = "$area`: $(Get-BulletTitle -Html $li.Groups[1].Value -Text $t)"; anchor = $s.Groups[1].Value; text = $t; link = $null }
                    }
                }
            }
        }
        # a) table rows: Type | Feature | Preview/GA | Description (What's new in Defender for Endpoint)
        # Only on the page that publishes its news as a table – other pages use tables for reference material
        if (-not $mode -and $p.ContainsKey('table')) { foreach ($tr in [regex]::Matches($body, '(?s)<tr[^>]*>(.*?)</tr>')) {
            $cells = @([regex]::Matches($tr.Groups[1].Value, '(?s)<td[^>]*>(.*?)</td>') | ForEach-Object { $_.Groups[1].Value })
            if ($cells.Count -lt 2) { continue }
            $feature = Strip $cells[1]; if (-not $feature) { continue }
            $stage = if ($cells.Count -ge 3) { Strip $cells[2] } else { '' }
            $desc = if ($cells.Count -ge 4) { Strip $cells[3] } else { Strip $cells[0] }
            $href = if ($cells[1] -match 'href="([^"]+)"') { $Matches[1] } else { $null }
            $link = if (-not $href) { $null } elseif ($href -match '^https?://') { $href } elseif ($href -match '^/') { "https://learn.microsoft.com$href" } else { "https://learn.microsoft.com/en-us/defender-endpoint/$href" }
            $title = $feature; if ($stage) { $title = "$feature ($stage)" }
            $entries += [pscustomobject]@{ title = $title; anchor = $s.Groups[1].Value; text = "$(Strip $cells[0]): $desc"; link = $link }
        } }
        # b) h3 sub-headings with first paragraph (macOS/Linux/XDR/Entra pages)
        if (-not $mode -and -not $entries.Count) {
            foreach ($h in [regex]::Matches($body, '(?s)<h3[^>]*?(?:id="([^"]*)")?[^>]*>(.*?)</h3>(.*?)(?=<h3[ >]|\z)')) {
                $para = ''; if ($h.Groups[3].Value -match '(?s)<(p|li)[^>]*>(.*?)</\1>') { $para = Strip $Matches[2] }
                $entries += [pscustomobject]@{ title = Strip $h.Groups[2].Value; anchor = $h.Groups[1].Value; text = $para; link = $null }
            }
        }
        # c) plain bullet list (Defender for Office 365)
        if (-not $mode -and -not $entries.Count) {
            foreach ($li in [regex]::Matches($body, '(?s)<li[^>]*>(.*?)</li>')) {
                $t = Strip $li.Groups[1].Value; if (-not $t) { continue }
                $entries += [pscustomobject]@{ title = (Get-BulletTitle -Html $li.Groups[1].Value -Text $t); anchor = $s.Groups[1].Value; text = $t; link = $null }
            }
        }
        foreach ($e in $entries) {
            if (-not $e.title -or $e.title -match '^(Related|Next steps|Feedback|See also)') { continue }
            $txt = $e.text; if ($txt.Length -gt 320) { $txt = $txt.Substring(0, 317) + '…' }
            $url = if ($e.link) { $e.link } elseif ($e.anchor) { "$($p.url)#$($e.anchor)" } else { $p.url }
            $label = $month -replace '\s*\(Service release \d+\)', ''
            if ("$label – $($e.title)" -match $builds) { continue }
            $items.Add((New-Item2 -Source $p.name -Topic $p.topic -Title "$label – $($e.title)" -Url $url -Date $(if ($isWeek) { $md.ToString('yyyy-MM-dd') } else { $md.ToString('yyyy-MM') }) -Summary $txt))
        }
    }
    # No dated section at all means the page layout changed; no item in the window is normal for a quiet month
    if (-not $dated -and -not $p.ContainsKey('optional')) { $empty.Add("$($p.name) (no dated sections found – page layout changed?)") }
}

# 2) Blogs (RSS). The Defender for Endpoint board was merged into the Microsoft Defender blog and returns nothing since.
#    filter: regular expression on the TITLE (general blogs mention every product somewhere in the text)
$tc = 'https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id='
$products = 'Defender|Intune|Entra|Purview|Sentinel|Agent 365|Conditional Access'
$feeds = @(
    @{ topic = 'Defender'; name = 'Tech Community: Microsoft Defender blog'; url = "${tc}MicrosoftThreatProtectionBlog"; filter = $null },
    @{ topic = 'Intune'; name = 'Tech Community: Intune blog'; url = "${tc}MicrosoftIntuneBlog"; filter = $null },
    @{ topic = 'Entra'; name = 'Tech Community: Entra blog'; url = "${tc}microsoft-entra-blog"; filter = $null },
    @{ topic = 'Agent365'; name = 'Tech Community: Agent 365 blog'; url = "${tc}agent-365-blog"; filter = $null },
    @{ topic = 'Security'; name = 'Tech Community: Security Community blog'; url = "${tc}microsoft-security-blog"; filter = $products },
    @{ topic = 'Security'; name = 'Microsoft Security blog'; url = 'https://www.microsoft.com/en-us/security/blog/feed/'; filter = $products }
)
foreach ($fd in $feeds) {
    $rss = Get-Html $fd.url; if (-not $rss) { $empty.Add("$($fd.name) (feed could not be read)"); continue }
    try {
        [xml]$x = $rss
        # XPath, not $x.rss.channel.item: on a feed without entries that expression returns the Item() method of the
        # XML node instead of nothing, and an empty feed would count as one entry
        $list = @($x.SelectNodes('/rss/channel/item'))
        if (-not $list.Count) { $empty.Add("$($fd.name) (feed has no entries – retired or moved?)") }
        foreach ($it in $list) {
            if ($null -eq $it -or -not ($it.PSObject.Properties.Name -contains 'title')) { continue }
            if ($fd.filter -and ([string]$it.title) -notmatch "(?i)$($fd.filter)") { continue }
            if (([string]$it.title) -match $promo) { continue }
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
            # The product is the title prefix ("Microsoft Purview: …"). Product tags and the description are not used:
            # entries of other products carry security tags or mention Agent 365 in passing.
            $prefix = ([string]$r.title -split ':', 2)[0]
            $pick = { param($t) if ($t -match 'Agent 365') { 'Agent365' } elseif ($t -match 'Defender for Office') { 'Office' } elseif ($t -match 'Defender for Endpoint|Defender Vulnerability Management|Defender XDR|Microsoft Defender\b') { 'Defender' } elseif ($t -match '\bIntune\b') { 'Intune' } elseif ($t -match '\bPurview\b') { 'Purview' } elseif ($t -match '\bEntra\b') { 'Entra' } else { $null } }   # word boundaries: "Business Central" contains "entra"
            $topic = & $pick $prefix
            if (-not $topic -and [string]$r.title -match 'Agent 365') { $topic = 'Agent365' }
            if ($topic -eq 'Purview' -and [string]$r.title -notmatch '(?i)data loss prevention|\bDLP\b|information protection|sensitivity|insider risk|audit|data security') { continue }
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
# Newest items per source only; what is held back stays unseen and comes with the next digest
$held = 0
$new = @($new | Group-Object source | ForEach-Object { $g = @($_.Group | Sort-Object { $_.date } -Descending); $held += [Math]::Max(0, $g.Count - $MaxPerSource); $g | Select-Object -First $MaxPerSource })
$shown = @{}; foreach ($i in $new) { $shown[$i.id] = $true }

# Digest
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# Microsoft security – news digest $([DateTime]::UtcNow.ToString('yyyy-MM-dd'))")
[void]$sb.AppendLine()
[void]$sb.AppendLine("$($new.Count) new item(s) from $($items.Count) collected$(if ($held) { " ($held more held back for the next digest)" }). Nothing has been changed in Gapsio – reply per item with **einbauen** / **implement** (what: check, baseline setting, docs) or **ignorieren** / **ignore**.")
foreach ($t in $topics.Keys) {
    $grp = @($new | Where-Object topic -eq $t); if (-not $grp.Count) { continue }
    [void]$sb.AppendLine(); [void]$sb.AppendLine("## $($topics[$t]) ($($grp.Count))")
    foreach ($s in @($grp | Group-Object source)) {
        [void]$sb.AppendLine(); [void]$sb.AppendLine("### $($s.Name)")
        foreach ($i in $s.Group) {
            [void]$sb.AppendLine("- [ ] **[$($i.title)]($($i.url))**$(if ($i.date) { " – $($i.date)" })")
            if ($i.summary) { [void]$sb.AppendLine("  $($i.summary)") }
            $hint = Get-GapsioHint "$($i.title) $($i.summary)"
            if ($hint) { [void]$sb.AppendLine("  _May concern: ${hint}_") }
        }
    }
}
if ($empty.Count) {
    [void]$sb.AppendLine(); [void]$sb.AppendLine("## Sources without a result ($($empty.Count))")
    [void]$sb.AppendLine(); [void]$sb.AppendLine('Check whether Microsoft moved or retired them – the script reads nothing from a source that is gone.')
    foreach ($e in $empty) { [void]$sb.AppendLine("- $e") }
}
[void]$sb.AppendLine(); [void]$sb.AppendLine('<sub>Generated by tools/Get-GapsioNews.ps1. Sources: Microsoft Learn, Tech Community RSS, Microsoft Security blog, Microsoft 365 roadmap API.</sub>')
$md = $sb.ToString()
if ($Output) { Set-Content -Path $Output -Value $md -Encoding utf8 } else { $md }

if (-not $NoState) {
    # Only what this digest shows (or an earlier one showed) counts as seen – held-back items come next time
    $all = @($seen.Keys) + @($items | Where-Object { $shown.ContainsKey($_.id) } | ForEach-Object id) | Sort-Object -Unique
    New-Item -ItemType Directory -Force -Path (Split-Path $StatePath) | Out-Null
    [pscustomobject]@{ updated = [DateTime]::UtcNow.ToString('o'); seen = @($all) } | ConvertTo-Json -Depth 3 | Set-Content -Path $StatePath -Encoding utf8
}
# An issue is also worth opening when a source has gone quiet
if ($env:GITHUB_OUTPUT) { Add-Content $env:GITHUB_OUTPUT "count=$($new.Count + $empty.Count)" }
