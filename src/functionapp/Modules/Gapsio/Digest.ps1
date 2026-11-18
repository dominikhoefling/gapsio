# Gapsio change digest: what Microsoft announces for the security products Gapsio audits – and what it asks the
# tenant to do, by when.
#
# Source: the Microsoft 365 message center of the tenant (Microsoft Graph admin/serviceAnnouncement/messages, v1.0,
# application permission ServiceMessage.Read.All – read-only). Only posts about Defender, Intune, Entra, Purview,
# Agent 365 and related security services are kept.
#
# No model is involved: the classification uses the fields Microsoft sets (category, isMajorChange, tags,
# actionRequiredByDateTime) and the sections Microsoft writes into the post ("When this will happen", "How this will
# affect your organization", "What you need to do to prepare"). Texts from Microsoft stay in English.
# Posts with a deadline, and major changes, become findings – so they can be assigned, documented as handled
# (accepted with a note) and sent to Teams like every other finding.

# Services whose posts are kept (regular expression on the service names of a post); extend with GAPSIO_DIGEST_SERVICES.
$script:GapsioDigestServices = 'Defender|Intune|Entra|Purview|Sentinel|Security Copilot|Agent 365|Exchange Online Protection'
$script:GapsioDigestHeadings = [ordered]@{
    when   = 'when (this|will this) (will )?happen'
    impact = 'how (this|will this) (will )?affects? your organi[sz]ation'
    todo   = 'what you (need to|can|should) do( to prepare)?'
    other  = 'compliance considerations?|learn more|additional information|message summary|before you begin'
}

function ConvertFrom-GapsioDigestHtml {
    <# .SYNOPSIS Message center HTML as plain text: one line per paragraph/list item, list items start with "• ". #>
    param([AllowNull()][string]$Html)
    if ([string]::IsNullOrWhiteSpace($Html)) { return '' }
    $t = $Html -replace '(?is)<(script|style)\b.*?</\1>', ''
    $t = $t -replace '(?i)<li\b[^>]*>', "`n• "
    $t = $t -replace '(?i)<br\s*/?>|</p>|</div>|</li>|</h[1-6]>|</tr>|</ul>|</ol>', "`n"
    $t = $t -replace '<[^>]+>', ''
    $t = [System.Net.WebUtility]::HtmlDecode($t) -replace "`u{00A0}", ' '
    (@($t -split "`n" | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } | Where-Object { $_ -and $_ -ne '•' }) -join "`n")
}

function Get-GapsioDigestSections {
    <#
    .SYNOPSIS
    Splits the text of a post at the headings Microsoft uses ("[When this will happen:]", "How this will affect your
    organization:", "What you need to do to prepare:" – with or without brackets and colon). Returns intro, when,
    impact, todo (empty string when a section is missing).
    #>
    param([AllowNull()][string]$Text)
    $out = [ordered]@{ intro = ''; when = ''; impact = ''; todo = '' }
    if (-not $Text) { return $out }
    $buf = @{ intro = [System.Collections.Generic.List[string]]::new() }
    $cur = 'intro'
    foreach ($line in ($Text -split "`n")) {
        $probe = ($line -replace '^[\[\s•*]+', '' -replace '[\]\s:*]+$', '').Trim()
        $hit = $null
        if ($probe.Length -le 70) { foreach ($k in $script:GapsioDigestHeadings.Keys) { if ($probe -match "^(?i)($($script:GapsioDigestHeadings[$k]))$") { $hit = $k; break } } }
        if ($hit) { $cur = $hit; if (-not $buf.ContainsKey($cur)) { $buf[$cur] = [System.Collections.Generic.List[string]]::new() }; continue }
        $buf[$cur].Add($line)
    }
    foreach ($k in @('intro', 'when', 'impact', 'todo')) { if ($buf.ContainsKey($k)) { $out[$k] = ($buf[$k] -join "`n").Trim() } }
    $out
}

function Get-GapsioDigestClip {
    # Shortens a text at a word boundary and marks the cut.
    param([AllowNull()][string]$Text, [int]$Max)
    $s = ([string]$Text).Trim()
    if ($s.Length -le $Max) { return $s }
    $cut = $s.Substring(0, $Max); $sp = $cut.LastIndexOf(' ')
    if ($sp -gt $Max * 0.6) { $cut = $cut.Substring(0, $sp) }
    $cut.TrimEnd(' ', ',', ';', ':') + ' …'
}

function Get-GapsioDigestArea {
    # Product family of a post, used for the filter in the portal (first match wins).
    param([string[]]$Services)
    $s = ($Services -join ' | ')
    if ($s -match 'Agent 365') { return 'Agents' }
    if ($s -match 'Defender for Office|Exchange Online Protection') { return 'Office' }
    if ($s -match 'Intune') { return 'Intune' }
    if ($s -match 'Entra') { return 'Entra' }
    if ($s -match 'Purview') { return 'Purview' }
    if ($s -match 'Defender|Sentinel|Security Copilot') { return 'Defender' }
    'Other'
}

function ConvertTo-GapsioDigestItem {
    <#
    .SYNOPSIS
    One message center post as a digest item. action: ActBy (deadline ahead), Overdue (deadline passed), Plan (major
    change, retirement or "plan for change"), Check (prevent or fix an issue), Info. priority: High, Medium, Low, Info.
    #>
    param([Parameter(Mandatory)]$Message, [datetime]$Now = [DateTime]::UtcNow)
    $date = { param($v) if ($null -eq $v -or [string]$v -eq '') { return $null }; try { ConvertTo-GapsioUtc $v } catch { $null } }
    $id = [string](Get-GapsioProp $Message 'id')
    $services = @(@(Get-GapsioProp $Message 'services') | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $tags = @(@(Get-GapsioProp $Message 'tags') | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $category = [string](Get-GapsioProp $Message 'category')
    $major = [bool](Get-GapsioProp $Message 'isMajorChange')
    $published = & $date (Get-GapsioProp $Message 'startDateTime')
    $updated = & $date (Get-GapsioProp $Message 'lastModifiedDateTime')
    $actBy = & $date (Get-GapsioProp $Message 'actionRequiredByDateTime')
    $expires = & $date (Get-GapsioProp $Message 'endDateTime')
    $details = @{}; foreach ($d in @(Get-GapsioProp $Message 'details')) { if ($d -and (Get-GapsioProp $d 'name')) { $details[[string]$d.name] = [string](Get-GapsioProp $d 'value') } }
    $text = ConvertFrom-GapsioDigestHtml ([string](Get-GapsioProp (Get-GapsioProp $Message 'body') 'content'))
    $sec = Get-GapsioDigestSections $text
    $retirement = [bool](@($tags | Where-Object { $_ -match 'Retirement' }).Count)
    $adminImpact = [bool](@($tags | Where-Object { $_ -match 'Admin impact' }).Count)

    $daysLeft = if ($actBy) { [int][Math]::Ceiling(($actBy.Date - $Now.Date).TotalDays) } else { $null }
    $action = if ($actBy -and $daysLeft -ge 0) { 'ActBy' } elseif ($actBy) { 'Overdue' }
    elseif ($major -or $retirement -or $category -eq 'planForChange') { 'Plan' }
    elseif ($category -eq 'preventOrFixIssue') { 'Check' } else { 'Info' }
    $priority = switch ($action) {
        'ActBy' { if ($daysLeft -le 14) { 'High' } elseif ($daysLeft -le 60) { 'Medium' } else { 'Low' } }
        'Overdue' { 'Medium' }
        'Plan' { if ($major -or $retirement) { 'Medium' } else { 'Low' } }
        'Check' { 'Low' }
        default { 'Info' }
    }
    $summary = if ($details['Summary']) { $details['Summary'] } else { $sec.intro }
    $iso = { param($d) if ($d) { $d.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }
    [pscustomobject][ordered]@{
        key        = Get-GapsioHash "digest|$id"
        fp         = Get-GapsioHash "$(& $iso $updated)|$(& $iso $actBy)|$category|$major"
        label      = New-GapsioText "Message center $id`: $([string](Get-GapsioProp $Message 'title'))" "Nachrichtencenter $id`: $([string](Get-GapsioProp $Message 'title'))"
        state      = "$action$(if ($actBy) { " by $($actBy.ToString('yyyy-MM-dd'))" })"
        id         = $id
        title      = [string](Get-GapsioProp $Message 'title')
        area       = Get-GapsioDigestArea -Services $services
        services   = $services
        category   = $category
        severity   = [string](Get-GapsioProp $Message 'severity')
        tags       = $tags
        isMajorChange = $major
        retirement = $retirement
        adminImpact = $adminImpact
        action     = $action
        priority   = $priority
        actBy      = $(if ($actBy) { $actBy.ToString('yyyy-MM-dd') } else { $null })
        daysLeft   = $daysLeft
        published  = & $iso $published
        updated    = & $iso $updated
        expires    = & $iso $expires
        isNew      = [bool]($published -and $published -gt $Now.AddDays(-7))
        isUpdated  = [bool]($updated -and $published -and $updated -gt $published.AddHours(1) -and $updated -gt $Now.AddDays(-7))
        summary    = Get-GapsioDigestClip $summary 700
        when       = Get-GapsioDigestClip $sec.when 700
        impact     = Get-GapsioDigestClip $sec.impact 1200
        todo       = Get-GapsioDigestClip $sec.todo 1500
        roadmapIds = @(([string]$details['RoadmapIds']) -split '[,;\s]+' | Where-Object { $_ -match '^\d+$' })
        url        = "https://admin.microsoft.com/Adminportal/Home#/MessageCenter/:/messages/$id"
    }
}

function Get-GapsioDigestMessages {
    <#
    .SYNOPSIS
    Message center posts of the tenant. Returns @{ ok; messages } – ok is $false when the call failed (permission
    ServiceMessage.Read.All missing), so the snapshot can say "could not be read" instead of "nothing announced".
    #>
    $sel = 'id,title,category,severity,services,tags,isMajorChange,startDateTime,endDateTime,lastModifiedDateTime,actionRequiredByDateTime,details,body'
    $r = Invoke-GapsioGraphSafe -All -Context 'Message center (ServiceMessage.Read.All)' -Path "admin/serviceAnnouncement/messages?`$select=$sel&`$top=100"
    [pscustomobject]@{ ok = ($null -ne $r); messages = @($r | Where-Object { $_ }) }
}

function Get-GapsioDigestFindings {
    <#
    .SYNOPSIS
    Findings from the digest: a post with a deadline (severity by the days left), a deadline that passed in the last
    30 days, and major changes or retirements published in the last 30 days. One finding per post, keyed by the
    post – the date or title Microsoft changes later does not create a second finding.
    #>
    param([object[]]$Items, [datetime]$Now = [DateTime]::UtcNow)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-GapsioText -En $en -De $de }
    $rec = & $T 'Read the post in the message center, assign an owner here and accept the finding with a note once it is handled.' 'Den Beitrag im Nachrichtencenter lesen, hier einen Verantwortlichen zuweisen und den Befund mit einer Notiz akzeptieren, sobald er erledigt ist.'
    foreach ($i in @($Items | Where-Object { $_ })) {
        $ask = if ($i.todo) { $i.todo } else { $i.summary }
        $ask = Get-GapsioDigestClip $ask 600
        $svc = (@($i.services) | Select-Object -First 3) -join ', '
        $tail = "$(if ($ask) { " Microsoft: $ask" }) ($($i.id), $svc)"
        if ($i.action -eq 'ActBy') {
            $f.Add((New-GapsioFinding -Severity $i.priority -Category 'ServiceChange' -Title (& $T "Microsoft asks for action by $($i.actBy): $($i.title)" "Microsoft verlangt Handlung bis $($i.actBy): $($i.title)") `
                        -Detail (& $T "This message center post has a deadline: $($i.actBy).$tail" "Dieser Beitrag im Nachrichtencenter hat eine Frist: $($i.actBy).$tail") -Recommendation $rec -Subject "digest|$($i.id)" -StableKey))
        }
        elseif ($i.action -eq 'Overdue' -and $i.daysLeft -ge -30) {
            $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'ServiceChange' -Title (& $T "Deadline passed on $($i.actBy): $($i.title)" "Frist am $($i.actBy) abgelaufen: $($i.title)") `
                        -Detail (& $T "The deadline of this message center post has passed: $($i.actBy). If the change was not prepared, it may already be in effect.$tail" "Die Frist dieses Beitrags im Nachrichtencenter ist abgelaufen: $($i.actBy). Wurde die Änderung nicht vorbereitet, ist sie möglicherweise schon wirksam.$tail") -Recommendation $rec -Subject "digest|$($i.id)" -StableKey))
        }
        elseif ($i.action -eq 'Plan' -and ($i.isMajorChange -or $i.retirement) -and $i.published -and (ConvertTo-GapsioUtc $i.published) -gt $Now.AddDays(-30)) {
            $kind = if ($i.retirement) { @('Retirement announced', 'Abkündigung angekündigt') } else { @('Major change announced', 'Größere Änderung angekündigt') }
            $f.Add((New-GapsioFinding -Severity 'Low' -Category 'ServiceChange' -Title (& $T "$($kind[0]): $($i.title)" "$($kind[1]): $($i.title)") `
                        -Detail (& $T "Microsoft marks this post as a $(if ($i.retirement) { 'retirement' } else { 'major change' }); it has no deadline.$(if ($i.when) { " When: $(Get-GapsioDigestClip $i.when 250)" })$tail" "Microsoft kennzeichnet diesen Beitrag als $(if ($i.retirement) { 'Abkündigung' } else { 'größere Änderung' }); eine Frist nennt er nicht.$(if ($i.when) { " Zeitpunkt: $(Get-GapsioDigestClip $i.when 250)" })$tail") -Recommendation $rec -Subject "digest|$($i.id)" -StableKey))
        }
    }
    @($f | Sort-Object { $script:GapsioSeverityOrder[$_.severity] }, { Get-GapsioProp $_.title 'en' })
}

function Invoke-GapsioDigestCollection {
    <#
    .SYNOPSIS
    Run of the change digest: reads the message center, keeps the posts about security products that have not expired,
    writes the snapshot (state/digest-latest.json) with drift and run history. When the message center cannot be
    read, the snapshot keeps the posts of the last successful run and says so (status, dataFrom).
    #>
    Reset-GapsioWarnings
    $started = [DateTime]::UtcNow
    Write-Information "Gapsio digest: start $($started.ToString('o'))" -InformationAction Continue
    $pattern = $script:GapsioDigestServices
    $extra = [string](Get-GapsioSetting -Name 'GAPSIO_DIGEST_SERVICES')
    if ($extra) { try { $null = [regex]::new($extra); $pattern = "$pattern|$extra" } catch { Add-GapsioWarning "GAPSIO_DIGEST_SERVICES is not a valid regular expression and was ignored: $extra" } }

    $src = Get-GapsioDigestMessages
    $items = @(foreach ($m in $src.messages) {
            $svc = (@(Get-GapsioProp $m 'services') -join ' | ')
            if ($svc -notmatch $pattern) { continue }
            $it = ConvertTo-GapsioDigestItem -Message $m -Now $started
            if ($it.expires -and (ConvertTo-GapsioUtc $it.expires) -lt $started) { continue }   # Microsoft has taken the post off the message center
            $it
        })
    $rank = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    $items = @($items | Sort-Object { $rank[$_.priority] }, { if ($_.actBy) { $_.actBy } else { '9999' } }, @{ Expression = 'published'; Descending = $true }, id)
    $findings = @(Get-GapsioDigestFindings -Items $items -Now $started)
    # The message center could not be read: keep the posts and findings of the last successful run. Writing an empty
    # list would report every post as removed now and as new again (with a notification) in the next run.
    $dataFrom = $started.ToString('o')
    if (-not $src.ok) {
        $prev = $null; try { $prev = Get-GapsioBlob -Container 'state' -Name 'digest-latest.json' } catch { $prev = $null }
        $items = @(@(Get-GapsioProp $prev 'items') | Where-Object { $_ })
        $findings = @(@(Get-GapsioProp $prev 'findings') | Where-Object { $_ })
        $dataFrom = $(if ($prev) { $d = [string](Get-GapsioProp $prev 'dataFrom'); if ($d) { $d } else { [string](Get-GapsioProp $prev 'generatedAt') } } else { $null })
    }
    $deadlines = @($items | Where-Object { $_.action -eq 'ActBy' } | Sort-Object actBy)
    $areas = [ordered]@{}; foreach ($g in @($items | Group-Object area | Sort-Object Name)) { $areas[$g.Name] = $g.Count }
    $sevCount = [ordered]@{}; foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $sevCount[$s] = @($findings | Where-Object { $_.severity -eq $s }).Count }

    $snapshot = [ordered]@{
        module      = 'digest'
        version     = (Get-GapsioVersion)
        generatedAt = [DateTime]::UtcNow.ToString('o')
        tenantId    = Get-GapsioSetting -Name 'GAPSIO_TENANT_ID'
        status      = $(if ($src.ok) { 'ok' } else { 'unavailable' })   # unavailable: the message center could not be read (see warnings)
        dataFrom    = $dataFrom                                          # when the posts below were read ($null: never)
        summary     = [ordered]@{
            posts        = @($src.messages).Count          # all posts in the message center
            items        = $items.Count                    # posts about security products
            new7d        = @($items | Where-Object { $_.isNew }).Count
            updated7d    = @($items | Where-Object { $_.isUpdated }).Count
            deadlines    = $deadlines.Count
            nextDeadline = $(if ($deadlines.Count) { $deadlines[0].actBy } else { $null })
            due14d       = @($deadlines | Where-Object { $_.daysLeft -le 14 }).Count
            overdue      = @($items | Where-Object { $_.action -eq 'Overdue' }).Count
            majorChanges = @($items | Where-Object { $_.isMajorChange -or $_.retirement }).Count
            areas        = $areas
            findings     = $sevCount
        }
        items       = @($items)
        findings    = @($findings)
        warnings    = @(Get-GapsioWarnings)
    }
    $r = Save-GapsioSnapshot -Module 'digest' -Snapshot $snapshot -Collections @('items', 'findings') -Started $started
    Write-Information "Gapsio digest: done, $($items.Count) post(s), $($r.changes) change(s), $($r.warnings) warning(s)." -InformationAction Continue
    $r
}
