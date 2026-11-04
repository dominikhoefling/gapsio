# Office preview: anti-phish policy drift (settings history + outcome correlation).
# Settings changes come from the Exchange admin audit trail (CloudAppEvents, Set-/New-AntiPhishPolicy ...),
# outcomes from EmailEvents (phish-classified mail per policy/day). Both are merged into a long-lived
# history blob (state/office-antiphish-history.json) because Advanced Hunting only keeps 30 days.

$script:GapsioAntiPhishKeySettings = @(
    'PhishThresholdLevel',
    'Enabled', 'Priority',
    'EnableMailboxIntelligence', 'EnableMailboxIntelligenceProtection', 'MailboxIntelligenceProtectionAction', 'MailboxIntelligenceQuarantineTag',
    'EnableTargetedUserProtection', 'TargetedUserProtectionAction', 'TargetedUserQuarantineTag',
    'EnableTargetedDomainsProtection', 'EnableOrganizationDomainsProtection', 'TargetedDomainProtectionAction', 'TargetedDomainQuarantineTag',
    'EnableSpoofIntelligence', 'AuthenticationFailAction', 'SpoofQuarantineTag',
    'HonorDmarcPolicy', 'DmarcRejectAction', 'DmarcQuarantineAction',
    'EnableFirstContactSafetyTips', 'EnableSimilarUsersSafetyTips', 'EnableSimilarDomainsSafetyTips', 'EnableUnusualCharactersSafetyTips',
    'EnableViaTag', 'EnableUnauthenticatedSender',
    'ExcludedSenders', 'ExcludedDomains', 'TargetedUsersToProtect', 'TargetedDomainsToProtect',
    'SentTo', 'SentToMemberOf', 'RecipientDomainIs', 'ExceptIfSentTo', 'ExceptIfSentToMemberOf', 'ExceptIfRecipientDomainIs',
    'AntiPhishPolicy'
)
$script:GapsioAntiPhishNoiseParams = @('Identity', 'Confirm', 'ErrorAction', 'WarningAction', 'Verbose', 'Debug', 'Force', 'WhatIf', 'Name', 'Organization', 'ErrorVariable', 'WarningVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'InformationAction', 'InformationVariable', 'ProgressAction')

$script:GapsioAntiPhishCmdlets = @('Set-AntiPhishPolicy', 'New-AntiPhishPolicy', 'Remove-AntiPhishPolicy', 'Set-AntiPhishRule', 'New-AntiPhishRule', 'Remove-AntiPhishRule', 'Enable-AntiPhishRule', 'Disable-AntiPhishRule')

$script:GapsioAntiPhishChangesQuery = @"
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in~ ('Set-AntiPhishPolicy','New-AntiPhishPolicy','Remove-AntiPhishPolicy','Set-AntiPhishRule','New-AntiPhishRule','Remove-AntiPhishRule','Enable-AntiPhishRule','Disable-AntiPhishRule')
| extend Raw = parse_json(tostring(column_ifexists('RawEventData','')))
| extend Policy = tostring(Raw.ObjectId), Params = tostring(Raw.Parameters),
         Actor = coalesce(tostring(column_ifexists('AccountDisplayName','')), tostring(column_ifexists('AccountId','')), tostring(Raw.UserId)),
         Result = tostring(Raw.ResultStatus)
| project Timestamp, ActionType, Policy, Actor, Params, Result
| order by Timestamp asc
| take 500
"@

$script:GapsioAntiPhishOutcomesQuery = @"
EmailEvents
| where Timestamp > ago(30d)
| extend Threat = tolower(tostring(column_ifexists('ThreatTypes','')))
| where Threat has 'phish'
| extend OrgPolicy=tostring(column_ifexists('OrgLevelPolicy','')), UserPolicy=tostring(column_ifexists('UserLevelPolicy','')),
         OrgAction=tolower(tostring(column_ifexists('OrgLevelAction',''))),
         UserAction=tolower(tostring(column_ifexists('UserLevelAction',''))),
         DeliveryAction=tolower(tostring(column_ifexists('DeliveryAction',''))),
         DeliveryLocation=tolower(tostring(column_ifexists('DeliveryLocation','')))
| extend Policy = iif(isnotempty(UserPolicy), UserPolicy, iif(isnotempty(OrgPolicy), OrgPolicy, '(no policy recorded)'))
| extend EffectiveAction = iif(isnotempty(UserAction), UserAction,
                       iif(isnotempty(OrgAction), OrgAction,
                       iif(isnotempty(DeliveryAction), DeliveryAction, DeliveryLocation)))
| extend Outcome = case(
    isempty(EffectiveAction), 'Other',
    EffectiveAction contains 'block' or EffectiveAction contains 'reject' or EffectiveAction contains 'drop' or EffectiveAction contains 'delete', 'Block',
    EffectiveAction contains 'quarantine', 'Quarantine',
    EffectiveAction contains 'junk' or EffectiveAction contains 'spam' or EffectiveAction contains 'jmf' or EffectiveAction contains 'scl', 'Junk',
    EffectiveAction contains 'allow' or EffectiveAction contains 'deliver' or EffectiveAction contains 'inbox' or EffectiveAction contains 'noaction' or EffectiveAction contains 'redirect' or EffectiveAction contains 'bypass', 'Delivered',
    'Other')
| extend DM = tolower(tostring(parse_json(tostring(column_ifexists('DetectionMethods',''))).Phish))
| extend Method = case(
    DM has 'mailbox', 'MailboxIntelligence',
    DM has 'impersonation', 'Impersonation',
    DM has 'spoof', 'Spoof',
    DM has 'filter' or DM has 'analysis' or DM has 'reputation' or DM has 'fingerprint' or DM has 'campaign' or DM has 'detonation', 'Filter',
    isempty(DM), 'Unknown',
    'Other')
| extend Confidence = tostring(parse_json(tostring(column_ifexists('ConfidenceLevel',''))).Phish)
| extend Confidence = iif(isempty(Confidence), 'n/a', Confidence)
| summarize events=count() by day=startofday(Timestamp), Policy, Method, Outcome, Confidence
| order by day asc
| take 5000
"@

function ConvertTo-GapsioDayKey {
    # 'yyyy-MM-dd' (UTC) from a string or DateTime (ConvertFrom-Json turns ISO strings into DateTime).
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) {
        $d = if ($Value.Kind -eq 'Local') { $Value.ToUniversalTime() } else { $Value }
        return $d.ToString('yyyy-MM-dd')
    }
    $s = [string]$Value
    if ($s -match '^\d{4}-\d{2}-\d{2}') { return $s.Substring(0, 10) }
    $dt = [datetime]::Parse($s, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
    $dt.ToString('yyyy-MM-dd')
}

function ConvertTo-GapsioIsoTs {
    # Round-trip ISO 8601 UTC string from a string or DateTime.
    param($Value)
    if ($null -eq $Value) { return '' }
    $dt = if ($Value -is [datetime]) { $Value } else { [datetime]::Parse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) }
    if ($dt.Kind -eq 'Local') { $dt = $dt.ToUniversalTime() } elseif ($dt.Kind -eq 'Unspecified') { $dt = [datetime]::SpecifyKind($dt, 'Utc') }
    $dt.ToString('o')
}

function ConvertFrom-GapsioAntiPhishParams {
    # Exchange audit "Parameters" -> ordered name/value map (noise removed, values flattened to strings).
    param([string]$Json)
    $out = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Json)) { return $out }
    try { $arr = $Json | ConvertFrom-Json -Depth 16 } catch { return $out }
    foreach ($p in @($arr)) {
        $n = [string](Get-GapsioProp $p 'Name'); if (-not $n) { continue }
        if ($script:GapsioAntiPhishNoiseParams -contains $n) { continue }
        $v = Get-GapsioProp $p 'Value'
        $s = if ($null -eq $v) { '' } elseif ($v -is [array]) { ($v -join ';') } else { [string]$v }
        $out[$n] = $s
    }
    $out
}

function Get-GapsioAntiPhishActionRank {
    # Higher = stricter. Used to tell "weakened" from "hardened" changes.
    param([string]$Value)
    switch -Regex ([string]$Value) {
        '^(Quarantine|Delete)$' { 3 }
        '^MoveToJmf$' { 2 }
        '^(Redirect|BccMessage)$' { 1 }
        '^NoAction$' { 0 }
        default { $null }
    }
}

function Get-GapsioAntiPhishChangeDirection {
    # 'weaker' | 'stronger' | 'neutral' for one setting change.
    param([string]$Name, [string]$Before, [string]$After)
    if ($Name -eq 'PhishThresholdLevel') {
        $b = 0; $a = 0
        if ([int]::TryParse($Before, [ref]$b) -and [int]::TryParse($After, [ref]$a)) { if ($a -lt $b) { return 'weaker' } elseif ($a -gt $b) { return 'stronger' } }
        return 'neutral'
    }
    if ($Name -like '*Action') {
        $rb = Get-GapsioAntiPhishActionRank $Before; $ra = Get-GapsioAntiPhishActionRank $After
        if ($null -ne $rb -and $null -ne $ra) { if ($ra -lt $rb) { return 'weaker' } elseif ($ra -gt $rb) { return 'stronger' } }
        return 'neutral'
    }
    if ($Name -like 'Enable*' -or $Name -eq 'Enabled' -or $Name -eq 'HonorDmarcPolicy') {
        $tb = [string]$Before -match '^(true|\$true|1)$'; $ta = [string]$After -match '^(true|\$true|1)$'
        if ($tb -and -not $ta) { return 'weaker' } elseif ($ta -and -not $tb) { return 'stronger' }
        return 'neutral'
    }
    if ($Name -in @('ExcludedSenders', 'ExcludedDomains', 'ExceptIfSentTo', 'ExceptIfSentToMemberOf', 'ExceptIfRecipientDomainIs')) {
        $cb = @([string]$Before -split ';' | Where-Object { $_ }).Count; $ca = @([string]$After -split ';' | Where-Object { $_ }).Count
        if ($ca -gt $cb) { return 'weaker' } elseif ($ca -lt $cb) { return 'stronger' }
    }
    'neutral'
}

function ConvertTo-GapsioAntiPhishMap {
    # PSCustomObject (from JSON) or dictionary -> ordered hashtable of strings.
    param($Object)
    $out = [ordered]@{}
    if ($null -eq $Object) { return $out }
    if ($Object -is [System.Collections.IDictionary]) { foreach ($k in $Object.Keys) { $out[[string]$k] = [string]$Object[$k] }; return $out }
    foreach ($p in $Object.PSObject.Properties) { $out[$p.Name] = [string]$p.Value }
    $out
}

function Test-GapsioAntiPhishPolicyMatch {
    # Audit ObjectId vs. EmailEvents policy name: compare case-insensitively, tolerate tenant prefixes / suffixes.
    param([string]$AuditName, [string]$EventPolicy)
    if (-not $AuditName -or -not $EventPolicy) { return $false }
    $a = $AuditName.Trim().ToLowerInvariant(); $e = $EventPolicy.Trim().ToLowerInvariant()
    if ($a -eq $e) { return $true }
    if ($a.Length -ge 4 -and ($e.Contains($a) -or $a.Contains($e))) { return $true }
    # "Office365 AntiPhish Default" vs "Office365 AntiPhish Default (Default)" etc.
    $strip = { param($s) ($s -replace '\s*\(.*?\)\s*', '' -replace '[^a-z0-9]', '') }
    (& $strip $a) -eq (& $strip $e)
}

function Measure-GapsioAntiPhishWindow {
    # Aggregates daily rows for a policy filter over [From, To) days.
    param([object[]]$Daily, [string]$Policy, [datetime]$From, [datetime]$To)
    $sum = [ordered]@{ events = 0; Quarantine = 0; Junk = 0; Delivered = 0; Block = 0; Other = 0; days = 0 }
    $daysSeen = @{}
    foreach ($d in $Daily) {
        $day = [datetime]$d.day
        if ($day -lt $From -or $day -ge $To) { continue }
        if ($Policy -and -not (Test-GapsioAntiPhishPolicyMatch -AuditName $Policy -EventPolicy ([string]$d.policy))) { continue }
        $n = [int]$d.events
        $sum.events += $n
        $o = [string]$d.outcome; if ($sum.Contains($o)) { $sum[$o] += $n } else { $sum.Other += $n }
        $daysSeen[$day.ToString('yyyy-MM-dd')] = $true
    }
    $sum.days = $daysSeen.Count
    $sum.deliveredPct = if ($sum.events -gt 0) { [math]::Round(100.0 * $sum.Delivered / $sum.events, 1) } else { $null }
    $sum.caughtPct = if ($sum.events -gt 0) { [math]::Round(100.0 * ($sum.Quarantine + $sum.Junk + $sum.Block) / $sum.events, 1) } else { $null }
    $sum
}

function Update-GapsioOfficeAntiPhishHistory {
    <#
    .SYNOPSIS
    Reads anti-phish settings changes + phish outcomes per policy/day from Advanced Hunting, merges them into
    state/office-antiphish-history.json and returns the compact object embedded into the office preview snapshot.
    Returns @{ antiphish = <object>; rows = @(probe rows); findings = @(findings) }.
    #>
    $now = [DateTime]::UtcNow
    $probeRows = [System.Collections.Generic.List[object]]::new()
    $findings = [System.Collections.Generic.List[object]]::new()
    $caveats = [System.Collections.Generic.List[string]]::new()

    # ---- 1. Load history ---------------------------------------------------------------------------------------
    $history = $null
    try { $history = Get-GapsioBlob -Container 'state' -Name 'office-antiphish-history.json' } catch { Add-GapsioWarning "anti-phish history: $($_.Exception.Message)" }
    $changes = @{}   # key -> ordered
    $daily = @{}     # key -> ordered
    foreach ($c in @(Get-GapsioProp $history 'changes')) {
        if ($null -eq $c) { continue }
        $ts = ConvertTo-GapsioIsoTs $c.ts
        $k = "$ts|$($c.cmdlet)|$($c.policy)"
        $changes[$k] = [ordered]@{ ts = $ts; cmdlet = [string]$c.cmdlet; policy = [string]$c.policy; actor = [string]$c.actor; result = [string]$c.result; settings = (ConvertTo-GapsioAntiPhishMap (Get-GapsioProp $c 'settings')) }
    }
    foreach ($d in @(Get-GapsioProp $history 'daily')) {
        if ($null -eq $d) { continue }
        $day = ConvertTo-GapsioDayKey $d.day
        $k = "$day|$($d.policy)|$($d.method)|$($d.outcome)|$($d.confidence)"
        $daily[$k] = [ordered]@{ day = $day; policy = [string]$d.policy; method = [string]$d.method; outcome = [string]$d.outcome; confidence = [string]$d.confidence; events = [int]$d.events }
    }
    $historySince = if (Get-GapsioProp $history 'since') { ConvertTo-GapsioIsoTs (Get-GapsioProp $history 'since') } else { $now.ToString('o') }

    # ---- 2. Settings changes (Exchange admin audit via CloudAppEvents) ----------------------------------------
    $newChanges = 0
    try {
        $r = @(Invoke-GapsioHuntingSafe -NoShard -Context 'office preview antiphish_policy_changes' -Timespan 'P30D' -Query $script:GapsioAntiPhishChangesQuery)
        foreach ($x in $r) {
            if ($null -eq $x) { continue }
            $ts = ConvertTo-GapsioIsoTs $x.Timestamp
            $cmdlet = [string]$x.ActionType
            $policy = [string]$x.Policy
            $k = "$ts|$cmdlet|$policy"
            if ($changes.ContainsKey($k)) { continue }
            $changes[$k] = [ordered]@{ ts = $ts; cmdlet = $cmdlet; policy = $policy; actor = [string]$x.Actor; result = [string]$x.Result; settings = (ConvertFrom-GapsioAntiPhishParams -Json ([string]$x.Params)) }
            $newChanges++
        }
        $probeRows.Add([ordered]@{ key = 'antiphish_policy_changes'; title = 'Anti-phish policy changes (Exchange admin audit)'; workload = 'Anti-phish drift'; status = 'ok'; error = $null; result = @([ordered]@{ rows = $r.Count; newChanges = $newChanges; tracked = $changes.Count }) })
        if ($r.Count -eq 0) { $caveats.Add('No anti-phish cmdlet activity found in CloudAppEvents for the last 30 days. Settings history starts with the first change observed after installation; the current absolute state cannot be read via Advanced Hunting.') }
    }
    catch {
        $probeRows.Add([ordered]@{ key = 'antiphish_policy_changes'; title = 'Anti-phish policy changes (Exchange admin audit)'; workload = 'Anti-phish drift'; status = 'error'; error = [string]$_.Exception.Message; result = @() })
    }

    # ---- 3. Outcomes per policy/day ---------------------------------------------------------------------------
    try {
        $r = @(Invoke-GapsioHuntingSafe -NoShard -Context 'office preview antiphish_outcomes' -Timespan 'P30D' -Query $script:GapsioAntiPhishOutcomesQuery)
        $windowDays = @{}
        foreach ($x in $r) { if ($x) { $windowDays[(ConvertTo-GapsioDayKey $x.day)] = $true } }
        # Days re-read from hunting replace what we had for those days (counts can still move for the current day).
        if ($windowDays.Count) { foreach ($k in @($daily.Keys)) { if ($windowDays.ContainsKey($daily[$k].day)) { $daily.Remove($k) } } }
        foreach ($x in $r) {
            if ($null -eq $x) { continue }
            $day = ConvertTo-GapsioDayKey $x.day
            $row = [ordered]@{ day = $day; policy = [string]$x.Policy; method = [string]$x.Method; outcome = [string]$x.Outcome; confidence = [string]$x.Confidence; events = [int]$x.events }
            $daily["$day|$($row.policy)|$($row.method)|$($row.outcome)|$($row.confidence)"] = $row
        }
        $probeRows.Add([ordered]@{ key = 'antiphish_outcomes'; title = 'Phish outcomes per policy (daily)'; workload = 'Anti-phish drift'; status = 'ok'; error = $null; result = @([ordered]@{ rows = $r.Count; days = $windowDays.Count; policies = @($r | ForEach-Object { $_.Policy } | Sort-Object -Unique).Count }) })
    }
    catch {
        $probeRows.Add([ordered]@{ key = 'antiphish_outcomes'; title = 'Phish outcomes per policy (daily)'; workload = 'Anti-phish drift'; status = 'error'; error = [string]$_.Exception.Message; result = @() })
    }

    # ---- 4. Trim + persist ------------------------------------------------------------------------------------
    $keepFrom = $now.AddDays(-400)
    $changeList = @($changes.Values | Where-Object { ([datetime]$_.ts) -ge $keepFrom } | Sort-Object { [datetime]$_.ts })
    $dailyList = @($daily.Values | Where-Object { ([datetime]$_.day) -ge $keepFrom } | Sort-Object { $_.day }, { $_.policy }, { $_.method }, { $_.outcome })
    $hist = [ordered]@{ version = 1; since = $historySince; updatedAt = $now.ToString('o'); changes = $changeList; daily = $dailyList }
    try { Set-GapsioBlob -Container 'state' -Name 'office-antiphish-history.json' -Object $hist -Depth 16 } catch { Add-GapsioWarning "anti-phish history write: $($_.Exception.Message)" }

    # ---- 5. Derive policy state, per-change effects, periods ---------------------------------------------------
    $tracked = $script:GapsioAntiPhishKeySettings
    $policyState = [ordered]@{}   # name -> @{ settings = ordered name -> @{ value; since; actor }; lastChange; kind }
    $effects = [System.Collections.Generic.List[object]]::new()
    $events = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $changeList) {
        $name = if ($c.policy) { $c.policy } else { '(unknown)' }
        if (-not $policyState.Contains($name)) { $policyState[$name] = [ordered]@{ policy = $name; kind = $(if ($c.cmdlet -like '*Rule') { 'rule' } else { 'policy' }); settings = [ordered]@{}; lastChange = $null; changes = 0; removed = $false } }
        $ps = $policyState[$name]
        $ps.lastChange = $c.ts; $ps.changes++
        if ($c.cmdlet -like 'Remove-*') { $ps.removed = $true }
        if ($c.cmdlet -like 'Enable-AntiPhishRule') { $c.settings['Enabled'] = 'True' }
        if ($c.cmdlet -like 'Disable-AntiPhishRule') { $c.settings['Enabled'] = 'False' }
        $diffs = [System.Collections.Generic.List[object]]::new()
        foreach ($sn in @($c.settings.Keys)) {
            $after = [string]$c.settings[$sn]
            $prev = if ($ps.settings.Contains($sn)) { [string]$ps.settings[$sn].value } else { $null }
            $isTracked = $tracked -contains $sn
            if ($null -ne $prev -and $prev -eq $after) { continue }
            $dir = if ($null -ne $prev) { Get-GapsioAntiPhishChangeDirection -Name $sn -Before $prev -After $after } else { 'neutral' }
            $diffs.Add([ordered]@{ setting = $sn; before = $prev; after = $after; direction = $dir; tracked = $isTracked })
            $ps.settings[$sn] = [ordered]@{ value = $after; since = $c.ts; actor = $c.actor }
        }
        $ev = [ordered]@{ ts = $c.ts; cmdlet = $c.cmdlet; policy = $name; actor = $c.actor; result = $c.result; diffs = @($diffs); weaker = @($diffs | Where-Object { $_.direction -eq 'weaker' }).Count; stronger = @($diffs | Where-Object { $_.direction -eq 'stronger' }).Count }
        $events.Add($ev)

        # Before/after effect window (7 days each) for changes that touch effect-relevant settings or the rule state.
        $relevant = @($diffs | Where-Object { $_.tracked }).Count -gt 0 -or $c.cmdlet -like 'Remove-*' -or $c.cmdlet -like '*able-AntiPhishRule'
        if (-not $relevant) { continue }
        $t = ([datetime]$c.ts).ToUniversalTime().Date
        $scopePolicy = $name
        $matchAny = @($dailyList | Where-Object { Test-GapsioAntiPhishPolicyMatch -AuditName $name -EventPolicy ([string]$_.policy) }).Count -gt 0
        if (-not $matchAny) { $scopePolicy = $null }
        $before = Measure-GapsioAntiPhishWindow -Daily $dailyList -Policy $scopePolicy -From $t.AddDays(-7) -To $t
        $after = Measure-GapsioAntiPhishWindow -Daily $dailyList -Policy $scopePolicy -From $t -To $t.AddDays(7)
        $delta = if ($null -ne $before.deliveredPct -and $null -ne $after.deliveredPct) { [math]::Round($after.deliveredPct - $before.deliveredPct, 1) } else { $null }
        $effects.Add([ordered]@{
                ts = $c.ts; policy = $name; cmdlet = $c.cmdlet; actor = $c.actor
                scope = $(if ($scopePolicy) { 'policy' } else { 'all' })
                changed = @($diffs | Where-Object { $_.tracked } | ForEach-Object { "$($_.setting): $(if ($null -ne $_.before) { "$($_.before) → " })$($_.after)" })
                weaker = $ev.weaker; stronger = $ev.stronger
                before = $before; after = $after
                afterComplete = ($now -ge $t.AddDays(7))
                deliveredDelta = $delta
            })
    }

    # Periods: for each policy with events, the stretches between change events with aggregated outcomes.
    $policyNames = @($dailyList | ForEach-Object { $_.policy } | Sort-Object -Unique)
    $periods = [System.Collections.Generic.List[object]]::new()
    $minDay = if ($dailyList.Count) { [datetime]($dailyList | Sort-Object { $_.day } | Select-Object -First 1).day } else { $now.Date }
    foreach ($pn in $policyNames) {
        $cuts = @($events | Where-Object { $_.policy -and (Test-GapsioAntiPhishPolicyMatch -AuditName $_.policy -EventPolicy $pn) -and @($_.diffs | Where-Object { $_.tracked }).Count -gt 0 } | ForEach-Object { ([datetime]$_.ts).ToUniversalTime().Date } | Sort-Object -Unique)
        $bounds = @($minDay) + @($cuts | Where-Object { $_ -gt $minDay }) + @($now.Date.AddDays(1))
        $state = [ordered]@{}
        for ($i = 0; $i -lt $bounds.Count - 1; $i++) {
            $from = $bounds[$i]; $to = $bounds[$i + 1]
            # Settings in effect during this period = last known values before $to (from matching change events).
            foreach ($e in @($events | Where-Object { $_.policy -and (Test-GapsioAntiPhishPolicyMatch -AuditName $_.policy -EventPolicy $pn) -and ([datetime]$_.ts).ToUniversalTime().Date -lt $to -and ($i -eq 0 -or ([datetime]$_.ts).ToUniversalTime().Date -ge $from) })) {
                foreach ($d in $e.diffs) { if ($d.tracked) { $state[$d.setting] = $d.after } }
            }
            $m = Measure-GapsioAntiPhishWindow -Daily $dailyList -Policy $pn -From $from -To $to
            if ($m.events -eq 0 -and $i -gt 0 -and $i -lt $bounds.Count - 2) { continue }
            $snap = [ordered]@{}; foreach ($k in $state.Keys) { $snap[$k] = $state[$k] }
            $periods.Add([ordered]@{ policy = $pn; from = $from.ToString('yyyy-MM-dd'); to = $to.AddDays(-1).ToString('yyyy-MM-dd'); current = ($i -eq $bounds.Count - 2); settings = $snap; threshold = $(if ($snap.Contains('PhishThresholdLevel')) { $snap['PhishThresholdLevel'] } else { $null }); outcomes = $m })
        }
    }

    # Per-policy, per-method 30-day summary for the UI matrix.
    $since30 = $now.Date.AddDays(-30)
    $matrix = @($dailyList | Where-Object { ([datetime]$_.day) -ge $since30 } | Group-Object { "$($_.policy)|$($_.method)" } | ForEach-Object {
            $g = $_.Group; $first = $g[0]
            $m = [ordered]@{ policy = $first.policy; method = $first.method; events = 0; Quarantine = 0; Junk = 0; Delivered = 0; Block = 0; Other = 0; high = 0 }
            foreach ($x in $g) { $m.events += $x.events; $m[$x.outcome] += $x.events; if ($x.confidence -eq 'High') { $m.high += $x.events } }
            $m.deliveredPct = if ($m.events) { [math]::Round(100.0 * $m.Delivered / $m.events, 1) } else { $null }
            $m
        } | Sort-Object { -$_.events })

    # ---- 6. Findings ------------------------------------------------------------------------------------------
    $recent = @($events | Where-Object { ([datetime]$_.ts) -ge $now.AddDays(-30) })
    $weakened = @($recent | Where-Object { $_.weaker -gt 0 })
    if ($weakened.Count) {
        $names = @($weakened | ForEach-Object { $_.policy } | Sort-Object -Unique) -join ', '
        $what = @($weakened | ForEach-Object { $_.diffs | Where-Object { $_.direction -eq 'weaker' } | ForEach-Object { "$($_.setting) $($_.before)→$($_.after)" } } | Select-Object -First 6) -join '; '
        $findings.Add([ordered]@{ id = 'office.antiphish_weakened'; severity = 'High'; category = 'mdo'; subject = 'antiphish'; title = @{ en = 'Anti-phish protection was weakened'; de = 'Anti-Phishing-Schutz wurde abgeschwächt' }; detail = @{ en = "$($weakened.Count) change(s) in 30 days lowered protection on: $names ($what)."; de = "$($weakened.Count) Änderung(en) in 30 Tagen haben den Schutz gesenkt bei: $names ($what)." }; recommendation = @{ en = 'Confirm the change was intended (change ticket) and compare delivered-phish rate before/after in the drift view.'; de = 'Prüfen, ob die Änderung beabsichtigt war (Change-Ticket) und die Zustellrate vor/nach in der Drift-Ansicht vergleichen.' } })
    }
    $worse = @($effects | Where-Object { $_.afterComplete -and $null -ne $_.deliveredDelta -and $_.deliveredDelta -ge 10 -and $_.after.events -ge 20 })
    if ($worse.Count) {
        $w = $worse | Sort-Object { -$_.deliveredDelta } | Select-Object -First 1
        $findings.Add([ordered]@{ id = 'office.antiphish_delivery_up'; severity = 'Medium'; category = 'mdo'; subject = 'antiphish'; title = @{ en = 'More phish delivered after a policy change'; de = 'Nach einer Policy-Änderung wurde mehr Phishing zugestellt' }; detail = @{ en = "'$($w.policy)' ($($w.cmdlet), $(([datetime]$w.ts).ToString('yyyy-MM-dd'))): delivered share $($w.before.deliveredPct)% → $($w.after.deliveredPct)% (7 days before/after, $($w.after.events) phish messages after)."; de = "'$($w.policy)' ($($w.cmdlet), $(([datetime]$w.ts).ToString('yyyy-MM-dd'))): Zustellanteil $($w.before.deliveredPct)% → $($w.after.deliveredPct)% (7 Tage vorher/nachher, $($w.after.events) Phishing-Nachrichten danach)." }; recommendation = @{ en = 'Review the changed settings (threshold, impersonation/spoof actions, exclusions) and roll back or tune.'; de = 'Geänderte Einstellungen (Threshold, Impersonation-/Spoof-Aktionen, Ausnahmen) prüfen und zurückrollen oder nachjustieren.' } })
    }
    $noActor = @($recent | Where-Object { $_.result -and $_.result -ne 'True' -and $_.result -ne 'Success' })
    if ($noActor.Count) { $caveats.Add("$($noActor.Count) audited cmdlet call(s) did not report success; they are listed but may not have taken effect.") }
    $caveats.Add('Policy names in mail telemetry (OrgLevelPolicy/UserLevelPolicy) are matched to audit object names heuristically; preset policies may appear under a different label.')
    $caveats.Add('Threshold 1 = Standard, 2 = Aggressive, 3 = More aggressive, 4 = Most aggressive. Effects are measured as 7 days before vs. 7 days after a change on phish-classified mail only.')

    $antiphish = [ordered]@{
        historySince = $historySince
        historyDays = [int][math]::Ceiling(($now - [datetime]$historySince).TotalDays)
        changes = @($events | Sort-Object { [datetime]$_.ts } -Descending | Select-Object -First 200)
        policies = @($policyState.Values)
        effects = @($effects | Sort-Object { [datetime]$_.ts } -Descending)
        periods = @($periods)
        matrix = @($matrix)
        daily = @($dailyList | Where-Object { ([datetime]$_.day) -ge $now.Date.AddDays(-90) })
        caveats = @($caveats)
    }
    @{ antiphish = $antiphish; rows = @($probeRows); findings = @($findings) }
}
