#Requires -Version 7.2
<#
.SYNOPSIS
    Fictitious snapshots for the private-preview modules (officepreview, purviewpreview) used by New-GapsioDemo.ps1.

.DESCRIPTION
    Both modules read Advanced Hunting only, which the test tenant in tests/Test-Gapsio.ps1 does not simulate. These
    snapshots follow the shape the collectors write (Invoke-GapsioOfficePreviewCollection with the anti-phish history,
    Invoke-GapsioPurviewPreviewCollection), with dates relative to now and a fixed random seed, so the demo and the
    website screenshots are reproducible. All names are made up; mail addresses use contoso.example.
#>

function Get-GapsioPreviewDemoData {
    param([DateTime]$Now = [DateTime]::UtcNow, [int]$Seed = 7)
    $rand = [Random]::new($Seed)
    $iso = { param([DateTime]$d) $d.ToString('o') }
    $days = @(29..0 | ForEach-Object { $Now.Date.AddDays(-$_) })
    $T = { param($en, $de) [ordered]@{ en = $en; de = $de } }

    # ---------------------------------------------------------------- Office preview (Defender for Office 365)
    $threatDaily = foreach ($d in $days) {
        foreach ($b in @(@{ k = 'Phish'; n = 38 }, @{ k = 'Malware'; n = 6 }, @{ k = 'Spam'; n = 410 }, @{ k = 'Bulk'; n = 190 })) {
            $spike = if ($b.k -eq 'Phish' -and $d -ge $Now.Date.AddDays(-9) -and $d -le $Now.Date.AddDays(-6)) { 2.6 } else { 1 }
            [ordered]@{ day = (& $iso $d); bucket = $b.k; events = [int]([Math]::Max(0, $b.n * $spike + $rand.Next(-[int]($b.n / 4), [int]($b.n / 4) + 1))) }
        }
    }
    $actionDaily = foreach ($d in $days) {
        $weak = $d -ge $Now.Date.AddDays(-12)
        foreach ($b in @(@{ k = 'Block'; n = 120 }, @{ k = 'Quarantine'; n = $(if ($weak) { 22 } else { 41 }) }, @{ k = 'Junk'; n = 380 }, @{ k = 'Allow'; n = $(if ($weak) { 2310 } else { 2240 }) })) {
            [ordered]@{ day = (& $iso $d); bucket = $b.k; events = [int]($b.n + $rand.Next(-[int]($b.n / 6), [int]($b.n / 6) + 1)) }
        }
    }
    $policies = @('Strict Preset Security Policy', 'Office365 AntiPhish Default (Default)', 'Contoso Executives')
    $changeTs = $Now.Date.AddDays(-12).AddHours(9).AddMinutes(41)
    $hardenTs = $Now.Date.AddDays(-47).AddHours(14).AddMinutes(5)
    $daily = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @(89..0 | ForEach-Object { $Now.Date.AddDays(-$_) })) {
        foreach ($p in $policies) {
            $base = switch ($p) { 'Contoso Executives' { 9 } 'Strict Preset Security Policy' { 4 } default { 26 } }
            $deliveredShare = if ($p -eq 'Contoso Executives' -and $d -ge $changeTs.Date) { 0.31 } elseif ($p -eq 'Contoso Executives') { 0.06 } else { 0.08 }
            $n = [Math]::Max(0, $base + $rand.Next(-3, 4))
            $del = [int][Math]::Round($n * $deliveredShare)
            $q = [int][Math]::Round(($n - $del) * 0.7); $j = $n - $del - $q
            foreach ($o in @(@{ k = 'Delivered'; v = $del }, @{ k = 'Quarantine'; v = $q }, @{ k = 'Junk'; v = $j })) {
                if ($o.v -gt 0) { $daily.Add([ordered]@{ policy = $p; day = $d.ToString('yyyy-MM-dd'); method = $(if ($p -eq 'Contoso Executives') { 'Impersonation user' } else { 'Spoof DMARC' }); confidence = $(if ($rand.Next(0, 3) -eq 0) { 'High' } else { 'Normal' }); outcome = $o.k; events = $o.v }) }
            }
        }
    }
    $win = {
        param($p, [DateTime]$from, [DateTime]$to)
        $rows = @($daily | Where-Object { $_.policy -eq $p -and [DateTime]$_.day -ge $from.Date -and [DateTime]$_.day -lt $to.Date })
        $m = [ordered]@{ events = 0; Quarantine = 0; Junk = 0; Delivered = 0; Block = 0; Other = 0 }
        foreach ($r in $rows) { $m.events += $r.events; $m[$r.outcome] += $r.events }
        $m.deliveredPct = if ($m.events) { [Math]::Round(100.0 * $m.Delivered / $m.events, 1) } else { $null }
        $m
    }
    $changes = @(
        [ordered]@{ ts = (& $iso $changeTs); policy = 'Contoso Executives'; cmdlet = 'Set-AntiPhishPolicy'; actor = 'lena.keller@contoso.example'; result = 'True'; weaker = 2; stronger = 0
            diffs = @(
                [ordered]@{ setting = 'PhishThresholdLevel'; before = '3'; after = '1'; direction = 'weaker'; tracked = $true },
                [ordered]@{ setting = 'TargetedUserProtectionAction'; before = 'Quarantine'; after = 'MoveToJmf'; direction = 'weaker'; tracked = $true }) }
        [ordered]@{ ts = (& $iso $Now.Date.AddDays(-12).AddHours(9).AddMinutes(44)); policy = 'Contoso Executives'; cmdlet = 'Set-AntiPhishRule'; actor = 'lena.keller@contoso.example'; result = 'True'; weaker = 0; stronger = 0
            diffs = @([ordered]@{ setting = 'Priority'; before = '0'; after = '1'; direction = 'neutral'; tracked = $false }) }
        [ordered]@{ ts = (& $iso $hardenTs); policy = 'Office365 AntiPhish Default'; cmdlet = 'Set-AntiPhishPolicy'; actor = 'sven.roth@contoso.example'; result = 'True'; weaker = 0; stronger = 2
            diffs = @(
                [ordered]@{ setting = 'EnableMailboxIntelligenceProtection'; before = 'False'; after = 'True'; direction = 'stronger'; tracked = $true },
                [ordered]@{ setting = 'PhishThresholdLevel'; before = '1'; after = '2'; direction = 'stronger'; tracked = $true }) }
        [ordered]@{ ts = (& $iso $Now.Date.AddDays(-63).AddHours(11)); policy = 'Contoso Executives'; cmdlet = 'New-AntiPhishPolicy'; actor = 'sven.roth@contoso.example'; result = 'True'; weaker = 0; stronger = 0
            diffs = @(
                [ordered]@{ setting = 'PhishThresholdLevel'; before = $null; after = '3'; direction = 'neutral'; tracked = $true },
                [ordered]@{ setting = 'TargetedUserProtectionAction'; before = $null; after = 'Quarantine'; direction = 'neutral'; tracked = $true },
                [ordered]@{ setting = 'EnableTargetedUserProtection'; before = $null; after = 'True'; direction = 'neutral'; tracked = $true }) }
    )
    $effects = @(
        [ordered]@{ ts = $changes[0].ts; policy = 'Contoso Executives'; cmdlet = 'Set-AntiPhishPolicy'; actor = $changes[0].actor; scope = 'policy'
            changed = @('PhishThresholdLevel: 3 → 1', 'TargetedUserProtectionAction: Quarantine → MoveToJmf'); weaker = 2; stronger = 0
            before = (& $win 'Contoso Executives' $changeTs.AddDays(-7) $changeTs); after = (& $win 'Contoso Executives' $changeTs $changeTs.AddDays(7)); afterComplete = $true }
        [ordered]@{ ts = $changes[2].ts; policy = 'Office365 AntiPhish Default'; cmdlet = 'Set-AntiPhishPolicy'; actor = $changes[2].actor; scope = 'policy'
            changed = @('EnableMailboxIntelligenceProtection: False → True', 'PhishThresholdLevel: 1 → 2'); weaker = 0; stronger = 2
            before = (& $win 'Office365 AntiPhish Default (Default)' $hardenTs.AddDays(-7) $hardenTs); after = (& $win 'Office365 AntiPhish Default (Default)' $hardenTs $hardenTs.AddDays(7)); afterComplete = $true }
    )
    foreach ($e in $effects) { $e.deliveredDelta = if ($null -ne $e.before.deliveredPct -and $null -ne $e.after.deliveredPct) { [Math]::Round($e.after.deliveredPct - $e.before.deliveredPct, 1) } else { $null } }
    $since30 = $Now.Date.AddDays(-30)
    $matrix = @($daily | Where-Object { [DateTime]$_.day -ge $since30 } | Group-Object { "$($_.policy)|$($_.method)" } | ForEach-Object {
            $m = [ordered]@{ policy = $_.Group[0].policy; method = $_.Group[0].method; events = 0; Quarantine = 0; Junk = 0; Delivered = 0; Block = 0; Other = 0; high = 0 }
            foreach ($x in $_.Group) { $m.events += $x.events; $m[$x.outcome] += $x.events; if ($x.confidence -eq 'High') { $m.high += $x.events } }
            $m.deliveredPct = if ($m.events) { [Math]::Round(100.0 * $m.Delivered / $m.events, 1) } else { $null }
            $m
        } | Sort-Object { -$_.events })
    $periods = @(
        [ordered]@{ policy = 'Contoso Executives'; from = $Now.Date.AddDays(-89).ToString('yyyy-MM-dd'); to = $changeTs.Date.AddDays(-1).ToString('yyyy-MM-dd'); current = $false; threshold = '3'
            settings = [ordered]@{ PhishThresholdLevel = '3'; TargetedUserProtectionAction = 'Quarantine'; EnableTargetedUserProtection = 'True' }; outcomes = (& $win 'Contoso Executives' $Now.Date.AddDays(-89) $changeTs.Date) }
        [ordered]@{ policy = 'Contoso Executives'; from = $changeTs.Date.ToString('yyyy-MM-dd'); to = $Now.Date.ToString('yyyy-MM-dd'); current = $true; threshold = '1'
            settings = [ordered]@{ PhishThresholdLevel = '1'; TargetedUserProtectionAction = 'MoveToJmf'; EnableTargetedUserProtection = 'True' }; outcomes = (& $win 'Contoso Executives' $changeTs.Date $Now.Date.AddDays(1)) }
        [ordered]@{ policy = 'Office365 AntiPhish Default (Default)'; from = $hardenTs.Date.ToString('yyyy-MM-dd'); to = $Now.Date.ToString('yyyy-MM-dd'); current = $true; threshold = '2'
            settings = [ordered]@{ PhishThresholdLevel = '2'; EnableMailboxIntelligenceProtection = 'True' }; outcomes = (& $win 'Office365 AntiPhish Default (Default)' $hardenTs.Date $Now.Date.AddDays(1)) }
    )
    $ex = $effects[0]
    $office = [ordered]@{
        generatedAt = (& $iso $Now.AddMinutes(-18)); windowDays = 30; ok = 19; errors = 0
        results = @(
            [ordered]@{ key = 'override_exposure'; title = 'Threat overrides that delivered mail'; workload = 'Email'; status = 'ok'; result = @([ordered]@{ rows = 84210; overridden = 37; dmarcFail = 412 }) }
            [ordered]@{ key = 'safelinks_clickthrough'; title = 'Safe Links click-through events'; workload = 'Email'; status = 'ok'; result = @([ordered]@{ rows = 1830; clickThrough = 23; uniqueUsers = 17; uniqueUrls = 21 }) }
            [ordered]@{ key = 'threat_trend_daily'; title = 'Threat trend (daily)'; workload = 'Dashboard'; status = 'ok'; result = @($threatDaily) }
            [ordered]@{ key = 'action_trend_daily'; title = 'Action outcomes (daily)'; workload = 'Dashboard'; status = 'ok'; result = @($actionDaily) }
            [ordered]@{ key = 'action_values_top'; title = 'Raw action values (top)'; workload = 'Dashboard'; status = 'ok'; result = @(
                    [ordered]@{ EffectiveAction = 'delivered to inbox'; events = 67210 }, [ordered]@{ EffectiveAction = 'moved to junk folder'; events = 11380 },
                    [ordered]@{ EffectiveAction = 'blocked'; events = 3604 }, [ordered]@{ EffectiveAction = 'quarantine'; events = 941 }) }
            [ordered]@{ key = 'campaign_top'; title = 'Top campaigns / themes'; workload = 'Dashboard'; status = 'ok'; result = @(
                    [ordered]@{ Campaign = 'Invoice overdue – shared document'; events = 312; recipients = 141 }, [ordered]@{ Campaign = 'Payroll update (credential phish)'; events = 188; recipients = 96 },
                    [ordered]@{ Campaign = 'Threat: Phish'; events = 121; recipients = 77 }, [ordered]@{ Campaign = 'Parcel delivery notice'; events = 64; recipients = 59 }) }
            [ordered]@{ key = 'zap_blind_spots'; title = 'Likely ZAP blind spots'; workload = 'Email'; status = 'ok'; result = @([ordered]@{ rows = 84210; withoutPost = 61 }) }
            [ordered]@{ key = 'own_domain_auth_posture'; title = 'Inbound mail with weak auth posture'; workload = 'Email auth'; status = 'ok'; result = @([ordered]@{ rows = 84210; dmarcFail = 412; spfFail = 958; dkimFail = 233 }) }
            [ordered]@{ key = 'first_contact_risk'; title = 'First-contact messages with URLs/attachments'; workload = 'Email'; status = 'ok'; result = @([ordered]@{ rows = 84210; firstContact = 5120; withThreat = 344 }) }
            [ordered]@{ key = 'encrypted_attachment_volume'; title = 'Encrypted/password-protected attachments'; workload = 'Email attachments'; status = 'ok'; result = @([ordered]@{ rows = 9112; encrypted = 58; uniqueSenders = 31 }) }
            [ordered]@{ key = 'tabl_ioc_coverage'; title = 'Tenant allow/block list and indicators'; workload = 'TABL'; status = 'ok'; result = @([ordered]@{ total = 64; active = 51; expiring14d = 6 }) }
            [ordered]@{ key = 'tabl_ioc_actions'; title = 'Indicator actions by type'; workload = 'TABL'; status = 'ok'; result = @(
                    [ordered]@{ IndicatorType = 'Domain'; Action = 'Block'; indicators = 28 }, [ordered]@{ IndicatorType = 'Url'; Action = 'Block'; indicators = 17 },
                    [ordered]@{ IndicatorType = 'EmailSender'; Action = 'Allow'; indicators = 12 }, [ordered]@{ IndicatorType = 'FileHash'; Action = 'Block'; indicators = 7 }) }
            [ordered]@{ key = 'effective_policy_map_users'; title = 'Effective policy map (recipients)'; workload = 'Policy map'; status = 'ok'; result = @(
                    [ordered]@{ Recipient = 'ceo@contoso.example'; events = 412; policies = 2; actions = @('quarantine', 'moved to junk folder'); policySet = @('Contoso Executives', 'Office365 AntiPhish Default (Default)') },
                    [ordered]@{ Recipient = 'cfo@contoso.example'; events = 377; policies = 2; actions = @('delivered to inbox', 'quarantine'); policySet = @('Contoso Executives', 'Office365 AntiPhish Default (Default)') },
                    [ordered]@{ Recipient = 'payroll@contoso.example'; events = 260; policies = 1; actions = @('moved to junk folder'); policySet = @('Office365 AntiPhish Default (Default)') }) }
            [ordered]@{ key = 'effective_policy_map_domains'; title = 'Effective policy map (domains)'; workload = 'Policy map'; status = 'ok'; result = @(
                    [ordered]@{ Domain = 'contoso.example'; events = 9810; users = 412; policies = 3; actions = @('delivered to inbox', 'quarantine', 'moved to junk folder'); policySet = $policies }) }
            [ordered]@{ key = 'antiphish_policy_changes'; title = 'Anti-phish policy and rule changes'; workload = 'Anti-phish'; status = 'ok'; result = @([ordered]@{ rows = $changes.Count; newChanges = 2; tracked = 3 }) }
            [ordered]@{ key = 'antiphish_outcomes'; title = 'Phish outcomes per policy (daily)'; workload = 'Anti-phish'; status = 'ok'; result = @([ordered]@{ rows = $daily.Count; days = 90; policies = $policies.Count }) }
        )
        findings = @(
            [ordered]@{ id = 'office.antiphish_weakened'; severity = 'High'; category = 'mdo'; subject = 'antiphish'
                title = (& $T 'Anti-phish protection was weakened' 'Anti-Phishing-Schutz wurde abgeschwächt')
                detail = (& $T '1 change(s) in 30 days lowered protection on: Contoso Executives (PhishThresholdLevel 3→1; TargetedUserProtectionAction Quarantine→MoveToJmf).' '1 Änderung(en) in 30 Tagen haben den Schutz gesenkt bei: Contoso Executives (PhishThresholdLevel 3→1; TargetedUserProtectionAction Quarantine→MoveToJmf).')
                recommendation = (& $T 'Confirm the change was intended (change ticket) and compare delivered-phish rate before/after in the drift view.' 'Prüfen, ob die Änderung beabsichtigt war (Change-Ticket) und die Zustellrate vor/nach in der Drift-Ansicht vergleichen.') }
            [ordered]@{ id = 'office.antiphish_delivery_up'; severity = 'Medium'; category = 'mdo'; subject = 'antiphish'
                title = (& $T 'More phish delivered after a policy change' 'Nach einer Policy-Änderung wurde mehr Phishing zugestellt')
                detail = (& $T "'Contoso Executives' (Set-AntiPhishPolicy, $($changeTs.ToString('yyyy-MM-dd'))): delivered share $($ex.before.deliveredPct)% → $($ex.after.deliveredPct)% (7 days before/after, $($ex.after.events) phish messages after)." "'Contoso Executives' (Set-AntiPhishPolicy, $($changeTs.ToString('yyyy-MM-dd'))): Zustellanteil $($ex.before.deliveredPct)% → $($ex.after.deliveredPct)% (7 Tage vorher/nachher, $($ex.after.events) Phishing-Nachrichten danach).")
                recommendation = (& $T 'Review the changed settings (threshold, impersonation/spoof actions, exclusions) and roll back or tune.' 'Geänderte Einstellungen (Threshold, Impersonation-/Spoof-Aktionen, Ausnahmen) prüfen und zurückrollen oder nachjustieren.') }
        )
        antiphish = [ordered]@{
            historySince = (& $iso $Now.Date.AddDays(-214)); historyDays = 214
            changes = $changes
            policies = @(
                [ordered]@{ policy = 'Contoso Executives'; lastChange = $changes[0].ts; removed = $false; settings = [ordered]@{
                        PhishThresholdLevel = [ordered]@{ value = '1'; since = $changes[0].ts; actor = 'lena.keller@contoso.example' }
                        TargetedUserProtectionAction = [ordered]@{ value = 'MoveToJmf'; since = $changes[0].ts; actor = 'lena.keller@contoso.example' }
                        EnableTargetedUserProtection = [ordered]@{ value = 'True'; since = $changes[3].ts; actor = 'sven.roth@contoso.example' } } }
                [ordered]@{ policy = 'Office365 AntiPhish Default'; lastChange = $changes[2].ts; removed = $false; settings = [ordered]@{
                        PhishThresholdLevel = [ordered]@{ value = '2'; since = $changes[2].ts; actor = 'sven.roth@contoso.example' }
                        EnableMailboxIntelligenceProtection = [ordered]@{ value = 'True'; since = $changes[2].ts; actor = 'sven.roth@contoso.example' } } }
            )
            effects = $effects; periods = $periods; matrix = $matrix
            daily = @($daily | Where-Object { [DateTime]$_.day -ge $Now.Date.AddDays(-90) })
            caveats = @(
                'Policy names in mail telemetry (OrgLevelPolicy/UserLevelPolicy) are matched to audit object names heuristically; preset policies may appear under a different label.'
                'Threshold 1 = Standard, 2 = Aggressive, 3 = More aggressive, 4 = Most aggressive. Effects are measured as 7 days before vs. 7 days after a change on phish-classified mail only.')
        }
    }

    # ---------------------------------------------------------------- Purview DLP preview
    $devNames = @('ws-1042', 'ws-1077', 'ws-1103', 'ws-1150', 'ws-1188', 'ws-1201', 'ws-1243', 'ws-1290', 'mbp-2011', 'mbp-2034', 'mbp-2052', 'ws-1311', 'ws-1325', 'ws-1340')
    $devices = @(for ($i = 0; $i -lt $devNames.Count; $i++) {
            $mac = $devNames[$i].StartsWith('mbp')
            $active = $i % 3 -ne 2 -and $devNames[$i] -ne 'mbp-2052'
            $ev = if ($active) { $rand.Next(4, 220) } else { 0 }
            [ordered]@{ device = $devNames[$i]; platform = $(if ($mac) { 'macOS' } else { 'Windows11' }); osVersion = $(if ($mac) { '15.6' } else { '10.0.26100' }); lastSeen = (& $iso $Now.AddHours(-$rand.Next(1, 40)))
                dlpActive = $active; dlpEvents = $ev; dlpLast = $(if ($active) { & $iso $Now.AddHours(-$rand.Next(2, 90)) } else { $null })
                operations = $(if ($active) { @(@('FileCopiedToRemovableMedia', 'FileUploadedToCloud', 'FilePrinted', 'FileCopiedToClipboard') | Select-Object -First ($rand.Next(1, 4))) } else { @() }) }
        })
    $silent = @($devices | Where-Object { -not $_.dlpActive }).Count
    $alertDaily = foreach ($d in $days) {
        foreach ($b in @(@{ k = 'High'; n = 1 }, @{ k = 'Medium'; n = 4 }, @{ k = 'Low'; n = 7 })) {
            $v = [Math]::Max(0, $b.n + $rand.Next(-2, 3)); if ($v) { [ordered]@{ day = (& $iso $d); bucket = $b.k; events = $v } }
        }
    }
    $cap = { param($id, $label, $lic, $en, $co, $sku, $plan) [ordered]@{ id = $id; label = $label; licensed = $lic; enabled = $en; consumed = $co; sources = @($(if ($lic) { [ordered]@{ skuPartNumber = $sku; enabled = $en; consumed = $co; status = 'Enabled'; plans = @("$plan (Success)") } })) } }
    $purview = [ordered]@{
        version = 1; generatedAt = (& $iso $Now.AddMinutes(-22)); windowDays = 30; ok = 12; errors = 0
        summary = [ordered]@{ capableDevices = $devices.Count; dlpActiveDevices = $devices.Count - $silent; silentDevices = $silent; auditFeed = $true; roleHolders = 9; labels = 7 }
        licensing = [ordered]@{
            capabilities = @(
                (& $cap 'endpointdlp' 'Endpoint DLP' $true 250 212 'SPE_E5' 'MICROSOFTENDPOINTDLP')
                (& $cap 'dlpcore' 'DLP for Exchange / SharePoint / OneDrive' $true 400 361 'SPE_E3' 'EXCHANGE_S_ENTERPRISE')
                (& $cap 'dlpteams' 'DLP for Teams chat / advanced DLP (E5)' $true 250 212 'SPE_E5' 'MIP_S_CLP2')
                (& $cap 'labels' 'Sensitivity labels (manual)' $true 400 361 'SPE_E3' 'MIP_S_CLP1')
                (& $cap 'autolabel' 'Auto-labelling / Information Protection premium' $true 250 212 'SPE_E5' 'MIP_S_CLP2')
                (& $cap 'insiderrisk' 'Insider Risk Management' $true 250 212 'SPE_E5' 'INSIDER_RISK')
                (& $cap 'auditpremium' 'Audit (Premium) / long-term retention' $true 250 212 'SPE_E5' 'M365_ADVANCED_AUDITING')
                (& $cap 'agents' 'Purview for AI agents' $false 0 0 $null $null)
            )
            users = [ordered]@{ endpointdlp = 212; mipPremium = 212; mipStandard = 361; insiderRisk = 212 }
        }
        devices = $devices
        roles = @(
            [ordered]@{ role = 'Global Administrator'; scope = 'Full Purview access, incl. DLP policies and content'; assignment = 'active'; principal = 'Nina Vogt'; upn = 'nina.vogt@contoso.example'; type = 'user'; directoryScope = '/' }
            [ordered]@{ role = 'Global Administrator'; scope = 'Full Purview access, incl. DLP policies and content'; assignment = 'eligible'; principal = 'Kai Becker'; upn = 'kai.becker@contoso.example'; type = 'user'; directoryScope = '/' }
            [ordered]@{ role = 'Compliance Administrator'; scope = 'Create/change DLP, label and retention policies'; assignment = 'active'; principal = 'Compliance Team (Demo)'; upn = ''; type = 'group'; directoryScope = '/' }
            [ordered]@{ role = 'Compliance Data Administrator'; scope = 'DLP policies + compliance data'; assignment = 'eligible'; principal = 'Dana Seidel'; upn = 'dana.seidel@contoso.example'; type = 'user'; directoryScope = '/' }
            [ordered]@{ role = 'Security Operator'; scope = 'Manage DLP alerts'; assignment = 'active'; principal = 'SOC Analysts (Demo)'; upn = ''; type = 'group'; directoryScope = '/' }
            [ordered]@{ role = 'Security Reader'; scope = 'Read DLP alerts and reports'; assignment = 'active'; principal = 'Bob (Demo)'; upn = 'bob.demo@contoso.example'; type = 'user'; directoryScope = '/' }
        )
        labels = @(
            [ordered]@{ id = 'l1'; name = 'Public'; parent = ''; sensitivity = 0; isActive = $true; contentFormats = @('file', 'email') }
            [ordered]@{ id = 'l2'; name = 'General'; parent = ''; sensitivity = 1; isActive = $true; contentFormats = @('file', 'email') }
            [ordered]@{ id = 'l3'; name = 'Confidential'; parent = ''; sensitivity = 2; isActive = $true; contentFormats = @('file', 'email', 'site', 'unifiedGroup') }
            [ordered]@{ id = 'l4'; name = 'All employees'; parent = 'Confidential'; sensitivity = 3; isActive = $true; contentFormats = @('file', 'email') }
            [ordered]@{ id = 'l5'; name = 'Finance'; parent = 'Confidential'; sensitivity = 4; isActive = $true; contentFormats = @('file', 'email') }
            [ordered]@{ id = 'l6'; name = 'Highly confidential'; parent = ''; sensitivity = 5; isActive = $true; contentFormats = @('file', 'email', 'site', 'unifiedGroup') }
            [ordered]@{ id = 'l7'; name = 'Board only'; parent = 'Highly confidential'; sensitivity = 6; isActive = $true; contentFormats = @('file', 'email') }
        )
        results = @(
            [ordered]@{ key = 'devices_platform'; title = 'MDE-onboarded devices by platform'; workload = 'Devices'; status = 'ok'; result = @([ordered]@{ OSPlatform = 'Windows11'; devices = 11; capable = 11 }, [ordered]@{ OSPlatform = 'macOS'; devices = 3; capable = 3 }, [ordered]@{ OSPlatform = 'WindowsServer2022'; devices = 4; capable = 0 }) }
            [ordered]@{ key = 'dlp_rule_matches'; title = 'DLP rule matches by workload and policy'; workload = 'DLP'; status = 'ok'; result = @(
                    [ordered]@{ Workload = 'Endpoint'; Policy = 'Protect customer data'; Rule = 'Credit card numbers – block USB'; events = 184; users = 22; LastEvent = (& $iso $Now.AddHours(-3)) },
                    [ordered]@{ Workload = 'Exchange'; Policy = 'Protect customer data'; Rule = 'External recipients'; events = 96; users = 31; LastEvent = (& $iso $Now.AddHours(-6)) },
                    [ordered]@{ Workload = 'SharePoint'; Policy = 'Finance documents'; Rule = 'Anonymous sharing'; events = 41; users = 9; LastEvent = (& $iso $Now.AddDays(-1)) }) }
            [ordered]@{ key = 'dlp_overrides'; title = 'DLP overrides and justifications'; workload = 'DLP'; status = 'ok'; result = @(
                    [ordered]@{ User = 'sales.rep1@contoso.example'; overrides = 14; LastEvent = (& $iso $Now.AddHours(-20)) }, [ordered]@{ User = 'sales.rep2@contoso.example'; overrides = 6; LastEvent = (& $iso $Now.AddDays(-2)) }) }
            [ordered]@{ key = 'dlp_alerts_daily'; title = 'DLP alerts (daily)'; workload = 'Alerts'; status = 'ok'; result = @($alertDaily) }
            [ordered]@{ key = 'dlp_alerts'; title = 'DLP alerts'; workload = 'Alerts'; status = 'ok'; result = @(
                    [ordered]@{ Severity = 'High'; Title = 'DLP policy match: credit card numbers copied to USB'; alerts = 9; LastEvent = (& $iso $Now.AddHours(-3)) },
                    [ordered]@{ Severity = 'Medium'; Title = 'DLP policy match: finance document shared anonymously'; alerts = 17; LastEvent = (& $iso $Now.AddDays(-1)) },
                    [ordered]@{ Severity = 'Low'; Title = 'DLP policy match: external e-mail with customer data'; alerts = 64; LastEvent = (& $iso $Now.AddHours(-6)) }) }
            [ordered]@{ key = 'label_changes'; title = 'Sensitivity labels removed or downgraded'; workload = 'Labels'; status = 'ok'; result = @([ordered]@{ User = 'project.lead@contoso.example'; removed = 3; downgraded = 8 }) }
        )
        findings = @(
            [ordered]@{ id = 'purview.devices_silent'; severity = 'Medium'; category = 'purview'
                title = (& $T 'Capable devices without Endpoint DLP activity' 'DLP-fähige Geräte ohne Endpoint-DLP-Aktivität')
                detail = (& $T "$silent of $($devices.Count) onboarded Windows/macOS devices reported no DLPEndpoint audit event in 30 days." "$silent von $($devices.Count) onboarded Windows-/macOS-Geräten haben in 30 Tagen kein DLPEndpoint-Audit-Ereignis gemeldet.")
                recommendation = (& $T 'Check Purview > Settings > Device onboarding, policy scope (devices/users) and that Endpoint DLP policies include the Devices location.' 'Purview > Einstellungen > Geräte-Onboarding, Policy-Scope (Geräte/Benutzer) und Speicherort „Geräte“ in den Endpoint-DLP-Richtlinien prüfen.') }
            [ordered]@{ id = 'purview.overrides'; severity = 'Medium'; category = 'purview'
                title = (& $T 'Users override DLP policies' 'Benutzer übersteuern DLP-Richtlinien')
                detail = (& $T '20 override(s)/justification(s) by 2 user(s) in 30 days.' '20 Override(s)/Begründung(en) von 2 Benutzer(n) in 30 Tagen.')
                recommendation = (& $T 'Review justifications; switch frequently overridden rules from "warn" to "block" or refine them.' 'Begründungen prüfen; häufig übersteuerte Regeln von „Warnen“ auf „Blockieren“ umstellen oder schärfen.') }
            [ordered]@{ id = 'purview.label_downgrades'; severity = 'Medium'; category = 'purview'
                title = (& $T 'Sensitivity labels removed or downgraded' 'Vertraulichkeitsbezeichnungen entfernt oder herabgestuft')
                detail = (& $T '3 removal(s), 8 downgrade(s) by 1 user(s).' '3 Entfernung(en), 8 Herabstufung(en) durch 1 Benutzer.')
                recommendation = (& $T 'Require justification for downgrades (label policy) and correlate with exfil activity.' 'Begründungspflicht für Herabstufungen (Label-Policy) aktivieren und mit Exfil-Aktivität korrelieren.') }
            [ordered]@{ id = 'purview.compliance_permanent'; severity = 'Low'; category = 'purview'
                title = (& $T 'Compliance roles assigned permanently' 'Compliance-Rollen dauerhaft zugewiesen')
                detail = (& $T '1 permanent Compliance (Data) Administrator assignment(s).' '1 dauerhafte Compliance-(Data-)Administrator-Zuweisung(en).')
                recommendation = (& $T 'Prefer PIM eligible assignments with approval.' 'PIM-berechtigte Zuweisungen mit Genehmigung bevorzugen.') }
        )
        warnings = @()
        notes = @(
            'Purview role groups (Compliance portal) have no Microsoft Graph API – only Entra roles are listed.'
            'Endpoint DLP device onboarding switch and DLP policies themselves are only readable via Security & Compliance PowerShell (Get-DlpCompliancePolicy).')
    }
    [ordered]@{ officepreview = $office; purviewpreview = $purview }
}
