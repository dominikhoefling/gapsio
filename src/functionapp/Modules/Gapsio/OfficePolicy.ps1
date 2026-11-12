# Office preview: changes to the protection policies of Defender for Office 365 and Exchange Online Protection.
#
# Source: the Exchange admin audit trail in CloudAppEvents (Defender for Cloud Apps, Microsoft 365 connector). The
# ActionType is the cmdlet name, RawEventData.ObjectId the object and RawEventData.Parameters the values that were set.
# Advanced Hunting keeps 30 days, so the changes are merged into state/office-policy-history.json (400 days).
#
# The policy configuration itself is not readable (no Graph API), so a change is not compared with the value before.
# A change is called "weakening" only when the value it sets is weak in itself – ZAP switched off, an allow entry
# created, Safe Links click-through allowed, a rule disabled. Anti-phish policies are listed here too, but rated in the
# anti-phish drift view (OfficeAntiPhish.ps1), which knows the value before.

$script:GapsioOfficePolicyFamilies = [ordered]@{
    AntiPhish        = @('AntiPhishPolicy', 'AntiPhishRule')
    AntiSpam         = @('HostedContentFilterPolicy', 'HostedContentFilterRule')
    OutboundSpam     = @('HostedOutboundSpamFilterPolicy', 'HostedOutboundSpamFilterRule')
    ConnectionFilter = @('HostedConnectionFilterPolicy')
    AntiMalware      = @('MalwareFilterPolicy', 'MalwareFilterRule')
    SafeAttachments  = @('SafeAttachmentPolicy', 'SafeAttachmentRule')
    SafeLinks        = @('SafeLinksPolicy', 'SafeLinksRule')
    GlobalSettings   = @('AtpPolicyForO365')
    PresetPolicies   = @('EOPProtectionPolicyRule', 'ATPProtectionPolicyRule', 'ATPBuiltInProtectionRule')
    AllowBlockList   = @('TenantAllowBlockListItems', 'TenantAllowBlockListSpoofItems')
    TransportRule    = @('TransportRule')
    QuarantinePolicy = @('QuarantinePolicy')
    Dkim             = @('DkimSigningConfig')
    Teams            = @('TeamsProtectionPolicy', 'TeamsProtectionPolicyRule')
    AdvancedDelivery = @('PhishSimOverridePolicy', 'SecOpsOverridePolicy', 'ExoPhishSimOverrideRule', 'ExoSecOpsOverrideRule')
}

$script:GapsioOfficePolicyChangesQuery = @"
// GapsioOffice:policy_changes
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType matches regex @"^(New|Set|Remove|Enable|Disable)-($((@($script:GapsioOfficePolicyFamilies.Values | ForEach-Object { $_ }) | Sort-Object -Unique) -join '|'))$"
| extend Raw = parse_json(tostring(RawEventData))
| extend Target = tostring(Raw.ObjectId), Params = tostring(Raw.Parameters), Actor = coalesce(AccountDisplayName, AccountId, tostring(Raw.UserId)), Result = tostring(Raw.ResultStatus)
| project Timestamp, ActionType, Target, Actor, Params, Result
| order by Timestamp asc
| take 1000
"@

function Get-GapsioOfficePolicyFamily {
    # Policy family of an Exchange cmdlet ('Set-SafeLinksPolicy' -> 'SafeLinks'); 'Other' when the noun is not known.
    param([string]$Cmdlet)
    $noun = ($Cmdlet -split '-', 2)[1]
    foreach ($f in $script:GapsioOfficePolicyFamilies.Keys) { if ($script:GapsioOfficePolicyFamilies[$f] -contains $noun) { return $f } }
    'Other'
}

function Get-GapsioOfficePolicyWeakening {
    <#
    .SYNOPSIS
    The values of one audited policy change that weaken protection in themselves. Returns @{ id; setting; value } per
    hit (id = reason code, translated in the portal: opw.<id>). Only New-/Set- values and disabled rules are rated;
    removed objects and anti-phish policies are not.
    #>
    param([string]$Family, [string]$Cmdlet, [System.Collections.IDictionary]$Settings)
    $out = [System.Collections.Generic.List[object]]::new()
    if (-not $Settings) { $Settings = @{} }
    $verb = ($Cmdlet -split '-', 2)[0]
    $val = { param($n) if ($Settings.Contains($n)) { [string]$Settings[$n] } else { $null } }
    $add = { param($id, $setting) $out.Add([ordered]@{ id = $id; setting = $setting; value = $(if ($setting) { & $val $setting } else { $null }) }) }
    $isFalse = { param($n) $Settings.Contains($n) -and ([string]$Settings[$n]) -match '^\$?(false|0)$' }
    $isTrue = { param($n) $Settings.Contains($n) -and ([string]$Settings[$n]) -match '^\$?(true|1)$' }
    $has = { param($n) $Settings.Contains($n) -and -not [string]::IsNullOrWhiteSpace([string]$Settings[$n]) }
    $in = { param($n, $values) $Settings.Contains($n) -and ($values -contains [string]$Settings[$n]) }

    if ($verb -eq 'Disable' -and $Family -in 'AntiSpam', 'OutboundSpam', 'AntiMalware', 'SafeAttachments', 'SafeLinks', 'PresetPolicies', 'Teams') { & $add 'ruleDisabled' $null }
    if ($verb -notin 'New', 'Set') { return @($out.ToArray()) }

    switch ($Family) {
        'AntiSpam' {
            if ((& $has 'HighConfidencePhishAction') -and (& $val 'HighConfidencePhishAction') -ne 'Quarantine') { & $add 'hcPhishNotQuarantined' 'HighConfidencePhishAction' }
            if (& $in 'PhishSpamAction' @('MoveToJmf', 'AddXHeader', 'ModifySubject', 'NoAction')) { & $add 'phishNotQuarantined' 'PhishSpamAction' }
            foreach ($n in 'SpamAction', 'HighConfidenceSpamAction') { if (& $in $n @('AddXHeader', 'ModifySubject', 'NoAction')) { & $add 'spamStaysInInbox' $n } }
            foreach ($n in 'ZapEnabled', 'SpamZapEnabled', 'PhishZapEnabled') { if (& $isFalse $n) { & $add 'zapOff' $n } }
            foreach ($n in 'AllowedSenders', 'AllowedSenderDomains') { if (& $has $n) { & $add 'allowedSenders' $n } }
        }
        'AntiMalware' {
            if (& $isFalse 'EnableFileFilter') { & $add 'fileFilterOff' 'EnableFileFilter' }
            if (& $isFalse 'ZapEnabled') { & $add 'zapOff' 'ZapEnabled' }
        }
        'SafeAttachments' {
            if (& $isFalse 'Enable') { & $add 'safeAttachmentsOff' 'Enable' }
            if (& $in 'Action' @('Allow', 'Monitor')) { & $add 'safeAttachmentsNoBlock' 'Action' }
        }
        'SafeLinks' {
            foreach ($n in 'EnableSafeLinksForEmail', 'EnableSafeLinksForTeams', 'EnableSafeLinksForOffice', 'ScanUrls', 'EnableForInternalSenders') { if (& $isFalse $n) { & $add 'safeLinksOff' $n } }
            if (& $isTrue 'AllowClickThrough') { & $add 'clickThroughAllowed' 'AllowClickThrough' }
            if (& $isTrue 'DisableUrlRewrite') { & $add 'safeLinksOff' 'DisableUrlRewrite' }
            if (& $has 'DoNotRewriteUrls') { & $add 'safeLinksExcluded' 'DoNotRewriteUrls' }
        }
        'ConnectionFilter' { if (& $has 'IPAllowList') { & $add 'ipAllowList' 'IPAllowList' } }
        'GlobalSettings' {
            foreach ($n in 'EnableATPForSPOTeamsODB', 'EnableSafeDocs') { if (& $isFalse $n) { & $add 'globalProtectionOff' $n } }
            if (& $isTrue 'AllowSafeDocsOpen') { & $add 'safeDocsBypass' 'AllowSafeDocsOpen' }
        }
        'AllowBlockList' {
            if ((& $isTrue 'Allow') -or (& $val 'Action') -eq 'Allow') {
                if (& $isTrue 'NoExpiration') { & $add 'allowEntryNoExpiry' 'NoExpiration' } else { & $add 'allowEntry' $(if ($Settings.Contains('ListType')) { 'ListType' } else { $null }) }
            }
        }
        'TransportRule' {
            if ((& $val 'SetSCL') -eq '-1') { & $add 'spamFilterBypass' 'SetSCL' }
            if ((& $val 'SetHeaderName') -match 'SkipSafe(Links|Attachment)Processing') { & $add 'safeBypassHeader' 'SetHeaderName' }
        }
        'Dkim' { if (& $isFalse 'Enabled') { & $add 'dkimOff' 'Enabled' } }
        'Teams' { if (& $isFalse 'ZapEnabled') { & $add 'teamsZapOff' 'ZapEnabled' } }
        'AdvancedDelivery' { & $add 'filterBypass' $null }
    }
    @($out.ToArray())
}

function Update-GapsioOfficePolicyHistory {
    <#
    .SYNOPSIS
    Reads the policy changes of the last 30 days from Advanced Hunting, merges them into
    state/office-policy-history.json and returns @{ policy = <object for the snapshot>; row = <probe row>;
    findings = @(...) }. The probe row has status 'unavailable' when the tenant has no CloudAppEvents table.
    #>
    $now = [DateTime]::UtcNow
    $title = 'Protection policy changes (Exchange admin audit)'
    $history = $null
    # A failed read must not be followed by a write: the 30 days in Advanced Hunting would replace up to 400 days of history
    $historyReadFailed = $false
    try { $history = Get-GapsioBlob -Container 'state' -Name 'office-policy-history.json' } catch { $historyReadFailed = $true; Add-GapsioWarning "office policy history could not be read (not updated in this run): $($_.Exception.Message)" }
    $changes = @{}
    foreach ($c in @(Get-GapsioProp $history 'changes')) {
        if ($null -eq $c) { continue }
        $ts = ConvertTo-GapsioIsoTs $c.ts
        $changes["$ts|$($c.cmdlet)|$($c.target)"] = [ordered]@{ ts = $ts; cmdlet = [string]$c.cmdlet; target = [string]$c.target; actor = [string]$c.actor; result = [string]$c.result; settings = (ConvertTo-GapsioAntiPhishMap (Get-GapsioProp $c 'settings')) }
    }
    $since = if (Get-GapsioProp $history 'since') { ConvertTo-GapsioIsoTs (Get-GapsioProp $history 'since') } else { $now.ToString('o') }

    $row = $null; $new = 0; $read = 0
    try {
        $r = @(Invoke-GapsioOfficeHunting -Context 'office preview policy_changes' -Query $script:GapsioOfficePolicyChangesQuery)
        $read = $r.Count
        foreach ($x in $r) {
            $ts = ConvertTo-GapsioIsoTs $x.Timestamp
            $k = "$ts|$($x.ActionType)|$($x.Target)"
            if ($changes.ContainsKey($k)) { continue }
            $settings = [ordered]@{}
            $all = ConvertFrom-GapsioAntiPhishParams -Json ([string]$x.Params)
            foreach ($n in @($all.Keys | Select-Object -First 25)) { $v = [string]$all[$n]; $settings[$n] = $(if ($v.Length -gt 300) { $v.Substring(0, 300) + '…' } else { $v }) }
            $changes[$k] = [ordered]@{ ts = $ts; cmdlet = [string]$x.ActionType; target = [string]$x.Target; actor = [string]$x.Actor; result = [string]$x.Result; settings = $settings }
            $new++
        }
    }
    catch {
        $msg = [string]$_.Exception.Message
        $text = Get-GapsioErrorText -Exception $_.Exception -Context 'office preview policy_changes ThreatHunting.Read.All'
        $row = [ordered]@{ key = 'policy_changes'; title = $title; workload = 'Policy changes'; status = $(if ($msg -match 'Failed to resolve table expression') { 'unavailable' } else { 'error' }); error = $text; result = @() }
    }

    $keepFrom = $now.AddDays(-400)
    $list = @($changes.Values | Where-Object { ([datetime]$_.ts) -ge $keepFrom } | Sort-Object { [datetime]$_.ts })
    if (-not $row -and -not $historyReadFailed) {
        try { Set-GapsioBlob -Container 'state' -Name 'office-policy-history.json' -Object ([ordered]@{ version = 1; since = $since; updatedAt = $now.ToString('o'); changes = $list }) -Depth 12 }
        catch { Add-GapsioWarning "office policy history write: $($_.Exception.Message)" }
    }

    $recentFrom = $now.AddDays(-30)
    $items = @(foreach ($c in $list) {
            $family = Get-GapsioOfficePolicyFamily -Cmdlet $c.cmdlet
            $failed = $c.result -and $c.result -notin 'True', 'Success', 'Succeeded'
            # Anti-phish changes are rated in the drift view, which knows the value before; failed calls changed nothing
            $weaker = @(if ($family -ne 'AntiPhish' -and -not $failed) { Get-GapsioOfficePolicyWeakening -Family $family -Cmdlet $c.cmdlet -Settings $c.settings })
            [ordered]@{ ts = $c.ts; cmdlet = $c.cmdlet; family = $family; target = $c.target; actor = $c.actor; result = $c.result; failed = [bool]$failed
                settings = $c.settings; weaker = $weaker; recent = (([datetime]$c.ts) -ge $recentFrom) }
        })
    $recent = @($items | Where-Object { $_.recent })
    $weakened = @($recent | Where-Object { @($_.weaker).Count -gt 0 })
    if (-not $row) {
        $row = [ordered]@{ key = 'policy_changes'; title = $title; workload = 'Policy changes'; status = 'ok'; error = $null
            result = @([ordered]@{ rows = $read; newChanges = $new; tracked = $list.Count; changes30d = $recent.Count; weakened30d = $weakened.Count }) }
    }

    # A finding needs this run's read: when the table could not be read, the history is shown but nothing is claimed
    $findings = [System.Collections.Generic.List[object]]::new()
    if ($weakened.Count -and $row.status -eq 'ok') {
        $what = @($weakened | Sort-Object { [datetime]$_.ts } -Descending | Select-Object -First 6 | ForEach-Object {
                $c = $_
                $vals = @($c.weaker | ForEach-Object { if ($_.setting) { "$($_.setting)=$($_.value)" } else { $c.cmdlet } } | Sort-Object -Unique) -join ', '
                "$($c.family)$(if ($c.target) { " '$($c.target)'" }): $vals ($($c.actor), $(([datetime]$c.ts).ToString('yyyy-MM-dd')))"
            }) -join '; '
        $findings.Add([ordered]@{ id = 'office.policy_weakened'; severity = 'High'
                title = @{ en = "$($weakened.Count) policy change(s) weakened Defender for Office 365 protection"; de = "$($weakened.Count) Richtlinienänderung(en) haben den Schutz von Defender for Office 365 abgeschwächt" }
                detail = @{ en = "In the last 30 days these changes set a value that lowers protection: $what$(if ($weakened.Count -gt 6) { ' …' })."; de = "In den letzten 30 Tagen haben diese Änderungen einen Wert gesetzt, der den Schutz senkt: $what$(if ($weakened.Count -gt 6) { ' …' })." }
                recommendation = @{ en = 'Confirm each change against its change ticket and roll back what was not intended. The configuration analyzer in the Defender portal compares the policies with the Standard and Strict presets.'; de = 'Jede Änderung mit ihrem Change-Ticket abgleichen und Unbeabsichtigtes zurücknehmen. Der Konfigurationsanalysator im Defender-Portal vergleicht die Richtlinien mit den Voreinstellungen Standard und Strict.' } })
    }

    $families = @($recent | Group-Object { $_.family } | ForEach-Object { [ordered]@{ family = $_.Name; changes = $_.Count; weakened = @($_.Group | Where-Object { @($_.weaker).Count -gt 0 }).Count } } | Sort-Object { -$_.changes })
    $policy = [ordered]@{
        historySince = $since
        historyDays  = [int][math]::Ceiling(($now - [datetime]$since).TotalDays)
        changes30d   = $recent.Count
        weakened30d  = $weakened.Count
        families     = $families
        changes      = @($items | Sort-Object { [datetime]$_.ts } -Descending | Select-Object -First 300)
    }
    @{ policy = $policy; row = $row; findings = @($findings.ToArray()) }
}
