function Invoke-GapsioOfficePreviewCollection {
    <#
    .SYNOPSIS
    Builds state/office-preview-latest.json from Defender Advanced Hunting (MDO telemetry).
    Private preview module for lab validation.
    #>
    if (-not (Test-GapsioFeature -Name 'hunting')) {
        $out = [ordered]@{
            generatedAt = [DateTime]::UtcNow.ToString('o')
            windowDays  = 30
            ok          = 0
            errors      = 1
            results     = @([ordered]@{ key = 'hunting'; title = 'Advanced Hunting access'; workload = 'platform'; status = 'error'; error = 'ThreatHunting.Read.All is not enabled in this installation.'; result = @() })
            findings    = @()
        }
        Set-GapsioBlob -Container 'state' -Name 'office-preview-latest.json' -Object $out
        return $out
    }

    $probes = @(
        [ordered]@{
            key = 'override_exposure'; title = 'Threat overrides that delivered mail'; workload = 'Email';
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend OrgAction = tostring(column_ifexists('OrgLevelAction','')), UserPolicy = tostring(column_ifexists('UserLevelPolicy','')), Auth = tostring(column_ifexists('AuthenticationDetails',''))
| summarize rows=count(), overridden=countif(tolower(OrgAction) has 'allow' or tolower(OrgAction) has 'deliver' or tolower(UserPolicy) has 'safe'), dmarcFail=countif(tolower(Auth) has 'dmarc=fail')
"@
        }
        [ordered]@{
            key = 'safelinks_clickthrough'; title = 'Safe Links click-through events'; workload = 'Email';
            query = @"
UrlClickEvents
| where Timestamp > ago(30d)
| extend Action=tostring(column_ifexists('ActionType','')), Workload=tostring(column_ifexists('Workload',''))
| summarize rows=count(), clickThrough=countif(tolower(Action) has 'clickthrough' or tolower(Action) has 'allow'), uniqueUsers=dcount(tostring(column_ifexists('AccountUpn',''))), uniqueUrls=dcount(tostring(column_ifexists('Url','')))
"@
        }
        [ordered]@{
            key = 'threat_trend_daily'; title = 'Threat trend (daily)'; workload = 'Dashboard'; returnMany = $true; maxRows = 500;
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend Threat = tolower(tostring(column_ifexists('ThreatTypes','')))
| extend Bucket = case(Threat has 'phish', 'Phish', Threat has 'malware', 'Malware', Threat has 'spam', 'Spam', Threat has 'bulk', 'Bulk', isempty(Threat), 'None', 'Other')
| summarize events=count() by day=startofday(Timestamp), bucket=Bucket
| order by day asc
"@
        }
        [ordered]@{
            key = 'action_trend_daily'; title = 'Action outcomes (daily)'; workload = 'Dashboard'; returnMany = $true; maxRows = 500;
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend OrgAction=tolower(tostring(column_ifexists('OrgLevelAction',''))),
         UserAction=tolower(tostring(column_ifexists('UserLevelAction',''))),
         DeliveryAction=tolower(tostring(column_ifexists('DeliveryAction',''))),
         DeliveryLocation=tolower(tostring(column_ifexists('DeliveryLocation','')))
| extend EffectiveAction = iif(isnotempty(UserAction), UserAction,
                       iif(isnotempty(OrgAction), OrgAction,
                       iif(isnotempty(DeliveryAction), DeliveryAction, DeliveryLocation)))
| extend Bucket = case(
    isempty(EffectiveAction), 'NoActionData',
    EffectiveAction contains 'block' or EffectiveAction contains 'reject' or EffectiveAction contains 'drop' or EffectiveAction contains 'delete', 'Block',
    EffectiveAction contains 'quarantine', 'Quarantine',
    EffectiveAction contains 'junk' or EffectiveAction contains 'spam' or EffectiveAction contains 'jmf' or EffectiveAction contains 'scl', 'Junk',
    EffectiveAction contains 'allow' or EffectiveAction contains 'deliver' or EffectiveAction contains 'inbox' or EffectiveAction contains 'noaction' or EffectiveAction contains 'redirect' or EffectiveAction contains 'bypass', 'Allow',
    'Other')
| summarize events=count() by day=startofday(Timestamp), bucket=Bucket
| order by day asc
"@
        }
        [ordered]@{
            key = 'action_values_top'; title = 'Raw action values (top)'; workload = 'Dashboard'; returnMany = $true; maxRows = 50;
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend OrgAction=tolower(tostring(column_ifexists('OrgLevelAction',''))),
         UserAction=tolower(tostring(column_ifexists('UserLevelAction',''))),
         DeliveryAction=tolower(tostring(column_ifexists('DeliveryAction',''))),
         DeliveryLocation=tolower(tostring(column_ifexists('DeliveryLocation','')))
| extend EffectiveAction = iif(isnotempty(UserAction), UserAction,
                       iif(isnotempty(OrgAction), OrgAction,
                       iif(isnotempty(DeliveryAction), DeliveryAction, DeliveryLocation)))
| summarize events=count() by EffectiveAction
| top 50 by events desc
"@
        }
        [ordered]@{
            key = 'campaign_top'; title = 'Top campaigns / themes'; workload = 'Dashboard'; returnMany = $true; maxRows = 50;
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend CampaignName=tostring(column_ifexists('CampaignName','')),
         CampaignId=tostring(column_ifexists('CampaignId','')),
         Threat=tostring(column_ifexists('ThreatTypes',''))
| extend Campaign = iif(isnotempty(CampaignName), CampaignName, iif(isnotempty(CampaignId), CampaignId, iif(isnotempty(Threat), strcat('Threat: ', Threat), 'Unknown')))
| summarize events=count(), recipients=dcount(tostring(column_ifexists('RecipientEmailAddress',''))) by Campaign
| top 20 by events desc
"@
        }
        [ordered]@{
            key = 'zap_blind_spots'; title = 'Likely ZAP blind spots'; workload = 'Email';
            query = @"
let post = EmailPostDeliveryEvents
| where Timestamp > ago(30d)
| summarize hasPost=1 by NetworkMessageId;
EmailEvents
| where Timestamp > ago(30d)
| where isnotempty(NetworkMessageId)
| join kind=leftouter post on NetworkMessageId
| summarize rows=count(), withoutPost=countif(isnull(hasPost))
"@
        }
        [ordered]@{
            key = 'own_domain_auth_posture'; title = 'Inbound mail with weak auth posture'; workload = 'Email auth';
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend Auth=tostring(column_ifexists('AuthenticationDetails',''))
| summarize rows=count(), dmarcFail=countif(tolower(Auth) has 'dmarc=fail'), spfFail=countif(tolower(Auth) has 'spf=fail'), dkimFail=countif(tolower(Auth) has 'dkim=fail')
"@
        }
        [ordered]@{
            key = 'first_contact_risk'; title = 'First-contact messages with URLs/attachments'; workload = 'Email';
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend IsFirst=tobool(column_ifexists('IsFirstContact', false))
| summarize rows=count(), firstContact=countif(IsFirst), withThreat=countif(isnotempty(tostring(column_ifexists('ThreatTypes',''))))
"@
        }
        [ordered]@{
            key = 'encrypted_attachment_volume'; title = 'Encrypted/password-protected attachments'; workload = 'Email attachments';
            query = @"
EmailAttachmentInfo
| where Timestamp > ago(30d)
| extend AF=tostring(column_ifexists('AdditionalFields',''))
| summarize rows=count(), encrypted=countif(tolower(AF) has 'password' or tolower(AF) has 'encrypted'), uniqueSenders=dcount(tostring(column_ifexists('SenderFromAddress','')))
"@
        }
        [ordered]@{
            key = 'policy_user_overlap'; title = 'Users hit by multiple user-level policies'; workload = 'Policy targeting';
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend UserPolicy = tostring(column_ifexists('UserLevelPolicy','')), Recipient = tolower(tostring(column_ifexists('RecipientEmailAddress','')))
| where isnotempty(UserPolicy) and isnotempty(Recipient)
| summarize policyCount=dcount(UserPolicy), policyList=make_set(UserPolicy, 20) by Recipient
| summarize users=count(), overlappedUsers=countif(policyCount > 1), maxPolicies=max(policyCount)
"@
        }
        [ordered]@{
            key = 'policy_domain_overlap'; title = 'Domains hit by multiple user-level policies'; workload = 'Policy targeting';
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend UserPolicy = tostring(column_ifexists('UserLevelPolicy','')), Recipient = tolower(tostring(column_ifexists('RecipientEmailAddress','')))
| where isnotempty(UserPolicy) and Recipient has '@'
| extend Domain = tostring(split(Recipient, '@')[1])
| where isnotempty(Domain)
| summarize policyCount=dcount(UserPolicy) by Domain
| summarize domains=count(), overlappedDomains=countif(policyCount > 1), maxPolicies=max(policyCount)
"@
        }
        [ordered]@{
            key = 'policy_effect_duplicates'; title = 'Many policies with same effective action'; workload = 'Policy quality';
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend UserPolicy=tostring(column_ifexists('UserLevelPolicy','')),
         OrgAction=tolower(tostring(column_ifexists('OrgLevelAction',''))),
         UserAction=tolower(tostring(column_ifexists('UserLevelAction',''))),
         Action=iif(isnotempty(UserAction), UserAction, OrgAction)
| where isnotempty(UserPolicy) and isnotempty(Action)
| summarize rows=count(), policies=dcount(UserPolicy) by Action
| summarize actions=count(), duplicateLikeActions=countif(policies > 1 and rows >= 50), maxPoliciesPerAction=max(policies)
"@
        }
        [ordered]@{
            key = 'policy_precedence_signals'; title = 'Possible precedence conflicts'; workload = 'Policy precedence';
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend OrgAction=tolower(tostring(column_ifexists('OrgLevelAction',''))),
         UserAction=tolower(tostring(column_ifexists('UserLevelAction',''))),
         UserPolicy=tostring(column_ifexists('UserLevelPolicy',''))
| where isnotempty(UserPolicy) and isnotempty(OrgAction) and isnotempty(UserAction)
| summarize rows=count(),
    allowVsBlock=countif(UserAction has 'allow' and (OrgAction has 'block' or OrgAction has 'quarantine' or OrgAction has 'junk')),
    blockVsAllow=countif((UserAction has 'block' or UserAction has 'quarantine' or UserAction has 'junk') and OrgAction has 'allow')
"@
        }
        [ordered]@{
            key = 'tabl_ioc_coverage'; title = 'TABL/IOC inventory snapshot'; workload = 'IOC / TABL';
            query = @"
ThreatIntelligenceIndicator
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, *) by IndicatorId
| summarize total=count(), active=countif(tobool(column_ifexists('Active', false))), inactive=countif(not(tobool(column_ifexists('Active', false)))),
    domain=countif(isnotempty(tostring(column_ifexists('DomainName','')))),
    url=countif(isnotempty(tostring(column_ifexists('Url','')))),
    ip=countif(isnotempty(tostring(column_ifexists('NetworkIP','')))),
    email=countif(isnotempty(tostring(column_ifexists('EmailSenderAddress','')))),
    fileHash=countif(isnotempty(tostring(column_ifexists('FileHashValue','')))),
    expiring14d=countif(todatetime(column_ifexists('ExpirationDateTime', datetime(null))) between (now() .. now()+14d))
"@
        }
        [ordered]@{
            key = 'tabl_ioc_actions'; title = 'TABL/IOC action breakdown (top)'; workload = 'IOC / TABL'; returnMany = $true; maxRows = 100;
            query = @"
ThreatIntelligenceIndicator
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, *) by IndicatorId
| extend IndicatorType = tostring(column_ifexists('IndicatorType','Unknown')), Action = tostring(column_ifexists('Action','Unknown'))
| summarize indicators=count() by IndicatorType, Action
| top 100 by indicators desc
"@
        }
        [ordered]@{
            key = 'effective_policy_map_users'; title = 'Effective policy map (top recipients)'; workload = 'Policy map'; returnMany = $true; maxRows = 100;
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend Recipient = tolower(tostring(column_ifexists('RecipientEmailAddress',''))),
         UserPolicy = tostring(column_ifexists('UserLevelPolicy','')),
         OrgAction = tolower(tostring(column_ifexists('OrgLevelAction',''))),
         UserAction = tolower(tostring(column_ifexists('UserLevelAction',''))),
         EffectiveAction = iif(isnotempty(UserAction), UserAction, OrgAction)
| where isnotempty(Recipient) and isnotempty(UserPolicy)
| extend Domain = tostring(split(Recipient, '@')[1])
| summarize events=count(), policies=dcount(UserPolicy), policySet=make_set(UserPolicy, 5), actions=make_set(EffectiveAction, 5), domains=dcount(Domain) by Recipient
| top 100 by events desc
"@
        }
        [ordered]@{
            key = 'effective_policy_map_domains'; title = 'Effective policy map (top domains)'; workload = 'Policy map'; returnMany = $true; maxRows = 100;
            query = @"
EmailEvents
| where Timestamp > ago(30d)
| extend Recipient = tolower(tostring(column_ifexists('RecipientEmailAddress',''))),
         UserPolicy = tostring(column_ifexists('UserLevelPolicy','')),
         OrgAction = tolower(tostring(column_ifexists('OrgLevelAction',''))),
         UserAction = tolower(tostring(column_ifexists('UserLevelAction',''))),
         EffectiveAction = iif(isnotempty(UserAction), UserAction, OrgAction)
| where Recipient has '@' and isnotempty(UserPolicy)
| extend Domain = tostring(split(Recipient, '@')[1])
| where isnotempty(Domain)
| summarize events=count(), users=dcount(Recipient), policies=dcount(UserPolicy), policySet=make_set(UserPolicy, 5), actions=make_set(EffectiveAction, 5) by Domain
| top 100 by events desc
"@
        }
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    $findings = [System.Collections.Generic.List[object]]::new()
    $ok = 0; $errors = 0
    foreach ($p in $probes) {
        try {
            $r = Invoke-GapsioHuntingSafe -NoShard -Context "office preview $($p.key)" -Timespan 'P30D' -Query $p.query
            $all = @($r)
            $maxRows = if ($p.maxRows) { [int]$p.maxRows } else { 1 }
            $resultRows = if ($p.returnMany) { @($all | Select-Object -First $maxRows) } else { @($all | Select-Object -First 1) }
            $row = [ordered]@{ key = $p.key; title = $p.title; workload = $p.workload; status = 'ok'; error = $null; result = @($resultRows) }
            $rows.Add($row)
            $ok++

            $x = @($resultRows | Select-Object -First 1)[0]
            if ($x) {
                switch ($p.key) {
                    'override_exposure' {
                        if ([int]$x.overridden -gt 0) {
                            $sev = if ([int]$x.dmarcFail -gt 0) { 'High' } else { 'Medium' }
                            $findings.Add([ordered]@{ id = 'office.override_exposure'; severity = $sev; category = 'mdo'; title = @{ en = 'Threat overrides delivered email'; de = 'Bedrohungs-Overrides haben E-Mails zugestellt' }; detail = @{ en = "$($x.overridden) overridden messages in 30 days ($($x.dmarcFail) with DMARC fail)."; de = "$($x.overridden) übersteuerte Nachrichten in 30 Tagen ($($x.dmarcFail) mit DMARC fail)." }; recommendation = @{ en = 'Review allow/override policies and transport exceptions.'; de = 'Allow-/Override-Richtlinien und Transport-Ausnahmen prüfen.' } })
                        }
                    }
                    'safelinks_clickthrough' {
                        if ([int]$x.clickThrough -gt 0) {
                            $findings.Add([ordered]@{ id = 'office.safelinks_clickthrough'; severity = 'Medium'; category = 'mdo'; title = @{ en = 'Users clicked through blocked URLs'; de = 'Benutzer haben blockierte URLs dennoch geöffnet' }; detail = @{ en = "$($x.clickThrough) click-through events by $($x.uniqueUsers) users in 30 days."; de = "$($x.clickThrough) Click-through-Ereignisse von $($x.uniqueUsers) Benutzern in 30 Tagen." }; recommendation = @{ en = 'Target awareness and conditional access hardening for repeat offenders.'; de = 'Awareness- und Conditional-Access-Härtung für Wiederholungstäter fokussieren.' } })
                        }
                    }
                    'zap_blind_spots' {
                        if ([int]$x.withoutPost -gt 0) {
                            $findings.Add([ordered]@{ id = 'office.zap_blind_spots'; severity = 'Medium'; category = 'mdo'; title = @{ en = 'Potential ZAP blind spots'; de = 'Mögliche ZAP-Blindstellen' }; detail = @{ en = "$($x.withoutPost) messages had no post-delivery event in 30 days."; de = "$($x.withoutPost) Nachrichten ohne Post-Delivery-Ereignis in 30 Tagen." }; recommendation = @{ en = 'Validate anti-phish/allowlist/transport exceptions against post-delivery actions.'; de = 'Anti-Phish-/Allowlist-/Transport-Ausnahmen gegen Post-Delivery-Aktionen prüfen.' } })
                        }
                    }
                    'own_domain_auth_posture' {
                        if (([int]$x.dmarcFail + [int]$x.spfFail + [int]$x.dkimFail) -gt 0) {
                            $findings.Add([ordered]@{ id = 'office.own_domain_auth_posture'; severity = 'High'; category = 'mdo'; title = @{ en = 'Mail auth failures observed'; de = 'Mail-Authentifizierungsfehler erkannt' }; detail = @{ en = "DMARC fail: $($x.dmarcFail), SPF fail: $($x.spfFail), DKIM fail: $($x.dkimFail) (30d)."; de = "DMARC fail: $($x.dmarcFail), SPF fail: $($x.spfFail), DKIM fail: $($x.dkimFail) (30T)." }; recommendation = @{ en = 'Review sender/authentication posture and strictness of domain policies.'; de = 'Absender-/Authentifizierungs-Posture und Striktheit der Domänenrichtlinien prüfen.' } })
                        }
                    }
                    'first_contact_risk' {
                        if ([int]$x.firstContact -gt 0 -and [int]$x.withThreat -gt 0) {
                            $findings.Add([ordered]@{ id = 'office.first_contact_risk'; severity = 'High'; category = 'mdo'; title = @{ en = 'Risky first-contact traffic detected'; de = 'Risikoreicher Erstkontakt-Verkehr erkannt' }; detail = @{ en = "$($x.firstContact) first-contact messages, $($x.withThreat) with threats (30d)."; de = "$($x.firstContact) Erstkontakt-Nachrichten, $($x.withThreat) mit Bedrohungen (30T)." }; recommendation = @{ en = 'Prioritise first-contact senders for investigation and tuning.'; de = 'Erstkontakt-Absender priorisiert untersuchen und Regeln abstimmen.' } })
                        }
                    }
                    'encrypted_attachment_volume' {
                        if ([int]$x.encrypted -gt 0) {
                            $findings.Add([ordered]@{ id = 'office.encrypted_attachment_volume'; severity = 'Medium'; category = 'mdo'; title = @{ en = 'Encrypted attachments reduce scanning visibility'; de = 'Verschlüsselte Anhänge reduzieren die Scan-Sichtbarkeit' }; detail = @{ en = "$($x.encrypted) encrypted/password-protected attachments in 30 days."; de = "$($x.encrypted) verschlüsselte/passwortgeschützte Anhänge in 30 Tagen." }; recommendation = @{ en = 'Track sender patterns and apply stricter handling for high-risk sources.'; de = 'Absender-Muster beobachten und riskante Quellen strenger behandeln.' } })
                        }
                    }
                    'policy_user_overlap' {
                        if ([int]$x.overlappedUsers -gt 0) {
                            $sev = if ([int]$x.maxPolicies -ge 4) { 'High' } else { 'Medium' }
                            $findings.Add([ordered]@{ id = 'office.policy_user_overlap'; severity = $sev; category = 'mdo'; title = @{ en = 'Users covered by multiple user-level policies'; de = 'Benutzer unter mehreren User-Level-Policies' }; detail = @{ en = "$($x.overlappedUsers) of $($x.users) users were hit by >1 user-level policy (max: $($x.maxPolicies))."; de = "$($x.overlappedUsers) von $($x.users) Benutzern wurden von >1 User-Level-Policy getroffen (max: $($x.maxPolicies))." }; recommendation = @{ en = 'Review policy scope overlap and consolidate where possible.'; de = 'Policy-Scopes auf Überschneidungen prüfen und konsolidieren.' } })
                        }
                    }
                    'policy_domain_overlap' {
                        if ([int]$x.overlappedDomains -gt 0) {
                            $findings.Add([ordered]@{ id = 'office.policy_domain_overlap'; severity = 'Medium'; category = 'mdo'; title = @{ en = 'Domains hit by multiple user-level policies'; de = 'Domänen unter mehreren User-Level-Policies' }; detail = @{ en = "$($x.overlappedDomains) of $($x.domains) recipient domains had >1 policy (max: $($x.maxPolicies))."; de = "$($x.overlappedDomains) von $($x.domains) Empfänger-Domänen hatten >1 Policy (max: $($x.maxPolicies))." }; recommendation = @{ en = 'Validate whether domain-based targeting can be simplified.'; de = 'Prüfen, ob domänenbasiertes Targeting vereinfacht werden kann.' } })
                        }
                    }
                    'policy_effect_duplicates' {
                        if ([int]$x.duplicateLikeActions -gt 0) {
                            $findings.Add([ordered]@{ id = 'office.policy_effect_duplicates'; severity = 'Low'; category = 'mdo'; title = @{ en = 'Multiple policies appear to produce the same action'; de = 'Mehrere Policies scheinen dieselbe Aktion zu erzeugen' }; detail = @{ en = "$($x.duplicateLikeActions) action bucket(s) are produced by multiple policies (max policies per action: $($x.maxPoliciesPerAction))."; de = "$($x.duplicateLikeActions) Aktions-Bucket(s) werden von mehreren Policies erzeugt (max Policies je Aktion: $($x.maxPoliciesPerAction))." }; recommendation = @{ en = 'Check for redundant policy settings and remove duplicate logic.'; de = 'Auf redundante Policy-Einstellungen prüfen und Duplikate entfernen.' } })
                        }
                    }
                    'policy_precedence_signals' {
                        $conflicts = ([int]$x.allowVsBlock + [int]$x.blockVsAllow)
                        if ($conflicts -gt 0) {
                            $sev = if ($conflicts -ge 20) { 'High' } else { 'Medium' }
                            $findings.Add([ordered]@{ id = 'office.policy_precedence_signals'; severity = $sev; category = 'mdo'; title = @{ en = 'Possible policy precedence conflicts observed'; de = 'Mögliche Policy-Precedence-Konflikte erkannt' }; detail = @{ en = "$conflicts conflicting action signal(s): allow-vs-block=$($x.allowVsBlock), block-vs-allow=$($x.blockVsAllow)."; de = "$conflicts Konflikt-Signal(e): allow-vs-block=$($x.allowVsBlock), block-vs-allow=$($x.blockVsAllow)." }; recommendation = @{ en = 'Review precedence/order and assignment boundaries between org-level and user-level policies.'; de = 'Precedence/Reihenfolge und Zuweisungsgrenzen zwischen Org- und User-Level-Policies prüfen.' } })
                        }
                    }
                    'tabl_ioc_coverage' {
                        if ([int]$x.total -gt 0 -and [int]$x.active -eq 0) {
                            $findings.Add([ordered]@{ id = 'office.tabl_ioc_inactive'; severity = 'Medium'; category = 'mdo'; title = @{ en = 'IOC inventory exists but no active indicators'; de = 'IOC-Bestand vorhanden, aber keine aktiven Indikatoren' }; detail = @{ en = "$($x.total) indicators in snapshot, active: 0."; de = "$($x.total) Indikatoren im Snapshot, aktiv: 0." }; recommendation = @{ en = 'Review indicator lifecycle and activate intended controls.'; de = 'Indikator-Lifecycle prüfen und beabsichtigte Kontrollen aktivieren.' } })
                        }
                        if ([int]$x.expiring14d -gt 0) {
                            $findings.Add([ordered]@{ id = 'office.tabl_ioc_expiring'; severity = 'Low'; category = 'mdo'; title = @{ en = 'Indicators expiring within 14 days'; de = 'Indikatoren laufen in 14 Tagen ab' }; detail = @{ en = "$($x.expiring14d) indicator(s) expire in the next 14 days."; de = "$($x.expiring14d) Indikator(en) laufen in den nächsten 14 Tagen ab." }; recommendation = @{ en = 'Validate renew/remove decisions before expiry.'; de = 'Verlängern/Entfernen vor Ablauf prüfen.' } })
                        }
                    }
                }
            }
        }
        catch {
            $rows.Add([ordered]@{ key = $p.key; title = $p.title; workload = $p.workload; status = 'error'; error = [string]$_.Exception.Message; result = @() })
            $errors++
        }
    }

    # Optional licensing context from the existing licensing module snapshot.
    try {
        $lic = Get-GapsioBlob -Container 'state' -Name 'licensing-latest.json'
        if ($lic -and $lic.summary) {
            $summary = $lic.summary
            $rows.Add([ordered]@{
                    key = 'licensing_context'
                    title = 'Licensing context (from licensing module snapshot)'
                    workload = 'Licensing'
                    status = 'ok'
                    error = $null
                    result = @([ordered]@{
                            mdoP2Enabled = [int]$summary.mdoP2Enabled
                            mdoP2Consumed = [int]$summary.mdoP2Consumed
                            mdoP1Enabled = [int]$summary.mdoP1Enabled
                            mdoP1Consumed = [int]$summary.mdoP1Consumed
                            mdoUsers = [int]$summary.mdoUsers
                            mdoUsersWithoutMde = [int]$summary.mdoUsersWithoutMde
                            usersLicensed = [int]$summary.licensedUsers
                            clients = [int]$summary.clients
                            clientsUnlicensed = [int]$summary.clientsUnlicensed
                            p2Enabled = [int]$summary.p2Enabled
                            p2Consumed = [int]$summary.p2Consumed
                        })
                })
            $ok++
            if ([int]$summary.clientsUnlicensed -gt 0) {
                $findings.Add([ordered]@{ id = 'office.licensing_context'; severity = 'Medium'; category = 'licensing'; title = @{ en = 'Unlicensed devices also observed in Office risk context'; de = 'Unlizenzierte Geräte auch im Office-Risikokontext sichtbar' }; detail = @{ en = "$($summary.clientsUnlicensed) client device(s) currently mapped to users without MDE licence coverage."; de = "$($summary.clientsUnlicensed) Client-Gerät(e) sind aktuell Benutzern ohne MDE-Lizenzabdeckung zugeordnet." }; recommendation = @{ en = 'Align user/device assignment with MDE licensing and policy targeting.'; de = 'Benutzer-/Gerätezuordnung mit MDE-Lizenzierung und Policy-Targeting abstimmen.' } })
            }
        }
        else {
            $rows.Add([ordered]@{ key = 'licensing_context'; title = 'Licensing context (from licensing module snapshot)'; workload = 'Licensing'; status = 'ok'; error = $null; result = @([ordered]@{ state = 'unavailable'; reason = 'Licensing module not enabled or not run yet'; action = 'Enable module "licensing" in GAPSIO_MODULES and run it once.' }) })
        }
    }
    catch {
        $rows.Add([ordered]@{ key = 'licensing_context'; title = 'Licensing context (from licensing module snapshot)'; workload = 'Licensing'; status = 'ok'; error = $null; result = @([ordered]@{ state = 'unavailable'; reason = [string]$_.Exception.Message; action = 'Enable module "licensing" and check permissions (Organization.Read.All, User.Read.All, ThreatHunting.Read.All).' }) })
    }

    # Anti-phish policy drift: settings history (Exchange admin audit) + phish outcomes per policy/day.
    $antiphish = $null
    try {
        $ap = Update-GapsioOfficeAntiPhishHistory
        foreach ($r in @($ap.rows)) { $rows.Add($r); if ($r.status -eq 'ok') { $ok++ } else { $errors++ } }
        foreach ($f in @($ap.findings)) { $findings.Add($f) }
        $antiphish = $ap.antiphish
    }
    catch {
        $rows.Add([ordered]@{ key = 'antiphish_drift'; title = 'Anti-phish drift'; workload = 'Anti-phish drift'; status = 'error'; error = [string]$_.Exception.Message; result = @() })
        $errors++
    }

    $out = [ordered]@{
        version     = 3
        generatedAt = [DateTime]::UtcNow.ToString('o')
        windowDays  = 30
        ok          = $ok
        errors      = $errors
        results     = @($rows)
        findings    = @($findings)
        antiphish   = $antiphish
    }
    Set-GapsioBlob -Container 'state' -Name 'office-preview-latest.json' -Object $out -Depth 16
    $out
}
