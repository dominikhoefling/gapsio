# Gapsio – module "officepreview" (private preview): Defender for Office 365 from Advanced Hunting.
#
# Every probe uses documented columns of the Defender XDR hunting schema (EmailEvents, EmailPostDeliveryEvents,
# UrlClickEvents – learn.microsoft.com/defender-xdr/advanced-hunting-emailevents-table and siblings):
#   - ThreatTypes / LatestDeliveryLocation      mail Defender currently rates as phish or malware that is still in an inbox
#   - OrgLevelAction / OrgLevelPolicy           allows defined by the organisation (Tenant Allow/Block List, transport rules …)
#   - UserLevelAction / UserLevelPolicy         allows from the recipient's own mailbox policy (safe senders …) – not admin policies
#   - IsClickedThrough                          users who continued past the Safe Links warning
#   - AuthenticationDetails, EmailDirection     inbound mail that claims one of your own sender domains and fails DMARC
#   - EmailActionPolicy / EmailAction           which protection acted on the mail
# Teams (MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo) and quarantine actions (CloudAppEvents, audit
# operations Quarantine…) are optional: a tenant without Defender for Office 365 Plan 2 or without the Microsoft 365
# connector of Defender for Cloud Apps does not have these tables – the probe is then "unavailable", not failed.
# A probe that fails is reported as failed – never as "no data". Values Microsoft does not enumerate (OrgLevelAction,
# AuthenticationDetails) are matched tolerantly. Policy configuration itself is not readable through Graph; changes to
# anti-phish policies come from the audit trail (OfficeAntiPhish.ps1).

function Invoke-GapsioOfficeHunting {
    # Advanced Hunting for the office module: throws on failure so a failed probe is never mistaken for an empty result.
    param([Parameter(Mandatory)][string]$Query, [string]$Context = 'office preview', [string]$Timespan = 'P30D')
    @(Invoke-GapsioHunting -Query $Query -Timespan $Timespan | Where-Object { $null -ne $_ })
}

$script:GapsioOfficeProbes = @(
    @{ key = 'threat_in_inbox'; title = 'Phish and malware still in inboxes'; workload = 'Email'; query = @'
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| extend Now = tolower(LatestDeliveryLocation), First = tolower(DeliveryLocation)
| summarize messages = count(),
    inInbox = countif(Now startswith "inbox"),
    inboxPhish = countif(Now startswith "inbox" and ThreatTypes has "Phish"),
    inboxMalware = countif(Now startswith "inbox" and ThreatTypes has "Malware"),
    inboxRecipients = dcountif(RecipientEmailAddress, Now startswith "inbox"),
    deliveredThenRemoved = countif(First startswith "inbox" and isnotempty(Now) and not(Now startswith "inbox"))
'@ }
    @{ key = 'threat_allowed'; title = 'Threats delivered by an allow'; workload = 'Email'; query = @'
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| extend OrgAllow = tolower(OrgLevelAction) has "allow", UserAllow = tolower(UserLevelAction) has "allow"
| where OrgAllow or UserAllow
| summarize messages = count(), delivered = countif(DeliveryAction =~ "Delivered"), byOrgPolicy = countif(OrgAllow), byMailboxPolicy = countif(UserAllow and not(OrgAllow)), recipients = dcount(RecipientEmailAddress)
'@ }
    @{ key = 'threat_allowed_policies'; title = 'Allows that delivered threats'; workload = 'Email'; many = 20; query = @'
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| extend OrgAllow = tolower(OrgLevelAction) has "allow", UserAllow = tolower(UserLevelAction) has "allow"
| where OrgAllow or UserAllow
| extend Level = iff(OrgAllow, "Organisation", "Mailbox"), Policy = iff(OrgAllow, OrgLevelPolicy, UserLevelPolicy)
| summarize messages = count(), delivered = countif(DeliveryAction =~ "Delivered"), recipients = dcount(RecipientEmailAddress) by Level, Policy
| top 20 by messages desc
'@ }
    @{ key = 'safelinks_clicks'; title = 'Safe Links clicks'; workload = 'Safe Links'; query = @'
UrlClickEvents
| where Timestamp > ago(30d)
| summarize clicks = count(), threatClicks = countif(isnotempty(ThreatTypes)), clickedThrough = countif(IsClickedThrough == true),
    clickThroughUsers = dcountif(AccountUpn, IsClickedThrough == true), clickThroughUrls = dcountif(Url, IsClickedThrough == true)
'@ }
    @{ key = 'safelinks_by_workload'; title = 'Safe Links clicks by workload'; workload = 'Safe Links'; many = 10; query = @'
UrlClickEvents
| where Timestamp > ago(30d)
| summarize clicks = count(), threatClicks = countif(isnotempty(ThreatTypes)), clickedThrough = countif(IsClickedThrough == true) by Workload
| order by clicks desc
'@ }
    @{ key = 'own_domain_spoof'; title = 'Own sender domains failing DMARC'; workload = 'Email authentication'; query = @'
let own = EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection in ("Outbound", "Intra-org")
| where isnotempty(SenderFromDomain)
| summarize by Domain = tolower(SenderFromDomain);
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| extend Domain = tolower(SenderFromDomain), Auth = tolower(AuthenticationDetails)
| where Domain in (own)
| extend DmarcFail = Auth matches regex "dmarc\"?\\s*[:=]\\s*\"?fail"
| summarize messages = count(), dmarcFail = countif(DmarcFail), dmarcFailDelivered = countif(DmarcFail and DeliveryAction =~ "Delivered"),
    domains = dcountif(Domain, DmarcFail), recipients = dcountif(RecipientEmailAddress, DmarcFail and DeliveryAction =~ "Delivered")
'@ }
    @{ key = 'post_delivery'; title = 'Post-delivery actions (ZAP, manual remediation)'; workload = 'Email'; query = @'
EmailPostDeliveryEvents
| where Timestamp > ago(30d)
| summarize events = count(), messages = dcount(NetworkMessageId), phishZap = countif(ActionType == "Phish ZAP"), malwareZap = countif(ActionType == "Malware ZAP"), manual = countif(ActionType == "Manual remediation")
'@ }
    @{ key = 'threat_trend_daily'; title = 'Threat trend (daily)'; workload = 'Dashboard'; many = 500; query = @'
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| extend Threat = tolower(ThreatTypes)
| extend Bucket = case(Threat has "phish", "Phish", Threat has "malware", "Malware", Threat has "spam", "Spam", isempty(Threat), "None", "Other")
| where Bucket != "None"
| summarize events = count() by day = startofday(Timestamp), bucket = Bucket
| order by day asc
'@ }
    @{ key = 'action_trend_daily'; title = 'Delivery outcomes (daily)'; workload = 'Dashboard'; many = 500; query = @'
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| extend Bucket = case(DeliveryLocation =~ "Quarantine", "Quarantine", DeliveryAction =~ "Blocked", "Block", DeliveryAction =~ "Junked", "Junk", DeliveryAction =~ "Delivered", "Allow", "Other")
| summarize events = count() by day = startofday(Timestamp), bucket = Bucket
| order by day asc
'@ }
    @{ key = 'threat_themes'; title = 'Threats by type and classification'; workload = 'Dashboard'; many = 20; query = @'
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where isnotempty(ThreatTypes)
| summarize events = count(), delivered = countif(DeliveryAction =~ "Delivered"), recipients = dcount(RecipientEmailAddress) by ThreatTypes, ThreatClassification
| top 20 by events desc
'@ }
    @{ key = 'policy_actions'; title = 'Which protection acted'; workload = 'Policy map'; many = 50; query = @'
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where isnotempty(EmailActionPolicy)
| summarize messages = count(), recipients = dcount(RecipientEmailAddress) by EmailActionPolicy, EmailAction
| top 50 by messages desc
'@ }
    @{ key = 'org_policies'; title = 'Organisation-level policies and their action'; workload = 'Policy map'; many = 50; query = @'
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where isnotempty(OrgLevelPolicy)
| summarize messages = count(), withThreat = countif(ThreatTypes has "Phish" or ThreatTypes has "Malware"), delivered = countif(DeliveryAction =~ "Delivered"), recipients = dcount(RecipientEmailAddress) by OrgLevelPolicy, OrgLevelAction
| top 50 by messages desc
'@ }
    @{ key = 'mailbox_policies'; title = 'Mailbox policies of recipients and their action'; workload = 'Policy map'; many = 50; query = @'
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where isnotempty(UserLevelPolicy)
| summarize messages = count(), withThreat = countif(ThreatTypes has "Phish" or ThreatTypes has "Malware"), delivered = countif(DeliveryAction =~ "Delivered"), recipients = dcount(RecipientEmailAddress) by UserLevelPolicy, UserLevelAction
| top 50 by messages desc
'@ }
    # --- Microsoft Teams (Defender for Office 365 Plan 2). The tables hold every message of conversations with
    # external participants and internal messages that contain URLs. A message can appear more than once (edits).
    @{ key = 'teams_threats'; title = 'Teams messages with a phishing or malware verdict'; workload = 'Teams'; optional = $true; query = @'
let removed = MessagePostDeliveryEvents
| where Timestamp > ago(30d)
| summarize by TeamsMessageId
| extend Removed = true;
MessageEvents
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, ThreatTypes, DeliveryAction, IsExternalThread, SenderEmailAddress) by TeamsMessageId
| extend Threat = tolower(ThreatTypes)
| extend IsThreat = Threat has "phish" or Threat has "malware"
| join kind=leftouter removed on TeamsMessageId
| extend Removed = coalesce(Removed, false)
| summarize messages = count(), threats = countif(IsThreat), phish = countif(Threat has "phish"), malware = countif(Threat has "malware"),
    blocked = countif(IsThreat and DeliveryAction =~ "Blocked"), delivered = countif(IsThreat and DeliveryAction =~ "Delivered"),
    stillThere = countif(IsThreat and DeliveryAction =~ "Delivered" and not(Removed)),
    external = countif(IsThreat and IsExternalThread == true), senders = dcountif(SenderEmailAddress, IsThreat)
'@ }
    @{ key = 'teams_post_delivery'; title = 'Teams post-delivery actions (ZAP, manual remediation)'; workload = 'Teams'; optional = $true; query = @'
MessagePostDeliveryEvents
| where Timestamp > ago(30d)
| summarize events = count(), messages = dcount(TeamsMessageId), phishZap = countif(ActionType == "Phish ZAP"), malwareZap = countif(ActionType == "Malware ZAP"),
    manual = countif(ActionType == "Manual remediation"), quarantined = countif(Action contains "quarantine")
'@ }
    @{ key = 'teams_threat_senders'; title = 'Senders of Teams messages with a threat verdict'; workload = 'Teams'; optional = $true; many = 20; query = @'
MessageEvents
| where Timestamp > ago(30d)
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| summarize arg_max(Timestamp, ThreatTypes, DeliveryAction, IsExternalThread, SenderEmailAddress, SenderType) by TeamsMessageId
| summarize messages = count(), delivered = countif(DeliveryAction =~ "Delivered"), external = countif(IsExternalThread == true), lastSeen = max(Timestamp) by SenderEmailAddress, SenderType, ThreatTypes
| top 20 by messages desc
'@ }
    # The verdict comes from the message: MessageUrlInfo.ThreatTypes is documented but does not resolve in real tenants.
    @{ key = 'teams_url_domains'; title = 'Domains of URLs in Teams messages with a threat verdict'; workload = 'Teams'; optional = $true; many = 20; query = @'
MessageEvents
| where Timestamp > ago(30d)
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| summarize arg_max(Timestamp, ThreatTypes) by TeamsMessageId
| join kind=inner (MessageUrlInfo | where Timestamp > ago(30d) | project TeamsMessageId, Url, UrlDomain) on TeamsMessageId
| summarize urls = dcount(Url), messages = dcount(TeamsMessageId) by UrlDomain, ThreatTypes
| top 20 by messages desc
'@ }
    # --- Quarantine (audit trail). Operation names start with "Quarantine" (QuarantineRelease, QuarantineReleaseRequest,
    # QuarantineReleaseRequestDeny, QuarantineDeleteMessage, QuarantinePreview, QuarantineExport, QuarantineViewHeader);
    # they are matched by their parts so older and newer spellings both count. RawEventData.NetworkMessageId links a
    # release to the mail in EmailEvents.
    @{ key = 'quarantine_actions'; title = 'Quarantine actions (audit trail)'; workload = 'Quarantine'; optional = $true; query = @'
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Quarantine"
| extend Kind = case(ActionType contains "Deny", "Denied", ActionType contains "ReleaseRequest", "Requested", ActionType contains "Release", "Released",
    ActionType contains "Delete", "Deleted", ActionType contains "Export", "Exported", ActionType contains "Preview", "Previewed", ActionType contains "Header", "HeaderViewed", "Other")
| summarize events = count(), released = countif(Kind == "Released"), requested = countif(Kind == "Requested"), denied = countif(Kind == "Denied"),
    deleted = countif(Kind == "Deleted"), previewed = countif(Kind == "Previewed"), exported = countif(Kind == "Exported")
'@ }
    @{ key = 'quarantine_released'; title = 'Released from quarantine, with the verdict of the mail'; workload = 'Quarantine'; optional = $true; query = @'
let mail = EmailEvents
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, ThreatTypes) by NetworkMessageId
| project MailId = NetworkMessageId, ThreatTypes;
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Quarantine" and ActionType contains "Release" and not(ActionType contains "Request")
| extend Raw = parse_json(tostring(RawEventData))
| extend NetworkMessageId = tostring(Raw.NetworkMessageId), Actor = coalesce(AccountDisplayName, AccountId, tostring(Raw.UserId))
| join kind=leftouter mail on $left.NetworkMessageId == $right.MailId
| extend Threat = tolower(ThreatTypes)
| summarize releases = count(), matched = countif(isnotempty(MailId)), phish = countif(Threat has "phish"), malware = countif(Threat has "malware"), spam = countif(Threat has "spam"), actors = dcount(Actor)
'@ }
    @{ key = 'quarantine_releasers'; title = 'Who released from quarantine'; workload = 'Quarantine'; optional = $true; many = 20; query = @'
let mail = EmailEvents
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, ThreatTypes) by NetworkMessageId
| project MailId = NetworkMessageId, ThreatTypes;
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Quarantine" and ActionType contains "Release" and not(ActionType contains "Request")
| extend Raw = parse_json(tostring(RawEventData))
| extend NetworkMessageId = tostring(Raw.NetworkMessageId), Actor = coalesce(AccountDisplayName, AccountId, tostring(Raw.UserId))
| join kind=leftouter mail on $left.NetworkMessageId == $right.MailId
| extend Threat = tolower(ThreatTypes)
| summarize releases = count(), phish = countif(Threat has "phish"), malware = countif(Threat has "malware"), lastRelease = max(Timestamp) by Actor
| top 20 by releases desc
'@ }
)

function Get-GapsioOfficeFindings {
    <#
    .SYNOPSIS
    Findings from the probe results (hashtable key -> rows). Only results of probes that ran successfully are passed in.
    #>
    param([hashtable]$Results)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-GapsioText -En $en -De $de }
    $one = { param($k) if ($Results.ContainsKey($k)) { @($Results[$k])[0] } else { $null } }

    $x = & $one 'threat_in_inbox'
    if ($x -and [int]$x.inInbox -gt 0) {
        $f.Add((New-GapsioFinding -Severity 'High' -Category 'Office' -Title (& $T "$([int]$x.inInbox) message(s) rated phish or malware are still in inboxes" "$([int]$x.inInbox) als Phishing oder Malware bewertete Nachricht(en) liegen noch in Posteingängen") `
                    -Detail (& $T "Defender for Office 365 currently rates these inbound messages as phishing ($([int]$x.inboxPhish)) or malware ($([int]$x.inboxMalware)), but their last known location is the inbox of $([int]$x.inboxRecipients) recipient(s) (30 days). ZAP did not remove them, or an allow or the recipient kept them there." `
                        "Defender for Office 365 bewertet diese eingehenden Nachrichten aktuell als Phishing ($([int]$x.inboxPhish)) oder Malware ($([int]$x.inboxMalware)), ihr letzter bekannter Ort ist aber der Posteingang von $([int]$x.inboxRecipients) Empfänger(n) (30 Tage). ZAP hat sie nicht entfernt, oder ein Allow bzw. der Empfänger hat sie dort gehalten.") `
                    -Recommendation (& $T 'Remediate the messages in Threat Explorer (soft delete), check that zero-hour auto purge is on in the anti-spam and anti-malware policies, and look at the allows below.' 'Die Nachrichten im Threat Explorer bereinigen (Soft Delete), prüfen, dass Zero-hour Auto Purge in den Anti-Spam- und Anti-Malware-Richtlinien aktiv ist, und die Allows unten ansehen.') -Subject 'office.threat_in_inbox' -StableKey))
    }
    $x = & $one 'threat_allowed'
    if ($x -and [int]$x.messages -gt 0) {
        $top = (@(@($Results['threat_allowed_policies']) | Where-Object { $_ } | Select-Object -First 5 | ForEach-Object { "$(if ($_.Policy) { $_.Policy } else { '(unnamed)' }) [$($_.Level)]: $([int]$_.messages)" })) -join '; '
        $f.Add((New-GapsioFinding -Severity $(if ([int]$x.delivered -gt 0) { 'High' } else { 'Medium' }) -Category 'Office' -Title (& $T "Allows let $([int]$x.messages) message(s) with a threat verdict through" "Allows haben $([int]$x.messages) Nachricht(en) mit Bedrohungsurteil durchgelassen") `
                    -Detail (& $T "$([int]$x.byOrgPolicy) through an organisation-level allow, $([int]$x.byMailboxPolicy) through the recipient's own mailbox policy (such as safe senders); $([int]$x.delivered) were delivered to $([int]$x.recipients) recipient(s) (30 days).$(if ($top) { " Top: $top." })" `
                        "$([int]$x.byOrgPolicy) über ein Allow auf Organisationsebene, $([int]$x.byMailboxPolicy) über die eigene Postfachregel des Empfängers (z. B. sichere Absender); $([int]$x.delivered) wurden an $([int]$x.recipients) Empfänger zugestellt (30 Tage).$(if ($top) { " Top: $top." })") `
                    -Recommendation (& $T 'Review the allow entries: Tenant Allow/Block List entries should expire, transport rules should not skip filtering for whole domains, and safe sender lists should not override phishing verdicts.' 'Die Allow-Einträge prüfen: Einträge der Tenant Allow/Block List sollten ablaufen, Transportregeln nicht die Filterung ganzer Domänen überspringen und Listen sicherer Absender keine Phishing-Urteile übersteuern.') -Subject 'office.threat_allowed' -StableKey))
    }
    $x = & $one 'safelinks_clicks'
    if ($x -and [int]$x.clickedThrough -gt 0) {
        $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'Office' -Title (& $T "Users clicked through the Safe Links warning $([int]$x.clickedThrough) time(s)" "Benutzer haben die Safe-Links-Warnung $([int]$x.clickedThrough)-mal übergangen") `
                    -Detail (& $T "$([int]$x.clickThroughUsers) user(s) chose `“Continue anyway`” for $([int]$x.clickThroughUrls) URL(s) in 30 days." "$([int]$x.clickThroughUsers) Benutzer haben in 30 Tagen bei $([int]$x.clickThroughUrls) URL(s) `„Trotzdem fortfahren`“ gewählt.") `
                    -Recommendation (& $T 'Switch off “Let users click through to the original URL” in the Safe Links policies.' '„Benutzern das Durchklicken zur ursprünglichen URL erlauben“ in den Safe-Links-Richtlinien ausschalten.') -Subject 'office.safelinks_clickthrough' -StableKey))
    }
    $x = & $one 'own_domain_spoof'
    if ($x -and [int]$x.dmarcFailDelivered -gt 0) {
        $f.Add((New-GapsioFinding -Severity 'High' -Category 'Office' -Title (& $T "$([int]$x.dmarcFailDelivered) message(s) spoofing your own domains were delivered" "$([int]$x.dmarcFailDelivered) Nachricht(en) mit gefälschter eigener Domäne wurden zugestellt") `
                    -Detail (& $T "Inbound mail with one of your own sender domains ($([int]$x.domains)) in the From header failed DMARC and was still delivered to $([int]$x.recipients) recipient(s) (30 days). Own domains are the ones seen in your outbound mail." `
                        "Eingehende Mail mit einer Ihrer eigenen Absenderdomänen ($([int]$x.domains)) im From-Header ist an DMARC gescheitert und wurde trotzdem an $([int]$x.recipients) Empfänger zugestellt (30 Tage). Eigene Domänen sind die, die in Ihrer ausgehenden Mail vorkommen.") `
                    -Recommendation (& $T 'Check what delivered them (connectors, transport rules, allows), honour the DMARC policy in the anti-phishing policy and move your own domains to p=reject.' 'Prüfen, was sie zugestellt hat (Connectors, Transportregeln, Allows), die DMARC-Richtlinie in der Anti-Phishing-Richtlinie beachten und die eigenen Domänen auf p=reject stellen.') -Subject 'office.own_domain_spoof' -StableKey))
    }
    $x = & $one 'teams_threats'
    if ($x -and [int]$x.stillThere -gt 0) {
        $f.Add((New-GapsioFinding -Severity 'High' -Category 'Office' -Title (& $T "$([int]$x.stillThere) Teams message(s) rated phishing or malware were delivered and not removed" "$([int]$x.stillThere) als Phishing oder Malware bewertete Teams-Nachricht(en) wurden zugestellt und nicht entfernt") `
                    -Detail (& $T "Defender for Office 365 rates $([int]$x.threats) Teams message(s) from $([int]$x.senders) sender(s) as phishing ($([int]$x.phish)) or malware ($([int]$x.malware)) in 30 days. $([int]$x.blocked) were blocked, $([int]$x.delivered) delivered; for $([int]$x.stillThere) of the delivered ones no post-delivery action (ZAP, manual remediation) is recorded. $([int]$x.external) are in conversations with external participants." `
                        "Defender for Office 365 bewertet in 30 Tagen $([int]$x.threats) Teams-Nachricht(en) von $([int]$x.senders) Absender(n) als Phishing ($([int]$x.phish)) oder Malware ($([int]$x.malware)). $([int]$x.blocked) wurden blockiert, $([int]$x.delivered) zugestellt; bei $([int]$x.stillThere) der zugestellten ist keine Aktion nach der Zustellung (ZAP, manuelle Bereinigung) verzeichnet. $([int]$x.external) liegen in Unterhaltungen mit externen Teilnehmern.") `
                    -Recommendation (& $T 'Remove the messages (Teams message entity in the Defender portal), check that zero-hour auto purge for Teams is on in the Teams protection policy, and review who may start chats from outside the organisation (external access, unmanaged accounts).' 'Die Nachrichten entfernen (Teams-Nachrichtenentität im Defender-Portal), prüfen, dass Zero-hour Auto Purge für Teams in der Teams-Schutzrichtlinie aktiv ist, und klären, wer von außen Chats beginnen darf (externer Zugriff, nicht verwaltete Konten).') -Subject 'office.teams_threat_delivered' -StableKey))
    }
    $x = & $one 'quarantine_released'
    if ($x -and ([int]$x.phish + [int]$x.malware) -gt 0) {
        $n = [int]$x.phish + [int]$x.malware
        $top = (@(@($Results['quarantine_releasers']) | Where-Object { $_ -and ([int]$_.phish + [int]$_.malware) -gt 0 } | Select-Object -First 5 | ForEach-Object { "$(if ($_.Actor) { $_.Actor } else { '(unknown)' }): $([int]$_.phish + [int]$_.malware)" })) -join '; '
        $f.Add((New-GapsioFinding -Severity $(if ([int]$x.malware -gt 0) { 'High' } else { 'Medium' }) -Category 'Office' -Title (& $T "$n message(s) with a phishing or malware verdict were released from quarantine" "$n Nachricht(en) mit Phishing- oder Malware-Urteil wurden aus der Quarantäne freigegeben") `
                    -Detail (& $T "$([int]$x.releases) release(s) by $([int]$x.actors) account(s) in 30 days; $([int]$x.matched) could be matched to mail telemetry, of those $([int]$x.phish) are rated phishing and $([int]$x.malware) malware.$(if ($top) { " Released by: $top." }) A release can be the correct handling of a false positive – or a threat that now sits in a mailbox." `
                        "$([int]$x.releases) Freigabe(n) durch $([int]$x.actors) Konto/Konten in 30 Tagen; $([int]$x.matched) ließen sich der Mail-Telemetrie zuordnen, davon sind $([int]$x.phish) als Phishing und $([int]$x.malware) als Malware bewertet.$(if ($top) { " Freigegeben von: $top." }) Eine Freigabe kann der richtige Umgang mit einem Fehlalarm sein – oder eine Bedrohung, die jetzt in einem Postfach liegt.") `
                    -Recommendation (& $T 'Review each release in the audit trail and in Threat Explorer. Report false positives to Microsoft instead of only releasing them, and use quarantine policies that let users request the release of phishing, not release it themselves.' 'Jede Freigabe im Audit-Trail und im Threat Explorer prüfen. Fehlalarme an Microsoft melden, statt sie nur freizugeben, und Quarantänerichtlinien nutzen, mit denen Benutzer die Freigabe von Phishing nur anfordern, nicht selbst durchführen können.') -Subject 'office.quarantine_threat_released' -StableKey))
    }
    @($f.ToArray())
}

function Invoke-GapsioOfficePreviewCollection {
    <#
    .SYNOPSIS
    Full run of the office module: probes, findings, anti-phish drift; writes the snapshot with change history and run
    index like the other modules (state/officepreview-latest.json).
    #>
    Reset-GapsioWarnings
    $started = [DateTime]::UtcNow
    $rows = [System.Collections.Generic.List[object]]::new()
    $results = @{}
    $findings = [System.Collections.Generic.List[object]]::new()
    $ok = 0; $errors = 0; $unavailable = 0
    $hunting = Test-GapsioFeature -Name 'hunting'
    if (-not $hunting) {
        $rows.Add([ordered]@{ key = 'hunting'; title = 'Advanced Hunting access'; workload = 'Platform'; status = 'error'; error = 'Feature Hunting (ThreatHunting.Read.All) is not enabled in this installation.'; result = @() })
        $errors++
    }
    else {
        foreach ($p in $script:GapsioOfficeProbes) {
            try {
                $all = @(Invoke-GapsioOfficeHunting -Query "// GapsioOffice:$($p.key)`n$($p.query)" -Context "office preview $($p.key)")
                $take = if ($p.many) { [int]$p.many } else { 1 }
                $res = @($all | Select-Object -First $take)
                $results[$p.key] = $res
                $rows.Add([ordered]@{ key = $p.key; title = $p.title; workload = $p.workload; status = 'ok'; error = $null; result = $res })
                $ok++
            }
            catch {
                # An optional table that the tenant does not have is "unavailable" – not a failed check
                $missing = $p.optional -and ([string]$_.Exception.Message) -match 'Failed to resolve table expression'
                $rows.Add([ordered]@{ key = $p.key; title = $p.title; workload = $p.workload; status = $(if ($missing) { 'unavailable' } else { 'error' }); error = (Get-GapsioErrorText -Exception $_.Exception -Context "office preview $($p.key) ThreatHunting.Read.All"); result = @() })
                if ($missing) { $unavailable++ } else { $errors++ }
            }
        }
        foreach ($x in @(Get-GapsioOfficeFindings -Results $results)) { $findings.Add($x) }
    }

    # Licence context from the licensing module (how many users hold a Defender for Office 365 plan)
    try {
        $lic = Get-GapsioBlob -Container 'state' -Name 'licensing-latest.json'
        $s = Get-GapsioProp $lic 'summary'
        if ($s) {
            $rows.Add([ordered]@{ key = 'licensing_context'; title = 'Defender for Office 365 licences (licensing module)'; workload = 'Licensing'; status = 'ok'; error = $null
                    result = @([ordered]@{ mdoUsers = [int]$s.mdoUsers; mdoP2Enabled = [int]$s.mdoP2Enabled; mdoP2Consumed = [int]$s.mdoP2Consumed; mdoP1Enabled = [int]$s.mdoP1Enabled; mdoP1Consumed = [int]$s.mdoP1Consumed }) })
        }
    }
    catch { }

    # Anti-phish policy drift: settings history (audit trail) + phish outcomes per policy and day
    $antiphish = $null
    if ($hunting) {
        try {
            $ap = Update-GapsioOfficeAntiPhishHistory
            foreach ($r in @($ap.rows)) { $rows.Add($r); if ($r.status -eq 'ok') { $ok++ } else { $errors++ } }
            foreach ($x in @($ap.findings)) {
                if (-not $x) { continue }
                $findings.Add((New-GapsioFinding -Severity ([string]$x.severity) -Category 'Office' -Title (ConvertTo-GapsioText $x.title) -Detail (ConvertTo-GapsioText $x.detail) -Recommendation (ConvertTo-GapsioText $x.recommendation) -Subject ([string]$x.id) -StableKey))
            }
            $antiphish = $ap.antiphish
        }
        catch {
            $rows.Add([ordered]@{ key = 'antiphish_drift'; title = 'Anti-phish drift'; workload = 'Anti-phish drift'; status = 'error'; error = [string]$_.Exception.Message; result = @() })
            $errors++
        }
    }

    # Changes to the protection policies of all families (audit trail, kept beyond the 30 days of Advanced Hunting)
    $policy = $null
    if ($hunting) {
        try {
            $pc = Update-GapsioOfficePolicyHistory
            $rows.Add($pc.row)
            switch ($pc.row.status) { 'ok' { $ok++ } 'unavailable' { $unavailable++ } default { $errors++ } }
            foreach ($x in @($pc.findings)) {
                if (-not $x) { continue }
                $findings.Add((New-GapsioFinding -Severity ([string]$x.severity) -Category 'Office' -Title (ConvertTo-GapsioText $x.title) -Detail (ConvertTo-GapsioText $x.detail) -Recommendation (ConvertTo-GapsioText $x.recommendation) -Subject ([string]$x.id) -StableKey))
            }
            $policy = $pc.policy
        }
        catch {
            $rows.Add([ordered]@{ key = 'policy_changes'; title = 'Protection policy changes (Exchange admin audit)'; workload = 'Policy changes'; status = 'error'; error = [string]$_.Exception.Message; result = @() })
            $errors++
        }
    }

    $one = { param($k) if ($results.ContainsKey($k)) { @($results[$k])[0] } else { $null } }
    $num = { param($o, $n) if ($o) { [int](Get-GapsioProp $o $n) } else { $null } }
    $sev = [ordered]@{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $sev[$s] = @($findings | Where-Object { $_.severity -eq $s }).Count }
    $snapshot = [ordered]@{
        module      = 'officepreview'
        version     = (Get-GapsioVersion)
        schema      = 5
        generatedAt = [DateTime]::UtcNow.ToString('o')
        tenantId    = Get-GapsioSetting -Name 'GAPSIO_TENANT_ID'
        windowDays  = 30
        ok          = $ok
        errors      = $errors
        unavailable = $unavailable
        summary     = [ordered]@{
            threatsInInbox      = & $num (& $one 'threat_in_inbox') 'inInbox'
            removedAfterDelivery = & $num (& $one 'threat_in_inbox') 'deliveredThenRemoved'
            threatsAllowed      = & $num (& $one 'threat_allowed') 'messages'
            clickThroughs       = & $num (& $one 'safelinks_clicks') 'clickedThrough'
            ownDomainSpoofDelivered = & $num (& $one 'own_domain_spoof') 'dmarcFailDelivered'
            zapActions          = $(if (& $one 'post_delivery') { [int](& $one 'post_delivery').phishZap + [int](& $one 'post_delivery').malwareZap } else { $null })
            teamsThreatsDelivered = & $num (& $one 'teams_threats') 'stillThere'
            quarantineReleases  = & $num (& $one 'quarantine_actions') 'released'
            quarantineThreatsReleased = $(if (& $one 'quarantine_released') { [int](& $one 'quarantine_released').phish + [int](& $one 'quarantine_released').malware } else { $null })
            policyChanges30d    = $(if ($policy -and $pc.row.status -eq 'ok') { [int]$policy.changes30d } else { $null })
            policyWeakened30d   = $(if ($policy -and $pc.row.status -eq 'ok') { [int]$policy.weakened30d } else { $null })
            findings            = $sev
        }
        results     = @($rows)
        findings    = @($findings)
        antiphish   = $antiphish
        policyChanges = $policy
        warnings    = @(Get-GapsioWarnings)
    }
    $r = Save-GapsioSnapshot -Module 'officepreview' -Snapshot $snapshot -Collections @('findings') -Started $started
    Write-Information "Gapsio office preview: done, $ok probe(s) ok, $errors failed, $unavailable unavailable, $($r.changes) change(s)." -InformationAction Continue
    $r
}
