# Gapsio – module "purviewpreview" (private preview): Microsoft Purview DLP / Endpoint DLP basics.
#
# What it collects (read-only):
#   1. Licences   – subscribedSkus mapped to Purview capabilities (Endpoint DLP, DLP for Exchange/SharePoint/OneDrive/Teams,
#                   sensitivity labels, auto-labelling, Content explorer, Insider Risk, trainable classifiers, Audit Premium …)
#                   plus how many users hold the Endpoint DLP / Information Protection Premium plan.
#   2. Devices    – MDE-onboarded Windows/macOS devices (Endpoint DLP capable) vs. devices that actually reported Endpoint
#                   DLP activity (audit record type DLPEndpoint via CloudAppEvents) – "capable but silent" devices are the gap.
#   3. Permissions – Entra roles that grant Purview/DLP access (active + eligible). Purview role groups have no Graph API.
#   4. Labels     – sensitivity labels (Graph, needs InformationProtectionPolicy.Read.All; skipped quietly otherwise).
#   5. Hunting    – DLP rule matches, user overrides/justifications, exfil channels (USB, cloud, print, share), label
#                   removals/downgrades, DLP/label/audit configuration changes (who changed what), DLP alerts.
# The Advanced Hunting probes need ThreatHunting.Read.All. CloudAppEvents carries Purview audit records only when the
# Defender for Cloud Apps "Microsoft 365" app connector is enabled – otherwise those probes return no rows (noted in the UI).

$script:GapsioPurviewCapabilities = @(
    @{ id = 'endpointdlp'; label = 'Endpoint DLP'; pattern = '^MICROSOFTENDPOINTDLP' }
    @{ id = 'dlpcore'; label = 'DLP for Exchange / SharePoint / OneDrive'; pattern = '^(EXCHANGE_S_ENTERPRISE|BPOS_S_DLPADDON|EOP_ENTERPRISE_PREMIUM|MIP_S_CLP1)' }
    @{ id = 'dlpteams'; label = 'DLP for Teams chat / advanced DLP (E5)'; pattern = '^(MIP_S_CLP2|MIP_S_EXCHANGE)$' }
    @{ id = 'labels'; label = 'Sensitivity labels (manual)'; pattern = '^(MIP_S_CLP1|RMS_S_PREMIUM(_GOV)?|RMS_S_ENTERPRISE)' }
    @{ id = 'autolabel'; label = 'Auto-labelling / Information Protection premium'; pattern = '^(MIP_S_CLP2|RMS_S_PREMIUM2)' }
    @{ id = 'contentexplorer'; label = 'Content explorer / Activity explorer'; pattern = '^(CONTENT_EXPLORER|CONTENTEXPLORER_STANDARD)' }
    @{ id = 'classifiers'; label = 'Trainable classifiers'; pattern = '^ML_CLASSIFICATION' }
    @{ id = 'insiderrisk'; label = 'Insider Risk Management'; pattern = '^INSIDER_RISK' }
    @{ id = 'commcompliance'; label = 'Communication Compliance'; pattern = '^MICROSOFT_COMMUNICATION_COMPLIANCE' }
    @{ id = 'auditpremium'; label = 'Audit (Premium) / long-term retention'; pattern = '^(M365_ADVANCED_AUDITING|AUDITING_10YEAR|10_ALR)' }
    @{ id = 'ediscovery'; label = 'eDiscovery (Premium)'; pattern = '^EQUIVIO_ANALYTICS' }
    @{ id = 'records'; label = 'Records / data lifecycle management'; pattern = '^(RECORDS_MANAGEMENT|INFO_GOVERNANCE)' }
    @{ id = 'infobarriers'; label = 'Information barriers'; pattern = '^INFORMATION_BARRIERS' }
    @{ id = 'lockbox'; label = 'Customer Lockbox'; pattern = '^(LOCKBOX_ENTERPRISE|CUSTOMERLOCKBOXA_ENTERPRISE)' }
    @{ id = 'agents'; label = 'Purview for AI agents'; pattern = '^(INFORMATION_PROTECTION_FOR_AGENTS|INSIDER_RISK_MANAGEMENT_FOR_AGENTS|EDISCOVERY_FOR_AGENTS)' }
)

# Entra roles with Purview / DLP reach (template IDs are identical in every tenant).
$script:GapsioPurviewRoles = [ordered]@{
    '62e90394-69f5-4237-9190-012177145e10' = @{ name = 'Global Administrator'; scope = 'Full Purview access, incl. DLP policies and content' }
    '17315797-102d-40b4-93e0-432062caca18' = @{ name = 'Compliance Administrator'; scope = 'Create/change DLP, label and retention policies' }
    'e6d1a23a-da11-4be4-9570-befc86d067a7' = @{ name = 'Compliance Data Administrator'; scope = 'DLP policies + compliance data' }
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = @{ name = 'Security Administrator'; scope = 'DLP alerts, some Purview settings' }
    '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f' = @{ name = 'Security Operator'; scope = 'Manage DLP alerts' }
    '5d6b6bb7-de71-4623-b4af-96380a352509' = @{ name = 'Security Reader'; scope = 'Read DLP alerts and reports' }
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451' = @{ name = 'Global Reader'; scope = 'Read Purview configuration' }
    '7495fdc4-34c4-4d15-a289-98788ce399fd' = @{ name = 'Azure Information Protection Administrator'; scope = 'Sensitivity labels and label policies' }
}

function Get-GapsioPurviewLicensing {
    $skus = Invoke-GapsioGraphSafe -All -Path 'subscribedSkus' -Context 'Subscribed SKUs (Organization.Read.All)'
    if ($null -eq $skus) { return $null }
    $caps = foreach ($c in $script:GapsioPurviewCapabilities) {
        $sources = [System.Collections.Generic.List[object]]::new()
        foreach ($s in @($skus)) {
            $hits = @(@(Get-GapsioProp $s 'servicePlans') | Where-Object { ([string]$_.servicePlanName).ToUpperInvariant() -match $c.pattern })
            if (-not $hits.Count) { continue }
            $sources.Add([ordered]@{
                    skuPartNumber = [string]$s.skuPartNumber
                    enabled       = [int](Get-GapsioProp (Get-GapsioProp $s 'prepaidUnits') 'enabled')
                    consumed      = [int]$s.consumedUnits
                    status        = [string]$s.capabilityStatus
                    plans         = @($hits | ForEach-Object { "$($_.servicePlanName) ($($_.provisioningStatus))" })
                })
        }
        [ordered]@{
            id = $c.id; label = $c.label; licensed = [bool]$sources.Count
            enabled = [int](($sources | Measure-Object -Property enabled -Sum).Sum)
            consumed = [int](($sources | Measure-Object -Property consumed -Sum).Sum)
            sources = @($sources)
        }
    }
    # Users who actually hold the key plans ($count with eventual consistency – one cheap call per plan).
    $userCounts = [ordered]@{}
    foreach ($p in @(
            @{ k = 'endpointdlp'; id = '64bfac92-2b17-4482-b5e5-a0304429de3e' },
            @{ k = 'mipPremium'; id = 'efb0351d-3b08-4503-993d-383af8de41e3' },
            @{ k = 'mipStandard'; id = '5136a095-5cf0-4aff-bec3-e84448b38ea5' },
            @{ k = 'insiderRisk'; id = 'd587c7a3-bda9-4f99-8776-9bcf59c84f75' })) {
        $r = Invoke-GapsioGraphSafe -Path "users?`$filter=assignedPlans/any(x:x/servicePlanId eq $($p.id) and x/capabilityStatus eq 'Enabled')&`$count=true&`$top=1&`$select=id" -Headers @{ ConsistencyLevel = 'eventual' } -Context 'Users with Purview plan (User.Read.All)'
        $userCounts[$p.k] = if ($r -and $r.PSObject.Properties['@odata.count']) { [int]$r.'@odata.count' } else { $null }
    }
    [ordered]@{ capabilities = @($caps); users = $userCounts }
}

function Get-GapsioPurviewRoleHolders {
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($rid in $script:GapsioPurviewRoles.Keys) {
        $meta = $script:GapsioPurviewRoles[$rid]
        $active = Invoke-GapsioGraphSafe -All -Context 'Entra role assignments (RoleManagement.Read.Directory)' -Path "roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$rid'&`$expand=principal"
        $eligible = Invoke-GapsioGraphSafe -All -Context 'Entra role eligibility (RoleManagement.Read.Directory)' -Path "roleManagement/directory/roleEligibilitySchedules?`$filter=roleDefinitionId eq '$rid'&`$expand=principal"
        foreach ($set in @(@{ t = 'active'; v = $active }, @{ t = 'eligible'; v = $eligible })) {
            foreach ($a in @($set.v)) {
                if (-not $a) { continue }
                $p = Get-GapsioProp $a 'principal'
                $type = ([string](Get-GapsioProp $p '@odata.type')) -replace '^#microsoft\.graph\.', ''
                $out.Add([ordered]@{
                        role = $meta.name; scope = $meta.scope; assignment = $set.t
                        principal = [string](Get-GapsioProp $p 'displayName')
                        upn = [string](Get-GapsioProp $p 'userPrincipalName')
                        type = $type
                        directoryScope = [string](Get-GapsioProp $a 'directoryScopeId')
                    })
            }
        }
    }
    @($out)
}

function Invoke-GapsioPurviewPreviewCollection {
    $rows = [System.Collections.Generic.List[object]]::new()
    $findings = [System.Collections.Generic.List[object]]::new()
    $ok = 0; $errors = 0
    $add = {
        param($key, $title, $workload, $status, $err, $result)
        $rows.Add([ordered]@{ key = $key; title = $title; workload = $workload; status = $status; error = $err; result = @($result) })
    }

    $probes = @(
        [ordered]@{ key = 'devices_platform'; title = 'MDE-onboarded devices by platform'; workload = 'Devices'; returnMany = $true; maxRows = 50
            query = @'
DeviceInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, OSPlatform, OnboardingStatus, DeviceName) by DeviceId
| where OnboardingStatus == "Onboarded"
| extend Capable = OSPlatform startswith "Windows1" or OSPlatform startswith "Windows11" or OSPlatform =~ "macOS"
| summarize devices = count(), capable = countif(Capable) by OSPlatform
| order by devices desc
'@ }
        [ordered]@{ key = 'devices_capable'; title = 'Endpoint DLP capable devices (Windows 10/11, macOS)'; workload = 'Devices'; returnMany = $true; maxRows = 5000
            query = @'
DeviceInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, OSPlatform, OnboardingStatus, DeviceName, OSVersion) by DeviceId
| where OnboardingStatus == "Onboarded"
| where OSPlatform startswith "Windows1" or OSPlatform =~ "macOS"
| project DeviceId, DeviceName = tolower(DeviceName), OSPlatform, OSVersion, LastSeen = Timestamp
'@ }
        [ordered]@{ key = 'devices_dlp_activity'; title = 'Devices reporting Endpoint DLP activity (audit DLPEndpoint)'; workload = 'Devices'; returnMany = $true; maxRows = 5000
            query = @'
CloudAppEvents
| where Timestamp > ago(30d)
| where toint(RawEventData.RecordType) == 63
| extend Device = tolower(tostring(RawEventData.DeviceName)), Op = tostring(RawEventData.Operation), User = tolower(tostring(RawEventData.UserId))
| where isnotempty(Device)
| summarize events = count(), users = dcount(User), operations = make_set(Op, 8), first = min(Timestamp), last = max(Timestamp) by Device
| order by events desc
'@ }
        [ordered]@{ key = 'dlp_rule_matches'; title = 'DLP rule matches by workload and policy'; workload = 'DLP'; returnMany = $true; maxRows = 200
            query = @'
CloudAppEvents
| where Timestamp > ago(30d)
| extend RT = toint(RawEventData.RecordType), Op = tostring(RawEventData.Operation)
| where RT in (11, 13, 33, 63, 99) or Op in~ ("DLPRuleMatch", "DlpRuleMatch", "DLPRuleUndo")
| extend Policy = coalesce(tostring(RawEventData.PolicyMatchInfo.PolicyName), tostring(RawEventData.PolicyDetails[0].PolicyName), "(unknown)"),
         Rule = coalesce(tostring(RawEventData.PolicyMatchInfo.RuleName), tostring(RawEventData.PolicyDetails[0].Rules[0].RuleName), ""),
         Workload = tostring(RawEventData.Workload)
| summarize events = count(), users = dcount(AccountObjectId), last = max(Timestamp) by Workload, Policy, Rule
| order by events desc
'@ }
        [ordered]@{ key = 'dlp_exfil_channels'; title = 'Endpoint DLP activities (USB, cloud upload, print, share, clipboard)'; workload = 'DLP'; returnMany = $true; maxRows = 50
            query = @'
CloudAppEvents
| where Timestamp > ago(30d)
| where toint(RawEventData.RecordType) == 63
| extend Op = tostring(RawEventData.Operation), Mode = toint(RawEventData.EnforcementMode), Sensitive = isnotempty(RawEventData.SensitiveInfoTypeData) or isnotempty(RawEventData.SensitivityLabelId)
| summarize events = count(), sensitive = countif(Sensitive), blocked = countif(Mode == 4), warned = countif(Mode in (2, 3)), audited = countif(Mode == 1), users = dcount(AccountObjectId), devices = dcount(tostring(RawEventData.DeviceName)) by Op
| order by events desc
'@ }
        [ordered]@{ key = 'dlp_overrides'; title = 'DLP overrides and business justifications by user'; workload = 'DLP'; returnMany = $true; maxRows = 100
            query = @'
CloudAppEvents
| where Timestamp > ago(30d)
| extend RT = toint(RawEventData.RecordType), Op = tostring(RawEventData.Operation), Just = tostring(RawEventData.Justification), Mode = toint(RawEventData.EnforcementMode)
| where (RT == 63 and (isnotempty(Just) or Mode == 3)) or Op in~ ("DLPRuleUndo", "DlpRuleUndo") or tostring(RawEventData) has "Override"
| extend User = tolower(coalesce(tostring(RawEventData.UserId), AccountDisplayName))
| summarize overrides = count(), operations = make_set(Op, 6), justifications = make_set(Just, 5), last = max(Timestamp) by User
| order by overrides desc
'@ }
        [ordered]@{ key = 'label_changes'; title = 'Sensitivity label removals and downgrades'; workload = 'Labels'; returnMany = $true; maxRows = 100
            query = @'
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has "SensitivityLabel" or ActionType has "MipLabel"
| extend EvType = toint(RawEventData.SensitivityLabelEventData.LabelEventType),
         User = tolower(coalesce(tostring(RawEventData.UserId), AccountDisplayName))
| extend Change = case(ActionType has "Removed" or EvType == 3, "removed", EvType == 2, "downgraded", EvType == 1, "upgraded", ActionType has "Applied", "applied", "changed")
| summarize events = count(), removed = countif(Change == "removed"), downgraded = countif(Change == "downgraded"), last = max(Timestamp) by User
| where removed > 0 or downgraded > 0
| order by removed + downgraded desc
'@ }
        [ordered]@{ key = 'labeled_files_endpoint'; title = 'Labeled files touched on endpoints (DeviceFileEvents)'; workload = 'Labels'; returnMany = $true; maxRows = 50
            query = @'
DeviceFileEvents
| where Timestamp > ago(30d)
| extend Label = tostring(column_ifexists("SensitivityLabel", "")), Protected = tobool(column_ifexists("IsAzureInfoProtectionApplied", false))
| where isnotempty(Label) or Protected
| summarize events = count(), devices = dcount(DeviceId), files = dcount(SHA1), removable = countif(FolderPath matches regex @"^[D-Zd-z]:\\" and not(FolderPath startswith @"C:")) by Label, ActionType
| order by events desc
'@ }
        [ordered]@{ key = 'config_changes'; title = 'DLP, label and audit configuration changes (who changed what)'; workload = 'Audit'; returnMany = $true; maxRows = 200
            query = @'
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType matches regex @"(?i)^(new|set|remove|enable|disable)-(dlp|label|autosensitivitylabel|adminauditlog|unifiedauditlog|retentioncompliance|insiderrisk|endpointdlp|policyconfig|dlpsensitiveinformationtype|dataclassification|compliancetag|informationbarrier|protectionalert)"
| extend Actor = tolower(coalesce(tostring(RawEventData.UserId), AccountDisplayName)),
         Target = coalesce(tostring(RawEventData.ObjectId), tostring(RawEventData.Parameters[0].Value)),
         AuditOff = ActionType =~ "Set-AdminAuditLogConfig" and tostring(RawEventData.Parameters) has "UnifiedAuditLogIngestionEnabled" and tostring(RawEventData.Parameters) has "False"
| project Timestamp, Actor, ActionType, Target, AuditOff, IPAddress
| order by Timestamp desc
'@ }
        [ordered]@{ key = 'dlp_alerts'; title = 'DLP alerts by severity and title'; workload = 'Alerts'; returnMany = $true; maxRows = 100
            query = @'
AlertInfo
| where Timestamp > ago(30d)
| where ServiceSource has "Data Loss Prevention" or DetectionSource has "Data Loss Prevention" or Category =~ "DataLossPrevention"
| summarize alerts = dcount(AlertId), last = max(Timestamp) by Severity, Title
| order by alerts desc
'@ }
        [ordered]@{ key = 'dlp_alerts_daily'; title = 'DLP alerts per day'; workload = 'Alerts'; returnMany = $true; maxRows = 60
            query = @'
AlertInfo
| where Timestamp > ago(30d)
| where ServiceSource has "Data Loss Prevention" or DetectionSource has "Data Loss Prevention" or Category =~ "DataLossPrevention"
| summarize events = dcount(AlertId) by day = startofday(Timestamp), bucket = Severity
| order by day asc
'@ }
        [ordered]@{ key = 'usb_after_label'; title = 'Labeled files copied to removable media (MDE + labels)'; workload = 'Exfiltration'; returnMany = $true; maxRows = 100
            query = @'
let usb = DeviceEvents
| where Timestamp > ago(30d) and ActionType == "UsbDriveMounted"
| extend Drive = tostring(parse_json(AdditionalFields).DriveLetter)
| summarize by DeviceId, Drive;
DeviceFileEvents
| where Timestamp > ago(30d) and ActionType in ("FileCreated", "FileModified", "FileRenamed")
| extend Drive = substring(FolderPath, 0, 2), Label = tostring(column_ifexists("SensitivityLabel", ""))
| join kind=inner usb on DeviceId, Drive
| summarize files = dcount(SHA1), labeled = dcountif(SHA1, isnotempty(Label)), last = max(Timestamp) by DeviceName, InitiatingProcessAccountName
| order by labeled desc, files desc
'@ }
    )

    foreach ($p in $probes) {
        try {
            $r = Invoke-GapsioHuntingSafe -NoShard -Context "purview preview $($p.key)" -Timespan 'P30D' -Query $p.query
            $all = @($r | Where-Object { $null -ne $_ })
            & $add $p.key $p.title $p.workload 'ok' $null @($all | Select-Object -First ([int]$p.maxRows))
            $ok++
        }
        catch { & $add $p.key $p.title $p.workload 'error' ([string]$_.Exception.Message) @(); $errors++ }
    }
    $byKey = @{}; foreach ($r in $rows) { $byKey[$r.key] = $r }

    # Coverage: capable devices without any Endpoint DLP audit activity.
    $capable = @($byKey['devices_capable'].result)
    $active = @{}; foreach ($d in @($byKey['devices_dlp_activity'].result)) { $n = ([string]$d.Device -split '\.')[0]; if ($n) { $active[$n] = $d } }
    $deviceRows = foreach ($d in $capable) {
        $short = ([string]$d.DeviceName -split '\.')[0]
        $a = $active[$short]
        [ordered]@{ device = [string]$d.DeviceName; platform = [string]$d.OSPlatform; osVersion = [string]$d.OSVersion; lastSeen = $d.LastSeen
            dlpActive = [bool]$a; dlpEvents = $(if ($a) { [int]$a.events } else { 0 }); dlpLast = $(if ($a) { $a.last } else { $null }); operations = $(if ($a) { @($a.operations) } else { @() }) }
    }
    $deviceRows = @($deviceRows)
    $silent = @($deviceRows | Where-Object { -not $_.dlpActive }).Count
    $cloudAppEventsSeen = (@($byKey['devices_dlp_activity'].result).Count + @($byKey['dlp_rule_matches'].result).Count + @($byKey['config_changes'].result).Count) -gt 0

    # Licences, roles, labels
    $lic = $null; try { $lic = Get-GapsioPurviewLicensing } catch { Add-GapsioWarning "Purview licensing: $($_.Exception.Message)" }
    $roles = @(); try { $roles = Get-GapsioPurviewRoleHolders } catch { Add-GapsioWarning "Purview roles: $($_.Exception.Message)" }
    $labels = $null
    $lr = Invoke-GapsioGraphSafe -Beta -All -Path 'security/informationProtection/sensitivityLabels' -Context 'Sensitivity labels (InformationProtectionPolicy.Read.All)'
    if ($null -ne $lr) {
        $labels = @($lr | ForEach-Object { [ordered]@{ id = [string]$_.id; name = [string]$_.name; description = [string]$_.description; sensitivity = $_.sensitivity; isActive = $_.isActive; parent = [string](Get-GapsioProp (Get-GapsioProp $_ 'parent') 'name'); contentFormats = @($_.contentFormats) } })
    }

    # Findings
    $F = { param($id, $sev, $en, $de, $den, $dde, $ren, $rde) $findings.Add([ordered]@{ id = "purview.$id"; severity = $sev; category = 'purview'; title = @{ en = $en; de = $de }; detail = @{ en = $den; de = $dde }; recommendation = @{ en = $ren; de = $rde } }) }
    $capEdlp = $lic ? @($lic.capabilities | Where-Object { $_.id -eq 'endpointdlp' })[0] : $null
    if ($capable.Count -and $silent -gt 0 -and $cloudAppEventsSeen) {
        & $F 'devices_silent' $(if ($silent / [Math]::Max(1, $capable.Count) -gt 0.5) { 'High' } else { 'Medium' }) 'Capable devices without Endpoint DLP activity' 'DLP-fähige Geräte ohne Endpoint-DLP-Aktivität' "$silent of $($capable.Count) onboarded Windows/macOS devices reported no DLPEndpoint audit event in 30 days." "$silent von $($capable.Count) onboarded Windows-/macOS-Geräten haben in 30 Tagen kein DLPEndpoint-Audit-Ereignis gemeldet." 'Check Purview > Settings > Device onboarding, policy scope (devices/users) and that Endpoint DLP policies include the Devices location.' 'Purview > Einstellungen > Geräte-Onboarding, Policy-Scope (Geräte/Benutzer) und Speicherort „Geräte“ in den Endpoint-DLP-Richtlinien prüfen.'
    }
    if (-not $cloudAppEventsSeen -and (Test-GapsioFeature -Name 'hunting')) {
        & $F 'no_audit_feed' 'Medium' 'No Purview audit records in Advanced Hunting' 'Keine Purview-Audit-Daten in Advanced Hunting' 'CloudAppEvents contained no DLP/label/config records in 30 days.' 'CloudAppEvents enthielt in 30 Tagen keine DLP-/Label-/Konfigurations-Einträge.' 'Enable the Defender for Cloud Apps "Microsoft 365" app connector and make sure unified audit logging is on.' 'Den Defender-for-Cloud-Apps-Connector „Microsoft 365“ aktivieren und sicherstellen, dass das Unified Audit Log eingeschaltet ist.'
    }
    if ($capEdlp -and -not $capEdlp.licensed -and $capable.Count) {
        & $F 'edlp_unlicensed' 'Medium' 'No Endpoint DLP licence' 'Keine Endpoint-DLP-Lizenz' "No subscribed SKU contains MICROSOFTENDPOINTDLP, but $($capable.Count) capable devices are onboarded." "Keine SKU enthält MICROSOFTENDPOINTDLP, aber $($capable.Count) fähige Geräte sind onboarded." 'Endpoint DLP needs M365 E5 / E5 Compliance / E5 Information Protection & Governance (or A5/G5, F5 Compliance).' 'Endpoint DLP benötigt M365 E5 / E5 Compliance / E5 Information Protection & Governance (oder A5/G5, F5 Compliance).'
    }
    $ov = @($byKey['dlp_overrides'].result)
    if ($ov.Count) {
        $total = ($ov | Measure-Object -Property overrides -Sum).Sum
        & $F 'overrides' 'Medium' 'Users override DLP policies' 'Benutzer übersteuern DLP-Richtlinien' "$total override(s)/justification(s) by $($ov.Count) user(s) in 30 days." "$total Override(s)/Begründung(en) von $($ov.Count) Benutzer(n) in 30 Tagen." 'Review justifications; switch frequently overridden rules from "warn" to "block" or refine them.' 'Begründungen prüfen; häufig übersteuerte Regeln von „Warnen“ auf „Blockieren“ umstellen oder schärfen.'
    }
    $lc = @($byKey['label_changes'].result)
    if ($lc.Count) {
        $rm = ($lc | Measure-Object -Property removed -Sum).Sum; $dg = ($lc | Measure-Object -Property downgraded -Sum).Sum
        & $F 'label_downgrades' $(if ($rm + $dg -ge 20) { 'High' } else { 'Medium' }) 'Sensitivity labels removed or downgraded' 'Vertraulichkeitsbezeichnungen entfernt oder herabgestuft' "$rm removal(s), $dg downgrade(s) by $($lc.Count) user(s)." "$rm Entfernung(en), $dg Herabstufung(en) durch $($lc.Count) Benutzer." 'Require justification for downgrades (label policy) and correlate with exfil activity.' 'Begründungspflicht für Herabstufungen (Label-Policy) aktivieren und mit Exfil-Aktivität korrelieren.'
    }
    $cc = @($byKey['config_changes'].result)
    $auditOff = @($cc | Where-Object { $_.AuditOff -eq $true })
    if ($auditOff.Count) {
        & $F 'audit_disabled' 'Critical' 'Unified audit logging was switched off' 'Unified Audit Log wurde ausgeschaltet' "$($auditOff.Count) change(s), last by $($auditOff[0].Actor)." "$($auditOff.Count) Änderung(en), zuletzt durch $($auditOff[0].Actor)." 'Re-enable immediately and restrict who holds the Audit Logs / Organization Management roles.' 'Sofort wieder einschalten und Inhaber der Rollen Audit Logs / Organization Management einschränken.'
    }
    elseif ($cc.Count) {
        $actors = @($cc | ForEach-Object Actor | Select-Object -Unique)
        & $F 'config_changes' 'Low' 'DLP / label / audit configuration changed' 'DLP-/Label-/Audit-Konfiguration geändert' "$($cc.Count) change(s) by $($actors.Count) actor(s) in 30 days." "$($cc.Count) Änderung(en) durch $($actors.Count) Akteur(e) in 30 Tagen." 'Confirm each change was approved (change management).' 'Jede Änderung gegen Change-Management abgleichen.'
    }
    $ga = @($roles | Where-Object { $_.role -eq 'Global Administrator' -and $_.assignment -eq 'active' -and $_.type -eq 'user' })
    if ($ga.Count -gt 4) {
        & $F 'ga_count' 'Medium' 'Many permanent Global Administrators' 'Viele permanente Globale Administratoren' "$($ga.Count) users hold Global Administrator permanently – each has full access to DLP policies and content." "$($ga.Count) Benutzer sind dauerhaft Globaler Administrator – jeder hat Vollzugriff auf DLP-Richtlinien und Inhalte." 'Use PIM (eligible) and least-privilege roles such as Compliance Data Administrator.' 'PIM (berechtigt) und Least-Privilege-Rollen wie Compliance Data Administrator nutzen.'
    }
    $permCompliance = @($roles | Where-Object { $_.role -in 'Compliance Administrator', 'Compliance Data Administrator' -and $_.assignment -eq 'active' })
    if ($permCompliance.Count) {
        & $F 'compliance_permanent' 'Low' 'Compliance roles assigned permanently' 'Compliance-Rollen dauerhaft zugewiesen' "$($permCompliance.Count) permanent Compliance (Data) Administrator assignment(s)." "$($permCompliance.Count) dauerhafte Compliance-(Data-)Administrator-Zuweisung(en)." 'Prefer PIM eligible assignments with approval.' 'PIM-berechtigte Zuweisungen mit Genehmigung bevorzugen.'
    }

    $out = [ordered]@{
        version     = 1
        generatedAt = [DateTime]::UtcNow.ToString('o')
        windowDays  = 30
        ok          = $ok
        errors      = $errors
        summary     = [ordered]@{
            capableDevices = $capable.Count
            dlpActiveDevices = @($deviceRows | Where-Object dlpActive).Count
            silentDevices = $silent
            auditFeed = $cloudAppEventsSeen
            roleHolders = @($roles | ForEach-Object { "$($_.upn)$($_.principal)" } | Select-Object -Unique).Count
            labels = $(if ($null -ne $labels) { @($labels).Count } else { $null })
        }
        licensing   = $lic
        devices     = $deviceRows
        roles       = @($roles)
        labels      = $labels
        results     = @($rows)
        findings    = @($findings)
        warnings    = @(Get-GapsioWarnings)
        notes       = @(
            'Purview role groups (Compliance portal) have no Microsoft Graph API – only Entra roles are listed.'
            'Endpoint DLP device onboarding switch and DLP policies themselves are only readable via Security & Compliance PowerShell (Get-DlpCompliancePolicy).'
        )
    }
    Set-GapsioBlob -Container 'state' -Name 'purview-preview-latest.json' -Object $out -Depth 16
    $out
}
