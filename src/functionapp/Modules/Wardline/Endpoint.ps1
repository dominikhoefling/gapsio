# Wardline Endpoint: Defender exclusions (Windows, macOS, Linux), allow indicators, ASR rules,
# MDAV baseline (target / configured / effective), combined findings and drift.
#
# Data model: enumerations are English codes (the portal translates them); free text shown to users
# (finding titles, details, recommendations, risk reasons) is bilingual via New-WlText.

$script:WlSeverityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }

# scid checks from DeviceTvmSecureConfigurationAssessment (see "Endpoint Agent Health Status Report",
# Microsoft Defender for Endpoint in Depth, 2nd ed., ch. 8).
$script:WlScidMap = [ordered]@{
    'scid-2010' = 'AntivirusEnabled'
    'scid-2012' = 'RealtimeProtection'
    'scid-91'   = 'BehaviorMonitoring'
    'scid-2016' = 'CloudProtection'
    'scid-2013' = 'PUAProtection'
    'scid-2003' = 'TamperProtection'
    'scid-2011' = 'AntivirusSignatureVersion'
    'scid-2014' = 'AntivirusReporting'
    'scid-2000' = 'SensorEnabled'
    'scid-2001' = 'SensorDataCollection'
    'scid-2002' = 'ImpairedCommunications'
}

# Running mode (DeviceTvmInfoGathering.AvMode) -> code
$script:WlAvModeMap = @{ '0' = 'Active'; '1' = 'Passive'; '2' = 'SxSPassive'; '4' = 'EdrBlock' }

function New-WlDevice {
    param([string]$Id, [string]$Name, [string]$Os)
    [ordered]@{
        deviceId = $Id; deviceName = $Name; os = $Os; osVersion = $null; deviceGroup = $null; deviceType = $null; lastSeen = $null; aadDeviceId = $null
        sensorHealth = $null; exposure = $null; joinType = $null; lastUser = $null; intuneDeviceId = $null; managedBy = $null
        inventoryAt = $null; localMergeDisabled = $null
        avMode = $null; avModeText = 'Unknown'; signatureUpToDate = $null; platformUpToDate = $null; engineUpToDate = $null
        avSignatureVersion = $null; avEngineVersion = $null; avPlatformVersion = $null; avSignatureTime = $null; agentVersion = $null
        checks = [ordered]@{}; networkProtectionSource = $null; localExclusions = 0; localExclusionsHighRisk = 0; exclusionAlerts = 0; asr = $null; asrBelowMinimum = $null; asrBlocked = $null
        tags = @(); internetFacing = $null; tvmExcluded = $null; tvmExclusionReason = $null; assetValue = $null; transient = $null; mitigationStatus = $null; clientVersion = $null
        troubleshooting30d = 0; troubleshootingActive = $false; troubleshootingLast = $null; tampering30d = 0; tamperingLast = $null
        thirdPartyAv = @()
    }
}

#region Response readiness (MDE API: machine actions and alert investigation state)
$script:WlResponseFacts = $null
function Get-WlResponseFacts {
    <#
    .SYNOPSIS
    Response actions of the last 90 days (isolation, live response, investigation package, AV scan …) and alerts of the
    last 30 days with their automated-investigation state. Feature 'response' (Machine.Read.All, Alert.Read.All).
    The automation level per device group and the live-response tenant settings are not exposed by any API; what can
    be seen is whether response capabilities are used, whether remediations wait for approval and whether isolations
    are forgotten.
    #>
    if (-not (Test-WlFeature -Name 'response')) { return $null }
    $res = 'https://api.securitycenter.microsoft.com'
    $base = (Get-WlSetting -Name 'WL_MDE_API' -Default 'https://api.securitycenter.microsoft.com/api/indicators') -replace '/indicators$', ''
    $pull = {
        param($Path, $Context)
        $items = [System.Collections.Generic.List[object]]::new()
        $uri = "$base/$Path"
        try {
            while ($uri) {
                $r = Invoke-WlRest -Uri $uri -Resource $res
                foreach ($i in @($r.value)) { if ($i) { $items.Add($i) } }
                $uri = if ($r.PSObject.Properties['@odata.nextLink']) { $r.'@odata.nextLink' } else { $null }
            }
        }
        catch { Add-WlWarning "${Context}: $($_.Exception.Message)" }
        $items.ToArray()
    }
    $since90 = [DateTime]::UtcNow.AddDays(-90).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $since30 = [DateTime]::UtcNow.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $actions = @(& $pull "machineactions?`$filter=creationDateTimeUtc ge $since90" 'MDE response actions (Machine.Read.All)')
    $alerts = @(& $pull "alerts?`$filter=alertCreationTime ge $since30" 'MDE alerts (Alert.Read.All)')
    $script:WlResponseFacts = [pscustomobject]@{
        since90 = $since90; since30 = $since30
        actions = @($actions | ForEach-Object {
                [pscustomobject]@{
                    id = [string]$_.id; type = [string]$_.type; status = [string]$_.status; requestor = [string](Get-WlProp $_ 'requestor')
                    deviceId = [string](Get-WlProp $_ 'machineId'); deviceName = [string](Get-WlProp $_ 'computerDnsName')
                    at = [string](Get-WlProp $_ 'creationDateTimeUtc'); updated = [string](Get-WlProp $_ 'lastUpdateDateTimeUtc')
                    commands = @(@(Get-WlProp $_ 'commands') | ForEach-Object { [string](Get-WlProp $_ 'command') } | Where-Object { $_ })
                }
            })
        alerts  = @($alerts | ForEach-Object {
                [pscustomobject]@{
                    id = [string]$_.id; title = [string](Get-WlProp $_ 'title'); severity = [string](Get-WlProp $_ 'severity'); status = [string](Get-WlProp $_ 'status')
                    investigationState = [string](Get-WlProp $_ 'investigationState'); deviceId = [string](Get-WlProp $_ 'machineId'); deviceName = [string](Get-WlProp $_ 'computerDnsName')
                    at = [string](Get-WlProp $_ 'alertCreationTime'); assignedTo = [string](Get-WlProp $_ 'assignedTo')
                }
            })
    }
    $script:WlResponseFacts
}

function Get-WlResponseFindings {
    param([object]$Facts, [int]$WindowsDevices)
    $f = [System.Collections.Generic.List[object]]::new()
    if (-not $Facts) { return @() }
    $T = { param($en, $de) New-WlText -En $en -De $de }
    $now = [DateTime]::UtcNow
    $age = { param($at) try { ($now - (ConvertTo-WlUtc $at)).TotalDays } catch { 0 } }
    $acts = @($Facts.actions); $alerts = @($Facts.alerts)

    # 1) Remediation actions waiting for approval for more than 24 hours (semi-automation without anyone approving)
    $pending = @($alerts | Where-Object { $_.investigationState -eq 'PendingApproval' -and (& $age $_.at) -ge 1 })
    if ($pending.Count) {
        $devs = @($pending | ForEach-Object { $_.deviceName } | Where-Object { $_ } | Sort-Object -Unique)
        $f.Add((New-WlFinding -Severity 'High' -Category 'Response' -Title (& $T "$($pending.Count) automated investigation(s) waiting for approval" "$($pending.Count) automatisierte Untersuchung(en) warten auf Genehmigung") `
                    -Detail (& $T "Automated investigation found remediation actions but the device group is set to semi-automation and nobody has approved them for more than a day. Devices: $($devs -join ', '). Until approved, the threat stays." `
                        "Die automatisierte Untersuchung hat Bereinigungsaktionen gefunden, aber die Gerätegruppe steht auf Semi-Automatisierung und seit über einem Tag hat niemand genehmigt. Geräte: $($devs -join ', '). Bis zur Genehmigung bleibt die Bedrohung.") `
                    -Recommendation (& $T 'Approve or reject in Action center. If approvals are regularly late, raise the automation level of the device group to Full – remediate threats automatically.' 'Im Action Center genehmigen oder ablehnen. Wenn Genehmigungen regelmäßig liegen bleiben, die Automatisierungsstufe der Gerätegruppe auf „Vollständig“ heben.') -Subject 'resp|pending-approval' -StableKey))
    }

    # 2) Alerts of Medium+ severity still New after 7 days (nobody triaged)
    $stale = @($alerts | Where-Object { $_.status -eq 'New' -and $_.severity -in 'Medium', 'High' -and (& $age $_.at) -ge 7 })
    if ($stale.Count) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Response' -Title (& $T "$($stale.Count) alert(s) untouched for 7+ days" "$($stale.Count) Alert(s) seit 7+ Tagen unbearbeitet") `
                    -Detail (& $T "Medium or high severity alerts are still in state New after a week – nobody has looked at them: $((@($stale | Sort-Object at | Select-Object -First 5 | ForEach-Object { "$($_.title) ($($_.deviceName))" })) -join '; ')$(if ($stale.Count -gt 5) { ' …' })." `
                        "Alerts mittlerer oder hoher Schwere stehen nach einer Woche noch auf „Neu“ – niemand hat sie angesehen: $((@($stale | Sort-Object at | Select-Object -First 5 | ForEach-Object { "$($_.title) ($($_.deviceName))" })) -join '; ')$(if ($stale.Count -gt 5) { ' …' }).") `
                    -Recommendation (& $T 'Triage and assign the alerts. Check whether the SOC has a working queue and notification for Defender alerts (e.g. email notifications or Sentinel).' 'Alerts triagieren und zuweisen. Prüfen, ob das SOC eine funktionierende Warteschlange und Benachrichtigung für Defender-Alerts hat (E-Mail-Benachrichtigung oder Sentinel).') -Subject 'resp|stale-alerts' -StableKey))
    }

    # 3) Devices isolated for more than 7 days without release
    $iso = @{}
    foreach ($a in @($acts | Where-Object { $_.type -in 'Isolate', 'Unisolate' -and $_.status -eq 'Succeeded' } | Sort-Object { ConvertTo-WlUtc $_.at })) {
        if ($a.type -eq 'Isolate') { $iso[$a.deviceId] = $a } else { $iso.Remove($a.deviceId) }
    }
    foreach ($a in @($iso.Values | Where-Object { (& $age $_.at) -ge 7 })) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Response' -Title (& $T 'Device isolated for more than 7 days' 'Gerät seit mehr als 7 Tagen isoliert') `
                    -Detail (& $T "$($a.deviceName) was isolated on $($a.at.Substring(0,10)) by $($a.requestor) and has not been released. Long isolations usually mean a forgotten incident – or a device that should be reimaged instead." `
                        "$($a.deviceName) wurde am $($a.at.Substring(0,10)) von $($a.requestor) isoliert und nicht wieder freigegeben. Lange Isolationen sind meist ein vergessener Vorfall – oder ein Gerät, das besser neu aufgesetzt wird.") `
                    -Recommendation (& $T 'Close the incident: release the device or reimage and offboard it.' 'Vorfall abschließen: Gerät freigeben oder neu aufsetzen und offboarden.') -Subject 'resp|isolated' -DeviceId $a.deviceId -DeviceName $a.deviceName))
    }

    # 4) Response actions failed or stuck (Pending/InProgress > 2 days)
    $stuck = @($acts | Where-Object { ($_.status -in 'Pending', 'InProgress' -and (& $age $_.at) -ge 2) -or $_.status -in 'Failed', 'TimeOut' })
    if ($stuck.Count -ge 3) {
        $byType = @($stuck | Group-Object type | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ', '
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Response' -Title (& $T "$($stuck.Count) response action(s) failed or stuck" "$($stuck.Count) Response-Aktion(en) fehlgeschlagen oder hängen") `
                    -Detail (& $T "In the last 90 days response actions did not complete ($byType). Common causes: device offline, sensor unhealthy, or live response disabled for servers." "In den letzten 90 Tagen wurden Response-Aktionen nicht abgeschlossen ($byType). Häufige Ursachen: Gerät offline, Sensor nicht gesund oder Live Response für Server deaktiviert.") `
                    -Recommendation (& $T 'Review the failed actions in Action center and check sensor health of the affected devices.' 'Fehlgeschlagene Aktionen im Action Center prüfen und die Sensor-Gesundheit der betroffenen Geräte kontrollieren.') -Subject 'resp|stuck' -StableKey))
    }

    # 5) Response capabilities never exercised (readiness) – 25+ Windows devices and no isolation, live response or investigation package in 90 days
    $exercised = @($acts | Where-Object { $_.type -in 'Isolate', 'LiveResponse', 'CollectInvestigationPackage', 'RestrictCodeExecution', 'StopAndQuarantineFile' })
    if ($WindowsDevices -ge 25 -and $exercised.Count -eq 0) {
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Response' -Title (& $T 'Response capabilities never used in 90 days' 'Response-Fähigkeiten in 90 Tagen nie genutzt') `
                    -Detail (& $T "No isolation, live response session, investigation package or code restriction was run in the last 90 days across $WindowsDevices Windows devices. Either nothing happened – or the team has never tested whether these actions work (permissions, live response enabled, servers included)." `
                        "In den letzten 90 Tagen wurde auf $WindowsDevices Windows-Geräten keine Isolation, Live-Response-Sitzung, kein Untersuchungspaket und keine Codebeschränkung ausgeführt. Entweder ist nichts passiert – oder das Team hat nie getestet, ob diese Aktionen funktionieren (Berechtigungen, Live Response aktiviert, Server eingeschlossen).") `
                    -Recommendation (& $T 'Run a response drill on a test device: isolate, open a live response session, collect an investigation package, release. Verify that live response (and for servers) is enabled under Settings → Endpoints → Advanced features.' 'Response-Übung auf einem Testgerät: isolieren, Live-Response-Sitzung öffnen, Untersuchungspaket sammeln, freigeben. Prüfen, dass Live Response (und für Server) unter Einstellungen → Endpunkte → Erweiterte Funktionen aktiviert ist.') -Subject 'resp|never' -StableKey))
    }

    # 6) Live response sessions that ran scripts – worth knowing who does it (information, Low)
    $scripts = @($acts | Where-Object { $_.type -eq 'LiveResponse' -and @($_.commands | Where-Object { $_ -match '^(RunScript|PutFile)' }).Count -gt 0 })
    if ($scripts.Count) {
        $who = @($scripts | ForEach-Object { $_.requestor } | Where-Object { $_ } | Sort-Object -Unique)
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Response' -Title (& $T "$($scripts.Count) live response session(s) ran or uploaded scripts" "$($scripts.Count) Live-Response-Sitzung(en) mit Skriptausführung oder -upload") `
                    -Detail (& $T "Scripts were run or uploaded through live response by: $($who -join ', '). Live response with script execution is the most powerful action in Defender – make sure 'unsigned script execution' is off and the scripts in the library are reviewed." `
                        "Über Live Response wurden Skripte ausgeführt oder hochgeladen von: $($who -join ', '). Live Response mit Skriptausführung ist die mächtigste Aktion in Defender – sicherstellen, dass „Ausführung nicht signierter Skripte“ aus ist und die Skripte in der Bibliothek geprüft sind.") `
                    -Recommendation (& $T 'Keep the live response library curated and signed; restrict live-response permissions (unified RBAC: liveresponse-advanced) to the IR team.' 'Live-Response-Bibliothek kuratiert und signiert halten; Live-Response-Rechte (Unified RBAC: liveresponse-advanced) auf das IR-Team begrenzen.') -Subject 'resp|scripts' -StableKey))
    }
    @($f)
}
#endregion

#region Policies (Intune / security settings management)
function Get-WlAssignmentText {
    # Assignment texts: "All devices", "All users", "Group: <name>", "Excluded: <name>" (translated in the portal)
    param([object[]]$Assignments, [hashtable]$GroupNames)
    $out = foreach ($a in @($Assignments)) {
        if ($null -eq $a) { continue }
        $t = Get-WlProp $a 'target'
        $type = [string](Get-WlProp $t '@odata.type')
        $gid = [string](Get-WlProp $t 'groupId')
        $gname = if ($gid) { Resolve-WlGroupName -GroupId $gid -Cache $GroupNames } else { $null }
        switch -Wildcard ($type) {
            '*allDevicesAssignmentTarget' { 'All devices'; break }
            '*allLicensedUsersAssignmentTarget' { 'All users'; break }
            '*exclusionGroupAssignmentTarget' { "Excluded: $gname"; break }
            '*groupAssignmentTarget' { "Group: $gname"; break }
            default { $type }
        }
    }
    @($out)
}

function Test-WlAssigned {
    # A policy only takes effect when it is assigned to at least one group or to all devices/users
    # (exclusion groups do not count).
    param([object[]]$Assignments)
    @($Assignments | Where-Object { $_ -and ([string]$_) -notlike 'Excluded:*' }).Count -gt 0
}

function Resolve-WlGroupName {
    param([string]$GroupId, [hashtable]$Cache)
    if (-not $GroupId) { return $null }
    if ($Cache.ContainsKey($GroupId)) { return $Cache[$GroupId] }
    $name = $GroupId
    try { $g = Invoke-WlGraph -Path "groups/$GroupId`?`$select=id,displayName"; if ($g.displayName) { $name = $g.displayName } } catch { }
    $Cache[$GroupId] = $name
    $name
}

function Get-WlExclusionTypeFromDefinition {
    param([string]$DefinitionId)
    $d = $DefinitionId.ToLowerInvariant()
    if ($d -match 'exclusions.*tamperprotection') { return 'TamperException' }
    if ($d -match 'allowedthreats') { return 'AllowedThreat' }
    if ($d -match 'attacksurfacereductiononlyexclusions|asronlyexclusion|perruleexclusions') { return 'ASR' }
    if ($d -match 'controlledfolderaccessallowedapplications|allowedapplications') { return 'CFA' }
    if ($d -match 'process') { return 'Process' }
    if ($d -match 'extension') { return 'Extension' }
    if ($d -match 'ipaddress|ip_address') { return 'IP' }
    # macOS/Linux: "excludedFileName" or "..._name" = process name
    if ($d -match '(_name|filename)$') { return 'Process' }
    'Path'
}

function Get-WlPlatformText {
    param([string]$Platforms)
    $p = $Platforms.ToLowerInvariant()
    if ($p -match 'macos') { return 'macOS' }
    if ($p -match 'linux') { return 'Linux' }
    if ($p -match 'windows') { return 'Windows' }
    $Platforms
}

$script:WlDefinitionCache = @{}
function Resolve-WlOptionDisplay {
    <#
    .SYNOPSIS
    Returns the display name / option value of a Settings Catalog choice (e.g. "real_time", "admin_only").
    Definitions are loaded once per run and cached.
    #>
    param([string]$DefinitionId, [string]$ItemId)
    if (-not $DefinitionId -or -not $ItemId) { return $null }
    if (-not $script:WlDefinitionCache.ContainsKey($DefinitionId)) {
        $d = $null
        try { $d = Invoke-WlGraph -Beta -Path "deviceManagement/configurationSettings('$DefinitionId')?`$select=id,options" } catch { $d = $null }
        $script:WlDefinitionCache[$DefinitionId] = $d
    }
    $def = $script:WlDefinitionCache[$DefinitionId]
    $opt = @(Get-WlProp $def 'options') | Where-Object { $_ -and [string](Get-WlProp $_ 'itemId') -eq $ItemId } | Select-Object -First 1
    if (-not $opt) { return $null }
    $ov = Get-WlProp (Get-WlProp $opt 'optionValue') 'value'
    $dn = [string](Get-WlProp $opt 'displayName')
    (@($dn, [string]$ov) | Where-Object { $_ } | Select-Object -Unique) -join ' / '
}

$script:WlTypeNames = @{
    Path = @('path', 'Pfad'); TempPath = @('temporary path', 'temporärer Pfad'); Process = @('process', 'Prozess'); Extension = @('extension', 'Erweiterung')
    IP = @('IP', 'IP'); ASR = @('ASR', 'ASR'); CFA = @('CFA', 'CFA'); TamperException = @('tamper', 'Tamper'); AllowedThreat = @('allowed threat', 'Erlaubte-Bedrohung')
}
function Get-WlTypeName {
    # Display name of an exclusion type code for finding texts: -De for German.
    param([string]$Type, [switch]$De)
    $n = $script:WlTypeNames[$Type]
    if (-not $n) { return $Type }
    if ($De) { $n[1] } else { $n[0] }
}

function New-WlPolicyExclusion {
    # Source: IntuneSettingsCatalog | IntuneTemplate | IntuneLegacy
    param([string]$Source, [string]$PolicyId, [string]$PolicyName, [string]$Platform, [string]$Type, [string]$Value,
        [string]$Scope = 'AV', [string]$AsrRule, [object[]]$Assignments, [string]$LastModified, [string]$DefinitionId)
    $risk = Get-WlExclusionRisk -Type $Type -Value $Value -Origin 'Policy' -Scope $Scope
    $key = Get-WlHash "pol|$PolicyId|$Type|$Scope|$AsrRule|$Value"
    [pscustomobject]@{
        key          = $key
        fp           = Get-WlHash "$Value|$Type|$Scope|$(@($Assignments) -join ';')"
        label        = New-WlText "$(Get-WlTypeName $Type) exclusion '$Value' ($PolicyName)" "$(Get-WlTypeName $Type -De)-Exclusion '$Value' ($PolicyName)"
        state        = "$Scope; $(@($Assignments) -join ', ')"
        source       = $Source
        policyId     = $PolicyId
        policyName   = $PolicyName
        platform     = $Platform
        type         = $Type
        scope        = $Scope
        asrRule      = $AsrRule
        value        = $Value
        contextual   = ($Value -match '\\:\{')
        assignments  = @($Assignments)
        assigned     = (Test-WlAssigned $Assignments)
        lastModified = $LastModified
        definitionId = $DefinitionId
        risk         = $risk
    }
}

function Get-WlEndpointPolicies {
    <#
    .SYNOPSIS
    Reads Defender-related Intune policies (Settings Catalog / security settings management, endpoint security
    templates, legacy device configuration) and extracts exclusions and setting values.
    #>
    $groupNames = @{}
    $exclusions = [System.Collections.Generic.List[object]]::new()
    $settingValues = [System.Collections.Generic.List[object]]::new()
    $policies = [System.Collections.Generic.List[object]]::new()
    # Windows: Defender CSP; macOS: com.apple.managedclient.preferences_<key> (com.microsoft.wdav); Linux: linux_mdatp_*
    $relevant = '^linux_|defender|mdatp|antivirus|exclu|attacksurfacereduction|controlledfolderaccess|tamperprotection|networkprotection|' +
    '^com\.apple\.managedclient\.preferences_(allowedthreats|disallowedthreatactions|enablerealtimeprotection|enforcementlevel.*|exclusions.*|passivemode|scanarchives|threattypesettings.*|automaticsamplesubmission.*|cloudblocklevel|enabled|diagnosticlevel|behaviormonitoring|ignoreexclusions)$'

    # 1) Settings Catalog (incl. endpoint security policies and security settings management from the Defender portal)
    $cps = Invoke-WlGraphSafe -Beta -All -Context 'Intune Settings Catalog (configurationPolicies)' `
        -Path 'deviceManagement/configurationPolicies?$select=id,name,platforms,technologies,lastModifiedDateTime,templateReference'
    foreach ($cp in @($cps)) {
        if ($null -eq $cp) { continue }
        $settings = Invoke-WlGraphSafe -Beta -All -Context "Settings of policy '$($cp.name)'" -Path "deviceManagement/configurationPolicies('$($cp.id)')/settings"
        $values = [System.Collections.Generic.List[object]]::new()
        foreach ($s in @($settings)) {
            if ($null -eq $s) { continue }
            foreach ($v in (Get-WlSettingValues -Instance (Get-WlProp $s 'settingInstance'))) {
                if ($v.definitionId -notmatch $relevant) { continue }
                # Linux/macOS options are often only numbered (_0/_1/_2) – add the option's display name
                $disp = $null
                if ($v.kind -eq 'choice' -and $v.definitionId -match '^(linux_|com\.apple\.managedclient\.preferences_)') { $disp = Resolve-WlOptionDisplay -DefinitionId $v.definitionId -ItemId $v.value }
                $v | Add-Member -NotePropertyName display -NotePropertyValue $disp -Force
                $values.Add($v)
            }
        }
        if ($values.Count -eq 0) { continue }

        $assign = Invoke-WlGraphSafe -Beta -All -Context "Assignments of policy '$($cp.name)'" -Path "deviceManagement/configurationPolicies('$($cp.id)')/assignments"
        $assignText = Get-WlAssignmentText -Assignments @($assign) -GroupNames $groupNames
        $tmpl = Get-WlProp $cp 'templateReference'
        $platform = Get-WlPlatformText ([string]$cp.platforms)
        $policies.Add([pscustomobject]@{
                id = $cp.id; name = $cp.name; kind = 'SettingsCatalog'; platforms = $platform
                template = [string](Get-WlProp $tmpl 'templateDisplayName'); lastModified = [string]$cp.lastModifiedDateTime; assignments = $assignText
            })

        foreach ($v in $values) {
            $settingValues.Add([pscustomobject]@{
                    policyId = $cp.id; policyName = $cp.name; platform = $platform; definitionId = $v.definitionId
                    value = $v.value; display = $v.display; kind = $v.kind; group = $v.group; assignments = $assignText; lastModified = [string]$cp.lastModifiedDateTime
                })
        }

        # Exclusions: string values of exclusion settings. In groups (Linux/macOS) a choice "..._global" or a
        # "scopes" list containing "global" means Global (AV+EDR).
        $exclValues = @($values | Where-Object {
                $_.kind -eq 'simple' -and $_.value -and $_.value -notmatch '^(true|false|\d+)$' -and
                $_.definitionId -match 'exclu|allowedapplications|allowedthreats' -and $_.definitionId -notmatch 'mergepolicy|hideexclusions|isdirectory|disablelocaladminmerge|ignoreexclusions|signingid|teamid|_args_|_scopes?$|_\$?type$'
            })
        foreach ($ev in $exclValues) {
            $scope = 'AV'; $asrRule = $null
            if ($ev.group) {
                $groupVals = @($values | Where-Object { $_.group -eq $ev.group -and ($_.kind -eq 'choice' -or $_.definitionId -match '_scopes?$') } | ForEach-Object { "$($_.value) $($_.display)" })
                if ($groupVals -match 'global') { $scope = 'Global' }
            }
            if ($tmpl -and ([string](Get-WlProp $tmpl 'templateDisplayName')) -match 'Global') { $scope = 'Global' }
            $type = Get-WlExclusionTypeFromDefinition -DefinitionId $ev.definitionId
            if ($type -eq 'ASR') {
                $scope = 'ASR'
                if ($ev.definitionId -match 'attacksurfacereductionrules_(.+?)_perruleexclusions') { $r = Get-WlAsrRuleBySuffix -Suffix $Matches[1]; $asrRule = if ($r) { $r.id } else { $Matches[1] } }
            }
            elseif ($type -eq 'CFA') { $scope = 'CFA' }
            if ($ev.group -and $ev.definitionId -match '_(path|name)$') {
                # In groups the type can be encoded as a choice (file/folder/process)
                $tchoice = @($values | Where-Object { $_.group -eq $ev.group -and $_.kind -eq 'choice' -and $_.definitionId -match 'type' } | Select-Object -First 1)
                if ($tchoice -and $tchoice[0].value -match 'process') { $type = 'Process' }
            }
            $exclusions.Add((New-WlPolicyExclusion -Source 'IntuneSettingsCatalog' -PolicyId $cp.id -PolicyName $cp.name -Platform $platform `
                        -Type $type -Value $ev.value -Scope $scope -AsrRule $asrRule -Assignments $assignText `
                        -LastModified ([string]$cp.lastModifiedDateTime) -DefinitionId $ev.definitionId))
        }
    }

    # 2) Older endpoint security templates (intents)
    $intents = Invoke-WlGraphSafe -Beta -All -Context 'Intune endpoint security templates (intents)' -Path 'deviceManagement/intents?$select=id,displayName,templateId,lastModifiedDateTime'
    foreach ($it in @($intents)) {
        if ($null -eq $it) { continue }
        $isettings = Invoke-WlGraphSafe -Beta -All -Context "Settings of template '$($it.displayName)'" -Path "deviceManagement/intents/$($it.id)/settings"
        $hits = @($isettings | Where-Object { $_ -and ([string](Get-WlProp $_ 'definitionId')) -match 'exclu|allowedapp|guardedfoldersallowed' })
        if ($hits.Count -eq 0) { continue }
        $assign = Invoke-WlGraphSafe -Beta -All -Context "Assignments of template '$($it.displayName)'" -Path "deviceManagement/intents/$($it.id)/assignments"
        $assignText = Get-WlAssignmentText -Assignments @($assign) -GroupNames $groupNames
        $policies.Add([pscustomobject]@{ id = $it.id; name = $it.displayName; kind = 'EndpointSecurityTemplate'; platforms = 'Windows'; template = $it.templateId; lastModified = [string]$it.lastModifiedDateTime; assignments = $assignText })
        foreach ($h in $hits) {
            $vals = @()
            try { $vals = @((Get-WlProp $h 'valueJson') | ConvertFrom-Json) } catch { }
            $type = Get-WlExclusionTypeFromDefinition ([string]$h.definitionId)
            foreach ($val in $vals) {
                if (-not $val -or $val -isnot [string]) { continue }
                $exclusions.Add((New-WlPolicyExclusion -Source 'IntuneTemplate' -PolicyId $it.id -PolicyName $it.displayName `
                            -Platform 'Windows' -Type $type -Value $val -Scope $(if ($type -in 'ASR', 'CFA') { $type } else { 'AV' }) -Assignments $assignText `
                            -LastModified ([string]$it.lastModifiedDateTime) -DefinitionId ([string]$h.definitionId)))
            }
        }
    }

    # 3) Legacy device configuration (endpoint protection / device restrictions)
    $legacyMap = [ordered]@{
        defenderFilesAndFoldersToExclude            = 'Path'
        defenderProcessesToExclude                  = 'Process'
        defenderFileExtensionsToExclude             = 'Extension'
        defenderAttackSurfaceReductionExcludedPaths = 'ASR'
        defenderGuardedFoldersAllowedAppPaths       = 'CFA'
    }
    $dcs = Invoke-WlGraphSafe -Beta -All -Context 'Intune device configuration (deviceConfigurations)' -Path 'deviceManagement/deviceConfigurations'
    foreach ($dc in @($dcs)) {
        if ($null -eq $dc) { continue }
        $found = @()
        foreach ($prop in $legacyMap.Keys) { $vals = @(Get-WlProp $dc $prop) | Where-Object { $_ }; if ($vals) { $found += , @($prop, $vals) } }
        if ($found.Count -eq 0) { continue }
        $assign = Invoke-WlGraphSafe -Beta -All -Context "Assignments of '$($dc.displayName)'" -Path "deviceManagement/deviceConfigurations/$($dc.id)/assignments"
        $assignText = Get-WlAssignmentText -Assignments @($assign) -GroupNames $groupNames
        $policies.Add([pscustomobject]@{ id = $dc.id; name = $dc.displayName; kind = 'LegacyConfiguration'; platforms = 'Windows'; template = [string]$dc.'@odata.type'; lastModified = [string]$dc.lastModifiedDateTime; assignments = $assignText })
        foreach ($f in $found) {
            $type = $legacyMap[$f[0]]
            foreach ($val in @($f[1])) {
                $exclusions.Add((New-WlPolicyExclusion -Source 'IntuneLegacy' -PolicyId $dc.id -PolicyName $dc.displayName `
                            -Platform 'Windows' -Type $type -Value ([string]$val) -Scope $(if ($type -in 'ASR', 'CFA') { $type } else { 'AV' }) -Assignments $assignText `
                            -LastModified ([string]$dc.lastModifiedDateTime) -DefinitionId $f[0]))
            }
        }
    }

    [pscustomobject]@{ Exclusions = $exclusions.ToArray(); SettingValues = $settingValues.ToArray(); Policies = $policies.ToArray() }
}
#endregion

#region Allow indicators (MDE API)
$script:WlIndicatorFacts = $null
function Get-WlAllowIndicators {
    if (-not (Test-WlFeature -Name 'indicators')) { return }
    $res = 'https://api.securitycenter.microsoft.com'
    $uri = Get-WlSetting -Name 'WL_MDE_API' -Default 'https://api.securitycenter.microsoft.com/api/indicators'
    $items = [System.Collections.Generic.List[object]]::new()
    try {
        while ($uri) {
            $r = Invoke-WlRest -Uri $uri -Resource $res
            foreach ($i in @($r.value)) { if ($i) { $items.Add($i) } }
            $uri = if ($r.PSObject.Properties['@odata.nextLink']) { $r.'@odata.nextLink' } else { $null }
        }
    }
    catch {
        Add-WlWarning "MDE indicators: $($_.Exception.Message)"
        return
    }
    # Facts about all indicators (any action) for the dependency checks: which types exist, and values that carry
    # both an Allow and a Block/Warn action (SmartScreen then picks whichever was created first).
    $types = @{}; $byValue = @{}
    foreach ($i in $items) {
        $t = [string](Get-WlProp $i 'indicatorType'); $v = ([string](Get-WlProp $i 'indicatorValue')).ToLowerInvariant(); $a = [string](Get-WlProp $i 'action')
        if ($t) { $types[$t] = $true }
        if (-not $byValue.ContainsKey($v)) { $byValue[$v] = [ordered]@{ type = $t; value = [string](Get-WlProp $i 'indicatorValue'); allow = $false; block = $false } }
        if ($a -match '^Allow') { $byValue[$v].allow = $true } elseif ($a -match '^(Block|Warn|Alert)') { $byValue[$v].block = $true }
    }
    $script:WlIndicatorFacts = [ordered]@{
        total     = $items.Count
        types     = @($types.Keys | Sort-Object)
        conflicts = @($byValue.Values | Where-Object { $_.allow -and $_.block } | ForEach-Object { [pscustomobject]$_ })
    }
    $out = foreach ($i in $items) {
        $action = [string](Get-WlProp $i 'action')
        if ($action -notmatch '^Allow') { continue }
        $type = [string](Get-WlProp $i 'indicatorType')
        $val = [string](Get-WlProp $i 'indicatorValue')
        [pscustomobject]@{
            key          = Get-WlHash "ind|$type|$val"
            fp           = Get-WlHash "$action|$([string](Get-WlProp $i 'expirationTime'))|$([string](Get-WlProp $i 'rbacGroupNames'))"
            label        = New-WlText "Allow indicator $type '$val'" "Allow-Indikator $type '$val'"
            state        = $action
            type         = $type
            value        = $val
            title        = [string](Get-WlProp $i 'title')
            createdBy    = [string](Get-WlProp $i 'createdBy')
            created      = [string](Get-WlProp $i 'creationTimeDateTimeUtc')
            expires      = [string](Get-WlProp $i 'expirationTime')
            deviceGroups = @(Get-WlProp $i 'rbacGroupNames')
            risk         = Get-WlIndicatorRisk -IndicatorType $type
        }
    }
    @($out)
}
#endregion

#region Devices (Advanced Hunting)
function Get-WlDeviceStates {
    $days = [int](Get-WlSetting -Name 'WL_DEVICE_LOOKBACK_DAYS' -Default '7')
    $devices = @{}

    # Columns per learn.microsoft.com/defender-xdr/advanced-hunting-deviceinfo-table. ManagedBy is not part of the documented
    # schema reference (it is shown in the portal's device inventory) – read via column_ifexists so the query cannot fail on it.
    $qInfo = @"
DeviceInfo
| where Timestamp > ago(${days}d)
| extend ManagedBy = column_ifexists("ManagedBy", "")
| summarize arg_max(Timestamp, DeviceName, OSPlatform, OSVersion, MachineGroup, DeviceType, OnboardingStatus, AadDeviceId, SensorHealthState, ExposureLevel, JoinType, LoggedOnUsers, ManagedBy,
    ClientVersion, RegistryDeviceTag, DeviceManualTags, DeviceDynamicTags, IsInternetFacing, IsExcluded, ExclusionReason, AssetValue, IsTransient, MitigationStatus) by DeviceId
| where isempty(OnboardingStatus) or OnboardingStatus == "Onboarded"
| extend LastUser = tostring(parse_json(LoggedOnUsers)[0].UserName)
| project DeviceId, DeviceName, OSPlatform, OSVersion, MachineGroup, DeviceType, AadDeviceId, SensorHealthState, ExposureLevel, JoinType, LastUser, ManagedBy, LastSeen = Timestamp,
    ClientVersion, RegistryDeviceTag, DeviceManualTags, DeviceDynamicTags, IsInternetFacing = tostring(IsInternetFacing), IsExcluded = tostring(IsExcluded), ExclusionReason, AssetValue, IsTransient = tostring(IsTransient), MitigationStatus
"@
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qInfo -Context 'Advanced Hunting DeviceInfo')) {
        if ($null -eq $r) { continue }
        $d = New-WlDevice -Id ([string]$r.DeviceId) -Name ([string]$r.DeviceName) -Os ([string]$r.OSPlatform)
        $d.osVersion = [string]$r.OSVersion; $d.deviceGroup = [string]$r.MachineGroup; $d.deviceType = [string]$r.DeviceType
        $d.lastSeen = [string]$r.LastSeen; $d.aadDeviceId = [string]$r.AadDeviceId
        $d.sensorHealth = [string](Get-WlProp $r 'SensorHealthState'); $d.exposure = [string](Get-WlProp $r 'ExposureLevel')
        $d.joinType = [string](Get-WlProp $r 'JoinType'); $d.lastUser = [string](Get-WlProp $r 'LastUser'); $d.managedBy = [string](Get-WlProp $r 'ManagedBy')
        $d.clientVersion = [string](Get-WlProp $r 'ClientVersion'); $d.assetValue = [string](Get-WlProp $r 'AssetValue'); $d.mitigationStatus = [string](Get-WlProp $r 'MitigationStatus')
        $d.tags = @(Get-WlDeviceTags -Manual ([string](Get-WlProp $r 'DeviceManualTags')) -Dynamic ([string](Get-WlProp $r 'DeviceDynamicTags')) -Registry ([string](Get-WlProp $r 'RegistryDeviceTag')))
        $d.internetFacing = ConvertTo-WlBoolOrNull (Get-WlProp $r 'IsInternetFacing')
        $d.tvmExcluded = ConvertTo-WlBoolOrNull (Get-WlProp $r 'IsExcluded'); $d.tvmExclusionReason = [string](Get-WlProp $r 'ExclusionReason')
        $d.transient = ConvertTo-WlBoolOrNull (Get-WlProp $r 'IsTransient')
        $devices[[string]$r.DeviceId] = $d
    }

    $ids = ($script:WlScidMap.Keys | ForEach-Object { "'$_'" }) -join ','
    $qTvm = @"
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ($ids)
| summarize arg_max(Timestamp, IsApplicable, IsCompliant, DeviceName, OSPlatform) by DeviceId, ConfigurationId
| project DeviceId, DeviceName, OSPlatform, ConfigurationId, IsApplicable = tobool(IsApplicable), IsCompliant = tobool(IsCompliant)
"@
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qTvm -Context 'Advanced Hunting DeviceTvmSecureConfigurationAssessment')) {
        if ($null -eq $r) { continue }
        $id = [string]$r.DeviceId
        if (-not $devices.ContainsKey($id)) { $devices[$id] = New-WlDevice -Id $id -Name ([string]$r.DeviceName) -Os ([string]$r.OSPlatform) }
        $name = $script:WlScidMap[[string]$r.ConfigurationId]
        $devices[$id].checks[$name] = if (-not [bool]$r.IsApplicable) { 'N/A' } elseif ([bool]$r.IsCompliant) { 'GOOD' } else { 'BAD' }
    }

    # macOS/Linux: map secure configurations by name via the knowledge base (scids differ per platform)
    $qTvmX = @"
let kb = DeviceTvmSecureConfigurationAssessmentKB
| where ConfigurationName has_any ("tamper", "real-time", "real time", "cloud", "potentially unwanted", "PUA", "behavior", "passive", "antivirus", "Defender", "network protection", "full disk", "system extension")
| project ConfigurationId, ConfigurationName;
DeviceTvmSecureConfigurationAssessment
| where OSPlatform in~ ("macOS", "Linux")
| join kind=inner kb on ConfigurationId
| summarize arg_max(Timestamp, IsApplicable, IsCompliant, DeviceName, OSPlatform, ConfigurationName) by DeviceId, ConfigurationId
| project DeviceId, DeviceName, OSPlatform, ConfigurationId, ConfigurationName, IsApplicable = tobool(IsApplicable), IsCompliant = tobool(IsCompliant)
"@
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qTvmX -Context 'Advanced Hunting secure configuration macOS/Linux')) {
        if ($null -eq $r) { continue }
        $id = [string]$r.DeviceId
        if (-not $devices.ContainsKey($id)) { $devices[$id] = New-WlDevice -Id $id -Name ([string]$r.DeviceName) -Os ([string]$r.OSPlatform) }
        $cn = ([string]$r.ConfigurationName).ToLowerInvariant()
        $name = switch -Regex ($cn) {
            'full disk' { 'FullDiskAccess'; break }
            'system extension' { 'SystemExtensions'; break }
            'tamper' { 'TamperProtection'; break }
            'network protection' { 'NetworkProtection'; break }
            'real.?time|enforcement' { 'RealtimeProtection'; break }
            'potentially unwanted|pua' { 'PUAProtection'; break }
            'behavio' { 'BehaviorMonitoring'; break }
            'cloud' { 'CloudProtection'; break }
            'passive' { 'PassiveModeOff'; break }
            default { $null }
        }
        if (-not $name) { continue }
        $result = if (-not [bool]$r.IsApplicable) { 'N/A' } elseif ([bool]$r.IsCompliant) { 'GOOD' } else { 'BAD' }
        # Several checks per category: BAD wins
        if ($devices[$id].checks[$name] -ne 'BAD') { $devices[$id].checks[$name] = $result }
    }

    # macOS/Linux: installed Defender agent version (101.YYMM.x) from the software inventory
    $qAgent = @"
DeviceTvmSoftwareInventory
| where OSPlatform in~ ("macOS", "Linux") and SoftwareVendor =~ "microsoft" and SoftwareName has "defender"
| summarize arg_max(SoftwareVersion, DeviceName) by DeviceId
| project DeviceId, DeviceName, SoftwareVersion
"@
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qAgent -Context 'Advanced Hunting Defender agent version macOS/Linux')) {
        if ($null -eq $r) { continue }
        $id = [string]$r.DeviceId
        if ($devices.ContainsKey($id)) { $devices[$id].agentVersion = [string]$r.SoftwareVersion }
    }

    # Windows: further protection features resolved by name via the knowledge base (no stable documented scids)
    $qTvmW = @"
let kb = DeviceTvmSecureConfigurationAssessmentKB
| where ConfigurationName has_any ("network protection", "controlled folder access", "block mode")
| project ConfigurationId, ConfigurationName;
DeviceTvmSecureConfigurationAssessment
| where OSPlatform startswith "Windows"
| join kind=inner kb on ConfigurationId
| summarize arg_max(Timestamp, IsApplicable, IsCompliant, DeviceName, OSPlatform, ConfigurationName) by DeviceId, ConfigurationId
| project DeviceId, DeviceName, OSPlatform, ConfigurationId, ConfigurationName, IsApplicable = tobool(IsApplicable), IsCompliant = tobool(IsCompliant)
"@
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qTvmW -Context 'Advanced Hunting secure configuration Windows (network protection, CFA, EDR block mode)')) {
        if ($null -eq $r) { continue }
        $id = [string]$r.DeviceId
        if (-not $devices.ContainsKey($id)) { continue }
        $cn = ([string]$r.ConfigurationName).ToLowerInvariant()
        $name = switch -Regex ($cn) {
            'network protection' { 'NetworkProtection'; break }
            'controlled folder' { 'ControlledFolderAccess'; break }
            'block mode' { 'EdrBlockMode'; break }
            default { $null }
        }
        if (-not $name) { continue }
        $result = if (-not [bool]$r.IsApplicable) { 'N/A' } elseif ([bool]$r.IsCompliant) { 'GOOD' } else { 'BAD' }
        if ($devices[$id].checks[$name] -ne 'BAD') { $devices[$id].checks[$name] = $result }
    }

    # Network protection: when TVM has no assessment for a device, its network protection events (30 days) show that it
    # is on – blocking (GOOD) or audit only (BAD). Devices without events stay unknown.
    $qNp = @"
// WardlineNetworkProtection
DeviceEvents
| where ActionType in ("ExploitGuardNetworkProtectionBlocked", "ExploitGuardNetworkProtectionAudited")
| summarize Blocked = countif(ActionType endswith "Blocked"), Audited = countif(ActionType endswith "Audited"), Last = max(Timestamp) by DeviceId
"@
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qNp -Context 'Advanced Hunting network protection events')) {
        if ($null -eq $r) { continue }
        $id = [string]$r.DeviceId
        if (-not $devices.ContainsKey($id) -or $devices[$id].checks.Contains('NetworkProtection')) { continue }
        $devices[$id].checks['NetworkProtection'] = if ([int]$r.Blocked -gt 0) { 'GOOD' } else { 'BAD' }
        $devices[$id].networkProtectionSource = if ([int]$r.Blocked -gt 0) { 'EventsBlock' } else { 'EventsAudit' }
    }

    $qInfoG = @"
DeviceTvmInfoGathering
| summarize arg_max(Timestamp, AdditionalFields) by DeviceId
| extend f = parse_json(AdditionalFields)
| project DeviceId, AvMode = tostring(f.AvMode), AvSig = tostring(f.AvIsSignatureUptoDate), AvPlat = tostring(f.AvIsPlatformUptodate), AvEng = tostring(f.AvIsEngineUptoDate),
    AvSigVer = tostring(f.AvSignatureVersion), AvEngVer = tostring(f.AvEngineVersion), AvPlatVer = tostring(f.AvPlatformVersion), AvSigTime = tostring(f.AvSignaturePublishTime)
"@
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qInfoG -Context 'Advanced Hunting DeviceTvmInfoGathering')) {
        if ($null -eq $r) { continue }
        $id = [string]$r.DeviceId
        if (-not $devices.ContainsKey($id)) { continue }
        $mode = [string]$r.AvMode
        $devices[$id].avMode = $mode
        $devices[$id].avModeText = if ($script:WlAvModeMap.ContainsKey($mode)) { $script:WlAvModeMap[$mode] } elseif ($mode) { "Mode $mode" } else { 'Unknown' }
        $devices[$id].signatureUpToDate = [string]$r.AvSig
        $devices[$id].platformUpToDate = [string]$r.AvPlat
        $devices[$id].engineUpToDate = [string]$r.AvEng
        $devices[$id].avSignatureVersion = [string](Get-WlProp $r 'AvSigVer'); $devices[$id].avEngineVersion = [string](Get-WlProp $r 'AvEngVer')
        $devices[$id].avPlatformVersion = [string](Get-WlProp $r 'AvPlatVer'); $devices[$id].avSignatureTime = [string](Get-WlProp $r 'AvSigTime')
    }

    $qAlerts = @"
AlertInfo
| where Timestamp > ago(30d)
| where Title has "exclusion" and (Title has "Defender" or Title has "antivirus")
| join kind=inner (AlertEvidence | where Timestamp > ago(30d) and isnotempty(DeviceId) | distinct AlertId, DeviceId) on AlertId
| summarize Alerts = dcount(AlertId), LastAlert = max(Timestamp) by DeviceId
"@
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qAlerts -Context 'Advanced Hunting exclusion alerts')) {
        if ($null -eq $r) { continue }
        $id = [string]$r.DeviceId
        if ($devices.ContainsKey($id)) { $devices[$id].exclusionAlerts = [int]$r.Alerts }
    }
    $devices
}

function ConvertTo-WlBoolOrNull {
    param($Value)
    $s = [string]$Value
    if ($s -match '^(true|1)$') { return $true }
    if ($s -match '^(false|0)$') { return $false }
    $null
}

function Get-WlDeviceTags {
    # DeviceManualTags / DeviceDynamicTags are documented as strings (JSON array in practice); RegistryDeviceTag is a single value.
    param([string]$Manual, [string]$Dynamic, [string]$Registry)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($raw in @($Manual, $Dynamic)) {
        if (-not $raw -or $raw -in 'null', '[]') { continue }
        $vals = $null
        if ($raw.TrimStart().StartsWith('[')) { try { $vals = @($raw | ConvertFrom-Json) } catch { $vals = $null } }
        if ($null -eq $vals) { $vals = @($raw -split '[;,]') }
        foreach ($v in $vals) { $t = ([string]$v).Trim(); if ($t -and -not $out.Contains($t)) { $out.Add($t) } }
    }
    if ($Registry) { $t = $Registry.Trim(); if ($t -and -not $out.Contains($t)) { $out.Add($t) } }
    $out.ToArray()
}

function Get-WlFleetFacts {
    <#
    .SYNOPSIS
    Fleet hygiene facts (documented sources):
      - troubleshooting mode (DeviceEvents, ActionType AntivirusTroubleshootModeEvent, AdditionalFields.TroubleshootingStateChangeReason)
      - tampering attempts (DeviceEvents, ActionType TamperingAttempt)
      - devices inactive for 90+ days that are still listed in the inventory (MDE API machines, feature 'response')
    Sets per-device counters and returns an object with the inactive machines.
    #>
    param([hashtable]$Devices)
    $qTs = @"
// WardlineFleetTroubleshooting
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "AntivirusTroubleshootModeEvent"
| extend p = parse_json(AdditionalFields)
| extend Reason = tostring(p.TroubleshootingStateChangeReason)
| summarize Starts = countif(Reason contains "started"), Name = take_any(DeviceName), arg_max(Timestamp, Reason) by DeviceId
"@
    $now = [DateTime]::UtcNow
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qTs -Context 'Advanced Hunting troubleshooting mode events')) {
        if ($null -eq $r) { continue }
        $id = [string]$r.DeviceId
        if (-not $Devices.ContainsKey($id)) { continue }
        $d = $Devices[$id]
        $d.troubleshooting30d = [int]$r.Starts; $d.troubleshootingLast = [string]$r.Timestamp
        $last = $null; try { $last = ConvertTo-WlUtc $r.Timestamp } catch { }
        # Troubleshooting mode switches off automatically after four hours
        $d.troubleshootingActive = [bool](([string]$r.Reason) -match 'started' -and $last -and $last -gt $now.AddHours(-4))
    }
    $qTamper = @"
// WardlineFleetTampering
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "TamperingAttempt"
| summarize Attempts = count(), Last = max(Timestamp), Name = take_any(DeviceName) by DeviceId
"@
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qTamper -Context 'Advanced Hunting tampering attempts')) {
        if ($null -eq $r) { continue }
        $id = [string]$r.DeviceId
        if (-not $Devices.ContainsKey($id)) { continue }
        $Devices[$id].tampering30d = [int]$r.Attempts; $Devices[$id].tamperingLast = [string]$r.Last
    }

    # Third-party AV/EDR products from the software inventory (vendor/product patterns, see $script:WlThirdPartyAv).
    $qAv = @"
// WardlineThirdPartyAv
DeviceTvmSoftwareInventory
| where SoftwareVendor has_any ("crowdstrike", "sentinelone", "sentinel labs", "carbon black", "broadcom", "symantec", "sophos", "trellix", "mcafee", "fireeye", "eset", "trend micro", "palo alto", "bitdefender", "kaspersky", "cylance", "blackberry", "cybereason", "withsecure", "f-secure", "elastic", "malwarebytes", "check point", "fortinet", "g data", "avast", "avg", "webroot", "tanium", "huntress", "cisco")
    or SoftwareName has_any ("falcon sensor", "sentinel agent", "carbon black", "cb defense", "endpoint protection", "endpoint security", "cortex xdr", "traps", "apex one", "deep security", "gravityzone", "elastic agent", "elastic endpoint", "secure endpoint", "amp for endpoints", "harmony endpoint", "forticlient", "intercept x", "huntress agent")
| where SoftwareVendor !has "microsoft"
| summarize Products = make_set(strcat(SoftwareVendor, " ", SoftwareName), 10) by DeviceId
"@
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qAv -Context 'Advanced Hunting software inventory (third-party AV/EDR)')) {
        if ($null -eq $r) { continue }
        $id = [string]$r.DeviceId
        if (-not $Devices.ContainsKey($id)) { continue }
        $list = $r.Products; if ($list -is [string]) { try { $list = $list | ConvertFrom-Json } catch { $list = @($list) } }
        $Devices[$id].thirdPartyAv = @(@($list) | ForEach-Object { [string]$_ } | Where-Object { $_ } | Sort-Object -Unique)
    }

    $inactive = @()
    if (Test-WlFeature -Name 'response') {
        $res = 'https://api.securitycenter.microsoft.com'
        $base = (Get-WlSetting -Name 'WL_MDE_API' -Default 'https://api.securitycenter.microsoft.com/api/indicators') -replace '/indicators$', ''
        $since = $now.AddDays(-90).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $items = [System.Collections.Generic.List[object]]::new()
        $uri = "$base/machines?`$filter=healthStatus eq 'Inactive' and lastSeen lt $since"
        try {
            while ($uri) {
                $r = Invoke-WlRest -Uri $uri -Resource $res
                foreach ($i in @($r.value)) { if ($i) { $items.Add($i) } }
                $uri = if ($r.PSObject.Properties['@odata.nextLink']) { $r.'@odata.nextLink' } else { $null }
            }
        }
        catch { Add-WlWarning "MDE inactive devices (Machine.Read.All): $($_.Exception.Message)" }
        $inactive = @($items | ForEach-Object {
                [pscustomobject]@{ deviceId = [string]$_.id; deviceName = [string](Get-WlProp $_ 'computerDnsName'); os = [string](Get-WlProp $_ 'osPlatform'); lastSeen = [string](Get-WlProp $_ 'lastSeen')
                    group = [string](Get-WlProp $_ 'rbacGroupName'); onboardingStatus = [string](Get-WlProp $_ 'onboardingStatus') }
            } | Sort-Object lastSeen)
    }
    [pscustomobject]@{ inactive = $inactive }
}

function Get-WlFleetFindings {
    <#
    .SYNOPSIS
    Fleet hygiene (category 'Fleet'):
      - internet-facing devices with high exposure
      - troubleshooting mode: active right now / used repeatedly in 30 days
      - tampering attempts in 30 days (per device)
      - devices excluded from Defender Vulnerability Management
      - onboarded devices without a device tag while the tenant tags most devices
      - inactive devices (90+ days) still listed in the inventory – offboarding candidates
    #>
    param([hashtable]$Devices, $Facts)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-WlText -En $en -De $de }
    $names = { param($rows) ((@($rows) | Select-Object -First 10 | ForEach-Object { $_.deviceName }) -join ', ') + $(if (@($rows).Count -gt 10) { ', …' } else { '' }) }
    $all = @($Devices.Values)

    foreach ($d in $all) {
        $tamperOff = ([string]$d.checks['TamperProtection']) -eq 'BAD'
        if ($d.internetFacing -eq $true -and $d.exposure -eq 'High') {
            $f.Add((New-WlFinding -Severity $(if ($tamperOff -or ($d.avMode -and $d.avMode -ne '0')) { 'High' } else { 'Medium' }) -Category 'Fleet' -Title (& $T 'Internet-facing device with high exposure' 'Internet-exponiertes Gerät mit hoher Exposure') `
                        -Detail (& $T "Defender marks $($d.deviceName) as internet-facing and rates its exposure level High$(if ($d.assetValue) { " (asset value $($d.assetValue))" }). Reachable from the internet and vulnerable at the same time." "Defender markiert $($d.deviceName) als internet-exponiert und bewertet die Exposure mit Hoch$(if ($d.assetValue) { " (Asset-Wert $($d.assetValue))" }). Aus dem Internet erreichbar und zugleich verwundbar.") `
                        -Recommendation (& $T 'Patch the security recommendations for this device first; check whether the exposure to the internet is intended (firewall, NAT, published ports).' 'Sicherheitsempfehlungen für dieses Gerät zuerst umsetzen; prüfen, ob die Internet-Exposition beabsichtigt ist (Firewall, NAT, veröffentlichte Ports).') -Subject "fleet|inet|$($d.deviceId)" -DeviceId $d.deviceId -DeviceName $d.deviceName))
        }
        if ($d.troubleshootingActive) {
            $f.Add((New-WlFinding -Severity 'High' -Category 'Fleet' -Title (& $T 'Troubleshooting mode active' 'Troubleshooting-Modus aktiv') `
                        -Detail (& $T "$($d.deviceName) is in Defender troubleshooting mode (started $($d.troubleshootingLast)). While it is active, local administrators can change policy-managed Defender settings and switch off tamper protection; policy changes are not applied." "$($d.deviceName) befindet sich im Defender-Troubleshooting-Modus (gestartet $($d.troubleshootingLast)). Solange er aktiv ist, können lokale Administratoren richtliniengesteuerte Defender-Einstellungen ändern und Tamper Protection abschalten; Richtlinienänderungen werden nicht angewendet.") `
                        -Recommendation (& $T 'Confirm that the session is known to the team (ticket) and that the device is being watched; it ends automatically after four hours.' 'Sicherstellen, dass die Sitzung dem Team bekannt ist (Ticket) und das Gerät beobachtet wird; der Modus endet automatisch nach vier Stunden.') -Subject "fleet|tsactive|$($d.deviceId)" -DeviceId $d.deviceId -DeviceName $d.deviceName))
        }
        elseif ($d.troubleshooting30d -ge 3) {
            $f.Add((New-WlFinding -Severity 'Medium' -Category 'Fleet' -Title (& $T "Troubleshooting mode used $($d.troubleshooting30d) times in 30 days" "Troubleshooting-Modus $($d.troubleshooting30d)-mal in 30 Tagen genutzt") `
                        -Detail (& $T "$($d.deviceName) was put into troubleshooting mode $($d.troubleshooting30d) times in the last 30 days (last $($d.troubleshootingLast)). Each session suspends tamper protection and policy enforcement for up to four hours." "$($d.deviceName) wurde in den letzten 30 Tagen $($d.troubleshooting30d)-mal in den Troubleshooting-Modus versetzt (zuletzt $($d.troubleshootingLast)). Jede Sitzung setzt Tamper Protection und Richtliniendurchsetzung für bis zu vier Stunden aus.") `
                        -Recommendation (& $T 'Find the root cause (performance, false positive, incompatible software) and fix it in policy instead of repeatedly weakening the device.' 'Ursache finden (Performance, False Positive, inkompatible Software) und per Richtlinie lösen, statt das Gerät wiederholt zu schwächen.') -Subject "fleet|tsrepeat|$($d.deviceId)" -DeviceId $d.deviceId -DeviceName $d.deviceName))
        }
        if ($d.tampering30d -gt 0) {
            $sev = if ($tamperOff -or $d.tampering30d -ge 10) { 'High' } else { 'Medium' }
            $f.Add((New-WlFinding -Severity $sev -Category 'Fleet' -Title (& $T "$($d.tampering30d) tampering attempt(s) in 30 days" "$($d.tampering30d) Manipulationsversuch(e) in 30 Tagen") `
                        -Detail (& $T "Defender recorded $($d.tampering30d) TamperingAttempt event(s) on $($d.deviceName) (last $($d.tamperingLast))$(if ($tamperOff) { ' – and tamper protection is off on this device, so such attempts succeed' }). Attempts to change protected Defender settings are typical for persistence and defence evasion, but also for misconfigured management scripts." "Defender hat auf $($d.deviceName) $($d.tampering30d) TamperingAttempt-Ereignis(se) aufgezeichnet (zuletzt $($d.tamperingLast))$(if ($tamperOff) { ' – und Tamper Protection ist auf diesem Gerät aus, solche Versuche sind also erfolgreich' }). Versuche, geschützte Defender-Einstellungen zu ändern, sind typisch für Persistenz und Defence Evasion, aber auch für fehlkonfigurierte Verwaltungsskripte.") `
                        -Recommendation (& $T 'Review the events in the device timeline (DeviceEvents, ActionType TamperingAttempt): which process, which setting? Fix scripts that write Defender settings directly; investigate anything unexplained.' 'Ereignisse in der Geräte-Timeline prüfen (DeviceEvents, ActionType TamperingAttempt): welcher Prozess, welche Einstellung? Skripte korrigieren, die Defender-Einstellungen direkt schreiben; Unerklärliches untersuchen.') -Subject "fleet|tamper|$($d.deviceId)" -DeviceId $d.deviceId -DeviceName $d.deviceName))
        }
    }

    # Third-party AV/EDR next to Defender: the interesting cases are "both active" (double scanning, exclusion mismatch,
    # unclear which product owns an incident) and the overall footprint (licence and architecture question).
    $thirdParty = @($all | Where-Object { @($_.thirdPartyAv).Count -gt 0 })
    foreach ($d in $thirdParty) {
        $products = (@($d.thirdPartyAv) -join ', ')
        if ($d.avMode -eq '0' -and $d.os -match '^Windows') {
            $f.Add((New-WlFinding -Severity 'Medium' -Category 'Fleet' -Title (& $T 'Third-party AV/EDR alongside active Defender Antivirus' 'Fremd-AV/EDR neben aktivem Defender Antivirus') `
                        -Detail (& $T "$($d.deviceName) has $products installed while Defender Antivirus runs in active mode. Two real-time engines compete for files and CPU, exclusions have to be kept in sync on both sides, and detections appear in two consoles. Defender did not switch to passive mode – the third-party product may not be registered with the Windows Security Center, or it may be an EDR-only sensor." "$($d.deviceName) hat $products installiert, während Defender Antivirus im aktiven Modus läuft. Zwei Echtzeit-Engines konkurrieren um Dateien und CPU, Ausschlüsse müssen auf beiden Seiten gepflegt werden, Erkennungen erscheinen in zwei Konsolen. Defender ist nicht in den passiven Modus gewechselt – das Fremdprodukt ist möglicherweise nicht im Windows Security Center registriert oder ein reiner EDR-Sensor.") `
                        -Recommendation (& $T 'Decide on one primary AV: either remove the third-party product (Defender for Endpoint P2 already covers EDR) or let Defender run in passive/EDR-block mode behind it. Mirror exclusions deliberately.' 'Ein primäres AV festlegen: Fremdprodukt entfernen (Defender for Endpoint P2 deckt EDR bereits ab) oder Defender dahinter im passiven/EDR-Block-Modus betreiben. Ausschlüsse bewusst spiegeln.') -Subject "fleet|3pav|$($d.deviceId)" -DeviceId $d.deviceId -DeviceName $d.deviceName))
        }
    }
    if ($thirdParty.Count) {
        $vendors = @{}
        foreach ($d in $thirdParty) { foreach ($p in @($d.thirdPartyAv)) { $v = ([string]$p -split ' ')[0]; $vendors[$v] = [int]$vendors[$v] + 1 } }
        $vendorText = (@($vendors.GetEnumerator() | Sort-Object { -$_.Value } | ForEach-Object { "$($_.Key) ($($_.Value))" }) -join ', ')
        $passive = @($thirdParty | Where-Object { $_.avMode -in '1', '2' }).Count
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Fleet' -Title (& $T "$($thirdParty.Count) onboarded device(s) with a third-party AV/EDR product" "$($thirdParty.Count) onboardete(s) Gerät(e) mit Fremd-AV/EDR-Produkt") `
                    -Detail (& $T "Vendors: $vendorText. $passive device(s) run Defender in passive mode behind the other product. Every onboarded device is covered by the Defender for Endpoint licence of its user – a second EDR on the same device is a double spend unless it is a deliberate migration or defence-in-depth decision." "Hersteller: $vendorText. $passive Gerät(e) betreiben Defender im passiven Modus hinter dem anderen Produkt. Jedes onboardete Gerät ist durch die Defender-for-Endpoint-Lizenz seines Benutzers abgedeckt – ein zweites EDR auf demselben Gerät ist eine Doppelausgabe, sofern es nicht bewusste Migration oder Defense-in-Depth ist.") `
                    -Recommendation (& $T 'Document the intended end state per vendor (migration to Defender, Defender passive, or removal) and track the device count in the device list (filter: third-party AV).' 'Zielzustand je Hersteller dokumentieren (Migration zu Defender, Defender passiv oder Entfernung) und die Gerätezahl in der Geräteliste verfolgen (Filter: Fremd-AV).') -Subject 'fleet|3pav' -StableKey |
                Add-Member -NotePropertyName deviceCount -NotePropertyValue $thirdParty.Count -PassThru | Add-Member -NotePropertyName deviceSample -NotePropertyValue @($thirdParty | Select-Object -First 10 | ForEach-Object deviceName) -PassThru))
    }

    $excluded = @($all | Where-Object { $_.tvmExcluded -eq $true })
    if ($excluded.Count) {
        $reasons = (@($excluded | ForEach-Object { $_.tvmExclusionReason } | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Fleet' -Title (& $T "$($excluded.Count) device(s) excluded from Vulnerability Management" "$($excluded.Count) Gerät(e) von Vulnerability Management ausgeschlossen") `
                    -Detail (& $T "Excluded devices do not appear in exposure score, security recommendations or vulnerability reports: $(& $names $excluded)$(if ($reasons) { ". Reasons: $reasons" })." "Ausgeschlossene Geräte tauchen weder im Exposure Score noch in Sicherheitsempfehlungen oder Schwachstellenberichten auf: $(& $names $excluded)$(if ($reasons) { ". Gründe: $reasons" }).") `
                    -Recommendation (& $T 'Review the exclusions regularly; remove them for devices that are back in service or were excluded only for a migration.' 'Ausschlüsse regelmäßig prüfen; für Geräte, die wieder im Einsatz sind oder nur für eine Migration ausgeschlossen wurden, entfernen.') -Subject 'fleet|tvmexcluded' -StableKey))
    }

    $tagged = @($all | Where-Object { @($_.tags).Count -gt 0 })
    $untagged = @($all | Where-Object { @($_.tags).Count -eq 0 })
    if ($all.Count -ge 10 -and $tagged.Count -ge ($all.Count / 2) -and $untagged.Count -gt 0) {
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Fleet' -Title (& $T "$($untagged.Count) onboarded device(s) without a device tag" "$($untagged.Count) onboardete(s) Gerät(e) ohne Geräte-Tag") `
                    -Detail (& $T "$($tagged.Count) of $($all.Count) devices carry a tag, these do not: $(& $names $untagged). If device groups, indicators or automation rules are scoped by tag, untagged devices fall through." "$($tagged.Count) von $($all.Count) Geräten tragen ein Tag, diese nicht: $(& $names $untagged). Wenn Gerätegruppen, Indikatoren oder Automatisierungsregeln per Tag gescopet sind, fallen ungetaggte Geräte durch.") `
                    -Recommendation (& $T 'Tag devices by dynamic tagging rules (Defender settings › Asset rule management) or via the onboarding package instead of by hand.' 'Geräte über dynamische Tagging-Regeln (Defender-Einstellungen › Asset-Regelverwaltung) oder das Onboarding-Paket taggen statt von Hand.') -Subject 'fleet|untagged' -StableKey))
    }

    $inactive = @(Get-WlProp $Facts 'inactive')
    if ($inactive.Count) {
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Fleet' -Title (& $T "$($inactive.Count) device(s) inactive for 90+ days still in the inventory" "$($inactive.Count) Gerät(e) seit 90+ Tagen inaktiv, aber noch im Inventar") `
                    -Detail (& $T "These onboarded devices have not reported to Defender for at least 90 days: $(& $names $inactive). They keep counting against device groups, reports and licences, and a stale record can mask a re-imaged device with the same name." "Diese onboardeten Geräte haben sich seit mindestens 90 Tagen nicht bei Defender gemeldet: $(& $names $inactive). Sie zählen weiter in Gerätegruppen, Berichten und Lizenzen, und ein veralteter Datensatz kann ein neu installiertes Gerät gleichen Namens verdecken.") `
                    -Recommendation (& $T 'Offboard retired devices (offboarding package or API) and remove them from Intune/Entra; keep an offboarding step in the decommissioning process.' 'Ausgemusterte Geräte offboarden (Offboarding-Paket oder API) und aus Intune/Entra entfernen; einen Offboarding-Schritt in den Außerbetriebnahme-Prozess aufnehmen.') -Subject 'fleet|inactive90' -StableKey))
    }
    @($f.ToArray())
}
#endregion

#region Local exclusions (Advanced Hunting: Windows registry, macOS/Linux mdatp)
function Get-WlRegistryExclusionCategory {
    param([string]$RegistryKey)
    $k = $RegistryKey.ToLowerInvariant()
    if ($k -match 'asronlyexclusions') { return 'ASR' }
    if ($k -match 'allowedapplications') { return 'CFA' }
    $leaf = ($RegistryKey -split '\\')[-1]
    switch ($leaf.ToLowerInvariant()) {
        'paths' { 'Path' }
        'processes' { 'Process' }
        'extensions' { 'Extension' }
        'ipaddresses' { 'IP' }
        'temporarypaths' { 'TempPath' }
        default { 'Path' }
    }
}

function ConvertFrom-WlMdatpCommand {
    <#
    .SYNOPSIS
    Parses an mdatp command line (macOS/Linux) into a normalised exclusion action.
    Examples: "mdatp exclusion folder add --path /opt/app --scope global",
              "mdatp exclusion process add --name java", "mdatp threat allowed add --name EICAR-Test-File".
    #>
    param([string]$CommandLine)
    if (-not $CommandLine) { return $null }
    $cl = $CommandLine
    $type = $null; $action = $null
    if ($cl -match '(?i)exclusion\s+(folder|file|extension|process)\s+(add|remove)') {
        $action = $Matches[2].ToLowerInvariant()
        $type = switch ($Matches[1].ToLowerInvariant()) { 'extension' { 'Extension' } 'process' { 'Process' } default { 'Path' } }
    }
    elseif ($cl -match '(?i)threat\s+allowed\s+(add|remove)') {
        $action = $Matches[1].ToLowerInvariant(); $type = 'AllowedThreat'
    }
    else { return $null }

    $value = $null
    if ($cl -match '(?i)--(path|name)\s+(?:"([^"]+)"|''([^'']+)''|(\S+))') {
        $value = @($Matches[2], $Matches[3], $Matches[4]) | Where-Object { $_ } | Select-Object -First 1
    }
    if (-not $value) { return $null }
    $scope = if ($cl -match '(?i)--scope\s+\S*global') { 'Global' } else { 'AV' }
    [pscustomobject]@{ Action = $action; Type = $type; Value = $value; Scope = $scope }
}

function Find-WlMpPreferenceCaller {
    <#
    .SYNOPSIS
    Registry changes made through Add-/Set-MpPreference (WMI) are written by the Defender service itself – the
    registry event then only shows MsMpEng.exe. This finds the real caller (e.g. powershell.exe with its command
    line) on the same device shortly before the change, whose command line contains the exclusion value.
    #>
    param($RegistryEvent, [object[]]$PsEvents)
    $value = ([string]$RegistryEvent.RegistryValueName).TrimEnd('\').ToLowerInvariant()
    if (-not $value) { return $null }
    $t = ConvertTo-WlUtc $RegistryEvent.Timestamp
    $best = $null; $bestDiff = [double]::MaxValue
    foreach ($p in @($PsEvents)) {
        if ($null -eq $p -or [string]$p.DeviceId -ne [string]$RegistryEvent.DeviceId) { continue }
        $pt = ConvertTo-WlUtc $p.Timestamp
        $diff = ($t - $pt).TotalSeconds
        if ($diff -lt -120 -or $diff -gt 900) { continue }
        if (-not ([string]$p.ProcessCommandLine).ToLowerInvariant().Contains($value)) { continue }
        if ([Math]::Abs($diff) -lt $bestDiff) { $best = $p; $bestDiff = [Math]::Abs($diff) }
    }
    $best
}

function ConvertTo-WlLocalEvents {
    <#
    .SYNOPSIS
    Normalises registry (Windows) and process events (macOS/Linux) into uniform exclusion events.
    #>
    param([object[]]$RegistryEvents, [object[]]$ProcessEvents, [object[]]$PsEvents)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @($RegistryEvents)) {
        if ($null -eq $e -or -not [string]$e.RegistryValueName) { continue }
        $regKey = [string]$e.RegistryKey
        $proc = [string]$e.InitiatingProcessFileName; $cmd = [string]$e.InitiatingProcessCommandLine; $acc = [string]$e.InitiatingProcessAccountName
        if (-not $proc -or $proc -in 'MsMpEng.exe', 'msmpeng.exe', 'WmiPrvSE.exe', 'wmiprvse.exe', 'MpCmdRun.exe') {
            $caller = Find-WlMpPreferenceCaller -RegistryEvent $e -PsEvents $PsEvents
            if ($caller) { $proc = [string]$caller.FileName; $cmd = [string]$caller.ProcessCommandLine; $acc = [string]$caller.AccountName }
        }
        $out.Add([pscustomobject]@{
                Timestamp = [string]$e.Timestamp; DeviceId = [string]$e.DeviceId; DeviceName = [string]$e.DeviceName; Platform = 'Windows'
                Action = if ([string]$e.ActionType -eq 'RegistryValueSet') { 'add' } else { 'remove' }
                Type = (Get-WlRegistryExclusionCategory -RegistryKey $regKey); Origin = if ($regKey -match '\\Policies\\') { 'GPO' } else { 'Local' }
                Value = [string]$e.RegistryValueName; Scope = 'AV'
                Process = $proc; CommandLine = $cmd; Account = $acc
            })
    }
    foreach ($e in @($ProcessEvents)) {
        if ($null -eq $e) { continue }
        $parsed = ConvertFrom-WlMdatpCommand -CommandLine ([string]$e.ProcessCommandLine)
        if (-not $parsed) { continue }
        $out.Add([pscustomobject]@{
                Timestamp = [string]$e.Timestamp; DeviceId = [string]$e.DeviceId; DeviceName = [string]$e.DeviceName; Platform = [string]$e.OSPlatform
                Action = $parsed.Action; Type = $parsed.Type; Origin = 'Local'; Value = $parsed.Value; Scope = $parsed.Scope
                Process = 'mdatp'; CommandLine = [string]$e.ProcessCommandLine; Account = [string]$e.AccountName
            })
    }
    $out.ToArray()
}

function Get-WlDeviceInventory {
    <#
    .SYNOPSIS
    Optional (app setting WL_DEVICE_INVENTORY=true): reads the results of the Wardline detection script from Intune
    Remediations. Returns the current local exclusions per device – including entries older than the 30 days
    covered by Advanced Hunting.
    #>
    if (-not (Test-WlFeature -Name 'inventory')) { return }
    $scripts = Invoke-WlGraphSafe -Beta -All -Context 'Device inventory (Intune Remediations)' -Path 'deviceManagement/deviceHealthScripts?$select=id,displayName'
    $hs = @($scripts | Where-Object { $_ -and ([string]$_.displayName) -like 'Wardline*' }) | Select-Object -First 1
    if (-not $hs) { Add-WlWarning 'Device inventory is enabled, but the Wardline detection script was not found in Intune. Run Install-Wardline.ps1 -DeviceInventory again.'; return }
    $states = Invoke-WlGraphSafe -Beta -All -Context 'Device inventory (results)' -Path "deviceManagement/deviceHealthScripts/$($hs.id)/deviceRunStates?`$expand=managedDevice"
    $typeMap = @{ P = 'Path'; R = 'Process'; E = 'Extension'; I = 'IP'; T = 'TempPath'; A = 'ASR'; C = 'CFA' }
    $runModes = @{ 'normal' = '0'; 'passive mode' = '1'; 'passive' = '1'; 'sxs passive mode' = '2'; 'edr block mode' = '4' }
    foreach ($st in @($states)) {
        if (-not $st) { continue }
        $raw = [string](Get-WlProp $st 'preRemediationDetectionScriptOutput')
        if (-not $raw.Trim()) { continue }
        try { $j = $raw | ConvertFrom-Json -Depth 8 } catch { continue }
        if ([int](Get-WlProp $j 'v') -ne 1) { continue }
        $md = Get-WlProp $st 'managedDevice'
        $entries = foreach ($e in @(Get-WlProp $j 'x')) {
            $a = @($e)
            if ($a.Count -lt 3) { continue }
            [pscustomobject]@{ type = $(if ($typeMap.ContainsKey([string]$a[0])) { $typeMap[[string]$a[0]] } else { 'Path' }); origin = $(if ([string]$a[1] -eq 'G') { 'GPO' } else { 'Local' }); value = [string]$a[2] }
        }
        $rm = ([string](Get-WlProp $j 'rm')).ToLowerInvariant()
        [pscustomobject]@{
            aadDeviceId   = [string](Get-WlProp $md 'azureADDeviceId')
            deviceName    = [string](Get-WlProp $md 'deviceName')
            at            = [string](Get-WlProp $st 'lastStateUpdateDateTime')
            mergeDisabled = ([int](Get-WlProp $j 'm') -eq 1)
            tamper        = ([int](Get-WlProp $j 'tp') -eq 1)
            runMode       = $(if ($runModes.ContainsKey($rm)) { $runModes[$rm] } else { $null })
            truncated     = ([int](Get-WlProp $j 'tr') -eq 1)
            entries       = @($entries)
            deviceId      = $null
        }
    }
}

function Resolve-WlInventoryDevices {
    <#
    .SYNOPSIS
    Maps inventory results (Intune) to Defender devices – by Entra device ID, otherwise by name – and takes over
    DisableLocalAdminMerge, Tamper Protection and running mode where Defender does not (yet) report them.
    #>
    param([object[]]$Inventory, [hashtable]$Devices)
    $byAad = @{}; $byName = @{}
    foreach ($d in $Devices.Values) {
        if ($d.aadDeviceId) { $byAad[([string]$d.aadDeviceId).ToLowerInvariant()] = $d }
        if ($d.deviceName) { $byName[(([string]$d.deviceName) -split '\.')[0].ToLowerInvariant()] = $d }
    }
    $resolved = foreach ($inv in @($Inventory)) {
        if (-not $inv) { continue }
        $d = $null
        if ($inv.aadDeviceId) { $d = $byAad[$inv.aadDeviceId.ToLowerInvariant()] }
        if (-not $d -and $inv.deviceName) { $d = $byName[($inv.deviceName -split '\.')[0].ToLowerInvariant()] }
        if (-not $d) { continue }
        $inv.deviceId = $d.deviceId
        $inv.deviceName = $d.deviceName
        $d.inventoryAt = $inv.at
        $d.localMergeDisabled = $inv.mergeDisabled
        if (-not $d.checks.Contains('TamperProtection')) { $d.checks['TamperProtection'] = $(if ($inv.tamper) { 'GOOD' } else { 'BAD' }) }
        if (-not $d.avMode -and $inv.runMode) { $d.avMode = $inv.runMode; $d.avModeText = $script:WlAvModeMap[$inv.runMode] }
        $inv
    }
    @($resolved)
}

function Update-WlLocalExclusionState {
    <#
    .SYNOPSIS
    Merges normalised events (add/remove) with the previous state, so the history survives beyond the
    Advanced Hunting retention (30 days).
    #>
    param([object[]]$Events, [object[]]$Previous, [object[]]$Inventory)
    $state = @{}
    # Values written by Wardline 0.1/0.2 (German codes) are migrated to the current codes.
    $legacy = @{ 'Pfad' = 'Path'; 'Prozess' = 'Process'; 'Erweiterung' = 'Extension'; 'Pfad (temporär)' = 'TempPath'; 'Erlaubte Bedrohung' = 'AllowedThreat'
        'Tamper-Ausnahme' = 'TamperException'; 'Lokal' = 'Local'; 'Global (AV+EDR)' = 'Global'; 'Advanced Hunting' = 'AdvancedHunting'; 'Geräte-Inventur' = 'DeviceInventory' }
    foreach ($p in @($Previous)) {
        if ($p -and (Get-WlProp $p 'key')) {
            $h = [ordered]@{}
            foreach ($prop in $p.PSObject.Properties) { $h[$prop.Name] = $prop.Value }
            foreach ($f in 'type', 'origin', 'scope', 'source') { if ($h.Contains($f) -and $h[$f] -and $legacy.ContainsKey([string]$h[$f])) { $h[$f] = $legacy[[string]$h[$f]] } }
            $h.key = Get-WlHash "loc|$($h.deviceId)|$($h.type)|$($h.origin)|$(if ($h.scope) { $h.scope } else { 'AV' })|$($h.value)"
            $state[[string]$h.key] = $h
        }
    }

    $sorted = @($Events | Where-Object { $_ } | Sort-Object { ConvertTo-WlUtc $_.Timestamp })
    foreach ($e in $sorted) {
        $key = Get-WlHash "loc|$($e.DeviceId)|$($e.Type)|$($e.Origin)|$($e.Scope)|$($e.Value)"
        $ts = (ConvertTo-WlUtc $e.Timestamp).ToString('o')
        $by = [ordered]@{ process = $e.Process; commandLine = $e.CommandLine; account = $e.Account }

        if ($state.ContainsKey($key) -and $state[$key].lastChange -and (ConvertTo-WlUtc $state[$key].lastChange) -ge (ConvertTo-WlUtc $ts)) { continue }

        if (-not $state.ContainsKey($key)) {
            $state[$key] = [ordered]@{ key = $key; deviceId = $e.DeviceId; deviceName = $e.DeviceName; platform = $e.Platform; type = $e.Type; origin = $e.Origin
                scope = $e.Scope; value = $e.Value; present = $false; firstSeen = $ts; lastChange = $ts; addedBy = $null; removedAt = $null; removedBy = $null
                source = 'AdvancedHunting'; confirmedAt = $null }
        }
        $s = $state[$key]
        $s.deviceName = $e.DeviceName
        if ($e.Action -eq 'add') {
            if (-not $s.present) { $s.addedBy = $by }
            $s.present = $true; $s.removedAt = $null; $s.removedBy = $null
        }
        else {
            $s.present = $false; $s.removedAt = $ts; $s.removedBy = $by
        }
        $s.lastChange = $ts
    }

    # Device inventory (optional): current state per device
    foreach ($inv in @($Inventory)) {
        if (-not $inv -or -not $inv.deviceId -or -not $inv.at) { continue }
        $at = ConvertTo-WlUtc $inv.at
        $atText = $at.ToString('o')
        $seenKeys = @{}
        foreach ($en in @($inv.entries)) {
            $key = Get-WlHash "loc|$($inv.deviceId)|$($en.type)|$($en.origin)|AV|$($en.value)"
            $seenKeys[$key] = $true
            if (-not $state.ContainsKey($key)) {
                $state[$key] = [ordered]@{ key = $key; deviceId = $inv.deviceId; deviceName = $inv.deviceName; platform = 'Windows'; type = $en.type; origin = $en.origin
                    scope = 'AV'; value = $en.value; present = $true; firstSeen = $atText; lastChange = $atText; addedBy = $null; removedAt = $null; removedBy = $null
                    source = 'DeviceInventory'; confirmedAt = $atText }
                continue
            }
            $s = $state[$key]
            if (-not $s.present -and (-not $s.lastChange -or (ConvertTo-WlUtc $s.lastChange) -le $at)) {
                $s.present = $true; $s.removedAt = $null; $s.removedBy = $null; $s.lastChange = $atText
            }
            $s.confirmedAt = $atText
        }
        if ($inv.truncated) { continue }
        foreach ($s in @($state.Values | Where-Object { $_.deviceId -eq $inv.deviceId -and $_.present -and $_.platform -eq 'Windows' })) {
            if ($seenKeys.ContainsKey($s.key)) { continue }
            if ($s.lastChange -and (ConvertTo-WlUtc $s.lastChange) -gt $at) { continue }
            $s.present = $false; $s.removedAt = $atText; $s.lastChange = $atText
            $s.removedBy = [ordered]@{ process = '(device inventory)'; commandLine = $null; account = $null }
        }
    }

    # Clean up removed entries after 90 days
    $cut = [DateTime]::UtcNow.AddDays(-90)
    $out = foreach ($s in $state.Values) {
        if (-not $s.present -and $s.removedAt -and (ConvertTo-WlUtc $s.removedAt) -lt $cut) { continue }
        $scope = if ($s.Contains('scope') -and $s.scope) { $s.scope } else { 'AV' }
        $s.risk = Get-WlExclusionRisk -Type $s.type -Value $s.value -Origin $s.origin -Scope $scope
        $s.label = if ($s.origin -eq 'GPO') { New-WlText "GPO $(Get-WlTypeName $s.type) exclusion '$($s.value)' on $($s.deviceName)" "GPO-$(Get-WlTypeName $s.type -De)-Exclusion '$($s.value)' auf $($s.deviceName)" }
        else { New-WlText "Local $(Get-WlTypeName $s.type) exclusion '$($s.value)' on $($s.deviceName)" "Lokale $(Get-WlTypeName $s.type -De)-Exclusion '$($s.value)' auf $($s.deviceName)" }
        $s.state = if ($s.present) { 'present' } else { 'removed' }
        $s.fp = Get-WlHash "$($s.present)"
        [pscustomobject]$s
    }
    @($out)
}

function Get-WlLocalExclusionEvents {
    $qReg = @"
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet", "RegistryValueDeleted")
| where RegistryKey contains @"\Windows Defender\Exclusions\" or RegistryKey contains @"\Windows Defender Exploit Guard\ASR\ASROnlyExclusions" or RegistryKey contains @"\Controlled Folder Access\AllowedApplications"
| project Timestamp, DeviceId, DeviceName, ActionType, RegistryKey, RegistryValueName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
| take 50000
"@
    $qProc = @"
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "mdatp"
| where (ProcessCommandLine has "exclusion" or ProcessCommandLine has "allowed") and (ProcessCommandLine has "add" or ProcessCommandLine has "remove")
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, OSPlatform) by DeviceId | project DeviceId, OSPlatform) on DeviceId
| project Timestamp, DeviceId, DeviceName, OSPlatform, ProcessCommandLine, AccountName
| order by Timestamp asc
| take 20000
"@
    $qPs = @"
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "MpPreference" and ProcessCommandLine has "Exclusion"
| project Timestamp, DeviceId, FileName, ProcessCommandLine, AccountName
| take 20000
"@
    $reg = Invoke-WlHuntingSafe -Query $qReg -Context 'Advanced Hunting DeviceRegistryEvents (local exclusions, Windows)'
    $proc = Invoke-WlHuntingSafe -Query $qProc -Context 'Advanced Hunting DeviceProcessEvents (local exclusions, macOS/Linux)'
    $ps = if (@($reg).Count) { Invoke-WlHuntingSafe -Query $qPs -Context 'Advanced Hunting DeviceProcessEvents (Add-/Set-MpPreference)' } else { @() }
    ConvertTo-WlLocalEvents -RegistryEvents @($reg) -ProcessEvents @($proc) -PsEvents @($ps)
}
#endregion

#region ASR rules (target / configured / effective per device and device group)
# Mapping: rule GUID, key in DeviceTvmInfoGathering.AsrConfigurationStates, TVM check (scid) and the suffix of the
# Settings Catalog setting device_vendor_msft_policy_config_defender_attacksurfacereductionrules_<suffix>.
$script:WlAsrRules = @(
    [pscustomobject]@{ id = 'email-exec';        guid = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'; key = 'ExecutableEmailContent';              scid = 'scid-2500'; suffix = 'blockexecutablecontentfromemailclientandwebmail'; name = 'Block executable content from email client and webmail' }
    [pscustomobject]@{ id = 'office-child';      guid = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; key = 'OfficeChildProcess';                  scid = 'scid-2501'; suffix = 'blockallofficeapplicationsfromcreatingchildprocesses'; name = 'Block all Office applications from creating child processes' }
    [pscustomobject]@{ id = 'office-exec';       guid = '3b576869-a4ec-4529-8536-b80a7769e899'; key = 'ExecutableOfficeContent';             scid = 'scid-2502'; suffix = 'blockofficeapplicationsfromcreatingexecutablecontent'; name = 'Block Office applications from creating executable content' }
    [pscustomobject]@{ id = 'office-inject';     guid = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; key = 'OfficeProcessInjection';              scid = 'scid-2503'; suffix = 'blockofficeapplicationsfrominjectingcodeintootherprocesses'; name = 'Block Office applications from injecting code into other processes' }
    [pscustomobject]@{ id = 'script-download';   guid = 'd3e037e1-3eb8-44c8-a917-57927947596d'; key = 'ScriptExecutableDownload';            scid = 'scid-2504'; suffix = 'blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent'; name = 'Block JavaScript or VBScript from launching downloaded executable content' }
    [pscustomobject]@{ id = 'obfuscated';        guid = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'; key = 'ObfuscatedScript';                    scid = 'scid-2505'; suffix = 'blockexecutionofpotentiallyobfuscatedscripts'; name = 'Block execution of potentially obfuscated scripts' }
    [pscustomobject]@{ id = 'macro-win32';       guid = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'; key = 'OfficeMacroWin32ApiCalls';            scid = 'scid-2506'; suffix = 'blockwin32apicallsfromofficemacros'; name = 'Block Win32 API calls from Office macros' }
    [pscustomobject]@{ id = 'prevalence';        guid = '01443614-cd74-433a-b99e-2ecdc07bfc25'; key = 'UntrustedExecutable';                 scid = 'scid-2507'; suffix = 'blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion'; name = 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion' }
    [pscustomobject]@{ id = 'ransomware';        guid = 'c1db55ab-c21a-4637-bb3f-a12568109d35'; key = 'Ransomware';                          scid = 'scid-2508'; suffix = 'useadvancedprotectionagainstransomware'; name = 'Use advanced protection against ransomware' }
    [pscustomobject]@{ id = 'lsass';             guid = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; key = 'LsassCredentialTheft';                scid = 'scid-2509'; suffix = 'blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem'; name = 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)' }
    [pscustomobject]@{ id = 'psexec-wmi';        guid = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'; key = 'PsexecWmiChildProcess';               scid = 'scid-2510'; suffix = 'blockprocesscreationsfrompsexecandwmicommands'; name = 'Block process creations originating from PSExec and WMI commands' }
    [pscustomobject]@{ id = 'usb';               guid = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'; key = 'UntrustedUsbProcess';                 scid = 'scid-2511'; suffix = 'blockuntrustedunsignedprocessesthatrunfromusb'; name = 'Block untrusted and unsigned processes that run from USB' }
    [pscustomobject]@{ id = 'office-comm';       guid = '26190899-1602-49e8-8b27-eb1d0a1ce869'; key = 'OfficeCommAppChildProcess';           scid = 'scid-2512'; suffix = 'blockofficecommunicationappfromcreatingchildprocesses'; name = 'Block Office communication application from creating child processes' }
    [pscustomobject]@{ id = 'adobe-child';       guid = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'; key = 'AdobeReaderChildProcess';             scid = 'scid-2513'; suffix = 'blockadobereaderfromcreatingchildprocesses'; name = 'Block Adobe Reader from creating child processes' }
    [pscustomobject]@{ id = 'wmi-persistence';   guid = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'; key = 'PersistenceThroughWmi';               scid = 'scid-2514'; suffix = 'blockpersistencethroughwmieventsubscription'; name = 'Block persistence through WMI event subscription' }
    [pscustomobject]@{ id = 'vulnerable-driver'; guid = '56a863a9-875e-4185-98a7-b882c64b5ce5'; key = 'VulnerableSignedDriver';              scid = 'scid-2515'; suffix = 'blockabuseofexploitedvulnerablesigneddrivers'; name = 'Block abuse of exploited vulnerable signed drivers' }
    [pscustomobject]@{ id = 'webshell';          guid = 'a8f5898e-1dc8-49a9-9878-85004b8a61e6'; key = 'BlockWebshellCreation';               scid = 'scid-2516'; suffix = 'blockwebshellcreationforservers'; name = 'Block Webshell creation for Servers' }
    [pscustomobject]@{ id = 'copied-tools';      guid = 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'; key = 'BlockCopiedOrImpersonatedSystemTools'; scid = 'scid-2517'; suffix = 'blockuseofcopiedorimpersonatedsystemtools'; name = 'Block use of copied or impersonated system tools' }
    [pscustomobject]@{ id = 'safemode-reboot';   guid = '33ddedf1-c6e0-47cb-833e-de6133960387'; key = 'BlockSafeModeReboot';                 scid = 'scid-2518'; suffix = 'blockrebootingmachineinsafemode'; name = 'Block rebooting machine in Safe Mode' }
)
$script:WlAsrModeRank = @{ 'Off' = 0; 'Audit' = 1; 'Warn' = 2; 'Block' = 3 }

function Get-WlAsrRuleBySuffix {
    param([string]$Suffix)
    $sx = ([string]$Suffix).ToLowerInvariant()
    $script:WlAsrRules | Where-Object { $_.suffix -eq $sx } | Select-Object -First 1
}

function Get-WlAsrRuleName {
    param([string]$Suffix)
    $r = Get-WlAsrRuleBySuffix -Suffix $Suffix
    if ($r) { $r.name } else { $Suffix }
}

function ConvertTo-WlAsrMode {
    # Normalises modes from Intune ("..._block"), TVM ("Block", "Off", "NotConfigured") and the registry (0/1/2/6).
    param([AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { return $null }
    $v = $Value.Trim().ToLowerInvariant()
    if (-not $v) { return $null }
    if ($v -match '(^|_)(block|enabled|1)$') { return 'Block' }
    if ($v -match '(^|_)(audit|auditmode|2)$') { return 'Audit' }
    if ($v -match '(^|_)(warn|6)$') { return 'Warn' }
    if ($v -match '(^|_)(off|disabled|notconfigured|not configured|0)$') { return 'Off' }
    $null
}

function Get-WlAsrDeviceStates {
    <#
    .SYNOPSIS
    Effective ASR mode per device and rule. Source 1: DeviceTvmInfoGathering (AsrConfigurationStates),
    source 2 (fills gaps): DeviceTvmSecureConfigurationAssessment, subcategory "Attack Surface Reduction".
    #>
    param([hashtable]$Devices)
    $byKey = @{}; foreach ($r in $script:WlAsrRules) { $byKey[$r.key.ToLowerInvariant()] = $r }
    $byScid = @{}; foreach ($r in $script:WlAsrRules) { $byScid[$r.scid] = $r }

    $qInfo = @"
DeviceTvmInfoGathering
| summarize arg_max(Timestamp, AdditionalFields) by DeviceId
| extend Asr = tostring(parse_json(tostring(AdditionalFields)).AsrConfigurationStates)
| where isnotempty(Asr)
| project DeviceId, Asr
"@
    foreach ($row in @(Invoke-WlHuntingSafe -Query $qInfo -Context 'Advanced Hunting ASR state (DeviceTvmInfoGathering)')) {
        if ($null -eq $row) { continue }
        $id = [string]$row.DeviceId
        if (-not $Devices.ContainsKey($id)) { continue }
        $j = $null; try { $j = [string]$row.Asr | ConvertFrom-Json -AsHashtable } catch { continue }
        if ($null -eq $Devices[$id].asr) { $Devices[$id].asr = [ordered]@{} }
        foreach ($k in @($j.Keys)) {
            $rule = $byKey[([string]$k).ToLowerInvariant()]
            if (-not $rule) { continue }
            $raw = [string]$j[$k]
            $Devices[$id].asr[$rule.id] = if ($raw) { ConvertTo-WlAsrMode $raw } else { 'n/a' }
        }
    }

    $qScid = @"
DeviceTvmSecureConfigurationAssessment
| where ConfigurationSubcategory == "Attack Surface Reduction"
| summarize arg_max(Timestamp, IsApplicable, Context) by DeviceId, ConfigurationId
| extend Mode = iff(tobool(IsApplicable), tostring(parse_json(tostring(Context))[0][0]), "n/a")
| summarize Modes = make_bag(bag_pack(ConfigurationId, Mode)) by DeviceId
"@
    foreach ($row in @(Invoke-WlHuntingSafe -Query $qScid -Context 'Advanced Hunting ASR state (TVM)')) {
        if ($null -eq $row) { continue }
        $id = [string]$row.DeviceId
        if (-not $Devices.ContainsKey($id)) { continue }
        $modes = Get-WlProp $row 'Modes'
        if ($modes -is [string]) { try { $modes = $modes | ConvertFrom-Json -AsHashtable } catch { continue } }
        if ($null -eq $Devices[$id].asr) { $Devices[$id].asr = [ordered]@{} }
        $keys = if ($modes -is [System.Collections.IDictionary]) { @($modes.Keys) } else { @($modes.PSObject.Properties.Name) }
        foreach ($k in $keys) {
            $rule = $byScid[[string]$k]
            if (-not $rule -or $Devices[$id].asr.Contains($rule.id)) { continue }   # TVM only fills gaps
            $raw = [string](Get-WlProp $modes $k)
            $Devices[$id].asr[$rule.id] = if ($raw -eq 'n/a') { 'n/a' } else { ConvertTo-WlAsrMode $raw }
        }
    }
}

function Get-WlAsrOverview {
    <#
    .SYNOPSIS
    Rates every ASR rule on three levels – target (baseline), configured (Intune) and effective (devices) – and
    aggregates the effective state per Defender device group.
    Status codes: OK, Conflict, NotConfigured, BelowTarget, DeviceDeviation, NoDeviceData, BlockRecommended
    #>
    param($Baseline, [object[]]$SettingValues, [hashtable]$Devices)
    $soll = @{}
    foreach ($b in @(Get-WlProp $Baseline 'asrRules')) { if ($b -and $b.id) { $soll[[string]$b.id] = $b } }
    $winDevices = @($Devices.Values | Where-Object { ([string]$_.os) -match '^Windows' })
    $grp = { param($d) if ($d.deviceGroup) { $d.deviceGroup } else { '(no group)' } }

    $rules = foreach ($r in $script:WlAsrRules) {
        $target = $soll[$r.id]
        $minimum = if ($target -and $target.minimum) { [string]$target.minimum } else { 'Audit' }
        $recommended = if ($target -and $target.recommended) { [string]$target.recommended } else { 'Block' }
        $severity = if ($target -and $target.severity) { [string]$target.severity } else { 'Medium' }

        $configured = @(foreach ($sv in @($SettingValues | Where-Object { $_ -and $_.kind -eq 'choice' -and $_.definitionId -match "attacksurfacereductionrules_$([regex]::Escape($r.suffix))$" })) {
                [pscustomobject]@{ policyId = $sv.policyId; policyName = $sv.policyName; mode = (ConvertTo-WlAsrMode $sv.value); assignments = $sv.assignments; assigned = (Test-WlAssigned $sv.assignments) }
            })
        $assigned = @($configured | Where-Object { $_.assigned })
        $assignedModes = @($assigned | ForEach-Object { $_.mode } | Where-Object { $_ } | Select-Object -Unique)
        $conflict = $assignedModes.Count -gt 1

        $eff = [ordered]@{ Block = 0; Warn = 0; Audit = 0; Off = 0; NotApplicable = 0; Unknown = 0 }
        $below = [System.Collections.Generic.List[object]]::new()
        foreach ($d in $winDevices) {
            $m = if ($d.asr) { $d.asr[$r.id] } else { $null }
            if ($m -eq 'n/a') { $eff.NotApplicable++; continue }
            if (-not $m) { $eff.Unknown++; continue }
            $eff[$m]++
            if ($script:WlAsrModeRank[$m] -lt $script:WlAsrModeRank[$minimum]) { $below.Add($d) }
        }
        $measured = $eff.Block + $eff.Warn + $eff.Audit + $eff.Off

        $status = if ($conflict) { 'Conflict' }
        elseif ($assigned.Count -eq 0 -and ($below.Count -gt 0 -or $measured -eq 0)) { 'NotConfigured' }
        elseif ($assignedModes.Count -and $script:WlAsrModeRank[$assignedModes[0]] -lt $script:WlAsrModeRank[$minimum]) { 'BelowTarget' }
        elseif ($below.Count -gt 0) { 'DeviceDeviation' }
        elseif ($measured -eq 0) { 'NoDeviceData' }
        elseif ($eff.Block -lt $measured -and $recommended -eq 'Block') { 'BlockRecommended' }
        else { 'OK' }

        $belowGroups = @($below | Group-Object { & $grp $_ } | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ group = $_.Name; devices = $_.Count } })
        [pscustomobject]@{
            key          = Get-WlHash "asr|$($r.id)"
            fp           = Get-WlHash "$status|$(@($configured | ForEach-Object { "$($_.policyId)=$($_.mode)" }) -join ';')|$($below.Count)"
            label        = New-WlText "ASR: $($r.name)" "ASR: $($r.name)"
            state        = $status
            id           = $r.id
            guid         = $r.guid
            name         = $r.name
            minimum      = $minimum
            recommended  = $recommended
            severity     = $severity
            note         = ConvertTo-WlText (Get-WlProp $target 'note')
            status       = $status
            conflict     = $conflict
            configured   = $configured
            effective    = $eff
            measured     = $measured
            belowMinimum = $below.Count
            belowByGroup = $belowGroups
        }
    }
    $rules = @($rules)

    # Aggregation per Defender device group (MachineGroup)
    $groups = foreach ($g in @($winDevices | Group-Object { & $grp $_ } | Sort-Object Name)) {
        $perRule = [ordered]@{}
        $devicesBelow = @{}
        foreach ($r in $rules) {
            $c = [ordered]@{ Block = 0; Warn = 0; Audit = 0; Off = 0; NotApplicable = 0; Unknown = 0; below = 0 }
            foreach ($d in $g.Group) {
                $m = if ($d.asr) { $d.asr[$r.id] } else { $null }
                if ($m -eq 'n/a') { $c.NotApplicable++; continue }
                if (-not $m) { $c.Unknown++; continue }
                $c[$m]++
                if ($script:WlAsrModeRank[$m] -lt $script:WlAsrModeRank[$r.minimum]) { $c.below++; $devicesBelow[$d.deviceId] = $true }
            }
            $perRule[$r.id] = $c
        }
        [pscustomobject]@{
            key          = Get-WlHash "asrgroup|$($g.Name)"
            fp           = Get-WlHash (($perRule.Keys | ForEach-Object { "$_=$($perRule[$_].Block)/$($perRule[$_].Audit)/$($perRule[$_].Warn)/$($perRule[$_].Off)" }) -join ';')
            label        = New-WlText "ASR device group $($g.Name)" "ASR-Gerätegruppe $($g.Name)"
            state        = "$($devicesBelow.Count)/$($g.Count) below target"
            group        = $g.Name
            devices      = $g.Count
            devicesBelow = $devicesBelow.Count
            rules        = $perRule
        }
    }

    # Per device: number of rules below target
    foreach ($d in $winDevices) {
        $n = 0; $blk = 0
        foreach ($r in $rules) {
            $m = if ($d.asr) { $d.asr[$r.id] } else { $null }
            if ($m -and $m -ne 'n/a') {
                if ($m -eq 'Block') { $blk++ }
                if ($script:WlAsrModeRank[$m] -lt $script:WlAsrModeRank[$r.minimum]) { $n++ }
            }
        }
        $d.asrBelowMinimum = $n
        $d.asrBlocked = $blk
    }

    [pscustomobject]@{
        rules   = $rules
        groups  = @($groups)
        catalog = @($script:WlAsrRules | ForEach-Object { [pscustomobject]@{ id = $_.id; guid = $_.guid; name = $_.name } })
    }
}
#endregion

#region Linux/macOS: local configuration changes (mdatp config, mdatp_managed.json)
function ConvertFrom-WlMdatpConfigCommand {
    <#
    .SYNOPSIS
    Detects "mdatp config <setting> --value <value>" and rates whether it weakens protection.
    #>
    param([string]$CommandLine)
    if ([string]$CommandLine -notmatch '(?i)\bconfig\s+([a-z0-9\-]+)\s+.*--value\s+(?:"([^"]+)"|''([^'']+)''|(\S+))') { return $null }
    $setting = $Matches[1].ToLowerInvariant()
    $value = (@($Matches[2], $Matches[3], $Matches[4]) | Where-Object { $_ } | Select-Object -First 1).ToLowerInvariant()
    $weakens = switch -Regex ($setting) {
        '^real-time-protection$|^behavior-monitoring$|^cloud$|^cloud-diagnostic$|^cloud-automatic-sample-submission$' { $value -match '^(disabled|false|off)$'; break }
        '^passive-mode$' { $value -match '^(enabled|true|on)$'; break }
        '^enforcement-level$|^antivirus-engine-enforcement-level$' { $value -match '^(passive|on_demand)$'; break }
        '^network-protection$' { $value -match '^(disabled|audit)$'; break }
        '^tamper-protection$' { $value -match '^(disabled|audit)$'; break }
        default { $false }
    }
    [pscustomobject]@{ Setting = $setting; Value = $value; Weakens = [bool]$weakens }
}

function Get-WlLinuxConfigEvents {
    $qCfg = @"
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "mdatp" and ProcessCommandLine has "config" and ProcessCommandLine has "--value"
| project Timestamp, DeviceId, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp asc
| take 10000
"@
    $qFile = @"
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath startswith "/etc/opt/microsoft/mdatp/managed"
| where ActionType in ("FileCreated", "FileModified", "FileDeleted", "FileRenamed")
| where InitiatingProcessFileName !in~ ("wdavdaemon", "mdatp", "mdatp_audisp_plugin", "telemetryd_v2")
| project Timestamp, DeviceId, DeviceName, ActionType, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
| take 5000
"@
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @(Invoke-WlHuntingSafe -Query $qCfg -Context 'Advanced Hunting mdatp config (Linux/macOS)')) {
        if ($null -eq $e) { continue }
        $p = ConvertFrom-WlMdatpConfigCommand -CommandLine ([string]$e.ProcessCommandLine)
        if (-not $p) { continue }
        $out.Add([pscustomobject]@{ kind = 'config'; at = [string]$e.Timestamp; deviceId = [string]$e.DeviceId; deviceName = [string]$e.DeviceName
                setting = $p.Setting; value = $p.Value; weakens = $p.Weakens; commandLine = [string]$e.ProcessCommandLine; account = [string]$e.AccountName })
    }
    foreach ($e in @(Invoke-WlHuntingSafe -Query $qFile -Context 'Advanced Hunting mdatp_managed.json (Linux)')) {
        if ($null -eq $e) { continue }
        $out.Add([pscustomobject]@{ kind = 'managed-file'; at = [string]$e.Timestamp; deviceId = [string]$e.DeviceId; deviceName = [string]$e.DeviceName
                setting = [string]$e.FolderPath; value = [string]$e.ActionType; weakens = ([string]$e.ActionType -eq 'FileDeleted')
                commandLine = [string]$e.InitiatingProcessCommandLine; account = [string]$e.InitiatingProcessAccountName; process = [string]$e.InitiatingProcessFileName })
    }
    $out.ToArray()
}
#endregion

#region Defender coverage gaps and exclusion usage
function Get-WlCoverage {
    <#
    .SYNOPSIS
    Devices that Defender for Endpoint does not (fully) protect:
      - onboarded devices whose sensor is inactive, misconfigured or has impaired communications (Advanced Hunting)
      - devices found by Defender device discovery that are not onboarded (Advanced Hunting)
      - feature "coverage": Intune-managed Windows/macOS/Linux devices that never showed up in Defender (Graph)
    Also records the Intune device ID on matching Defender devices (deep links in the portal).
    #>
    param([hashtable]$Devices)
    $out = [System.Collections.Generic.List[object]]::new()
    $add = {
        param($Id, $Name, $Os, $Source, $Status, $LastSeen, $User, $Aad, $IntuneId)
        $out.Add([pscustomobject]@{
                key = Get-WlHash "cov|$Source|$(if ($Id) { $Id } else { $Name })"; fp = Get-WlHash $Status
                label = New-WlText "Coverage: $Name" "Abdeckung: $Name"; state = $Status
                deviceId = $Id; deviceName = $Name; os = $Os; source = $Source; status = $Status; lastSeen = $LastSeen; user = $User; aadDeviceId = $Aad; intuneDeviceId = $IntuneId
            })
    }
    $sensorStatus = @{ 'Inactive' = 'SensorInactive'; 'Misconfigured' = 'Misconfigured'; 'ImpairedCommunication' = 'ImpairedCommunications'; 'NoSensorData' = 'NoSensorData' }
    foreach ($d in $Devices.Values) {
        if ($d.sensorHealth -and $d.sensorHealth -ne 'Active') {
            $st = if ($sensorStatus.ContainsKey([string]$d.sensorHealth)) { $sensorStatus[[string]$d.sensorHealth] } else { 'SensorIssue' }
            & $add $d.deviceId $d.deviceName $d.os 'Defender' $st $d.lastSeen $d.lastUser $d.aadDeviceId $null
        }
    }

    # All devices Defender knows (30 days), incl. device discovery – also the reference list for the Intune comparison
    $known = @{}; $knownNames = @{}
    $days = [int](Get-WlSetting -Name 'WL_DEVICE_LOOKBACK_DAYS' -Default '7')
    $q = @"
// WardlineCoverage
DeviceInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp, DeviceName, OSPlatform, OnboardingStatus, AadDeviceId, DeviceType) by DeviceId
| project DeviceId, DeviceName, OSPlatform, OnboardingStatus, AadDeviceId, DeviceType, LastSeen = Timestamp
"@
    $all = Invoke-WlHuntingSafe -Query $q -Context 'Advanced Hunting device coverage'
    foreach ($r in @($all)) {
        if ($null -eq $r) { continue }
        $name = [string]$r.DeviceName
        if ($r.AadDeviceId) { $known[([string]$r.AadDeviceId).ToLowerInvariant()] = $r }
        if ($name) { $knownNames[($name -split '\.')[0].ToLowerInvariant()] = $r }
        $ob = [string]$r.OnboardingStatus
        $id = [string]$r.DeviceId
        if ($ob -eq 'Onboarded' -or -not $ob) {
            $last = $null; try { $last = ConvertTo-WlUtc $r.LastSeen } catch { }
            if (-not $Devices.ContainsKey($id) -and $last -and $last -lt [DateTime]::UtcNow.AddDays(-$days)) {
                & $add $id $name ([string]$r.OSPlatform) 'Defender' 'SensorInactive' ([string]$r.LastSeen) $null ([string]$r.AadDeviceId) $null
            }
        }
        elseif ($ob -eq 'Can be onboarded') { & $add $id $name ([string]$r.OSPlatform) 'DeviceDiscovery' 'CanBeOnboarded' ([string]$r.LastSeen) $null ([string]$r.AadDeviceId) $null }
    }
    foreach ($d in $Devices.Values) {
        if ($d.aadDeviceId) { $known[([string]$d.aadDeviceId).ToLowerInvariant()] = $d }
        if ($d.deviceName) { $knownNames[(([string]$d.deviceName) -split '\.')[0].ToLowerInvariant()] = $d }
    }

    if (Test-WlFeature -Name 'coverage') {
        $md = Invoke-WlGraphSafe -All -Context 'Intune managed devices (DeviceManagementManagedDevices.Read.All)' `
            -Path 'deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,azureADDeviceId,lastSyncDateTime,userPrincipalName'
        $byAad = @{}; $byName = @{}
        foreach ($d in $Devices.Values) {
            if ($d.aadDeviceId) { $byAad[([string]$d.aadDeviceId).ToLowerInvariant()] = $d }
            if ($d.deviceName) { $byName[(([string]$d.deviceName) -split '\.')[0].ToLowerInvariant()] = $d }
        }
        foreach ($m in @($md)) {
            if ($null -eq $m) { continue }
            $os = [string]$m.operatingSystem
            if ($os -notmatch '^(Windows|macOS|Linux)') { continue }
            $sync = $null; try { $sync = ConvertTo-WlUtc $m.lastSyncDateTime } catch { }
            if ($sync -and $sync -lt [DateTime]::UtcNow.AddDays(-30)) { continue }
            $aad = ([string]$m.azureADDeviceId).ToLowerInvariant()
            $short = (([string]$m.deviceName) -split '\.')[0].ToLowerInvariant()
            $dev = if ($aad -and $byAad.ContainsKey($aad)) { $byAad[$aad] } elseif ($short -and $byName.ContainsKey($short)) { $byName[$short] } else { $null }
            if ($dev) { $dev.intuneDeviceId = [string]$m.id; continue }
            if (($aad -and $known.ContainsKey($aad)) -or ($short -and $knownNames.ContainsKey($short))) { continue }
            & $add $null ([string]$m.deviceName) $os 'Intune' 'NotOnboarded' ([string]$m.lastSyncDateTime) ([string]$m.userPrincipalName) ([string]$m.azureADDeviceId) ([string]$m.id)
        }
    }
    @($out.ToArray())
}

function Get-WlCoverageFindings {
    param([object[]]$Coverage)
    $T = { param($en, $de) New-WlText $en $de }
    $f = [System.Collections.Generic.List[object]]::new()
    $names = { param($rows) ((@($rows) | Select-Object -First 10 | ForEach-Object { $_.deviceName }) -join ', ') + $(if (@($rows).Count -gt 10) { ', …' } else { '' }) }
    $notOnb = @($Coverage | Where-Object { $_.status -eq 'NotOnboarded' })
    if ($notOnb.Count) {
        $f.Add((New-WlFinding -Severity 'High' -Category 'Coverage' -Title (& $T "$($notOnb.Count) Intune-managed device(s) not onboarded to Defender for Endpoint" "$($notOnb.Count) Intune-verwaltete(s) Gerät(e) nicht in Defender for Endpoint onboarded") `
                    -Detail (& $T "These devices synced with Intune in the last 30 days but never reported to Defender: $(& $names $notOnb). No EDR, no Advanced Hunting, no exclusion audit." "Diese Geräte haben sich in den letzten 30 Tagen bei Intune gemeldet, aber nie bei Defender: $(& $names $notOnb). Kein EDR, kein Advanced Hunting, keine Exclusion-Prüfung.") `
                    -Recommendation (& $T 'Onboard them via the Intune EDR policy (endpoint security › Endpoint detection and response) and check the sensor service (Sense).' 'Über die Intune-EDR-Richtlinie onboarden (Endpunktsicherheit › Endpunkterkennung und -reaktion) und den Sensordienst (Sense) prüfen.') -Subject 'cov-intune' -StableKey))
    }
    $sensor = @($Coverage | Where-Object { $_.status -in 'SensorInactive', 'Misconfigured', 'ImpairedCommunications', 'NoSensorData', 'SensorIssue' })
    if ($sensor.Count) {
        $f.Add((New-WlFinding -Severity 'High' -Category 'Coverage' -Title (& $T "$($sensor.Count) onboarded device(s) with sensor problems" "$($sensor.Count) onboardete(s) Gerät(e) mit Sensorproblemen") `
                    -Detail (& $T "Inactive, misconfigured or impaired sensors: $(& $names $sensor). Their protection state and local exclusions are not current." "Inaktive, falsch konfigurierte oder eingeschränkte Sensoren: $(& $names $sensor). Schutzstatus und lokale Exclusions sind nicht aktuell.") `
                    -Recommendation (& $T 'Check the devices (powered off for long? offboarded? proxy/firewall to the Defender cloud?) and remove retired devices.' 'Geräte prüfen (lange ausgeschaltet? offboarded? Proxy/Firewall zur Defender-Cloud?) und ausgemusterte Geräte entfernen.') -Subject 'cov-sensor' -StableKey))
    }
    $disc = @($Coverage | Where-Object { $_.status -eq 'CanBeOnboarded' })
    if ($disc.Count) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Coverage' -Title (& $T "$($disc.Count) discovered device(s) can be onboarded" "$($disc.Count) erkannte(s) Gerät(e) können onboarded werden") `
                    -Detail (& $T "Defender device discovery found devices that are not onboarded: $(& $names $disc)." "Die Defender-Geräteerkennung hat nicht onboardete Geräte gefunden: $(& $names $disc).") `
                    -Recommendation (& $T 'Onboard them or document why they are out of scope.' 'Onboarden oder dokumentieren, warum sie außerhalb des Scopes sind.') -Subject 'cov-discovery' -StableKey))
    }
    @($f.ToArray())
}

function Get-WlUsageFindings {
    param([object[]]$Exclusions)
    $unused = @($Exclusions | Where-Object { $_ -and $_.usage -eq 'Unused' })
    if (-not $unused.Count) { return @() }
    $list = ((@($unused) | Select-Object -First 8 | ForEach-Object { $_.value }) -join ', ') + $(if ($unused.Count -gt 8) { ', …' } else { '' })
    @(New-WlFinding -Severity 'Low' -Category 'Hygiene' -Title (New-WlText "$($unused.Count) exclusion(s) without any activity in 30 days" "$($unused.Count) Exclusion(s) ohne jede Aktivität in 30 Tagen") `
            -Detail (New-WlText "No process or file activity was seen for these excluded values on any device in the last 30 days: $list. They are probably no longer needed." "Für diese ausgeschlossenen Werte gab es in den letzten 30 Tagen auf keinem Gerät Prozess- oder Dateiaktivität: $list. Sie werden wahrscheinlich nicht mehr gebraucht.") `
            -Recommendation (New-WlText 'Review them with the application owners and remove unused exclusions (Exclusions › filter "No activity").' 'Mit den Anwendungsverantwortlichen prüfen und ungenutzte Exclusions entfernen (Exclusions › Filter „Keine Aktivität“).') -Subject 'unused' -StableKey)
}

function Get-WlUsageKey {
    <#
    .SYNOPSIS
    Normalises an exclusion for the usage check. Returns $null for values that cannot be checked reliably
    (wildcards, environment variables, IPs, ...).
    #>
    param([string]$Type, [string]$Value)
    if (-not $Value) { return $null }
    $v = ($Value -replace '\\:\{.*$', '').Trim().ToLowerInvariant()
    if ($v -match '[\*\?%]|\$\{|\$env:|^\{|^<') { return $null }
    switch ($Type) {
        'Process' {
            if ($v -match '[\\/]') { return "f|$v" }
            return "n|$v"
        }
        { $_ -in 'Path', 'ASR', 'CFA', 'TempPath' } {
            $p = $v.TrimEnd('\', '/')
            if ($p.Length -lt 4) { return $null }
            return "p|$p"
        }
        'Extension' { $e = $v.TrimStart('*'); if (-not $e.StartsWith('.')) { $e = ".$e" }; return "e|$e" }
        default { return $null }
    }
}

function Add-WlExclusionUsage {
    <#
    .SYNOPSIS
    Checks in Advanced Hunting whether excluded processes, paths and file types showed any activity in the last 30 days
    (process or file events on any device). Exclusions without activity are candidates for removal.
    Adds usage = Used | Unused | NotChecked, usageHits and usageLast to each exclusion.
    #>
    param([object[]]$Exclusions, [int]$Max = 150)
    $keys = [ordered]@{}
    foreach ($x in @($Exclusions)) {
        if (-not $x) { continue }
        $k = Get-WlUsageKey -Type ([string]$x.type) -Value ([string]$x.value)
        $x | Add-Member -NotePropertyName usageKey -NotePropertyValue $k -Force
        $x | Add-Member -NotePropertyName usage -NotePropertyValue 'NotChecked' -Force
        $x | Add-Member -NotePropertyName usageHits -NotePropertyValue $null -Force
        $x | Add-Member -NotePropertyName usageLast -NotePropertyValue $null -Force
        if ($k -and $keys.Count -lt $Max) { $keys[$k] = $true }
    }
    if (-not $keys.Count -or -not (Test-WlFeature -Name 'hunting')) { return }
    $sel = { param($prefix) @($keys.Keys | Where-Object { $_.StartsWith("$prefix|") } | ForEach-Object { $_.Substring(2) }) }
    $names = & $sel 'n'; $files = & $sel 'f'; $paths = & $sel 'p'; $exts = & $sel 'e'
    $dyn = { param($a) if (@($a).Count) { 'dynamic(' + (ConvertTo-Json -InputObject @($a) -Compress) + ')' } else { 'dynamic([])' } }
    $parts = @()
    if ($names.Count) { $parts += "(DeviceProcessEvents | where Timestamp > ago(30d) | where FileName in~ (names) | summarize Hits = count(), Last = max(Timestamp) by Key = strcat('n|', tolower(FileName)))" }
    if ($files.Count) { $parts += "(DeviceProcessEvents | where Timestamp > ago(30d) | extend fp = tolower(FolderPath) | where fp in (files) | summarize Hits = count(), Last = max(Timestamp) by Key = strcat('f|', fp))" }
    if ($paths.Count) {
        $or = (@($paths | ForEach-Object { 'p startswith ' + (ConvertTo-Json -InputObject $_ -Compress) }) -join ' or ')
        $parts += "(union DeviceProcessEvents, DeviceFileEvents | where Timestamp > ago(30d) | extend p = tolower(FolderPath) | where $or | mv-apply pref = paths to typeof(string) on (where p startswith pref) | summarize Hits = count(), Last = max(Timestamp) by Key = strcat('p|', pref))"
    }
    if ($exts.Count) { $parts += "(DeviceFileEvents | where Timestamp > ago(30d) | extend e = tolower(extract(@'(\.[^.\\/]+)$', 1, FileName)) | where e in (exts) | summarize Hits = count(), Last = max(Timestamp) by Key = strcat('e|', e))" }
    $q = "// WardlineUsage`nlet names = $(& $dyn $names);`nlet files = $(& $dyn $files);`nlet paths = $(& $dyn $paths);`nlet exts = $(& $dyn $exts);`nunion $($parts -join ",`n")"
    $rows = Invoke-WlHuntingSafe -Query $q -Context 'Advanced Hunting exclusion usage (30 days)' -ShardColumn 'Key'
    if ($null -eq $rows) { return }
    $hits = @{}
    foreach ($r in @($rows)) { if ($r -and $r.Key) { $hits[[string]$r.Key] = $r } }
    foreach ($x in @($Exclusions)) {
        if (-not $x -or -not $x.usageKey -or -not $keys.Contains($x.usageKey)) { continue }
        if ($hits.ContainsKey($x.usageKey)) { $x.usage = 'Used'; $x.usageHits = [long]$hits[$x.usageKey].Hits; $x.usageLast = [string]$hits[$x.usageKey].Last }
        else { $x.usage = 'Unused'; $x.usageHits = 0 }
    }
}
#endregion

#region Baseline & findings
function Test-WlBaseline {
    <#
    .SYNOPSIS
    Rates every baseline check on three levels: target (baseline), configured (Intune policies) and effective
    (device state from Advanced Hunting). Checks are per platform (Windows/macOS/Linux).
    Status codes: OK, Deviation, NotConfigured, NotAssigned, Inconsistent, DeviceDeviation, NoData, NotRelevant
    #>
    param($Baseline, [object[]]$SettingValues, [hashtable]$Devices)
    $results = foreach ($chk in @($Baseline.checks)) {
        $defId = [string](Get-WlProp $chk 'definitionId')
        $defPattern = [string](Get-WlProp $chk 'definitionIdPattern')
        $platform = [string](Get-WlProp $chk 'platform')
        if (-not $platform) { $platform = 'Windows' }
        $expect = Get-WlProp $chk 'expect'
        $effName = [string](Get-WlProp $chk 'effective')
        $hasConfig = [bool]($defId -or $defPattern)

        $configured = @()
        if ($hasConfig) {
            $matchesDef = @($SettingValues | Where-Object {
                    $_ -and (($defId -and $_.definitionId -ieq $defId) -or ($defPattern -and $_.definitionId -match $defPattern)) -and
                    (-not $_.platform -or $_.platform -eq $platform)
                })
            # Group settings (e.g. macOS/Linux threatTypeSettings): only entries whose group matches the filter
            $gf = Get-WlProp $chk 'groupFilter'
            if ($gf) {
                $gfDef = [string](Get-WlProp $gf 'definitionId'); $gfPat = [string](Get-WlProp $gf 'definitionIdPattern'); $gfExp = Get-WlProp $gf 'expect'
                $okGroups = @($SettingValues | Where-Object { $_ -and $_.group -and (($gfDef -and $_.definitionId -ieq $gfDef) -or ($gfPat -and $_.definitionId -match $gfPat)) -and (Test-WlBaselineValue -Value $_.value -Expect $gfExp -Display $_.display) } | ForEach-Object { "$($_.policyId)|$($_.group)" })
                $matchesDef = @($matchesDef | Where-Object { $okGroups -contains "$($_.policyId)|$($_.group)" })
            }
            $configured = @(foreach ($sv in $matchesDef) {
                    [pscustomobject]@{ policyId = $sv.policyId; policyName = $sv.policyName; value = $(if ($sv.display) { "$($sv.value) ($($sv.display))" } else { $sv.value }); ok = (Test-WlBaselineValue -Value $sv.value -Expect $expect -Display $sv.display); assignments = $sv.assignments; assigned = (Test-WlAssigned $sv.assignments) }
                })
        }

        # Effective state: only devices of the matching platform
        $platformDevices = @($Devices.Values | Where-Object { $_.os -and ([string]$_.os).ToLowerInvariant().StartsWith($platform.ToLowerInvariant().Substring(0, 3)) })
        $eff = $null
        $checkName = if ($effName -and $script:WlScidMap.Contains($effName)) { $script:WlScidMap[$effName] } elseif ($effName -and $effName -ne 'avmode') { $effName } else { $null }
        if ($checkName) {
            $good = 0; $bad = 0; $na = 0
            foreach ($d in $platformDevices) { switch ($d.checks[$checkName]) { 'GOOD' { $good++ } 'BAD' { $bad++ } default { $na++ } } }
            $eff = [ordered]@{ check = $checkName; good = $good; bad = $bad; unknown = $na }
        }
        elseif ($effName -eq 'avmode') {
            $good = @($platformDevices | Where-Object { $_.avMode -eq '0' }).Count
            $bad = @($platformDevices | Where-Object { $_.avMode -and $_.avMode -ne '0' }).Count
            $eff = [ordered]@{ check = 'RunningMode'; good = $good; bad = $bad; unknown = ($platformDevices.Count - $good - $bad) }
        }

        $status = if (-not $hasConfig) {
            if ($eff -and $eff.bad -gt 0) { 'DeviceDeviation' } elseif ($eff -and $eff.good -gt 0) { 'OK' } else { 'NoData' }
        }
        elseif ($configured.Count -eq 0) { 'NotConfigured' }
        elseif (@($configured | Where-Object { $_.assigned }).Count -eq 0) { 'NotAssigned' }
        elseif (@($configured | Where-Object { $_.assigned -and -not $_.ok }).Count -eq 0) {
            if ($eff -and $eff.bad -gt 0) { 'DeviceDeviation' } else { 'OK' }
        }
        elseif (@($configured | Where-Object { $_.assigned -and $_.ok }).Count -eq 0) { 'Deviation' }
        else { 'Inconsistent' }

        # Platform without devices and without policies: not relevant
        if ($status -in 'NotConfigured', 'NotAssigned' -and $platformDevices.Count -eq 0 -and $platform -ne 'Windows') { $status = 'NotRelevant' }

        $title = ConvertTo-WlText (Get-WlProp $chk 'title')
        [pscustomobject]@{
            key          = Get-WlHash "base|$($chk.id)"
            fp           = Get-WlHash "$status|$(@($configured | ForEach-Object { "$($_.policyId)=$($_.value)" }) -join ';')|$(if ($eff) { $eff.bad })"
            label        = New-WlText "Baseline: $(Get-WlProp $title 'en')" "Baseline: $(Get-WlProp $title 'de')"
            state        = $status
            id           = $chk.id
            title        = $title
            platform     = $platform
            category     = ConvertTo-WlText (Get-WlProp $chk 'category')
            severity     = $chk.severity
            expected     = ConvertTo-WlText (Get-WlProp $chk 'expectText')
            rationale    = ConvertTo-WlText (Get-WlProp $chk 'rationale')
            remediation  = ConvertTo-WlText (Get-WlProp $chk 'remediation')
            definitionId = if ($defId) { $defId } else { $defPattern }
            status       = $status
            configured   = $configured
            effective    = $eff
        }
    }
    @($results)
}

function New-WlFinding {
    <#
    .SYNOPSIS
    Creates a finding. -Title/-Detail/-Recommendation are bilingual objects from New-WlText.
    Severity: Critical, High, Medium, Low. Category codes are translated in the portal.
    #>
    param([string]$Severity, [string]$Category, $Title, $Detail, $Recommendation, [string]$Subject, [string]$DeviceId, [string]$DeviceName, [switch]$StableKey)
    $titleEn = [string](Get-WlProp $Title 'en'); if (-not $titleEn) { $titleEn = [string]$Title }
    # -StableKey: for aggregated findings whose title contains a count – the key must not change with the count
    # (accepted risks and drift refer to the key); a changed count shows up as "Changed".
    [pscustomobject]@{
        key            = $(if ($StableKey) { Get-WlHash "find|$Category|$Subject|$DeviceId" } else { Get-WlHash "find|$Category|$titleEn|$Subject|$DeviceId" })
        fp             = Get-WlHash "$Severity|$(Get-WlProp $Detail 'en')"
        label          = $Title
        state          = $Severity
        severity       = $Severity
        category       = $Category
        title          = $Title
        detail         = $Detail
        recommendation = $Recommendation
        deviceId       = $DeviceId
        deviceName     = $DeviceName
        subject        = $(if ($Subject) { $Subject } else { $null })
    }
}

function Get-WlDependencyFindings {
    <#
    .SYNOPSIS
    Interdependency findings: settings that are configured but inert because a prerequisite is missing.
    Sources: Defender product documentation and "Microsoft Defender for Endpoint in Depth" (2nd ed.), in particular
    the dependency table (ch. 13) and the notes on cloud block level, behavior monitoring and passive mode.
      - Cloud block level below High: ASR rules do not raise alerts (EDR alerts need High Plus)
      - Cloud protection off: reputation-based ASR rules, EDR in block mode, BAFS and the tenant-wide Tamper
        Protection toggle (delivered through the cloud protection channel) do not work
      - Behavior monitoring off: indicators, network protection and web content filtering stop working
      - Passive mode: ASR, network protection, cloud protection and indicators are not enforced
      - Tamper Protection for exclusions needs DisableLocalAdminMerge
      - Network protection on Windows Server needs AllowNetworkProtectionOnWinServer
      - Indicators: RFC1918 IPs are ignored, URL paths only match in Edge, Allow+Block on the same value,
        file indicators without EnableFileHashComputation
    #>
    param([hashtable]$Devices, [object[]]$Baseline, [object[]]$SettingValues, $Asr, [object[]]$Indicators)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-WlText -En $en -De $de }
    $byId = @{}; foreach ($b in @($Baseline)) { if ($b) { $byId[$b.id] = $b } }
    $bad = { param($id) $byId[$id] -and $byId[$id].status -in 'Deviation', 'NotConfigured', 'NotAssigned', 'Inconsistent' }
    $svOn = { param($pattern) @($SettingValues | Where-Object { $_ -and $_.definitionId -match $pattern -and (Test-WlAssigned $_.assignments) -and [string]$_.value -match '_1$|true' }).Count -gt 0 }
    $rules = @(Get-WlProp $Asr 'rules')
    $activeRules = @($rules | Where-Object { $_ -and @($_.configured | Where-Object { $_.assigned -and $_.mode -in 'Block', 'Warn' }).Count -gt 0 })
    $reputationRules = @($rules | Where-Object { $_ -and $_.id -in 'prevalence', 'ransomware' -and @($_.configured | Where-Object { $_.assigned -and $_.mode -ne 'Off' }).Count -gt 0 })
    $winDevices = @($Devices.Values | Where-Object { ([string]$_.os) -match '^Windows' })
    $hasIndicators = [bool]($script:WlIndicatorFacts -and $script:WlIndicatorFacts.total -gt 0) -or @($Indicators).Count -gt 0

    # 1) Cloud block level below High while ASR rules block/warn -> no ASR alerts
    if ($activeRules.Count -gt 0 -and (& $bad 'cloud-block-level')) {
        $f.Add((New-WlFinding -Severity 'High' -Category 'Dependency' -Title (& $T 'ASR rules block without alerting: cloud block level below High' 'ASR-Regeln blockieren ohne Alarm: Cloud-Blockierstufe unter Hoch') `
                    -Detail (& $T "$($activeRules.Count) ASR rule(s) are assigned in block or warn mode, but the cloud block level is not at least High ($($byId['cloud-block-level'].status)). Below High, Defender raises no alerts for ASR events at all; EDR alerts tied to ASR need High Plus. Blocks still happen, but the SOC does not see them." `
                        "$($activeRules.Count) ASR-Regel(n) sind im Block- oder Warn-Modus zugewiesen, die Cloud-Blockierstufe ist aber nicht mindestens Hoch ($($byId['cloud-block-level'].status)). Unterhalb von Hoch erzeugt Defender für ASR-Ereignisse gar keine Alerts; EDR-Alerts zu ASR brauchen High Plus. Blockiert wird trotzdem – das SOC sieht es nur nicht.") `
                    -Recommendation (& $T 'Set CloudBlockLevel to High (High Plus for devices with ASR-based EDR alerting) in the same ring as the ASR rules.' 'CloudBlockLevel auf Hoch setzen (High Plus für Geräte mit ASR-basiertem EDR-Alerting), im selben Ring wie die ASR-Regeln.') -Subject 'dep|asr-blocklevel' -StableKey))
    }

    # 2) Cloud protection: tenant level (policy) and per device
    if ($reputationRules.Count -gt 0 -and (& $bad 'cloud-protection')) {
        $names = (@($reputationRules | ForEach-Object { $_.name }) -join '; ')
        $f.Add((New-WlFinding -Severity 'High' -Category 'Dependency' -Title (& $T 'Reputation-based ASR rules without cloud protection' 'Reputationsbasierte ASR-Regeln ohne Cloud-Schutz') `
                    -Detail (& $T "The rules '$names' need cloud-delivered protection to evaluate prevalence, age and trust. Cloud protection is not enforced by policy ($($byId['cloud-protection'].status)) – on devices where it is off these rules do nothing." `
                        "Die Regeln '$names' brauchen Cloud-delivered Protection, um Verbreitung, Alter und Vertrauen zu bewerten. Cloud-Schutz ist per Richtlinie nicht erzwungen ($($byId['cloud-protection'].status)) – auf Geräten ohne Cloud-Schutz bewirken diese Regeln nichts.") `
                    -Recommendation (& $T 'Enforce AllowCloudProtection = 1 in the baseline policy for every device that receives ASR rules.' 'AllowCloudProtection = 1 in der Basisrichtlinie für alle Geräte mit ASR-Regeln erzwingen.') -Subject 'dep|asr-cloud' -StableKey))
    }
    foreach ($d in $winDevices) {
        if ($d.checks['CloudProtection'] -ne 'BAD') { continue }
        $inert = [System.Collections.Generic.List[string]]::new(); $inertDe = [System.Collections.Generic.List[string]]::new()
        $devRep = @($reputationRules | Where-Object { $d.asr -and $d.asr[$_.id] -and $d.asr[$_.id] -notin 'Off', 'n/a' })
        if ($devRep.Count) { $inert.Add("$($devRep.Count) reputation-based ASR rule(s)"); $inertDe.Add("$($devRep.Count) reputationsbasierte ASR-Regel(n)") }
        if ($d.checks['EdrBlockMode'] -eq 'GOOD' -or $d.avMode -eq '4') { $inert.Add('EDR in block mode'); $inertDe.Add('EDR im Block-Modus') }
        if ($d.checks['TamperProtection'] -eq 'GOOD') { $inert.Add('Tamper Protection changes from the portal (delivered via the cloud protection channel)'); $inertDe.Add('Tamper-Protection-Änderungen aus dem Portal (werden über den Cloud-Schutz-Kanal ausgeliefert)') }
        if ($hasIndicators) { $inert.Add('file and certificate indicators'); $inertDe.Add('Datei- und Zertifikatsindikatoren') }
        $inert.Add('block at first sight, cloud block level and sample submission'); $inertDe.Add('Block at First Sight, Cloud-Blockierstufe und Probenübermittlung')
        $f.Add((New-WlFinding -Severity 'High' -Category 'Dependency' -Title (& $T 'Cloud protection off: dependent protections are inert' 'Cloud-Schutz aus: abhängige Schutzfunktionen wirkungslos') `
                    -Detail (& $T "On $($d.deviceName) cloud-delivered protection is off. Without it the following do not work: $($inert -join '; ')." "Auf $($d.deviceName) ist Cloud-delivered Protection aus. Ohne sie funktionieren nicht: $($inertDe -join '; ').") `
                    -Recommendation (& $T 'Enable cloud-delivered protection; check MAPS connectivity (MpCmdRun -ValidateMapsConnection) and the proxy.' 'Cloud-delivered Protection aktivieren; MAPS-Konnektivität (MpCmdRun -ValidateMapsConnection) und Proxy prüfen.') `
                    -Subject 'dep|cloud' -DeviceId $d.deviceId -DeviceName $d.deviceName))
    }

    # 3) Behavior monitoring off -> indicators, network protection, web content filtering stop working
    $npConfigured = [bool]($byId['network-protection'] -and $byId['network-protection'].status -ne 'NotConfigured')
    foreach ($d in $winDevices) {
        if ($d.checks['BehaviorMonitoring'] -ne 'BAD') { continue }
        $dep = @(); $depDe = @()
        if ($hasIndicators) { $dep += 'custom indicators (file, IP, URL)'; $depDe += 'benutzerdefinierte Indikatoren (Datei, IP, URL)' }
        if ($npConfigured -or $d.checks['NetworkProtection'] -eq 'GOOD') { $dep += 'network protection and web content filtering'; $depDe += 'Network Protection und Web Content Filtering' }
        if (-not $dep.Count) { continue }
        $f.Add((New-WlFinding -Severity 'High' -Category 'Dependency' -Title (& $T 'Behavior monitoring off: indicators and network protection are inert' 'Verhaltensüberwachung aus: Indikatoren und Network Protection wirkungslos') `
                    -Detail (& $T "Behavior monitoring is off on $($d.deviceName). It is the engine behind $($dep -join ' and ') – they silently stop working on this device." "Auf $($d.deviceName) ist die Verhaltensüberwachung aus. Sie ist die Grundlage für $($depDe -join ' und ') – diese fallen auf dem Gerät still aus.") `
                    -Recommendation (& $T 'Enforce AllowBehaviorMonitoring = 1 and check for local or GPO overrides (effective settings).' 'AllowBehaviorMonitoring = 1 erzwingen und lokale bzw. GPO-Überschreibungen prüfen (effektive Einstellungen).') `
                    -Subject 'dep|bm' -DeviceId $d.deviceId -DeviceName $d.deviceName))
    }

    # 4) Passive mode -> configured ASR / network protection / indicators are not enforced
    foreach ($d in $winDevices) {
        if ($d.avMode -notin '1', '2') { continue }
        $asrOn = @(if ($d.asr) { $d.asr.Keys | Where-Object { $d.asr[$_] -in 'Block', 'Warn', 'Audit' } })
        $parts = @(); $partsDe = @()
        if ($asrOn.Count) { $parts += "$($asrOn.Count) ASR rule(s)"; $partsDe += "$($asrOn.Count) ASR-Regel(n)" }
        if ($d.checks['NetworkProtection'] -eq 'GOOD' -or $npConfigured) { $parts += 'network protection'; $partsDe += 'Network Protection' }
        if ($d.checks['CloudProtection'] -eq 'GOOD') { $parts += 'cloud protection / block at first sight'; $partsDe += 'Cloud-Schutz / Block at First Sight' }
        if ($hasIndicators) { $parts += 'custom indicators'; $partsDe += 'benutzerdefinierte Indikatoren' }
        if (-not $parts.Count) { continue }
        $f.Add((New-WlFinding -Severity 'High' -Category 'Dependency' -Title (& $T 'Passive mode: configured protections are not enforced' 'Passiv-Modus: konfigurierte Schutzfunktionen greifen nicht') `
                    -Detail (& $T "$($d.deviceName) runs Defender Antivirus in passive mode. The following are configured or reported as on, but are not enforced in passive mode: $($parts -join ', '). Only EDR, SmartScreen in Edge and post-breach remediation remain." `
                        "$($d.deviceName) betreibt Defender Antivirus im Passiv-Modus. Folgendes ist konfiguriert bzw. wird als aktiv gemeldet, greift im Passiv-Modus aber nicht: $($partsDe -join ', '). Es bleiben EDR, SmartScreen in Edge und die Post-Breach-Bereinigung.") `
                    -Recommendation (& $T 'Switch to active mode once the third-party AV is removed (ForceDefenderPassiveMode = 0 on servers); until then enable EDR in block mode.' 'Nach Entfernen des Drittanbieter-AV auf Aktiv umstellen (ForceDefenderPassiveMode = 0 auf Servern); bis dahin EDR im Block-Modus aktivieren.') `
                    -Subject 'dep|passive' -DeviceId $d.deviceId -DeviceName $d.deviceName))
    }

    # 5) Tamper Protection for exclusions needs DisableLocalAdminMerge (and Intune/SSM as source)
    $tpOn = @($winDevices | Where-Object { $_.checks['TamperProtection'] -eq 'GOOD' }).Count
    if ($tpOn -gt 0 -and (& $bad 'disable-local-admin-merge')) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Dependency' -Title (& $T 'Exclusions are not tamper-protected (DisableLocalAdminMerge missing)' 'Exclusions sind nicht durch Tamper Protection geschützt (DisableLocalAdminMerge fehlt)') `
                    -Detail (& $T "Tamper Protection is on for $tpOn device(s), but it only protects exclusions when DisableLocalAdminMerge is enabled and the exclusions come from Intune or security settings management. DisableLocalAdminMerge is $($byId['disable-local-admin-merge'].status) – local admins and malware can still add exclusions." `
                        "Tamper Protection ist auf $tpOn Gerät(en) aktiv, schützt Exclusions aber nur, wenn DisableLocalAdminMerge aktiv ist und die Exclusions aus Intune bzw. Security Settings Management stammen. DisableLocalAdminMerge ist $($byId['disable-local-admin-merge'].status) – lokale Admins und Malware können weiterhin Exclusions hinzufügen.") `
                    -Recommendation (& $T 'Enforce DisableLocalAdminMerge = 1 via Intune/security settings management (not GPO); verify TPExclusions on a device afterwards.' 'DisableLocalAdminMerge = 1 per Intune/Security Settings Management erzwingen (nicht GPO); danach TPExclusions auf einem Gerät prüfen.') -Subject 'dep|tp-exclusions' -StableKey))
    }

    # 6) Network protection on Windows Server needs AllowNetworkProtectionOnWinServer
    $servers = @($winDevices | Where-Object { ([string]$_.os) -match 'Server' })
    if ($servers.Count -gt 0 -and $npConfigured -and -not (& $svOn 'allownetworkprotectiononwinserver')) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Dependency' -Title (& $T 'Network protection not enabled for Windows Server' 'Network Protection für Windows Server nicht aktiviert') `
                    -Detail (& $T "Network protection is configured, and $($servers.Count) Windows Server(s) are onboarded, but no assigned policy sets AllowNetworkProtectionOnWinServer. On servers network protection stays off without it (and AllowDatagramProcessingOnWinServer for UDP)." `
                        "Network Protection ist konfiguriert und $($servers.Count) Windows Server sind onboardet, aber keine zugewiesene Richtlinie setzt AllowNetworkProtectionOnWinServer. Ohne diesen Schalter bleibt Network Protection auf Servern aus (für UDP zusätzlich AllowDatagramProcessingOnWinServer).") `
                    -Recommendation (& $T 'Add AllowNetworkProtectionOnWinServer = 1 (and, after testing, AllowDatagramProcessingOnWinServer) to the server policy.' 'AllowNetworkProtectionOnWinServer = 1 (und nach Test AllowDatagramProcessingOnWinServer) in die Server-Richtlinie aufnehmen.') -Subject 'dep|np-server' -StableKey))
    }

    # 7) Indicators
    $facts = $script:WlIndicatorFacts
    foreach ($i in @($Indicators)) {
        if ($i.type -match '^Ip' -and $i.value -match '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)') {
            $f.Add((New-WlFinding -Severity 'Low' -Category 'Dependency' -Title (& $T "Indicator for a private IP has no effect: $($i.value)" "Indikator für private IP wirkt nicht: $($i.value)") `
                        -Detail (& $T 'Defender does not evaluate custom indicators for private (RFC 1918) or loopback addresses. This indicator is dead configuration.' 'Defender wertet benutzerdefinierte Indikatoren für private (RFC 1918) oder Loopback-Adressen nicht aus. Dieser Indikator ist tote Konfiguration.') `
                        -Recommendation (& $T 'Remove it; use network protection exclusions or firewall rules for internal addresses.' 'Entfernen; für interne Adressen Network-Protection-Ausnahmen oder Firewall-Regeln verwenden.') -Subject "dep|ind|$($i.key)"))
        }
        if ($i.type -match '^Url' -and $i.value -match '^[^/]+/.+') {
            $f.Add((New-WlFinding -Severity 'Low' -Category 'Dependency' -Title (& $T "URL indicator with a path only matches in Edge: $($i.value)" "URL-Indikator mit Pfad wirkt nur in Edge: $($i.value)") `
                        -Detail (& $T 'Outside Microsoft Edge, network protection only sees the host name (TLS SNI). The path part of this indicator is ignored in other browsers and processes – the allow applies to the whole host there.' 'Außerhalb von Microsoft Edge sieht Network Protection nur den Hostnamen (TLS-SNI). Der Pfadanteil dieses Indikators wird in anderen Browsern und Prozessen ignoriert – dort gilt die Freigabe für den ganzen Host.') `
                        -Recommendation (& $T 'Check whether a host-level allow is acceptable; otherwise restrict the use case to Edge.' 'Prüfen, ob eine Freigabe auf Host-Ebene vertretbar ist; sonst den Anwendungsfall auf Edge beschränken.') -Subject "dep|ind|$($i.key)"))
        }
    }
    foreach ($c in @(if ($facts) { $facts.conflicts })) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Dependency' -Title (& $T "Allow and block indicator for the same value: $($c.value)" "Allow- und Block-Indikator für denselben Wert: $($c.value)") `
                    -Detail (& $T 'Both an allow and a block/warn indicator exist for this value. Defender resolves this by whichever was created first, not by the stricter action – the result is unpredictable for administrators.' 'Für diesen Wert existieren ein Allow- und ein Block-/Warn-Indikator. Defender entscheidet nach dem zuerst angelegten Indikator, nicht nach der strengeren Aktion – das Ergebnis ist für Administratoren nicht vorhersehbar.') `
                    -Recommendation (& $T 'Keep exactly one indicator per value.' 'Pro Wert genau einen Indikator behalten.') -Subject "dep|ind-conflict|$($c.type)|$($c.value)"))
    }
    if ($facts -and @($facts.types | Where-Object { $_ -match '^File' }).Count -gt 0 -and $winDevices.Count -gt 0 -and -not (& $svOn 'enablefilehashcomputation')) {
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Dependency' -Title (& $T 'File indicators without EnableFileHashComputation' 'Dateiindikatoren ohne EnableFileHashComputation') `
                    -Detail (& $T 'File hash indicators exist, but no assigned policy enables file hash computation. Defender then only matches files for which it already has a hash – new or rarely seen files are not blocked or allowed immediately.' 'Es existieren Datei-Hash-Indikatoren, aber keine zugewiesene Richtlinie aktiviert die Hash-Berechnung. Defender vergleicht dann nur Dateien, für die bereits ein Hash vorliegt – neue oder selten gesehene Dateien werden nicht sofort blockiert bzw. freigegeben.') `
                    -Recommendation (& $T 'Set EnableFileHashComputation = 1 (Defender CSP) for devices that rely on file indicators; expect a small performance cost.' 'EnableFileHashComputation = 1 (Defender CSP) für Geräte setzen, die auf Dateiindikatoren angewiesen sind; geringe Performancekosten einplanen.') -Subject 'dep|filehash' -StableKey))
    }
    @($f)
}

function Get-WlUpdateFindings {
    <#
    .SYNOPSIS
    Update hygiene: platform/engine age relative to the fleet, signature age, and update-ring design
    (platform/engine/security-intelligence channels, gradual release).
    Platform versions are 4.18.YYMMn.x (monthly); Microsoft supports the current and the two previous
    releases (N-2). Engine versions are 1.1.YYMM0.x. Signatures are published several times a day.
    #>
    param([hashtable]$Devices, [object[]]$SettingValues)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-WlText -En $en -De $de }
    $now = [DateTime]::UtcNow
    $month = { param($v) if ([string]$v -match '^\d+\.\d+\.(\d{2})(\d{2})\d*\.') { [int]$Matches[1] * 12 + [int]$Matches[2] } else { $null } }
    $active = @($Devices.Values | Where-Object {
            $ls = $null; try { if ($_.lastSeen) { $ls = ConvertTo-WlUtc $_.lastSeen } } catch {}
            -not $ls -or ($now - $ls).TotalDays -le 14 })
    $win = @($active | Where-Object { ([string]$_.os) -match '^Windows' })

    # 1) Platform age vs. fleet (N-2) and version sprawl
    $withPlat = @($win | Where-Object { & $month $_.avPlatformVersion })
    if ($withPlat.Count -ge 2) {
        $ref = ($withPlat | ForEach-Object { & $month $_.avPlatformVersion } | Measure-Object -Maximum).Maximum
        foreach ($d in $withPlat) {
            $lag = $ref - (& $month $d.avPlatformVersion)
            if ($lag -le 2) { continue }
            $sev = if ($lag -ge 6) { 'High' } else { 'Medium' }
            $f.Add((New-WlFinding -Severity $sev -Category 'Updates' -Title (& $T 'Defender platform outside the supported window (N-2)' 'Defender-Plattform außerhalb des Support-Fensters (N-2)') `
                        -Detail (& $T "$($d.deviceName) runs platform $($d.avPlatformVersion), $lag monthly releases behind the newest version in this tenant. Microsoft supports only the current and the two previous platform releases; older platforms miss protection features, and ASR/EDR capabilities tied to newer platforms are silently unavailable." `
                            "$($d.deviceName) läuft mit Plattform $($d.avPlatformVersion), $lag Monatsreleases hinter der neuesten Version in diesem Tenant. Microsoft unterstützt nur die aktuelle und die zwei vorherigen Plattform-Releases; ältere Plattformen fehlen Schutzfunktionen, und an neuere Plattformen gebundene ASR-/EDR-Fähigkeiten sind still nicht verfügbar.") `
                        -Recommendation (& $T 'Check the update path for this device: Windows Update / WSUS category "Microsoft Defender Antivirus" approved, MoCAMP/KB4052623 allowed, no blocking proxy. Then verify with Get-MpComputerStatus.' 'Update-Pfad des Geräts prüfen: Windows Update / WSUS-Kategorie „Microsoft Defender Antivirus“ freigegeben, MoCAMP/KB4052623 erlaubt, kein blockierender Proxy. Danach mit Get-MpComputerStatus verifizieren.') `
                        -Subject 'upd|platform-lag' -DeviceId $d.deviceId -DeviceName $d.deviceName))
        }
        $distinct = @($withPlat | ForEach-Object { & $month $_.avPlatformVersion } | Sort-Object -Unique)
        if ($distinct.Count -ge 4 -and $withPlat.Count -ge 10) {
            $f.Add((New-WlFinding -Severity 'Low' -Category 'Updates' -Title (& $T 'Defender platform version sprawl' 'Defender-Plattformversionen zersplittert') `
                        -Detail (& $T "$($withPlat.Count) active Windows devices run $($distinct.Count) different monthly platform releases. A healthy fleet sits on at most two or three (current ring plus devices in transition); more usually means a broken update path for a subset of devices." `
                            "$($withPlat.Count) aktive Windows-Geräte laufen auf $($distinct.Count) verschiedenen Monats-Releases der Plattform. Eine gesunde Flotte liegt auf höchstens zwei bis drei (aktueller Ring plus Geräte im Übergang); mehr bedeutet meist einen defekten Update-Pfad für einen Teil der Geräte.") `
                        -Recommendation (& $T 'Group the lagging devices by update source (WSUS, Intune, air-gapped) and fix the path rather than the individual devices.' 'Zurückhängende Geräte nach Update-Quelle gruppieren (WSUS, Intune, abgeschottet) und den Pfad statt der einzelnen Geräte reparieren.') -Subject 'upd|sprawl' -StableKey))
        }
    }

    # 2) Signature age on devices that are actually online
    foreach ($d in $active) {
        if (-not $d.avSignatureTime) { continue }
        $sigAt = $null; try { $sigAt = ConvertTo-WlUtc $d.avSignatureTime } catch { continue }
        $age = [math]::Floor(($now - $sigAt).TotalDays)
        if ($age -lt 3) { continue }
        $sev = if ($age -ge 7) { 'High' } else { 'Medium' }
        $f.Add((New-WlFinding -Severity $sev -Category 'Updates' -Title (& $T 'Security intelligence older than three days on an active device' 'Security Intelligence auf aktivem Gerät älter als drei Tage') `
                    -Detail (& $T "$($d.deviceName) was seen recently, but its security intelligence (version $($d.avSignatureVersion)) was published $age days ago. Signatures are released several times a day; a device that is online and still days behind has a broken update source – the 'up to date' flag alone can hide this." `
                        "$($d.deviceName) war kürzlich online, seine Security Intelligence (Version $($d.avSignatureVersion)) wurde aber vor $age Tagen veröffentlicht. Signaturen erscheinen mehrmals täglich; ein Gerät, das online ist und trotzdem Tage hinterherhängt, hat eine defekte Update-Quelle – das 'aktuell'-Flag allein verdeckt das.") `
                    -Recommendation (& $T 'Check SignatureFallbackOrder and connectivity to MMPC/WU; run "MpCmdRun -SignatureUpdate" on the device and read Get-MpComputerStatus.' 'SignatureFallbackOrder und Verbindung zu MMPC/WU prüfen; auf dem Gerät „MpCmdRun -SignatureUpdate“ ausführen und Get-MpComputerStatus lesen.') `
                    -Subject 'upd|sig-age' -DeviceId $d.deviceId -DeviceName $d.deviceName))
    }

    # 3) Update-ring design (tenant level)
    $assigned = @($SettingValues | Where-Object { $_ -and (Test-WlAssigned $_.assignments) })
    $chan = { param($pattern) @($assigned | Where-Object { $_.definitionId -match $pattern -and [string]$_.value -match '_(\d+)$' } | ForEach-Object { [pscustomobject]@{ v = [int]([regex]::Match([string]$_.value, '_(\d+)$').Groups[1].Value); policy = $_.policyName } }) }
    $plat = @(& $chan 'platformupdateschannel'); $eng = @(& $chan 'engineupdateschannel'); $sig = @(& $chan 'securityintelligenceupdateschannel')
    $gradualOff = @($assigned | Where-Object { $_.definitionId -match 'disablegradualrelease' -and [string]$_.value -match '_1$|true' })

    if ($gradualOff.Count) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Updates' -Title (& $T 'Gradual release disabled for Defender updates' 'Gradual Release für Defender-Updates deaktiviert') `
                    -Detail (& $T "DisableGradualRelease is set in '$(@($gradualOff | ForEach-Object { $_.policyName } | Sort-Object -Unique) -join ', ')'. All affected devices receive every platform, engine and signature update immediately, without Microsoft's staged rollout. That removes the safety net against a bad update across the whole fleet; it is meant for break-fix, not for production." `
                        "DisableGradualRelease ist in '$(@($gradualOff | ForEach-Object { $_.policyName } | Sort-Object -Unique) -join ', ')' gesetzt. Alle betroffenen Geräte erhalten jedes Plattform-, Engine- und Signatur-Update sofort, ohne Microsofts gestaffelten Rollout. Das entfernt das Sicherheitsnetz gegen ein fehlerhaftes Update für die ganze Flotte; gedacht ist es für Break-Fix, nicht für Produktion.") `
                    -Recommendation (& $T 'Remove DisableGradualRelease and use the update channels (Beta/Preview for a pilot ring, Staged/Broad for production) instead.' 'DisableGradualRelease entfernen und stattdessen die Update-Kanäle nutzen (Beta/Preview für den Pilotring, Staged/Broad für Produktion).') -Subject 'upd|gradual-off' -StableKey))
    }
    $critical = @($plat + $eng | Where-Object { $_.v -eq 6 })
    if ($critical.Count) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Updates' -Title (& $T 'Defender updates on the "Critical – Time delay" channel' 'Defender-Updates im Kanal „Critical – Time delay“') `
                    -Detail (& $T "Policy '$(@($critical | ForEach-Object { $_.policy } | Sort-Object -Unique) -join ', ')' puts platform/engine updates on the Critical channel, which delays them by about two weeks. Devices on this channel run with known-fixed bugs and without new protection capabilities for that time." `
                        "Richtlinie '$(@($critical | ForEach-Object { $_.policy } | Sort-Object -Unique) -join ', ')' legt Plattform-/Engine-Updates auf den Critical-Kanal, der sie um etwa zwei Wochen verzögert. Geräte in diesem Kanal laufen so lange mit bereits behobenen Fehlern und ohne neue Schutzfunktionen.") `
                    -Recommendation (& $T 'Limit the Critical channel to a small set of genuinely change-sensitive systems; use Broad for the rest.' 'Critical-Kanal auf wenige, wirklich änderungsempfindliche Systeme begrenzen; für den Rest Broad verwenden.') -Subject 'upd|critical-channel' -StableKey))
    }
    if (@($sig | Where-Object { $_.v -eq 5 }).Count) {
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Updates' -Title (& $T 'Security intelligence on the Broad channel' 'Security Intelligence im Broad-Kanal') `
                    -Detail (& $T 'The security intelligence update channel is set to Current Channel (Broad). Devices then receive new signatures only after the gradual release cycle has completed – they lag behind the rest of the world by hours. Microsoft intends this only for a small set of datacenter systems.' 'Der Kanal für Security-Intelligence-Updates steht auf Current Channel (Broad). Geräte erhalten neue Signaturen dann erst nach Abschluss des gestaffelten Rollouts – sie hängen Stunden hinter dem Rest der Welt. Microsoft sieht das nur für wenige Rechenzentrumssysteme vor.') `
                    -Recommendation (& $T 'Leave the security intelligence channel at Not configured or Staged for the general population.' 'Den Security-Intelligence-Kanal für die breite Masse auf Nicht konfiguriert oder Staged lassen.') -Subject 'upd|sig-broad' -StableKey))
    }
    if ($win.Count -ge 10) {
        $configured = @($plat + $eng | Where-Object { $_.v -gt 0 })
        if (-not $configured.Count) {
            $f.Add((New-WlFinding -Severity 'Low' -Category 'Updates' -Title (& $T 'No Defender update rings defined' 'Keine Defender-Update-Ringe definiert') `
                        -Detail (& $T "$($win.Count) Windows devices are onboarded, but no assigned policy sets a platform or engine update channel. Every device then follows Microsoft's default gradual rollout, with no pilot group of your own to catch a problematic platform release before it reaches servers and critical clients." `
                            "$($win.Count) Windows-Geräte sind onboardet, aber keine zugewiesene Richtlinie setzt einen Plattform- oder Engine-Update-Kanal. Alle Geräte folgen dann Microsofts Standard-Rollout, ohne eigene Pilotgruppe, die ein problematisches Plattform-Release abfängt, bevor es Server und kritische Clients erreicht.") `
                        -Recommendation (& $T 'Define rings: a pilot group on Beta or Current Channel (Preview), the broad population on Current Channel (Staged/Broad).' 'Ringe definieren: Pilotgruppe auf Beta oder Current Channel (Preview), breite Masse auf Current Channel (Staged/Broad).') -Subject 'upd|no-rings' -StableKey))
        }
        elseif (-not @($configured | Where-Object { $_.v -in 2, 3 }).Count) {
            $f.Add((New-WlFinding -Severity 'Low' -Category 'Updates' -Title (& $T 'Defender update rings without a pilot group' 'Defender-Update-Ringe ohne Pilotgruppe') `
                        -Detail (& $T 'Update channels are configured, but no assigned policy puts any device on Beta or Current Channel (Preview). Platform problems are then discovered on the production population instead of a pilot ring.' 'Update-Kanäle sind konfiguriert, aber keine zugewiesene Richtlinie legt Geräte auf Beta oder Current Channel (Preview). Plattformprobleme fallen dann in der Produktion statt im Pilotring auf.') `
                        -Recommendation (& $T 'Assign a small, representative group (IT, security team) to Beta or Preview.' 'Eine kleine, repräsentative Gruppe (IT, Security-Team) auf Beta oder Preview legen.') -Subject 'upd|no-pilot' -StableKey))
        }
    }
    @($f)
}

function Get-WlInventoryFindings {
    <#
    .SYNOPSIS
    Inventory and grouping hygiene:
      - onboarded devices without a device group (they land in "Ungrouped devices": default RBAC scope and
        automation level, usually not what the design intended)
      - duplicate device records (same name or Entra device ID under several Defender device IDs – golden image
        or reimaging without offboarding; breaks grouping, indicators and counts)
      - onboarded Windows devices with no management channel (ManagedBy unknown): no Intune, ConfigMgr or
        security settings management – no Defender policy reaches them
      - ASR rules left in audit mode although the policy has not been touched for 90+ days ("eternal audit")
    #>
    param([hashtable]$Devices, [object[]]$SettingValues, $Asr)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-WlText -En $en -De $de }
    $names = { param($rows) ((@($rows) | Select-Object -First 10 | ForEach-Object { $_.deviceName }) -join ', ') + $(if (@($rows).Count -gt 10) { ', …' } else { '' }) }
    $all = @($Devices.Values)

    # 1) Ungrouped devices (only when the tenant uses device groups at all)
    $grouped = @($all | Where-Object { $_.deviceGroup -and $_.deviceGroup -notmatch '^(UnassignedGroup|Ungrouped devices.*)$' })
    $ungrouped = @($all | Where-Object { -not $_.deviceGroup -or $_.deviceGroup -match '^(UnassignedGroup|Ungrouped devices.*)$' })
    if ($grouped.Count -gt 0 -and $ungrouped.Count -gt 0) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Inventory' -Title (& $T "$($ungrouped.Count) onboarded device(s) not in any device group" "$($ungrouped.Count) onboardete(s) Gerät(e) in keiner Gerätegruppe") `
                    -Detail (& $T "The tenant uses device groups, but these devices fall into 'Ungrouped devices (default)': $(& $names $ungrouped). They inherit the default group's automation level and are visible to every role that is scoped to the default group – usually not what the RBAC design intended." "Der Tenant nutzt Gerätegruppen, diese Geräte fallen aber in 'Nicht gruppierte Geräte (Standard)': $(& $names $ungrouped). Sie erben die Automatisierungsstufe der Standardgruppe und sind für jede auf die Standardgruppe berechtigte Rolle sichtbar – meist nicht, was das RBAC-Design vorsah.") `
                    -Recommendation (& $T 'Extend the device-group rules (name, domain, tag, OS) so that every device matches a group, and set the default group to Full automation.' 'Gerätegruppen-Regeln (Name, Domäne, Tag, OS) so erweitern, dass jedes Gerät eine Gruppe trifft, und die Standardgruppe auf volle Automatisierung stellen.') -Subject 'inv|ungrouped' -StableKey))
    }

    # 2) Duplicate device records
    $byKey = @{}
    foreach ($d in $all) {
        $k = if ($d.aadDeviceId) { "aad:$(([string]$d.aadDeviceId).ToLowerInvariant())" } elseif ($d.deviceName) { "name:$((([string]$d.deviceName) -split '\.')[0].ToLowerInvariant())" } else { $null }
        if (-not $k) { continue }
        if (-not $byKey.ContainsKey($k)) { $byKey[$k] = [System.Collections.Generic.List[object]]::new() }
        $byKey[$k].Add($d)
    }
    foreach ($k in $byKey.Keys) {
        $group = @($byKey[$k]); if ($group.Count -lt 2) { continue }
        $name = $group[0].deviceName
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Inventory' -Title (& $T "Duplicate device records: $name" "Doppelte Gerätedatensätze: $name") `
                    -Detail (& $T "$($group.Count) Defender device IDs share the same $(if ($k -like 'aad:*') { 'Entra device ID' } else { 'name' }). Typical causes: a golden image onboarded before sysprep, reimaging without offboarding, or a device re-registered after a hardware swap. Duplicates distort counts, device-group membership and per-device indicators, and the stale record keeps showing an outdated protection state." "$($group.Count) Defender-Geräte-IDs teilen sich $(if ($k -like 'aad:*') { 'dieselbe Entra-Geräte-ID' } else { 'denselben Namen' }). Typische Ursachen: ein vor Sysprep onboardetes Golden Image, Neuinstallation ohne Offboarding oder Neuregistrierung nach Hardwaretausch. Duplikate verfälschen Zählungen, Gruppenzugehörigkeit und gerätebezogene Indikatoren, und der alte Datensatz zeigt weiter einen veralteten Schutzstatus.") `
                    -Recommendation (& $T 'Offboard or exclude the stale record; onboard images only after sysprep (never bake the sensor ID into the image). Consider "Hide potential duplicate device records" in Defender settings.' 'Veralteten Datensatz offboarden oder ausschließen; Images erst nach Sysprep onboarden (Sensor-ID nie ins Image backen). Option „Mögliche doppelte Gerätedatensätze ausblenden“ in den Defender-Einstellungen erwägen.') -Subject "inv|dup|$k"))
    }

    # 3) No management channel
    $unmanaged = @($all | Where-Object { ([string]$_.os) -match '^Windows' -and $_.managedBy -and $_.managedBy -match '^(Unknown|None)$' })
    if ($unmanaged.Count -gt 0 -and @($SettingValues).Count -gt 0) {
        $f.Add((New-WlFinding -Severity 'High' -Category 'Inventory' -Title (& $T "$($unmanaged.Count) onboarded Windows device(s) without a management channel" "$($unmanaged.Count) onboardete(s) Windows-Gerät(e) ohne Verwaltungskanal") `
                    -Detail (& $T "Defender reports no manager (Intune, ConfigMgr or security settings management) for: $(& $names $unmanaged). None of the Defender policies in this tenant reach these devices – they run with local defaults or whatever a GPO sets, and nothing Wardline evaluates from Intune applies to them." "Defender meldet für diese Geräte keinen Verwalter (Intune, ConfigMgr oder Security Settings Management): $(& $names $unmanaged). Keine der Defender-Richtlinien dieses Tenants erreicht sie – sie laufen mit lokalen Standardwerten oder dem, was eine GPO setzt, und nichts von dem, was Wardline aus Intune bewertet, gilt für sie.") `
                    -Recommendation (& $T 'Enable security settings management (Defender settings › Endpoints › Enforcement scope) for these devices, or enrol them in Intune. Verify with the "Managed by" field on the device page.' 'Security Settings Management (Defender-Einstellungen › Endpunkte › Erzwingungsbereich) für diese Geräte aktivieren oder sie in Intune aufnehmen. Mit dem Feld „Verwaltet von“ auf der Geräteseite prüfen.') -Subject 'inv|unmanaged' -StableKey))
    }

    # 4) Eternal audit: ASR rule in audit mode, policy untouched for 90+ days
    $now = [DateTime]::UtcNow
    foreach ($r in @(Get-WlProp $Asr 'rules')) {
        if (-not $r) { continue }
        $auditPolicies = @($r.configured | Where-Object { $_.assigned -and $_.mode -eq 'Audit' } | ForEach-Object { $_.policyId } | Sort-Object -Unique)
        if (-not $auditPolicies.Count) { continue }
        $stale = foreach ($pid in $auditPolicies) {
            $sv = @($SettingValues | Where-Object { $_.policyId -eq $pid -and $_.lastModified })[0]
            if (-not $sv) { continue }
            $lm = $null; try { $lm = ConvertTo-WlUtc $sv.lastModified } catch { continue }
            $ageDays = [math]::Floor(($now - $lm).TotalDays)
            if ($ageDays -ge 90) { [pscustomobject]@{ policy = $sv.policyName; days = $ageDays } }
        }
        $stale = @($stale); if (-not $stale.Count) { continue }
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Inventory' -Title (& $T "ASR rule in audit mode for $($stale[0].days)+ days: $($r.name)" "ASR-Regel seit $($stale[0].days)+ Tagen im Audit-Modus: $($r.name)") `
                    -Detail (& $T "Policy '$($stale[0].policy)' keeps this rule in audit mode and has not been modified for $($stale[0].days) days. Audit mode is an evaluation step (typically 30 days), not a protection state: it logs what would have been blocked and blocks nothing." "Richtlinie '$($stale[0].policy)' hält diese Regel im Audit-Modus und wurde seit $($stale[0].days) Tagen nicht geändert. Audit ist ein Bewertungsschritt (typisch 30 Tage), kein Schutzzustand: Er protokolliert, was blockiert worden wäre, und blockiert nichts.") `
                    -Recommendation (& $T 'Review the audit events in Advanced Hunting (DeviceEvents, AsrAudited), add the necessary exclusions and move the rule to Block or Warn.' 'Audit-Ereignisse in Advanced Hunting prüfen (DeviceEvents, AsrAudited), nötige Ausnahmen ergänzen und die Regel auf Block oder Warn stellen.') -Subject "inv|audit|$($r.id)" -StableKey))
    }
    @($f)
}

function Get-WlPlatformFindings {
    <#
    .SYNOPSIS
    macOS and Linux specifics (category 'Platform'): Full Disk Access and system extensions on macOS, outdated agent
    builds (101.YYMM.x), Macs managed outside Intune, and platforms without any Intune Defender policy.
    #>
    param([hashtable]$Devices, [object[]]$Policies)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-WlText -En $en -De $de }
    $macs = @($Devices.Values | Where-Object { $_.os -eq 'macOS' })
    $linux = @($Devices.Values | Where-Object { $_.os -eq 'Linux' })
    $names = { param($rows) (@($rows | ForEach-Object { $_.deviceName } | Sort-Object -Unique | Select-Object -First 10) -join ', ') + $(if (@($rows).Count -gt 10) { ' …' } else { '' }) }

    # 1) macOS without Full Disk Access – the sensor cannot read protected locations (Mail, Messages, Safari, Downloads of other users)
    foreach ($d in @($macs | Where-Object { $_.checks['FullDiskAccess'] -eq 'BAD' })) {
        $f.Add((New-WlFinding -Severity 'High' -Category 'Platform' -Title (& $T 'Defender on macOS without Full Disk Access' 'Defender auf macOS ohne Full Disk Access') `
                    -Detail (& $T "$($d.deviceName): the Defender system extension has no Full Disk Access (TCC). Antivirus and EDR cannot inspect protected folders and the device reports only part of its activity." "$($d.deviceName): Die Defender-Systemerweiterung hat keinen Full Disk Access (TCC). Virenschutz und EDR können geschützte Ordner nicht prüfen, das Gerät meldet nur einen Teil seiner Aktivität.") `
                    -Recommendation (& $T 'Deploy the Privacy Preferences Policy Control (PPPC) profile for com.microsoft.wdav and com.microsoft.wdav.epsext via Intune or Jamf; users cannot grant it reliably themselves.' 'Das PPPC-Profil (Privacy Preferences Policy Control) für com.microsoft.wdav und com.microsoft.wdav.epsext per Intune oder Jamf verteilen; Benutzer können es selbst nicht zuverlässig erteilen.') -Subject 'plat|fda' -DeviceId $d.deviceId -DeviceName $d.deviceName))
    }
    # 2) macOS system/network extensions not approved
    foreach ($d in @($macs | Where-Object { $_.checks['SystemExtensions'] -eq 'BAD' })) {
        $f.Add((New-WlFinding -Severity 'High' -Category 'Platform' -Title (& $T 'Defender system extensions not approved on macOS' 'Defender-Systemerweiterungen auf macOS nicht genehmigt') `
                    -Detail (& $T "$($d.deviceName): the endpoint security or network extension is not loaded. Without them real-time protection, EDR sensor data and network protection do not work – the app is installed but inert." "$($d.deviceName): Die Endpoint-Security- oder Netzwerkerweiterung ist nicht geladen. Ohne sie funktionieren Echtzeitschutz, EDR-Sensordaten und Netzwerkschutz nicht – die App ist installiert, aber wirkungslos.") `
                    -Recommendation (& $T 'Deploy the system extension approval profile (com.microsoft.wdav.epsext, com.microsoft.wdav.netext) and the network filter profile through MDM.' 'Das Profil zur Genehmigung der Systemerweiterungen (com.microsoft.wdav.epsext, com.microsoft.wdav.netext) und das Netzwerkfilter-Profil per MDM verteilen.') -Subject 'plat|sysext' -DeviceId $d.deviceId -DeviceName $d.deviceName))
    }

    # 3) Agent build age: 101.YYMM.x – more than 6 months behind the newest build of the same platform in the fleet
    foreach ($grp in @(@{ os = 'macOS'; rows = $macs }, @{ os = 'Linux'; rows = $linux })) {
        $ver = @($grp.rows | Where-Object { $_.agentVersion -match '^\d+\.(\d{2})(\d{2})\.' } | ForEach-Object { [pscustomobject]@{ d = $_; m = ([int]$Matches[1]) * 12 + [int]$Matches[2]; v = $_.agentVersion } })
        if ($ver.Count -lt 2) { continue }
        $max = ($ver | Measure-Object m -Maximum).Maximum
        $old = @($ver | Where-Object { $max - $_.m -ge 6 })
        if (-not $old.Count) { continue }
        $newest = @($ver | Where-Object { $_.m -eq $max })[0].v
        $auditd = if ($grp.os -eq 'Linux' -and @($old | Where-Object { $_.m -lt (24 * 12 + 8) }).Count) { ' Builds before 101.2408 still rely on auditd, which is no longer supported as event provider.' } else { '' }
        $auditdDe = if ($auditd) { ' Builds vor 101.2408 nutzen noch auditd, das als Ereignisquelle nicht mehr unterstützt wird.' } else { '' }
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Platform' -Title (& $T "$($old.Count) $($grp.os) device(s) with a Defender agent 6+ months behind" "$($old.Count) $($grp.os)-Gerät(e) mit 6+ Monate altem Defender-Agent") `
                    -Detail (& $T "Newest build in the fleet is $newest; these devices run $((@($old | ForEach-Object { "$($_.d.deviceName) ($($_.v))" } | Select-Object -First 8)) -join ', ')$(if ($old.Count -gt 8) { ' …' }). Old agents miss sensor fixes and fall out of support after about nine months.$auditd" `
                        "Neuester Build in der Flotte ist $newest; diese Geräte laufen mit $((@($old | ForEach-Object { "$($_.d.deviceName) ($($_.v))" } | Select-Object -First 8)) -join ', ')$(if ($old.Count -gt 8) { ' …' }). Alte Agents fehlen Sensor-Fixes, nach etwa neun Monaten fallen sie aus dem Support.$auditdDe") `
                    -Recommendation (& $T "$(if ($grp.os -eq 'macOS') { 'Check Microsoft AutoUpdate (MAU) reaches these Macs and that the update channel is set; on Jamf-managed Macs verify the MAU profile.' } else { 'Check the package repository and update job (apt/yum/zypper) on these hosts; pin the production channel and automate upgrades.' })" "$(if ($grp.os -eq 'macOS') { 'Prüfen, ob Microsoft AutoUpdate (MAU) diese Macs erreicht und der Update-Kanal gesetzt ist; bei Jamf das MAU-Profil kontrollieren.' } else { 'Paket-Repository und Update-Job (apt/yum/zypper) auf diesen Hosts prüfen; Production-Kanal setzen und Upgrades automatisieren.' })") -Subject "plat|agent-old|$($grp.os)" -StableKey))
    }

    # 4) Platforms present but without any Intune Defender policy – Wardline cannot see the intended configuration
    $polPlat = @($Policies | ForEach-Object { $_.platforms } | Where-Object { $_ } | Sort-Object -Unique)
    foreach ($grp in @(@{ os = 'macOS'; rows = $macs }, @{ os = 'Linux'; rows = $linux })) {
        if ($grp.rows.Count -lt 1 -or $polPlat -contains $grp.os) { continue }
        $foreign = @($grp.rows | Where-Object { $_.managedBy -and $_.managedBy -notmatch 'Intune' })
        $sev = if ($grp.os -eq 'macOS' -and $foreign.Count -eq $grp.rows.Count) { 'Low' } else { 'Medium' }
        $f.Add((New-WlFinding -Severity $sev -Category 'Platform' -Title (& $T "$($grp.rows.Count) $($grp.os) device(s) without an Intune Defender policy" "$($grp.rows.Count) $($grp.os)-Gerät(e) ohne Intune-Defender-Richtlinie") `
                    -Detail (& $T "Defender runs on $($grp.rows.Count) $($grp.os) device(s) ($(& $names $grp.rows)) but no Intune policy targets $($grp.os). $(if ($grp.os -eq 'Linux') { 'Settings then come from a local mdatp_managed.json or from nothing at all – Wardline can only observe the device state, not the intended configuration.' } elseif ($foreign.Count) { "$($foreign.Count) of them are managed outside Intune ($(@($foreign | ForEach-Object { $_.managedBy } | Sort-Object -Unique) -join ', ')), probably Jamf – those profiles are invisible to Wardline." } else { 'Settings then come from the defaults or a third-party MDM – Wardline can only observe the device state, not the intended configuration.' })" `
                        "Defender läuft auf $($grp.rows.Count) $($grp.os)-Gerät(en) ($(& $names $grp.rows)), aber keine Intune-Richtlinie zielt auf $($grp.os). $(if ($grp.os -eq 'Linux') { 'Die Einstellungen kommen dann aus einer lokalen mdatp_managed.json oder gar nicht – Wardline sieht nur den Gerätezustand, nicht die beabsichtigte Konfiguration.' } elseif ($foreign.Count) { "$($foreign.Count) davon werden außerhalb von Intune verwaltet ($(@($foreign | ForEach-Object { $_.managedBy } | Sort-Object -Unique) -join ', ')), vermutlich Jamf – diese Profile sind für Wardline unsichtbar." } else { 'Die Einstellungen kommen dann aus den Standardwerten oder einem Fremd-MDM – Wardline sieht nur den Gerätezustand, nicht die beabsichtigte Konfiguration.' })") `
                    -Recommendation (& $T "$(if ($grp.os -eq 'Linux') { 'Manage Linux Defender settings through Intune security settings management (Linux) or document the mdatp_managed.json baseline and keep it in version control.' } else { 'Either manage macOS Defender through Intune (security settings management works alongside Jamf) or compare the Jamf profiles against the baseline manually.' })" "$(if ($grp.os -eq 'Linux') { 'Linux-Defender-Einstellungen über Intune Security Settings Management (Linux) verwalten oder die mdatp_managed.json-Baseline dokumentieren und versionieren.' } else { 'macOS-Defender entweder über Intune verwalten (Security Settings Management läuft neben Jamf) oder die Jamf-Profile manuell gegen die Baseline prüfen.' })") -Subject "plat|nopolicy|$($grp.os)" -StableKey))
    }
    @($f)
}

function Get-WlEndpointFindings {
    <#
    .SYNOPSIS
    Derives findings – especially combined findings (e.g. Tamper Protection off AND local exclusions).
    #>
    param([hashtable]$Devices, [object[]]$PolicyExclusions, [object[]]$LocalExclusions, [object[]]$Indicators, [object[]]$Baseline, [object[]]$SettingValues,
        $Asr, [object[]]$LinuxEvents, [object[]]$Policies)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-WlText -En $en -De $de }
    $byId = @{}; foreach ($b in @($Baseline)) { if ($b) { $byId[$b.id] = $b } }
    $mergeBlockedWin = ($byId['disable-local-admin-merge'] -and $byId['disable-local-admin-merge'].status -eq 'OK')
    $mergeBlockedMac = ($byId['mac-exclusions-merge-policy'] -and $byId['mac-exclusions-merge-policy'].status -eq 'OK')
    $mergeBlockedLinux = ($byId['linux-exclusions-merge-policy'] -and $byId['linux-exclusions-merge-policy'].status -eq 'OK')

    # Per device
    foreach ($d in $Devices.Values) {
        $tp = $d.checks['TamperProtection']; $rtp = $d.checks['RealtimeProtection']; $av = $d.checks['AntivirusEnabled']
        $cloud = $d.checks['CloudProtection']; $bm = $d.checks['BehaviorMonitoring']; $sensor = $d.checks['ImpairedCommunications']
        $locals = @($LocalExclusions | Where-Object { $_.present -and $_.deviceId -eq $d.deviceId })
        $highLocals = @($locals | Where-Object { $_.risk.level -in 'Critical', 'High' })
        $d.localExclusions = $locals.Count
        $d.localExclusionsHighRisk = $highLocals.Count
        $dn = $d.deviceName

        if ($locals.Count -gt 0 -and $tp -eq 'BAD') {
            $f.Add((New-WlFinding -Severity 'Critical' -Category 'Combined' -Title (& $T 'Tamper Protection off and local exclusions present' 'Tamper Protection aus und lokale Exclusions vorhanden') `
                        -Detail (& $T "Tamper Protection is not active on $dn and there are $($locals.Count) local exclusion(s) ($($highLocals.Count) high risk). Attackers use exactly this combination to drop tools into excluded paths." `
                            "Auf $dn ist Tamper Protection nicht aktiv und es existieren $($locals.Count) lokale Exclusion(s) ($($highLocals.Count) mit hohem Risiko). Genau diese Kombination nutzen Angreifer, um Werkzeuge in ausgenommenen Pfaden abzulegen.") `
                        -Recommendation (& $T 'Turn on Tamper Protection, enforce DisableLocalAdminMerge, review and remove local exclusions.' 'Tamper Protection aktivieren, DisableLocalAdminMerge erzwingen, lokale Exclusions prüfen und entfernen.') `
                        -Subject 'tp+local' -DeviceId $d.deviceId -DeviceName $dn))
        }
        elseif ($tp -eq 'BAD') {
            $f.Add((New-WlFinding -Severity 'Critical' -Category 'Device' -Title (& $T 'Tamper Protection not active' 'Tamper Protection nicht aktiv') `
                        -Detail (& $T "Defender settings can be changed locally on $dn." "Auf $dn können Defender-Einstellungen lokal verändert werden.") `
                        -Recommendation (& $T 'Turn on Tamper Protection tenant-wide or via Intune.' 'Tamper Protection mandantenweit oder per Intune aktivieren.') -Subject 'tp' -DeviceId $d.deviceId -DeviceName $dn))
        }

        if ($d.avMode -eq '1' -or $d.avMode -eq '2' -or $d.checks['PassiveModeOff'] -eq 'BAD') {
            $extraEn = if ($locals.Count -gt 0) { " In addition there are $($locals.Count) local exclusion(s)." } else { '' }
            $extraDe = if ($locals.Count -gt 0) { " Zusätzlich $($locals.Count) lokale Exclusion(s)." } else { '' }
            $f.Add((New-WlFinding -Severity 'Critical' -Category 'Device' -Title (& $T 'Microsoft Defender Antivirus in passive mode' 'Microsoft Defender Antivirus im Passiv-Modus') `
                        -Detail (& $T "$dn runs in mode '$($d.avModeText)'. If this is not intended, a third-party or fake AV registration (e.g. Defendnot) may have disabled protection.$extraEn" `
                            "$dn läuft im Modus '$($d.avModeText)'. Ist das nicht beabsichtigt, kann eine fremde oder gefälschte AV-Registrierung (z. B. Defendnot) den Schutz ausgehebelt haben.$extraDe") `
                        -Recommendation (& $T 'Check the running mode; if no third-party AV is intended, investigate the cause and switch back to active.' 'Running Mode prüfen; falls kein Drittanbieter-AV vorgesehen ist, Ursache untersuchen und auf Aktiv zurückstellen.') `
                        -Subject 'passive' -DeviceId $d.deviceId -DeviceName $dn))
        }
        if ($av -eq 'BAD') { $f.Add((New-WlFinding -Severity 'Critical' -Category 'Device' -Title (& $T 'Antivirus disabled' 'Antivirus deaktiviert') -Detail (& $T "Defender reports antivirus as inactive on $dn." "Auf $dn meldet Defender Antivirus als nicht aktiv.") -Recommendation (& $T 'Enable Defender Antivirus or resolve the conflict with older policies.' 'Defender Antivirus aktivieren bzw. Konflikt mit älteren Richtlinien beseitigen.') -Subject 'av' -DeviceId $d.deviceId -DeviceName $dn)) }
        if ($rtp -eq 'BAD') { $f.Add((New-WlFinding -Severity 'Critical' -Category 'Device' -Title (& $T 'Real-time protection disabled' 'Echtzeitschutz deaktiviert') -Detail (& $T "Real-time protection is off on $dn." "Auf $dn ist der Echtzeitschutz aus.") -Recommendation (& $T 'Enforce real-time protection by policy.' 'Echtzeitschutz per Richtlinie erzwingen.') -Subject 'rtp' -DeviceId $d.deviceId -DeviceName $dn)) }
        if ($bm -eq 'BAD') { $f.Add((New-WlFinding -Severity 'High' -Category 'Device' -Title (& $T 'Behavior monitoring disabled' 'Verhaltensüberwachung deaktiviert') -Detail (& $T "Behavior monitoring is off on $dn." "Auf $dn ist die Verhaltensüberwachung aus.") -Recommendation (& $T 'Enforce behavior monitoring by policy.' 'Behavior Monitoring per Richtlinie erzwingen.') -Subject 'bm' -DeviceId $d.deviceId -DeviceName $dn)) }
        if ($cloud -eq 'BAD') { $f.Add((New-WlFinding -Severity 'High' -Category 'Device' -Title (& $T 'Cloud protection disabled' 'Cloud-Schutz deaktiviert') -Detail (& $T "Cloud protection is off on $dn. Block at first sight, indicators and parts of the ASR rules do not work without it." "Auf $dn ist der Cloud-Schutz aus. Damit funktionieren Block at First Sight, Indikatoren und Teile der ASR-Regeln nicht.") -Recommendation (& $T 'Enable cloud-delivered protection and sample submission.' 'Cloud-delivered Protection und Sample-Übermittlung aktivieren.') -Subject 'cloud' -DeviceId $d.deviceId -DeviceName $dn)) }
        if ($sensor -eq 'BAD') { $f.Add((New-WlFinding -Severity 'High' -Category 'Device' -Title (& $T 'EDR sensor with impaired communication' 'EDR-Sensor mit gestörter Kommunikation') -Detail (& $T "$dn reports impaired communication of the EDR sensor." "$dn meldet eingeschränkte Kommunikation des EDR-Sensors.") -Recommendation (& $T 'Check proxy/firewall and the required URLs (WinHTTP).' 'Proxy/Firewall und erforderliche URLs prüfen (WinHTTP).') -Subject 'sensor' -DeviceId $d.deviceId -DeviceName $dn)) }
        if ($d.exclusionAlerts -gt 0) { $f.Add((New-WlFinding -Severity 'High' -Category 'Combined' -Title (& $T 'Defender alert about a suspicious exclusion' 'Defender-Alert zu verdächtiger Exclusion') -Detail (& $T "$($d.exclusionAlerts) alert(s) about suspicious exclusions on $dn in the last 30 days." "Für $dn gab es in den letzten 30 Tagen $($d.exclusionAlerts) Alert(s) zu verdächtigen Exclusions.") -Recommendation (& $T 'Investigate the alert in the Defender portal and assess the exclusion.' 'Alert im Defender-Portal untersuchen und Exclusion bewerten.') -Subject 'alert' -DeviceId $d.deviceId -DeviceName $dn)) }

        $os = [string]$d.os
        $mergeBlocked = if ($os -match '^mac') { $mergeBlockedMac } elseif ($os -match '^Linux') { $mergeBlockedLinux } elseif ($null -ne $d.localMergeDisabled) { [bool]$d.localMergeDisabled } else { $mergeBlockedWin }
        if ($locals.Count -gt 0 -and -not $mergeBlocked -and $tp -ne 'BAD') {
            if ($os -match '^mac|^Linux') {
                $detail = & $T "There are $($locals.Count) local exclusion(s) (mdatp) on $dn. Unless the exclusions merge policy is 'admin_only', local and managed exclusions are merged." `
                    "Auf $dn existieren $($locals.Count) lokale Exclusion(s) (mdatp). Solange die Merge-Policy der Exclusions nicht auf 'admin_only' steht, werden lokale und verwaltete Exclusions zusammengeführt."
                $reco = & $T "Enforce exclusions merge policy = admin_only via Intune / security settings management." "Merge-Policy der Exclusions = admin_only per Intune/Security Settings Management erzwingen."
            }
            else {
                $detail = & $T "There are $($locals.Count) local exclusion(s) on $dn. Without DisableLocalAdminMerge they are merged with the central exclusions – and Tamper Protection only protects exclusions when DisableLocalAdminMerge is enabled." `
                    "Auf $dn existieren $($locals.Count) lokale Exclusion(s). Ohne DisableLocalAdminMerge werden sie mit den zentralen Exclusions zusammengeführt – und Tamper Protection schützt Exclusions nur, wenn DisableLocalAdminMerge aktiv ist."
                $reco = & $T 'Enforce DisableLocalAdminMerge via Intune / security settings management.' 'DisableLocalAdminMerge per Intune/Security Settings Management erzwingen.'
            }
            $f.Add((New-WlFinding -Severity 'High' -Category 'Combined' -Title (& $T 'Local exclusions are effective' 'Lokale Exclusions sind wirksam') -Detail $detail -Recommendation $reco -Subject 'merge' -DeviceId $d.deviceId -DeviceName $dn))
        }
    }

    # High-risk local exclusions individually
    foreach ($l in @($LocalExclusions | Where-Object { $_.present -and $_.risk.level -eq 'Critical' })) {
        $rEn = (@($l.risk.reasons) | ForEach-Object { Get-WlProp $_ 'en' }) -join '; '
        $rDe = (@($l.risk.reasons) | ForEach-Object { Get-WlProp $_ 'de' }) -join '; '
        $f.Add((New-WlFinding -Severity 'Critical' -Category 'Exclusion' -Title (& $T "Critical local exclusion: $($l.value)" "Kritische lokale Exclusion: $($l.value)") `
                    -Detail (& $T "$(Get-WlTypeName $l.type) exclusion on $($l.deviceName), set by $($l.addedBy.process). Reasons: $rEn" "$(Get-WlTypeName $l.type -De)-Exclusion auf $($l.deviceName), gesetzt von $($l.addedBy.process). Gründe: $rDe") `
                    -Recommendation (& $T 'Clarify the origin and remove it; if needed, manage it centrally as a narrow, contextual exclusion.' 'Herkunft klären und entfernen; falls nötig als eng gefasste, kontextuelle Exclusion zentral verwalten.') `
                    -Subject $l.key -DeviceId $l.deviceId -DeviceName $l.deviceName))
    }

    # Policy exclusions
    foreach ($p in @($PolicyExclusions | Where-Object { $_.risk.level -in 'Critical', 'High' })) {
        $rEn = (@($p.risk.reasons) | ForEach-Object { Get-WlProp $_ 'en' }) -join '; '
        $rDe = (@($p.risk.reasons) | ForEach-Object { Get-WlProp $_ 'de' }) -join '; '
        if (-not $p.assigned) {
            $f.Add((New-WlFinding -Severity 'Low' -Category 'Exclusion' -Title (& $T "Risky $(Get-WlTypeName $p.type) exclusion in an unassigned policy: $($p.value)" "Riskante $(Get-WlTypeName $p.type -De)-Exclusion in nicht zugewiesener Richtlinie: $($p.value)") `
                        -Detail (& $T "Policy '$($p.policyName)' is not assigned to any group and therefore has no effect. Risk once assigned: $($p.risk.level). $rEn" "Richtlinie '$($p.policyName)' ist derzeit keiner Gruppe zugewiesen und wirkt daher nicht. Risiko bei Zuweisung: $($p.risk.level). $rDe") `
                        -Recommendation (& $T 'Delete the policy if it is no longer needed, or narrow the exclusion before assigning it.' 'Richtlinie entfernen, falls nicht mehr benötigt, oder Exclusion vor einer Zuweisung eng fassen.') -Subject $p.key))
            continue
        }
        $f.Add((New-WlFinding -Severity $p.risk.level -Category 'Exclusion' -Title (& $T "Risky $(Get-WlTypeName $p.type) exclusion: $($p.value)" "Riskante $(Get-WlTypeName $p.type -De)-Exclusion: $($p.value)") `
                    -Detail (& $T "Policy '$($p.policyName)' ($($p.scope)), assigned to: $(@($p.assignments) -join ', '). Reasons: $rEn" "Richtlinie '$($p.policyName)' ($($p.scope)), zugewiesen an: $(@($p.assignments) -join ', '). Gründe: $rDe") `
                    -Recommendation (& $T 'Narrow the exclusion as far as possible (file instead of folder, contextual syntax, no interpreter) and recertify it regularly.' 'Exclusion so eng wie möglich fassen (Datei statt Ordner, kontextuelle Syntax, kein Interpreter) und regelmäßig rezertifizieren.') -Subject $p.key))
    }

    # Indicators
    foreach ($i in @($Indicators | Where-Object { $_.risk.level -in 'Critical', 'High' })) {
        $rEn = (@($i.risk.reasons) | ForEach-Object { Get-WlProp $_ 'en' }) -join '; '
        $rDe = (@($i.risk.reasons) | ForEach-Object { Get-WlProp $_ 'de' }) -join '; '
        $f.Add((New-WlFinding -Severity $i.risk.level -Category 'Indicator' -Title (& $T "Allow indicator: $($i.type) $($i.value)" "Allow-Indikator: $($i.type) $($i.value)") `
                    -Detail (& $T "$rEn Created by $($i.createdBy)." "$rDe Erstellt von $($i.createdBy).") `
                    -Recommendation (& $T 'Review the need, set an expiry date, prefer SHA256 indicators.' 'Notwendigkeit prüfen, Ablaufdatum setzen, SHA256-Indikatoren bevorzugen.') -Subject $i.key))
    }

    # Baseline
    $statusText = @{ Deviation = @('deviation', 'Abweichung'); NotConfigured = @('not configured', 'nicht konfiguriert'); NotAssigned = @('not assigned', 'nicht zugewiesen'); Inconsistent = @('inconsistent', 'uneinheitlich'); DeviceDeviation = @('deviation on devices', 'Abweichung am Gerät') }
    foreach ($b in @($Baseline | Where-Object { $statusText.ContainsKey($_.status) })) {
        $sev = if ($b.status -eq 'Inconsistent' -and $b.severity -in 'Critical', 'High') { 'Medium' } else { $b.severity }
        $st = $statusText[$b.status]
        $f.Add((New-WlFinding -Severity $sev -Category 'Baseline' -Title (& $T "$(Get-WlProp $b.title 'en'): $($st[0])" "$(Get-WlProp $b.title 'de'): $($st[1])") -Detail $b.rationale -Recommendation $b.remediation -Subject $b.id))
    }

    # ASR rules: target / configured / effective
    foreach ($r in @(Get-WlProp $Asr 'rules')) {
        if (-not $r) { continue }
        $groupsText = (@($r.belowByGroup | Select-Object -First 5 | ForEach-Object { "$($_.group) ($($_.devices))" }) -join ', ')
        $assignedText = (@($r.configured | Where-Object { $_.assigned } | ForEach-Object { "$($_.policyName) = $($_.mode)" }) -join '; ')
        switch ($r.status) {
            'Conflict' {
                $f.Add((New-WlFinding -Severity 'High' -Category 'ASR' -Title (& $T "ASR rule in conflict: $($r.name)" "ASR-Regel mit Konflikt: $($r.name)") `
                            -Detail (& $T "Several assigned policies set different modes: $assignedText. Intune applies none of the conflicting values." "Mehrere zugewiesene Richtlinien setzen unterschiedliche Modi: $assignedText. Intune wendet bei Konflikten keine der Einstellungen an.") `
                            -Recommendation (& $T 'Configure the rule in only one policy per device group.' 'Regel nur in einer Richtlinie pro Gerätegruppe konfigurieren.') -Subject "asr|$($r.id)"))
            }
            'NotConfigured' {
                $f.Add((New-WlFinding -Severity $r.severity -Category 'ASR' -Title (& $T "ASR rule not configured: $($r.name)" "ASR-Regel nicht konfiguriert: $($r.name)") `
                            -Detail (& $T "No assigned policy sets this rule. Target: at least $($r.minimum), recommended $($r.recommended). $($r.belowMinimum) device(s) are below target$(if ($groupsText) { " – device groups: $groupsText" })." `
                                "Keine zugewiesene Richtlinie setzt diese Regel. Soll: mindestens $($r.minimum), empfohlen $($r.recommended). $($r.belowMinimum) Gerät(e) liegen unter dem Soll$(if ($groupsText) { " – Gerätegruppen: $groupsText" }).") `
                            -Recommendation (& $T "Roll the rule out in audit mode first, review the events, then switch to $($r.recommended)." "Regel zunächst im Audit-Modus ausrollen, Ereignisse auswerten und dann auf $($r.recommended) stellen.") -Subject "asr|$($r.id)"))
            }
            'BelowTarget' {
                $f.Add((New-WlFinding -Severity $r.severity -Category 'ASR' -Title (& $T "ASR rule below target: $($r.name)" "ASR-Regel unter Soll: $($r.name)") `
                            -Detail (& $T "Configured: $assignedText. Target: at least $($r.minimum)." "Konfiguriert: $assignedText. Soll: mindestens $($r.minimum).") `
                            -Recommendation (& $T "Review audit events, keep ASR exclusions narrow, then switch to $($r.recommended)." "Audit-Ereignisse auswerten, nötige ASR-Exclusions eng fassen, dann auf $($r.recommended) umstellen.") -Subject "asr|$($r.id)"))
            }
            'DeviceDeviation' {
                $f.Add((New-WlFinding -Severity $r.severity -Category 'ASR' -Title (& $T "ASR rule not effective everywhere: $($r.name)" "ASR-Regel wirkt nicht überall: $($r.name)") `
                            -Detail (& $T "$($r.belowMinimum) device(s) are below target ($($r.minimum)) although the rule is configured$(if ($groupsText) { " – device groups: $groupsText" }). Common causes: device not in the assigned group, conflict with a GPO, Defender in passive mode." `
                                "$($r.belowMinimum) Gerät(e) liegen unter dem Soll ($($r.minimum)), obwohl die Regel konfiguriert ist$(if ($groupsText) { " – Gerätegruppen: $groupsText" }). Häufige Ursachen: Gerät nicht in der zugewiesenen Gruppe, Konflikt mit GPO, Defender im Passiv-Modus.") `
                            -Recommendation (& $T 'Check assignments and device groups; verify Get-MpPreference (AttackSurfaceReductionRules_Actions) on affected devices.' 'Zuweisung und Gerätegruppen prüfen; auf betroffenen Geräten Get-MpPreference (AttackSurfaceReductionRules_Actions) kontrollieren.') -Subject "asr|$($r.id)"))
            }
            'BlockRecommended' {
                $f.Add((New-WlFinding -Severity 'Low' -Category 'ASR' -Title (& $T "ASR rule not yet in block mode: $($r.name)" "ASR-Regel noch nicht im Block-Modus: $($r.name)") `
                            -Detail (& $T "$($r.effective.Block) of $($r.measured) devices block; the rest are in audit/warn. Audit is a stage, not a goal – switch to block after one to three months as a rule of thumb." `
                                "$($r.effective.Block) von $($r.measured) Geräten blockieren, die übrigen stehen auf Audit/Warn. Audit ist eine Etappe, kein Ziel – als Faustregel nach ein bis drei Monaten auf Block umstellen.") `
                            -Recommendation (& $T 'Review audit events (DeviceEvents, ActionType Asr*Audited) and switch to block.' 'Audit-Ereignisse (DeviceEvents, ActionType Asr*Audited) auswerten und auf Block umstellen.') -Subject "asr|$($r.id)"))
            }
        }
    }

    # Linux/macOS: local configuration changes. The latest change per device and setting counts
    # (re-enabled later = no finding).
    foreach ($g in @($LinuxEvents | Where-Object { $_ -and ($_.kind -eq 'config' -or $_.weakens) } | Group-Object deviceId, setting)) {
        $e = @($g.Group | Sort-Object { ConvertTo-WlUtc $_.at })[-1]
        if (-not $e.weakens) { continue }
        if ($e.kind -eq 'config') {
            $f.Add((New-WlFinding -Severity 'High' -Category 'Device' -Title (& $T "Defender weakened locally: $($e.setting) = $($e.value)" "Defender lokal geschwächt: $($e.setting) = $($e.value)") `
                        -Detail (& $T "On $($e.deviceName) '$($e.setting)' was set to '$($e.value)' using 'mdatp config' (account: $($e.account), $($e.at)). Command line: $($e.commandLine)" `
                            "Auf $($e.deviceName) wurde per 'mdatp config' die Einstellung '$($e.setting)' auf '$($e.value)' gesetzt (Konto: $($e.account), $($e.at)). Befehlszeile: $($e.commandLine)") `
                        -Recommendation (& $T 'Enforce the setting centrally (Intune / security settings management or mdatp_managed.json); managed values override local ones.' 'Einstellung zentral erzwingen (Intune/Security Settings Management bzw. mdatp_managed.json); verwaltete Werte überschreiben lokale.') `
                        -Subject "cfg|$($e.setting)" -DeviceId $e.deviceId -DeviceName $e.deviceName))
        }
        else {
            $f.Add((New-WlFinding -Severity 'High' -Category 'Device' -Title (& $T 'Managed Defender configuration deleted' 'Verwaltete Defender-Konfiguration gelöscht') `
                        -Detail (& $T "$($e.setting) was deleted on $($e.deviceName) (process: $($e.process), account: $($e.account))." "Auf $($e.deviceName) wurde $($e.setting) gelöscht (Prozess: $($e.process), Konto: $($e.account)).") `
                        -Recommendation (& $T 'Clarify the cause; redeploy the configuration.' 'Ursache klären; Konfiguration erneut verteilen.') -Subject 'managed-file' -DeviceId $e.deviceId -DeviceName $e.deviceName))
        }
    }
    foreach ($g in @($LinuxEvents | Where-Object { $_ -and $_.kind -eq 'managed-file' -and -not $_.weakens } | Group-Object deviceId)) {
        $e = @($g.Group | Sort-Object { ConvertTo-WlUtc $_.at })[-1]
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Device' -Title (& $T 'Managed Defender configuration changed locally' 'Verwaltete Defender-Konfiguration lokal geändert') `
                    -Detail (& $T "$($e.setting) was changed $($g.Count) time(s) on $($e.deviceName) outside of Defender, last by $($e.process) ($($e.account)). This may be configuration management such as Ansible – or someone bypassing settings." `
                        "Auf $($e.deviceName) wurde $($e.setting) $($g.Count)-mal außerhalb von Defender geändert, zuletzt durch $($e.process) ($($e.account)). Das kann eine Konfigurationsverwaltung wie Ansible sein – oder jemand, der Einstellungen umgeht.") `
                    -Recommendation (& $T 'Check whether the process belongs to your regular configuration management.' 'Prüfen, ob der Prozess zur regulären Konfigurationsverwaltung gehört.') -Subject 'managed-file-mod' -DeviceId $e.deviceId -DeviceName $e.deviceName))
    }

    foreach ($x in @(Get-WlDependencyFindings -Devices $Devices -Baseline $Baseline -SettingValues $SettingValues -Asr $Asr -Indicators $Indicators)) { $f.Add($x) }
    foreach ($x in @(Get-WlUpdateFindings -Devices $Devices -SettingValues $SettingValues)) { $f.Add($x) }
    foreach ($x in @(Get-WlInventoryFindings -Devices $Devices -SettingValues $SettingValues -Asr $Asr)) { $f.Add($x) }
    foreach ($x in @(Get-WlPlatformFindings -Devices $Devices -Policies $Policies)) { $f.Add($x) }

    @($f | Sort-Object { $script:WlSeverityOrder[$_.severity] }, category, { Get-WlProp $_.title 'en' })
}
#endregion

#region Device statistics and search (large fleets)
$script:WlDeviceIndexColumns = @('deviceId', 'deviceName', 'os', 'osVersion', 'deviceGroup', 'deviceType', 'managedBy', 'avMode', 'avModeText', 'sensorHealth', 'signatureUpToDate', 'platformUpToDate',
    'asrBelowMinimum', 'asrBlocked', 'localExclusions', 'localExclusionsHighRisk', 'exclusionAlerts', 'lastSeen', 'lastUser', 'intuneDeviceId', 'aadDeviceId', 'checks',
    'exposure', 'internetFacing', 'tags', 'tampering30d', 'troubleshooting30d', 'thirdPartyAv', '_filter', '_search')
$script:WlDeviceFeatures = @('TamperProtection', 'RealtimeProtection', 'CloudProtection', 'BehaviorMonitoring', 'PUAProtection', 'NetworkProtection', 'ControlledFolderAccess', 'EdrBlockMode')

function Get-WlDeviceChartState {
    # The same classification the portal charts use – evaluated server-side so filters work on 300,000 devices.
    param($Device, [string]$Chart)
    $checks = Get-WlProp $Device 'checks'
    switch ($Chart) {
        'sig' { $v = [string](Get-WlProp $Device 'signatureUpToDate'); if ($v -match '^(true|1)$') { 'on' } elseif ($v -match '^(false|0)$') { 'off' } else { 'unknown' } }
        'sensor' { $v = [string](Get-WlProp $Device 'sensorHealth'); if (-not $v) { 'unknown' } elseif ($v -match '^active$') { 'on' } else { 'off' } }
        'mode' { $m = [string](Get-WlProp $Device 'avMode'); if ($m -eq '0') { 'Active' } elseif ($m -eq '4') { 'EdrBlock' } elseif ($m -in '1', '2') { 'Passive' } else { 'Unknown' } }
        'os' { $o = [string](Get-WlProp $Device 'os'); if ($o) { $o } else { '–' } }
        default {
            $v = [string](Get-WlProp $checks $Chart)
            if ($v -eq 'GOOD') { 'on' } elseif ($v -eq 'BAD') { 'off' } elseif ($v -eq 'N/A') { 'na' } else { 'unknown' }
        }
    }
}

function Test-WlDeviceIssue {
    param($Device)
    $checks = Get-WlProp $Device 'checks'
    $vals = if ($checks -is [System.Collections.IDictionary]) { @($checks.Values) } elseif ($checks) { @($checks.PSObject.Properties.Value) } else { @() }
    if ($vals -contains 'BAD') { return $true }
    $m = [string](Get-WlProp $Device 'avMode'); if ($m -and $m -ne '0') { return $true }
    foreach ($p in 'localExclusions', 'exclusionAlerts', 'asrBelowMinimum') { $v = Get-WlProp $Device $p; if ($v -and [int]$v -gt 0) { return $true } }
    $false
}

function Get-WlDeviceFilter {
    <#
    .SYNOPSIS
    Pre-computed filter tokens of a device (" TamperProtection:off sig:on sensor:on mode:Active issue:1 asrBelow:1 "),
    stored with the device and in the index, so statistics and server-side search are plain string operations
    even for 300,000 devices. Single source of truth for the chart states (same rules as the portal).
    #>
    param([Parameter(Mandatory)]$Device)
    # Inline property access on purpose (called once per device; 300,000 devices must finish in seconds).
    $isDict = $Device -is [System.Collections.IDictionary]
    $props = $null; if (-not $isDict) { $props = $Device.PSObject.Properties }
    $get = { param($n) if ($isDict) { return $Device[$n] }; $p = $props[$n]; if ($p) { return $p.Value }; $null }
    $checks = & $get 'checks'
    $cDict = $checks -is [System.Collections.IDictionary]
    $cProps = $null; if ($checks -and -not $cDict) { $cProps = $checks.PSObject.Properties }
    $sb = [System.Text.StringBuilder]::new(' ')
    $bad = $false
    foreach ($c in $script:WlDeviceFeatures) {
        $v = $null
        if ($cDict) { $v = $checks[$c] } elseif ($cProps) { $p = $cProps[$c]; if ($p) { $v = $p.Value } }
        $v = [string]$v
        $s = if ($v -eq 'GOOD') { 'on' } elseif ($v -eq 'BAD') { 'off' } elseif ($v -eq 'N/A') { 'na' } else { 'unknown' }
        [void]$sb.Append($c).Append(':').Append($s).Append(' ')
    }
    if ($cDict) { foreach ($v in $checks.Values) { if ($v -eq 'BAD') { $bad = $true; break } } } elseif ($cProps) { foreach ($p in $cProps) { if ($p.Value -eq 'BAD') { $bad = $true; break } } }
    $v = [string](& $get 'signatureUpToDate'); [void]$sb.Append('sig:').Append($(if ($v -match '^(true|1)$') { 'on' } elseif ($v -match '^(false|0)$') { 'off' } else { 'unknown' })).Append(' ')
    $v = [string](& $get 'sensorHealth'); [void]$sb.Append('sensor:').Append($(if (-not $v) { 'unknown' } elseif ($v -match '^active$') { 'on' } else { 'off' })).Append(' ')
    $m = [string](& $get 'avMode'); [void]$sb.Append('mode:').Append($(if ($m -eq '0') { 'Active' } elseif ($m -eq '4') { 'EdrBlock' } elseif ($m -eq '1' -or $m -eq '2') { 'Passive' } else { 'Unknown' })).Append(' ')
    $issue = $bad -or ($m -and $m -ne '0')
    $asr = & $get 'asrBelowMinimum'; $asrBelow = $asr -and [int]$asr -gt 0
    if (-not $issue) { $issue = $asrBelow; if (-not $issue) { foreach ($n in 'localExclusions', 'exclusionAlerts') { $x = & $get $n; if ($x -and [int]$x -gt 0) { $issue = $true; break } } } }
    [void]$sb.Append('issue:').Append($(if ($issue) { '1' } else { '0' })).Append(' ')
    [void]$sb.Append('asrBelow:').Append($(if ($asrBelow) { '1' } else { '0' })).Append(' ')
    $inet = & $get 'internetFacing'; [void]$sb.Append('inet:').Append($(if ($inet -eq $true -or "$inet" -match '^(true|1)$') { '1' } else { '0' })).Append(' ')
    $tp = & $get 'tampering30d'; [void]$sb.Append('tampering:').Append($(if ($tp -and [int]$tp -gt 0) { '1' } else { '0' })).Append(' ')
    $ta = & $get 'thirdPartyAv'; [void]$sb.Append('3pav:').Append($(if ($ta -and @($ta).Count -gt 0 -and "$ta" -ne '') { '1' } else { '0' })).Append(' ')
    $ts = & $get 'troubleshooting30d'; [void]$sb.Append('troubleshooting:').Append($(if ($ts -and [int]$ts -gt 0) { '1' } else { '0' })).Append(' ')
    $sb.ToString()
}

function Get-WlDeviceSearchText {
    param([Parameter(Mandatory)]$Device)
    if ($Device -is [System.Collections.IDictionary]) { return "$($Device['deviceName']) $($Device['os']) $($Device['osVersion']) $($Device['deviceGroup']) $($Device['lastUser']) $(@($Device['tags']) -join ' ') $(@($Device['thirdPartyAv']) -join ' ')".ToLowerInvariant() }
    "$($Device.deviceName) $($Device.os) $($Device.osVersion) $($Device.deviceGroup) $($Device.lastUser) $(@($Device.tags) -join ' ') $(@($Device.thirdPartyAv) -join ' ')".ToLowerInvariant()
}

function Get-WlDeviceStats {
    <#
    .SYNOPSIS
    Counts for the device charts (per protection feature, signatures, sensor, run mode, platform, device group,
    devices with issues) – stored in the snapshot so the portal does not need the device list for the overview.
    Reads the pre-computed _filter tokens; devices without them (unit tests) are classified on the fly.
    #>
    param([AllowEmptyCollection()][object[]]$Devices)
    $chartIds = @($script:WlDeviceFeatures) + @('sig', 'sensor', 'mode', '3pav')
    $counts = @{}; foreach ($c in $chartIds + @('os')) { $counts[$c] = [System.Collections.Generic.Dictionary[string, int]]::new() }
    $groups = [System.Collections.Generic.Dictionary[string, int]]::new(); $issues = 0; $n = 0
    foreach ($d in $Devices) {
        if ($null -eq $d) { continue }
        $n++
        $isDict = $d -is [System.Collections.IDictionary]
        $props = $null; if (-not $isDict) { $props = $d.PSObject.Properties }
        $get = { param($name) if ($isDict) { return $d[$name] }; $p = $props[$name]; if ($p) { return $p.Value }; $null }
        $filter = & $get '_filter'
        if (-not $filter) { $filter = Get-WlDeviceFilter -Device $d }
        foreach ($tok in ([string]$filter).Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
            $i = $tok.IndexOf(':'); if ($i -lt 1) { continue }
            $k = $tok.Substring(0, $i); $v = $tok.Substring($i + 1)
            if ($k -eq 'issue') { if ($v -eq '1') { $issues++ }; continue }
            if ($counts.ContainsKey($k)) { $counts[$k][$v] = $(if ($counts[$k].ContainsKey($v)) { $counts[$k][$v] + 1 } else { 1 }) }
        }
        $os = [string](& $get 'os'); if (-not $os) { $os = '–' }
        $counts['os'][$os] = $(if ($counts['os'].ContainsKey($os)) { $counts['os'][$os] + 1 } else { 1 })
        $g = [string](& $get 'deviceGroup')
        if ($g) { $groups[$g] = $(if ($groups.ContainsKey($g)) { $groups[$g] + 1 } else { 1 }) }
    }
    $charts = [ordered]@{}
    foreach ($c in $chartIds + @('os')) { $o = [ordered]@{}; foreach ($k in ($counts[$c].Keys | Sort-Object)) { $o[$k] = $counts[$c][$k] }; $charts[$c] = $o }
    $grp = [ordered]@{}; foreach ($k in ($groups.Keys | Sort-Object)) { $grp[$k] = $groups[$k] }
    [ordered]@{ devices = $n; issues = $issues; charts = $charts; groups = $grp }
}

function ConvertFrom-WlDeviceIndexRow {
    # Index rows are strings; give the portal the same shapes as the full device object (numbers, checks object).
    param([Parameter(Mandatory)]$Index, [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Row)
    $o = [ordered]@{}
    $names = $Index.names
    for ($i = 0; $i -lt $names.Count; $i++) {
        $name = $names[$i]
        if ($name -eq 'page' -or $name.StartsWith('_')) { continue }
        $v = if ($i -lt $Row.Count) { $Row[$i] } else { '' }
        switch ($name) {
            'checks' { $c = [ordered]@{}; foreach ($kv in $v.Split(';')) { $e = $kv.IndexOf('='); if ($e -gt 0) { $c[$kv.Substring(0, $e)] = $kv.Substring($e + 1) } }; $o.checks = $c }
            { $_ -in 'asrBelowMinimum', 'asrBlocked', 'localExclusions', 'exclusionAlerts', 'tampering30d', 'troubleshooting30d' } { $o[$name] = $(if ($v -eq '') { $null } else { [int]$v }) }
            'localExclusionsHighRisk' { $o[$name] = ($v -match '^(true|1)$') }
            'internetFacing' { $o[$name] = $(if ($v -eq '') { $null } else { $v -match '^(true|1)$' }) }
            { $_ -in 'tags', 'thirdPartyAv' } { $o[$name] = @($v.Split(';', [StringSplitOptions]::RemoveEmptyEntries)) }
            default { $o[$name] = $(if ($v -eq '') { $null } else { $v }) }
        }
    }
    [pscustomobject]$o
}

function Search-WlDevices {
    <#
    .SYNOPSIS
    Server-side device list for the portal: free text (name, platform, version, group, user), platform, device
    group, only devices with issues, chart segment (<chart>|<state>), ASR below minimum; paged and sorted (issues
    first, then by name). Works on the cached columnar index with pre-computed filter tokens.
    #>
    param([string]$Query, [string]$Os, [string]$Group, [switch]$IssuesOnly, [string]$Chart, [switch]$AsrBelow, [int]$Page = 0, [int]$Size = 200)
    $ix = Get-WlPagedIndexRaw -Module 'endpoint' -Name 'devices'
    $cols = $ix.cols
    $q = ([string]$Query).Trim().ToLowerInvariant()
    $tokens = [System.Collections.Generic.List[string]]::new()
    if ($Chart -match '^([^|]+)\|(.+)$') { if ($Matches[1] -eq 'os') { if (-not $Os) { $Os = $Matches[2] } } else { $tokens.Add(" $($Matches[1]):$($Matches[2]) ") } }
    if ($IssuesOnly) { $tokens.Add(' issue:1 ') }
    if ($AsrBelow) { $tokens.Add(' asrBelow:1 ') }
    $ciOs = $cols['os']; $ciGroup = $cols['deviceGroup']; $ciFilter = $cols['_filter']; $ciSearch = $cols['_search']; $ciName = $cols['deviceName']
    $hits = [System.Collections.Generic.List[string[]]]::new()
    $keys = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $ix.rows) {
        if ($Os -and $r[$ciOs] -ne $Os) { continue }
        if ($Group -and $r[$ciGroup] -ne $Group) { continue }
        if ($tokens.Count) { $f = $r[$ciFilter]; $ok = $true; foreach ($t in $tokens) { if (-not $f.Contains($t)) { $ok = $false; break } }; if (-not $ok) { continue } }
        if ($q -and -not $r[$ciSearch].Contains($q)) { continue }
        $hits.Add($r)
        $keys.Add($(if ($r[$ciFilter].Contains(' issue:1 ')) { '0' } else { '1' }) + $r[$ciName])
    }
    $order = [int[]]::new($hits.Count); for ($i = 0; $i -lt $order.Length; $i++) { $order[$i] = $i }
    $keyArr = $keys.ToArray()
    [Array]::Sort($keyArr, $order, [StringComparer]::OrdinalIgnoreCase)
    $Size = [Math]::Max(1, [Math]::Min(1000, $Size)); if ($Page -lt 0) { $Page = 0 }
    $start = $Page * $Size
    $rows = [System.Collections.Generic.List[object]]::new()
    for ($i = $start; $i -lt $hits.Count -and $i -lt $start + $Size; $i++) { $rows.Add((ConvertFrom-WlDeviceIndexRow -Index $ix -Row $hits[$order[$i]])) }
    [ordered]@{
        total = $hits.Count; page = $Page; size = $Size; pages = [int][Math]::Ceiling($hits.Count / $Size)
        rows  = @($rows.ToArray())
    }
}

function Get-WlDevice {
    param([Parameter(Mandatory)][string]$DeviceId)
    Get-WlPagedItem -Module 'endpoint' -Name 'devices' -Property 'deviceId' -Value $DeviceId
}
#endregion

function Merge-WlDeviceFindings {
    <#
    .SYNOPSIS
    Large fleets: when the same per-device finding (category, subject, severity) affects more devices than
    WL_FINDING_ROLLUP (default 200), the individual findings are replaced by one rolled-up finding with the
    device count and a sample of device names. Below the threshold, findings stay per device.
    #>
    param([AllowEmptyCollection()][object[]]$Findings, [int]$Threshold = [int](Get-WlSetting -Name 'WL_FINDING_ROLLUP' -Default '200'))
    $out = [System.Collections.Generic.List[object]]::new()
    $groups = [ordered]@{}
    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }
        if (-not $f.deviceId) { $out.Add($f); continue }
        $subject = [string]$f.subject
        $gk = if ($subject) { "$($f.category)|$($f.severity)|$subject" } else { "$($f.category)|$($f.severity)|$(([string]$f.title.en).Replace([string]$f.deviceName, '*'))" }
        if (-not $groups.Contains($gk)) { $groups[$gk] = [System.Collections.Generic.List[object]]::new() }
        $groups[$gk].Add($f)
    }
    foreach ($gk in $groups.Keys) {
        $g = $groups[$gk]
        if ($g.Count -le $Threshold) { foreach ($f in $g) { $out.Add($f) }; continue }
        $first = $g[0]
        $names = @($g | ForEach-Object { [string]$_.deviceName } | Where-Object { $_ } | Sort-Object -Unique)
        $n = $g.Count
        $sub = { param($text, $en) $s = [string]$text; if ($first.deviceName -and $s.Contains([string]$first.deviceName)) { $s.Replace([string]$first.deviceName, $(if ($en) { "$n devices" } else { "$n Geräten" })) } else { "$s ($(if ($en) { "$n devices" } else { "$n Geräte" }))" } }
        $sample = @($names | Select-Object -First 25)
        $more = $names.Count - $sample.Count
        $title = New-WlText -En (& $sub (Get-WlProp $first.title 'en') $true) -De (& $sub (Get-WlProp $first.title 'de') $false)
        $detail = New-WlText -En "$n devices are affected. Example from $($first.deviceName): $(Get-WlProp $first.detail 'en') Devices (sample): $($sample -join ', ')$(if ($more -gt 0) { " and $more more" }). Use the device list with the matching filter for the full set." `
            -De "$n Geräte sind betroffen. Beispiel von $($first.deviceName): $(Get-WlProp $first.detail 'de') Geräte (Auswahl): $($sample -join ', ')$(if ($more -gt 0) { " und $more weitere" }). Die vollständige Menge zeigt die Geräteliste mit passendem Filter."
        $r = New-WlFinding -Severity $first.severity -Category $first.category -Title $title -Detail $detail -Recommendation $first.recommendation -Subject "rollup|$gk" -StableKey
        $r | Add-Member -NotePropertyName deviceCount -NotePropertyValue $n
        $r | Add-Member -NotePropertyName deviceSample -NotePropertyValue $sample
        $out.Add($r)
    }
    @($out | Sort-Object { $script:WlSeverityOrder[$_.severity] }, category, { Get-WlProp $_.title 'en' })
}

function Invoke-WlEndpointCollection {
    <#
    .SYNOPSIS
    Full run of the endpoint module; writes the snapshot, state and drift to storage.
    #>
    Reset-WlWarnings
    $started = [DateTime]::UtcNow
    Write-Information "Wardline endpoint: start $($started.ToString('o'))" -InformationAction Continue

    $baseline = Get-WlBaseline
    $pol = Get-WlEndpointPolicies
    $indicators = Get-WlAllowIndicators
    $response = Get-WlResponseFacts
    $devices = Get-WlDeviceStates

    $prevLocal = @()
    try { $prevLocal = @(Get-WlBlob -Container 'state' -Name 'endpoint-localstate.json') } catch { Add-WlWarning "Local exclusion state could not be read: $($_.Exception.Message)" }
    $events = Get-WlLocalExclusionEvents
    $inventory = Resolve-WlInventoryDevices -Inventory @(Get-WlDeviceInventory) -Devices $devices
    $local = Update-WlLocalExclusionState -Events $events -Previous $prevLocal -Inventory $inventory

    Get-WlAsrDeviceStates -Devices $devices
    $asr = Get-WlAsrOverview -Baseline $baseline -SettingValues $pol.SettingValues -Devices $devices
    $linuxEvents = Get-WlLinuxConfigEvents

    $coverage = Get-WlCoverage -Devices $devices
    $fleet = Get-WlFleetFacts -Devices $devices
    Add-WlExclusionUsage -Exclusions (@($pol.Exclusions) + @($local | Where-Object { $_.present }))

    $baselineResults = Test-WlBaseline -Baseline $baseline -SettingValues $pol.SettingValues -Devices $devices
    $findings = @(Get-WlEndpointFindings -Devices $devices -PolicyExclusions $pol.Exclusions -LocalExclusions $local -Indicators $indicators -Baseline $baselineResults -SettingValues $pol.SettingValues -Asr $asr -LinuxEvents $linuxEvents -Policies $pol.Policies) +
        @(Get-WlCoverageFindings -Coverage $coverage) + @(Get-WlUsageFindings -Exclusions (@($pol.Exclusions) + @($local | Where-Object { $_.present }))) +
        @(Get-WlResponseFindings -Facts $response -WindowsDevices @($devices.Values | Where-Object { $_.os -eq 'Windows' }).Count) +
        @(Get-WlFleetFindings -Devices $devices -Facts $fleet)
    $findings = @(Merge-WlDeviceFindings -Findings $findings)

    $deviceList = @($(foreach ($d in $devices.Values) {
                $d.key = Get-WlHash "dev|$($d.deviceId)"
                $d.label = New-WlText "Device $($d.deviceName)" "Gerät $($d.deviceName)"
                $d.state = "Mode=$($d.avModeText); " + (@($d.checks.Keys | ForEach-Object { "$_=$($d.checks[$_])" }) -join '; ') +
                $(if ($d.asr) { '; ASR ' + (@($d.asr.Keys | ForEach-Object { "$_=$($d.asr[$_])" }) -join ',') } else { '' })
                $d.fp = Get-WlHash "$($d.state)|$($d.localExclusions)"
                $d._filter = Get-WlDeviceFilter -Device $d
                $d._search = Get-WlDeviceSearchText -Device $d
                [pscustomobject]$d
            }) | Sort-Object deviceName, deviceId)

    $seen = @($pol.SettingValues | ForEach-Object { $_.definitionId } | Sort-Object -Unique)
    $sevCount = [ordered]@{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $sevCount[$s] = @($findings | Where-Object { $_.severity -eq $s }).Count }

    $snapshot = [ordered]@{
        module               = 'endpoint'
        version              = (Get-WlVersion)
        generatedAt          = [DateTime]::UtcNow.ToString('o')
        tenantId             = Get-WlSetting -Name 'WL_TENANT_ID'
        baselineName         = ConvertTo-WlText (Get-WlProp $baseline 'name')
        baselineSource       = [string](Get-WlProp $baseline 'source')
        localDetection       = $(if (Test-WlFeature -Name 'inventory') { 'AdvancedHuntingAndInventory' } else { 'AdvancedHunting' })
        summary              = [ordered]@{
            devices                = @($deviceList).Count
            devicesWithInventory   = @($inventory).Count
            policyExclusions       = @($pol.Exclusions).Count
            localExclusionsPresent = @($local | Where-Object { $_.present }).Count
            allowIndicators        = @($indicators).Count
            edrExclusions          = @(@($pol.Exclusions) + @($local | Where-Object { $_.present }) | Where-Object { $_.scope -eq 'Global' }).Count + @($indicators).Count
            asrRulesOk             = @($asr.rules | Where-Object { $_.status -eq 'OK' }).Count
            asrRulesTotal          = @($asr.rules).Count
            asrDevicesBelow        = @($deviceList | Where-Object { $_.asrBelowMinimum -gt 0 }).Count
            findings               = $sevCount
            coverageGaps           = @($coverage | Where-Object { $_.status -ne 'CanBeOnboarded' }).Count
            discoveredDevices      = @($coverage | Where-Object { $_.status -eq 'CanBeOnboarded' }).Count
            unusedExclusions       = @(@($pol.Exclusions) + @($local | Where-Object { $_.present }) | Where-Object { $_.usage -eq 'Unused' }).Count
            baselineOk             = @($baselineResults | Where-Object { $_.status -eq 'OK' }).Count
            baselineTotal          = @($baselineResults).Count
            responseActions90d     = $(if ($response) { @($response.actions).Count } else { $null })
            alertsPendingApproval  = $(if ($response) { @($response.alerts | Where-Object { $_.investigationState -eq 'PendingApproval' }).Count } else { $null })
            fleet                  = [ordered]@{
                internetFacingHigh    = @($deviceList | Where-Object { $_.internetFacing -eq $true -and $_.exposure -eq 'High' }).Count
                troubleshootingActive = @($deviceList | Where-Object { $_.troubleshootingActive }).Count
                troubleshooting30d    = @($deviceList | Where-Object { $_.troubleshooting30d -gt 0 }).Count
                tampering30d          = @($deviceList | Where-Object { $_.tampering30d -gt 0 }).Count
                thirdPartyAv          = @($deviceList | Where-Object { @($_.thirdPartyAv).Count -gt 0 }).Count
                tvmExcluded           = @($deviceList | Where-Object { $_.tvmExcluded -eq $true }).Count
                tagged                = @($deviceList | Where-Object { @($_.tags).Count -gt 0 }).Count
                transient             = @($deviceList | Where-Object { $_.transient -eq $true }).Count
                inactive90d           = $(if (Test-WlFeature -Name 'response') { @($fleet.inactive).Count } else { $null })
            }
        }
        policies             = @($pol.Policies)
        policyExclusions     = @($pol.Exclusions)
        localExclusions      = @($local)
        indicators           = @($indicators)
        deviceStats          = Get-WlDeviceStats -Devices $deviceList
        devices              = @($deviceList)
        coverage             = @($coverage | Sort-Object status, deviceName)
        baseline             = @($baselineResults)
        asrRules             = @($asr.rules)
        asrGroups            = @($asr.groups)
        asrCatalog           = @($asr.catalog)
        localConfigEvents    = @($linuxEvents | Select-Object -Last 500)
        responseActions      = @($(if ($response) { $response.actions } else { @() }))
        inactiveDevices      = @($fleet.inactive | Select-Object -First 1000)
        findings             = @($findings)
        seenDefenderSettings = $seen
        warnings             = @(Get-WlWarnings)
    }

    Set-WlBlob -Container 'state' -Name 'endpoint-localstate.json' -Object @($local)
    $r = Save-WlSnapshot -Module 'endpoint' -Snapshot $snapshot -Collections @('policyExclusions', 'localExclusions', 'indicators', 'devices', 'coverage', 'baseline', 'asrRules', 'asrGroups', 'findings') -Started $started `
        -Paged @('devices', 'coverage') -Index @{ devices = $script:WlDeviceIndexColumns; coverage = @('deviceId', 'deviceName', 'status', 'os', 'source', 'user', 'lastSeen', 'aadDeviceId', 'intuneDeviceId') }
    Write-Information "Wardline endpoint: done, $($r.changes) change(s), $($r.warnings) warning(s)." -InformationAction Continue
    $r
}
