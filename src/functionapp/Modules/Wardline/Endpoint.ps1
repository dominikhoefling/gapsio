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
        inventoryAt = $null; localMergeDisabled = $null
        avMode = $null; avModeText = 'Unknown'; signatureUpToDate = $null; platformUpToDate = $null; engineUpToDate = $null
        checks = [ordered]@{}; localExclusions = 0; localExclusionsHighRisk = 0; exclusionAlerts = 0; asr = $null; asrBelowMinimum = $null; asrBlocked = $null
    }
}

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
                    value = $v.value; display = $v.display; kind = $v.kind; group = $v.group; assignments = $assignText
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

    $qInfo = @"
DeviceInfo
| where Timestamp > ago(${days}d)
| summarize arg_max(Timestamp, DeviceName, OSPlatform, OSVersion, MachineGroup, DeviceType, OnboardingStatus, AadDeviceId) by DeviceId
| where isempty(OnboardingStatus) or OnboardingStatus == "Onboarded"
| project DeviceId, DeviceName, OSPlatform, OSVersion, MachineGroup, DeviceType, AadDeviceId, LastSeen = Timestamp
"@
    foreach ($r in @(Invoke-WlHuntingSafe -Query $qInfo -Context 'Advanced Hunting DeviceInfo')) {
        if ($null -eq $r) { continue }
        $d = New-WlDevice -Id ([string]$r.DeviceId) -Name ([string]$r.DeviceName) -Os ([string]$r.OSPlatform)
        $d.osVersion = [string]$r.OSVersion; $d.deviceGroup = [string]$r.MachineGroup; $d.deviceType = [string]$r.DeviceType
        $d.lastSeen = [string]$r.LastSeen; $d.aadDeviceId = [string]$r.AadDeviceId
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
| where ConfigurationName has_any ("tamper", "real-time", "real time", "cloud", "potentially unwanted", "PUA", "behavior", "passive", "antivirus", "Defender")
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
            'tamper' { 'TamperProtection'; break }
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

    $qInfoG = @"
DeviceTvmInfoGathering
| summarize arg_max(Timestamp, AdditionalFields) by DeviceId
| extend f = parse_json(AdditionalFields)
| project DeviceId, AvMode = tostring(f.AvMode), AvSig = tostring(f.AvIsSignatureUptoDate), AvPlat = tostring(f.AvIsPlatformUptodate), AvEng = tostring(f.AvIsEngineUptoDate)
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
        $s.fp = Get-WlHash "$($s.present)|$($s.removedAt)"
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
    param([string]$Severity, [string]$Category, $Title, $Detail, $Recommendation, [string]$Subject, [string]$DeviceId, [string]$DeviceName)
    $titleEn = [string](Get-WlProp $Title 'en'); if (-not $titleEn) { $titleEn = [string]$Title }
    [pscustomobject]@{
        key            = Get-WlHash "find|$Category|$titleEn|$Subject|$DeviceId"
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
    }
}

function Get-WlEndpointFindings {
    <#
    .SYNOPSIS
    Derives findings – especially combined findings (e.g. Tamper Protection off AND local exclusions).
    #>
    param([hashtable]$Devices, [object[]]$PolicyExclusions, [object[]]$LocalExclusions, [object[]]$Indicators, [object[]]$Baseline, [object[]]$SettingValues,
        $Asr, [object[]]$LinuxEvents)
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

    @($f | Sort-Object { $script:WlSeverityOrder[$_.severity] }, category, { Get-WlProp $_.title 'en' })
}
#endregion

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
    $devices = Get-WlDeviceStates

    $prevLocal = @()
    try { $prevLocal = @(Get-WlBlob -Container 'state' -Name 'endpoint-localstate.json') } catch { Add-WlWarning "Local exclusion state could not be read: $($_.Exception.Message)" }
    $events = Get-WlLocalExclusionEvents
    $inventory = Resolve-WlInventoryDevices -Inventory @(Get-WlDeviceInventory) -Devices $devices
    $local = Update-WlLocalExclusionState -Events $events -Previous $prevLocal -Inventory $inventory

    Get-WlAsrDeviceStates -Devices $devices
    $asr = Get-WlAsrOverview -Baseline $baseline -SettingValues $pol.SettingValues -Devices $devices
    $linuxEvents = Get-WlLinuxConfigEvents

    $baselineResults = Test-WlBaseline -Baseline $baseline -SettingValues $pol.SettingValues -Devices $devices
    $findings = Get-WlEndpointFindings -Devices $devices -PolicyExclusions $pol.Exclusions -LocalExclusions $local -Indicators $indicators -Baseline $baselineResults -SettingValues $pol.SettingValues -Asr $asr -LinuxEvents $linuxEvents

    $deviceList = foreach ($d in $devices.Values) {
        $d.key = Get-WlHash "dev|$($d.deviceId)"
        $d.label = New-WlText "Device $($d.deviceName)" "Gerät $($d.deviceName)"
        $d.state = "Mode=$($d.avModeText); " + (@($d.checks.Keys | ForEach-Object { "$_=$($d.checks[$_])" }) -join '; ') +
        $(if ($d.asr) { '; ASR ' + (@($d.asr.Keys | ForEach-Object { "$_=$($d.asr[$_])" }) -join ',') } else { '' })
        $d.fp = Get-WlHash "$($d.state)|$($d.localExclusions)"
        [pscustomobject]$d
    }

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
            baselineOk             = @($baselineResults | Where-Object { $_.status -eq 'OK' }).Count
            baselineTotal          = @($baselineResults).Count
        }
        policies             = @($pol.Policies)
        policyExclusions     = @($pol.Exclusions)
        localExclusions      = @($local)
        indicators           = @($indicators)
        devices              = @($deviceList)
        baseline             = @($baselineResults)
        asrRules             = @($asr.rules)
        asrGroups            = @($asr.groups)
        asrCatalog           = @($asr.catalog)
        localConfigEvents    = @($linuxEvents | Select-Object -Last 500)
        findings             = @($findings)
        seenDefenderSettings = $seen
        warnings             = @(Get-WlWarnings)
    }

    Set-WlBlob -Container 'state' -Name 'endpoint-localstate.json' -Object @($local)
    $r = Save-WlSnapshot -Module 'endpoint' -Snapshot $snapshot -Collections @('policyExclusions', 'localExclusions', 'indicators', 'devices', 'baseline', 'asrRules', 'asrGroups', 'findings') -Started $started
    Write-Information "Wardline endpoint: done, $($r.changes) change(s), $($r.warnings) warning(s)." -InformationAction Continue
    $r
}
