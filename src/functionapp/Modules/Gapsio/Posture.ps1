# Gapsio posture checks that build on the endpoint data. All read-only; only the detection rules need a permission
# of their own.
#   - Policy conflicts      Intune settings that reach the same device with different values (no extra permission)
#   - Device control        USB storage in use versus device control policies (Advanced Hunting, no extra permission)
#   - Attack disruption     what can be verified of the prerequisites of automatic attack disruption – and what cannot
#   - Detection rules       custom detection rules that were switched off, fail or act automatically
#                           (feature Detections: CustomDetection.Read.All)
# Sources are documented Microsoft APIs and Advanced Hunting tables; everything Microsoft does not expose is reported
# as "not measurable", never guessed.

#region Which devices does a policy reach?
function Get-GapsioDeviceMatchKeys {
    # Keys a device can be matched by in group memberships: its Entra device ID and its last user.
    param($Device)
    $keys = @()
    if ($Device.aadDeviceId) { $keys += "dev:$($Device.aadDeviceId)" }
    if ($Device.lastUser) { $u = [string]$Device.lastUser; $keys += "upn:$u"; $keys += "usr:$((($u -split '\\')[-1] -split '@')[0])" }
    , @($keys)
}

function Test-GapsioAssignmentTargetsDevice {
    <#
    .SYNOPSIS
    Whether the raw Intune assignments of a policy reach a device: all devices / all users / a group the device or its
    last user is in, minus exclusion groups. Devices without an Entra device ID only match "all devices/users".
    #>
    param([object[]]$Assignments, [string[]]$Keys, [hashtable]$Cache)
    $in = $false; $out = $false
    $member = { param($g) $m = Get-GapsioGroupMemberKeys -GroupId $g -Cache $Cache; $null -ne $m -and @($Keys | Where-Object { $m.Contains($_) }).Count -gt 0 }
    foreach ($a in @($Assignments)) {
        $t = Get-GapsioProp $a 'target'; $type = [string](Get-GapsioProp $t '@odata.type'); $gid = [string](Get-GapsioProp $t 'groupId')
        switch -Wildcard ($type) {
            '*allDevicesAssignmentTarget' { $in = $true }
            '*allLicensedUsersAssignmentTarget' { $in = $true }
            '*exclusionGroupAssignmentTarget' { if ($gid -and (& $member $gid)) { $out = $true } }
            '*groupAssignmentTarget' { if ($gid -and -not $in -and (& $member $gid)) { $in = $true } }
        }
    }
    $in -and -not $out
}

function Get-GapsioPolicyDeviceMap {
    <#
    .SYNOPSIS
    Policy ID -> IDs of the devices the policy reaches (platform family and assignments). Only for the given policies.
    #>
    param([hashtable]$Devices, [hashtable]$Targets, [hashtable]$PolicyPlatform, [hashtable]$Cache = @{})
    $map = @{}
    foreach ($polId in $PolicyPlatform.Keys) { $map[[string]$polId] = [System.Collections.Generic.HashSet[string]]::new() }
    if (-not $Devices -or -not $Targets) { return $map }
    foreach ($d in $Devices.Values) {
        $keys = Get-GapsioDeviceMatchKeys -Device $d
        $family = if ($d.os) { Get-GapsioPlatformText ([string]$d.os) } else { $null }
        foreach ($polId in $PolicyPlatform.Keys) {
            $plat = [string]$PolicyPlatform[$polId]
            if ($plat -and $family -and (Get-GapsioPlatformText $plat) -ne $family) { continue }
            if (Test-GapsioAssignmentTargetsDevice -Assignments @($Targets[$polId]) -Keys $keys -Cache $Cache) { [void]$map[[string]$polId].Add([string]$d.deviceId) }
        }
    }
    $map
}
#endregion

#region Policy conflicts
function Get-GapsioSettingShortName {
    # Readable name of a Settings Catalog definition ID (ASR rules by their name).
    param([string]$DefinitionId)
    $d = [string]$DefinitionId
    if ($d -match 'attacksurfacereductionrules_(.+)$' -and $d -notmatch 'exclusions') { return "ASR: $(Get-GapsioAsrRuleName -Suffix $Matches[1])" }
    $d -replace '^(device_vendor_msft_policy_config_defender_|device_vendor_msft_defender_configuration_|device_vendor_msft_policy_config_|com\.apple\.managedclient\.preferences_|linux_mdatp_managed_|user_vendor_msft_policy_config_)', ''
}

function Get-GapsioPolicyConflicts {
    <#
    .SYNOPSIS
    Settings that reach the same device from two or more assigned Intune policies with different values.
    Microsoft: "When multiple policies configure the same setting with different values, the setting might fail to
    apply and be flagged as conflicted"; conflicting ASR rules are left out of the merged rule set
    (learn.microsoft.com/intune/intune-service/protect/endpoint-security-policy, …/endpoint-security-asr-policy).
    Only single-value settings are compared (choices, switches, numbers) – lists such as exclusions merge and are not
    conflicts. Without device data (feature Hunting off) the overlap is judged by the assignment texts.
    #>
    param([object[]]$SettingValues, [hashtable]$Devices, [hashtable]$Targets)
    $rows = @($SettingValues | Where-Object {
            $_ -and (Test-GapsioAssigned $_.assignments) -and ($_.kind -eq 'choice' -or ($_.kind -eq 'simple' -and ([string]$_.value) -match '^(true|false|-?\d+)$'))
        })
    $perPolicy = @{}
    foreach ($r in $rows) { $k = "$($r.policyId)|$($r.definitionId)"; $perPolicy[$k] = 1 + [int]$perPolicy[$k] }
    $byDef = [ordered]@{}
    foreach ($r in $rows) {
        if ($perPolicy["$($r.policyId)|$($r.definitionId)"] -gt 1) { continue }   # the same setting several times in one policy = list entry
        $k = "$($r.platform)|$($r.definitionId)"
        if (-not $byDef.Contains($k)) { $byDef[$k] = [System.Collections.Generic.List[object]]::new() }
        $byDef[$k].Add($r)
    }
    $candidates = @($byDef.Keys | Where-Object { @($byDef[$_] | ForEach-Object { [string]$_.value } | Sort-Object -Unique).Count -gt 1 })
    if (-not $candidates.Count) { return @() }

    $haveDevices = $Devices -and $Devices.Count -gt 0
    $map = @{}
    if ($haveDevices) {
        $platforms = @{}
        foreach ($k in $candidates) { foreach ($r in $byDef[$k]) { $platforms[[string]$r.policyId] = [string]$r.platform } }
        $map = Get-GapsioPolicyDeviceMap -Devices $Devices -Targets $Targets -PolicyPlatform $platforms
    }
    $short = { param($r) $v = [string]$r.value; $p = "$($r.definitionId)_"; if ($r.display) { [string]$r.display } elseif ($v.StartsWith($p, [StringComparison]::OrdinalIgnoreCase)) { $v.Substring($p.Length) } else { $v } }
    $out = foreach ($k in $candidates) {
        $list = $byDef[$k]; $first = $list[0]
        $affected = $null; $names = @(); $overlap = 'Assignment'
        if ($haveDevices) {
            $valuesByDevice = @{}
            foreach ($r in $list) {
                foreach ($id in $map[[string]$r.policyId]) {
                    if (-not $valuesByDevice.ContainsKey($id)) { $valuesByDevice[$id] = [System.Collections.Generic.HashSet[string]]::new() }
                    [void]$valuesByDevice[$id].Add([string]$r.value)
                }
            }
            $hit = @($valuesByDevice.Keys | Where-Object { $valuesByDevice[$_].Count -gt 1 })
            if (-not $hit.Count) { continue }   # the policies go to different devices (rings) – no conflict
            $affected = $hit.Count; $overlap = 'Devices'
            $names = @($hit | ForEach-Object { [string]$Devices[$_].deviceName } | Sort-Object | Select-Object -First 20)
        }
        else {
            # No device data: a conflict is likely when two policies with different values share a target
            $shared = $false
            for ($i = 0; $i -lt $list.Count -and -not $shared; $i++) {
                for ($j = $i + 1; $j -lt $list.Count -and -not $shared; $j++) {
                    if ([string]$list[$i].value -eq [string]$list[$j].value) { continue }
                    $a = @($list[$i].assignments | Where-Object { $_ -notlike 'Excluded:*' }); $b = @($list[$j].assignments | Where-Object { $_ -notlike 'Excluded:*' })
                    if (@($a | Where-Object { $_ -in $b -or $_ -in 'All devices', 'All users' }).Count -or @($b | Where-Object { $_ -in 'All devices', 'All users' }).Count) { $shared = $true }
                }
            }
            if (-not $shared) { continue }
        }
        $values = @($list | Group-Object { [string]$_.value } | ForEach-Object {
                [pscustomobject]@{
                    value    = (& $short $_.Group[0])
                    policies = @($_.Group | ForEach-Object { [pscustomobject]@{ id = [string]$_.policyId; name = [string]$_.policyName; assignments = @($_.assignments) } })
                }
            } | Sort-Object value)
        $setting = Get-GapsioSettingShortName -DefinitionId $first.definitionId
        [pscustomobject]@{
            key          = Get-GapsioHash "conflict|$k"
            fp           = Get-GapsioHash ((@($values | ForEach-Object { "$($_.value)=$((@($_.policies | ForEach-Object id)) -join ',')" }) -join ';') + "|$affected")
            label        = New-GapsioText "Policy conflict: $setting" "Policy-Konflikt: $setting"
            state        = "$(@($values).Count) values, $(if ($null -ne $affected) { "$affected device(s)" } else { 'shared assignment' })"
            definitionId = [string]$first.definitionId
            setting      = $setting
            platform     = [string]$first.platform
            isAsrRule    = [bool]($setting -like 'ASR:*')
            values       = $values
            overlap      = $overlap
            devices      = $affected
            deviceNames  = $names
        }
    }
    @($out | Sort-Object @{ Expression = { [int]$_.devices }; Descending = $true }, setting)
}

function Get-GapsioPolicyConflictFindings {
    param([object[]]$Conflicts)
    $c = @($Conflicts | Where-Object { $_ })
    if (-not $c.Count) { return @() }
    $T = { param($en, $de) New-GapsioText -En $en -De $de }
    $line = { param($x) "$($x.setting) [$($x.platform)]: $((@($x.values | ForEach-Object { "$($_.value) ($((@($_.policies | ForEach-Object name)) -join ', '))" })) -join ' vs. ')$(if ($null -ne $x.devices) { " – $($x.devices) device(s)" })" }
    $list = (@($c | Select-Object -First 6 | ForEach-Object { & $line $_ })) -join '; '
    $more = if ($c.Count -gt 6) { ' …' } else { '' }
    $asr = @($c | Where-Object { $_.isAsrRule }).Count
    @(New-GapsioFinding -Severity 'Medium' -Category 'Conflict' -Title (& $T "$($c.Count) Defender setting(s) reach the same devices with different values" "$($c.Count) Defender-Einstellung(en) erreichen dieselben Geräte mit unterschiedlichen Werten") `
            -Detail (& $T "Two or more assigned Intune policies configure the same setting differently for the same devices: $list$more. Intune treats all policy types as equal – a conflicting setting may not be applied at all$(if ($asr) { ", and a conflicting ASR rule is left out of the merged rule set ($asr rule(s) here)" })." `
                "Zwei oder mehr zugewiesene Intune-Richtlinien konfigurieren dieselbe Einstellung für dieselben Geräte unterschiedlich: $list$more. Intune behandelt alle Richtlinientypen gleichrangig – eine Einstellung im Konflikt wird möglicherweise gar nicht angewendet$(if ($asr) { ", und eine ASR-Regel im Konflikt fehlt im zusammengeführten Regelsatz (hier $asr Regel(n))" }).") `
            -Recommendation (& $T 'Decide on one value per setting: remove it from one of the policies or separate the assignments (exclusion groups). Check the affected devices on the Baseline and ASR pages – they show what is actually in effect.' 'Pro Einstellung für einen Wert entscheiden: aus einer der Richtlinien entfernen oder die Zuweisungen trennen (Ausschlussgruppen). Die betroffenen Geräte auf den Seiten Baseline und ASR prüfen – dort steht, was tatsächlich wirkt.') `
            -Subject 'conflict|settings' -StableKey)
}
#endregion

#region Device control
# Settings that configure device control or removable storage (Defender device control, removable storage access,
# device installation restrictions).
$script:GapsioDeviceControlSetting = 'devicecontrol|removablestorage|removabledisk|deviceinstallation_(prevent|allow)'

function Get-GapsioDeviceControl {
    <#
    .SYNOPSIS
    USB storage in use versus device control:
      - Intune policies with device control / removable storage settings and the devices they reach
      - USB drive mounts per device (DeviceEvents, ActionType UsbDriveMounted) – reported for onboarded devices by default
      - device control policy events (DeviceEvents, ActionType RemovableStoragePolicyTriggered; Microsoft caps them at
        300 per device and day and only writes them for policies with an audit entry)
    Device control is supported on Windows 10/11 and macOS, not on servers. Policies deployed by Group Policy are not
    visible here.
    #>
    param([object[]]$SettingValues, [hashtable]$Devices, [hashtable]$Targets)
    $polRows = @($SettingValues | Where-Object { $_ -and ([string]$_.definitionId) -match $script:GapsioDeviceControlSetting })
    $policies = @($polRows | Group-Object policyId | ForEach-Object {
            $f = $_.Group[0]
            [pscustomobject]@{ id = [string]$f.policyId; name = [string]$f.policyName; platform = [string]$f.platform; assignments = @($f.assignments); assigned = [bool](Test-GapsioAssigned $f.assignments); settings = $_.Count }
        } | Sort-Object name)
    $assigned = @($policies | Where-Object assigned)
    $map = @{}
    if ($assigned.Count -and $Devices -and $Devices.Count) {
        $platforms = @{}; foreach ($p in $assigned) { $platforms[$p.id] = $p.platform }
        $map = Get-GapsioPolicyDeviceMap -Devices $Devices -Targets $Targets -PolicyPlatform $platforms
    }
    $policyNames = @{}   # deviceId -> names of the device control policies that reach it
    foreach ($p in $assigned) { foreach ($id in @($map[$p.id])) { if (-not $policyNames.ContainsKey($id)) { $policyNames[$id] = [System.Collections.Generic.List[string]]::new() }; $policyNames[$id].Add($p.name) } }

    $usage = if (Test-GapsioFeature -Name 'hunting') { 'ok' } else { 'off' }
    $rows = @{}
    $row = {
        param($Id, $Name)
        if (-not $rows.ContainsKey($Id)) {
            $d = if ($Devices -and $Devices.ContainsKey($Id)) { $Devices[$Id] } else { $null }
            $rows[$Id] = [ordered]@{
                deviceId = $Id; deviceName = $(if ($d) { [string]$d.deviceName } else { [string]$Name }); os = $(if ($d) { [string]$d.os } else { $null })
                supported = $(if ($d) { [bool](([string]$d.os) -match '^(Windows1[01]|macOS)') } else { $null })   # device control: Windows 10/11 and macOS, no servers
                mounts = 0; drives = 0; lastMount = $null; triggers = 0; denied = 0; lastTrigger = $null; triggeredPolicies = @()
                hasPolicy = $(if ($d) { $policyNames.ContainsKey($Id) } else { $null }); policies = $(if ($policyNames.ContainsKey($Id)) { @($policyNames[$Id]) } else { @() })
            }
        }
        $rows[$Id]
    }
    if ($usage -eq 'ok') {
        $qMount = @"
// GapsioUsbMounts
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("UsbDriveMounted", "UsbDriveMount")
| extend f = parse_json(AdditionalFields)
| summarize Mounts = count(), Drives = dcount(tostring(f.SerialNumber)), LastMount = max(Timestamp), Name = take_any(DeviceName) by DeviceId
"@
        $mounts = Invoke-GapsioHuntingSafe -Query $qMount -Context 'Advanced Hunting USB drive mounts'
        if ($null -eq $mounts) { $usage = 'failed' }
        foreach ($r in @($mounts)) {
            if (-not $r -or -not $r.DeviceId) { continue }
            $x = & $row ([string]$r.DeviceId) ([string]$r.Name)
            $x.mounts = [int]$r.Mounts; $x.drives = [int]$r.Drives; $x.lastMount = ConvertTo-GapsioIsoUtc $r.LastMount
        }
        $qTrig = @"
// GapsioDeviceControl
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "RemovableStoragePolicyTriggered"
| extend f = parse_json(AdditionalFields)
| extend Verdict = tolower(tostring(f.RemovableStoragePolicyVerdict))
| summarize Triggers = count(), Denied = countif(Verdict contains "den" or Verdict contains "block"), Policies = make_set(tostring(f.RemovableStoragePolicy), 5), LastTrigger = max(Timestamp), Name = take_any(DeviceName) by DeviceId
"@
        foreach ($r in @(Invoke-GapsioHuntingSafe -Query $qTrig -Context 'Advanced Hunting device control events')) {
            if (-not $r -or -not $r.DeviceId) { continue }
            $x = & $row ([string]$r.DeviceId) ([string]$r.Name)
            $x.triggers = [int]$r.Triggers; $x.denied = [int]$r.Denied; $x.lastTrigger = ConvertTo-GapsioIsoUtc $r.LastTrigger
            $x.triggeredPolicies = @(@($r.Policies) | ForEach-Object { [string]$_ } | Where-Object { $_ })
        }
    }
    $deviceRows = @($rows.Values | ForEach-Object { [pscustomobject]$_ } | Sort-Object @{ Expression = { [int]($_.hasPolicy -eq $false -and $_.supported -eq $true) }; Descending = $true }, @{ Expression = { $_.mounts }; Descending = $true }, deviceName)
    $usb = @($deviceRows | Where-Object { $_.mounts -gt 0 })
    [pscustomobject]@{
        usage    = $usage
        policies = $policies
        devices  = $deviceRows
        summary  = [ordered]@{
            policies         = $policies.Count
            assignedPolicies = $assigned.Count
            usbDevices       = $usb.Count
            usbWithoutPolicy = @($usb | Where-Object { $_.hasPolicy -eq $false -and $_.supported }).Count
            usbMounts        = [int](($usb | Measure-Object mounts -Sum).Sum)
            triggers         = [int](($deviceRows | Measure-Object triggers -Sum).Sum)
            denied           = [int](($deviceRows | Measure-Object denied -Sum).Sum)
        }
    }
}

function Get-GapsioDeviceControlFindings {
    param($DeviceControl)
    if (-not $DeviceControl -or $DeviceControl.usage -ne 'ok') { return @() }
    $T = { param($en, $de) New-GapsioText -En $en -De $de }
    $open = @($DeviceControl.devices | Where-Object { $_.mounts -gt 0 -and $_.hasPolicy -eq $false -and $_.supported })
    if (-not $open.Count) { return @() }
    $names = (@($open | Select-Object -First 8 | ForEach-Object { "$($_.deviceName) ($($_.mounts))" })) -join ', '
    $more = if ($open.Count -gt 8) { ' …' } else { '' }
    $none = [int]$DeviceControl.summary.assignedPolicies -eq 0
    @(New-GapsioFinding -Severity 'Medium' -Category 'DeviceControl' -Title (& $T "USB storage used on $($open.Count) device(s) without a device control policy" "USB-Speicher auf $($open.Count) Gerät(en) ohne Device-Control-Richtlinie genutzt") `
            -Detail (& $T "USB drives were mounted in the last 30 days on devices that no Intune device control or removable storage policy reaches: $names$more (mounts in brackets).$(if ($none) { ' No such policy is assigned in Intune at all.' }) Without device control, data can leave on any USB drive and nothing is blocked or audited." `
                "In den letzten 30 Tagen wurden USB-Laufwerke auf Geräten eingebunden, die keine Intune-Richtlinie für Device Control oder Wechseldatenträger erreicht: $names$more (Einbindungen in Klammern).$(if ($none) { ' In Intune ist überhaupt keine solche Richtlinie zugewiesen.' }) Ohne Device Control können Daten über jeden USB-Stick abfließen, und nichts wird blockiert oder auditiert.") `
            -Recommendation (& $T 'Assign a device control policy (Intune › Endpoint security › Attack surface reduction › Device control) – start in audit mode, then deny write access for unapproved drives. Device control configured by Group Policy is not visible to Gapsio.' 'Eine Device-Control-Richtlinie zuweisen (Intune › Endpunktsicherheit › Verringerung der Angriffsfläche › Gerätesteuerung) – im Audit-Modus beginnen, dann Schreibzugriff für nicht freigegebene Laufwerke verweigern. Per Gruppenrichtlinie konfiguriertes Device Control sieht Gapsio nicht.') `
            -Subject 'devicecontrol|usb-nopolicy' -StableKey)
}
#endregion

#region Attack disruption readiness
# Minimum Sense agent version for the Contain User action (learn.microsoft.com/defender-xdr/configure-attack-disruption).
$script:GapsioContainUserMinSense = [version]'10.8470'

function Get-GapsioDisruptionReadiness {
    <#
    .SYNOPSIS
    What can be verified of the prerequisites of automatic attack disruption
    (learn.microsoft.com/defender-xdr/configure-attack-disruption):
      - Sense agent version for Contain User (DeviceInfo.ClientVersion)                         measurable
      - devices that are managed but not onboarded (cannot be isolated)                          measurable
      - Defender for Identity signals (IdentityDirectoryEvents) – needed to disable AD accounts  measurable
      - disruption events of the last 30 days (DisruptionAndResponseEvents)                      measurable
      - device discovery mode, remediation level of device groups, exclusions from automated
        response (users, device groups, IPs)                                                     no API – listed as
                                                                                                 "not measurable"
    Each check: id, status (OK | Gap | Review | NotMeasurable), title, detail, where (portal path), source.
    #>
    param([hashtable]$Devices, [object[]]$Coverage)
    $T = { param($en, $de) New-GapsioText -En $en -De $de }
    $hunting = Test-GapsioFeature -Name 'hunting'
    $checks = [System.Collections.Generic.List[object]]::new()
    $add = {
        param($Id, $Status, $Title, $Detail, $Where, $Source, $Count, $Total, $DeviceNames)
        $checks.Add([pscustomobject]@{ id = $Id; status = $Status; title = $Title; detail = $Detail; where = $Where; source = $Source; count = $Count; total = $Total; devices = @($DeviceNames) })
    }

    # 1) Sense agent version (Contain User)
    $win = @(@($Devices.Values) | Where-Object { $_ -and ([string]$_.os) -like 'Windows*' })
    $below = [System.Collections.Generic.List[object]]::new(); $known = 0
    foreach ($d in $win) {
        $v = $null
        if (-not [version]::TryParse((([string]$d.clientVersion) -replace '[^0-9.].*$', ''), [ref]$v)) { continue }
        $known++
        if ($v -lt $script:GapsioContainUserMinSense) { $below.Add($d) }
    }
    $min = $script:GapsioContainUserMinSense.ToString()
    if (-not $hunting -or -not $known) {
        & $add 'sense' 'NotMeasurable' (& $T 'Sense agent version for Contain User' 'Sense-Agent-Version für Contain User') `
        (& $T "Contain User needs Sense agent $min or later. No agent versions are available$(if (-not $hunting) { ' (feature Hunting is off)' })." "Contain User braucht den Sense-Agent ab $min. Es liegen keine Agent-Versionen vor$(if (-not $hunting) { ' (Feature Hunting ist aus)' }).") $null 'DeviceInfo.ClientVersion' $null $win.Count @()
    }
    elseif ($below.Count) {
        & $add 'sense' 'Gap' (& $T 'Sense agent version for Contain User' 'Sense-Agent-Version für Contain User') `
        (& $T "$($below.Count) of $known Windows device(s) run a Sense agent older than $min. A contained user can still sign in to these devices." "$($below.Count) von $known Windows-Gerät(en) haben einen Sense-Agent älter als $min. Ein eingedämmter Benutzer kann sich an diesen Geräten weiter anmelden.") `
            $null 'DeviceInfo.ClientVersion' $below.Count $known @($below | Sort-Object deviceName | Select-Object -First 50 | ForEach-Object { "$($_.deviceName) ($($_.clientVersion))" })
    }
    else {
        & $add 'sense' 'OK' (& $T 'Sense agent version for Contain User' 'Sense-Agent-Version für Contain User') `
        (& $T "All $known Windows device(s) with a known agent version run Sense $min or later." "Alle $known Windows-Gerät(e) mit bekannter Agent-Version haben Sense ab $min.") $null 'DeviceInfo.ClientVersion' 0 $known @()
    }

    # 2) Managed but not onboarded: cannot be isolated
    $gaps = @($Coverage | Where-Object { $_ -and $_.status -ne 'CanBeOnboarded' })
    $discovered = @($Coverage | Where-Object { $_ -and $_.status -eq 'CanBeOnboarded' }).Count
    if ($gaps.Count) {
        & $add 'onboarding' 'Gap' (& $T 'Devices that disruption can act on' 'Geräte, auf denen Disruption wirken kann') `
        (& $T "$($gaps.Count) device(s) are not (fully) covered by Defender for Endpoint (see Devices › coverage). Automatic isolation only works on onboarded devices with a working sensor." "$($gaps.Count) Gerät(e) sind nicht (vollständig) von Defender for Endpoint abgedeckt (siehe Geräte › Abdeckung). Automatische Isolation wirkt nur auf onboardeten Geräten mit funktionierendem Sensor.") `
            $null 'Coverage' $gaps.Count $null @($gaps | Select-Object -First 50 | ForEach-Object { [string]$_.deviceName })
    }
    else {
        & $add 'onboarding' $(if ($hunting) { 'OK' } else { 'NotMeasurable' }) (& $T 'Devices that disruption can act on' 'Geräte, auf denen Disruption wirken kann') `
        (& $T 'No coverage gaps were found in this run.' 'In diesem Lauf wurden keine Abdeckungslücken gefunden.') $null 'Coverage' 0 $null @()
    }

    # 3) Defender for Identity signals
    $mdi = $null; $mdiError = $null
    if ($hunting) {
        try { $r = @(Invoke-GapsioHunting -Query "// GapsioMdi`nIdentityDirectoryEvents`n| where Timestamp > ago(7d)`n| summarize Events = count()" -Timespan 'P7D'); $mdi = if ($r.Count) { [long]$r[0].Events } else { 0 } }
        catch { $mdiError = $true }
    }
    $mdiTitle = & $T 'Defender for Identity signals' 'Defender-for-Identity-Signale'
    $mdiWhere = & $T 'Settings › Identities › Sensors' 'Einstellungen › Identitäten › Sensoren'
    if ($mdi -gt 0) { & $add 'mdi' 'OK' $mdiTitle (& $T "Defender for Identity reported $mdi directory event(s) in the last 7 days. Disabling an Active Directory account needs the sensor on the domain controller that holds the account." "Defender for Identity hat in den letzten 7 Tagen $mdi Verzeichnisereignis(se) gemeldet. Zum Deaktivieren eines Active-Directory-Kontos muss der Sensor auf dem Domänencontroller mit dem Konto laufen.") $mdiWhere 'IdentityDirectoryEvents' $mdi $null @() }
    elseif (-not $hunting) { & $add 'mdi' 'NotMeasurable' $mdiTitle (& $T 'Feature Hunting is off.' 'Feature Hunting ist aus.') $mdiWhere 'IdentityDirectoryEvents' $null $null @() }
    else { & $add 'mdi' 'Review' $mdiTitle (& $T "No Defender for Identity data $(if ($mdiError) { 'could be read' } else { 'in the last 7 days' }). With on-premises Active Directory, disruption cannot disable compromised AD accounts without the Defender for Identity sensor on the domain controllers. Cloud-only tenants do not need it." "Keine Defender-for-Identity-Daten $(if ($mdiError) { 'lesbar' } else { 'in den letzten 7 Tagen' }). Mit lokalem Active Directory kann Disruption kompromittierte AD-Konten ohne den Defender-for-Identity-Sensor auf den Domänencontrollern nicht deaktivieren. Reine Cloud-Mandanten brauchen ihn nicht.") $mdiWhere 'IdentityDirectoryEvents' 0 $null @() }

    # 4) Not exposed by any API: say so and name the place to check
    & $add 'discovery' 'NotMeasurable' (& $T 'Device discovery in Standard mode' 'Gerätesuche im Standard-Modus') `
    (& $T "Contain Device for unmanaged devices needs Standard discovery. Microsoft exposes the mode in the portal only.$(if ($discovered) { " Discovery currently lists $discovered device(s) that can be onboarded." })" "Contain Device für nicht verwaltete Geräte braucht die Standard-Gerätesuche. Microsoft zeigt den Modus nur im Portal.$(if ($discovered) { " Die Gerätesuche listet derzeit $discovered Gerät(e), die onboardet werden können." })") `
    (& $T 'Settings › Device discovery › Discovery setup' 'Einstellungen › Gerätesuche › Einrichtung') $null $discovered $null @()
    & $add 'automation' 'NotMeasurable' (& $T 'Remediation level of the device groups' 'Automatisierungsstufe der Gerätegruppen') `
    (& $T 'Recommended: "Full – remediate threats automatically". A group set to "No automated response" is excluded from disruption and from automated investigation. No API returns the level.' 'Empfohlen: „Vollständig – Bedrohungen automatisch beheben“. Eine Gruppe mit „Keine automatisierte Reaktion“ ist von Disruption und automatischer Untersuchung ausgenommen. Keine API liefert die Stufe.') `
    (& $T 'Settings › Endpoints › Device groups › Remediation level' 'Einstellungen › Endpunkte › Gerätegruppen › Wartungsstufe') $null $null $null @()
    & $add 'exclusions' 'NotMeasurable' (& $T 'Exclusions from automated response' 'Ausnahmen von der automatisierten Reaktion') `
    (& $T 'Users, device groups and IP addresses can be excluded from containment. Microsoft advises against it and offers no API to list them – review them regularly and document each one.' 'Benutzer, Gerätegruppen und IP-Adressen können von der Eindämmung ausgenommen werden. Microsoft rät davon ab und bietet keine API, um sie aufzulisten – regelmäßig prüfen und jede Ausnahme dokumentieren.') `
    (& $T 'Settings › Microsoft Defender XDR › Automated response › Identities / Devices' 'Einstellungen › Microsoft Defender XDR › Automatisierte Reaktion › Identitäten / Geräte') $null $null $null @()

    # 5) What disruption did in the last 30 days
    $events = @(); $eventsStatus = if ($hunting) { 'ok' } else { 'off' }
    if ($hunting) {
        try {
            $events = @(Invoke-GapsioHunting -Query "// GapsioDisruption`nDisruptionAndResponseEvents`n| where Timestamp > ago(30d)`n| summarize Events = count(), Devices = dcount(DeviceId), Last = max(Timestamp) by ActionType, ReportType" | Where-Object { $_ } | ForEach-Object {
                    [pscustomobject]@{ actionType = [string]$_.ActionType; reportType = [string]$_.ReportType; events = [int]$_.Events; devices = [int]$_.Devices; last = ConvertTo-GapsioIsoUtc $_.Last }
                } | Sort-Object @{ Expression = { $_.events }; Descending = $true })
        }
        catch { $eventsStatus = 'unavailable' }
    }
    [pscustomobject]@{
        minSense     = $min
        checks       = $checks.ToArray()
        events       = $events
        eventsStatus = $eventsStatus
        summary      = [ordered]@{
            gaps          = @($checks | Where-Object { $_.status -eq 'Gap' }).Count
            review        = @($checks | Where-Object { $_.status -eq 'Review' }).Count
            notMeasurable = @($checks | Where-Object { $_.status -eq 'NotMeasurable' }).Count
            ok            = @($checks | Where-Object { $_.status -eq 'OK' }).Count
            events30d     = [int](($events | Measure-Object events -Sum).Sum)
        }
    }
}

function Get-GapsioDisruptionFindings {
    param($Readiness)
    if (-not $Readiness) { return @() }
    $T = { param($en, $de) New-GapsioText -En $en -De $de }
    $sense = @($Readiness.checks | Where-Object { $_.id -eq 'sense' -and $_.status -eq 'Gap' })[0]
    if (-not $sense) { return @() }
    $names = (@($sense.devices | Select-Object -First 8)) -join ', '
    @(New-GapsioFinding -Severity 'Medium' -Category 'Response' -Title (& $T "Contain User cannot be enforced on $($sense.count) Windows device(s)" "Contain User lässt sich auf $($sense.count) Windows-Gerät(en) nicht durchsetzen") `
            -Detail (& $T "Automatic attack disruption contains a compromised user on every device – but only devices with Sense agent $($Readiness.minSense) or later enforce it. Older agents: $names$(if ($sense.count -gt 8) { ' …' })." "Automatic Attack Disruption dämmt einen kompromittierten Benutzer auf jedem Gerät ein – durchgesetzt wird das aber nur von Geräten mit Sense-Agent ab $($Readiness.minSense). Ältere Agents: $names$(if ($sense.count -gt 8) { ' …' }).") `
            -Recommendation (& $T 'Bring the devices up to date (Windows cumulative updates carry the Sense agent; down-level servers use the unified agent package).' 'Die Geräte aktualisieren (die kumulativen Windows-Updates enthalten den Sense-Agent; ältere Server nutzen das Unified-Agent-Paket).') `
            -Subject 'disruption|sense' -StableKey)
}
#endregion

#region Custom detection rules (feature Detections)
# Automated actions of a rule that change something on devices, accounts or mail.
$script:GapsioDetectionImpactActions = 'isolateDevices', 'restrictAppExecutions', 'stopAndQuarantineFiles', 'disableUsers', 'forceUserPasswordResets', 'markUsersAsCompromised', 'blockFiles', 'allowFiles', 'hardDeleteEmails', 'softDeleteEmails', 'moveEmailsToDeletedItems', 'moveEmailsToJunk', 'moveEmailsToInbox'

function Get-GapsioDetectionRules {
    <#
    .SYNOPSIS
    Custom detection rules of Defender XDR (Graph security/rules/detectionRules, CustomDetection.Read.All):
    status (enabled | disabled | autoDisabled), schedule, alert severity, automated actions, who changed the rule.
    Microsoft removed the run history from the API; when a response still carries lastRunDetails it is used, its
    absence is never read as "ran fine". Alerts of the last 30 days are matched by the alert title (AlertInfo) – a
    rule with a dynamic title cannot be matched and shows no number.
    Returns $null when the feature is off, otherwise { status = ok | failed; rules }.
    #>
    if (-not (Test-GapsioFeature -Name 'detections')) { return $null }
    $raw = $null
    try { $raw = @(Invoke-GapsioGraph -All -Path 'security/rules/detectionRules') }
    catch {
        try { $raw = @(Invoke-GapsioGraph -Beta -All -Path 'security/rules/detectionRules') }
        catch { Add-GapsioWarning "Custom detection rules (CustomDetection.Read.All): $(Get-GapsioErrorText -Exception $_.Exception -Context 'Custom detection rules CustomDetection.Read.All')"; return [pscustomobject]@{ status = 'failed'; rules = @() } }
    }
    $alerts = $null
    $rows = Invoke-GapsioHuntingSafe -NoShard -Context 'Advanced Hunting alerts per title' -Query "// GapsioDetectionAlerts`nAlertInfo`n| where Timestamp > ago(30d)`n| summarize Alerts = dcount(AlertId), Last = max(Timestamp) by Title"
    if ($null -ne $rows) { $alerts = @{}; foreach ($a in @($rows)) { if ($a -and $a.Title) { $alerts[([string]$a.Title).ToLowerInvariant()] = $a } } }

    $rules = foreach ($r in @($raw)) {
        if (-not $r) { continue }
        $status = [string](Get-GapsioProp $r 'status')
        if (-not $status) { $en = Get-GapsioProp $r 'isEnabled'; $status = if ($null -eq $en) { 'unknown' } elseif ($en) { 'enabled' } else { 'disabled' } }
        $sched = Get-GapsioProp $r 'schedule'
        $freq = [string](Get-GapsioProp $sched 'frequency'); if (-not $freq) { $freq = [string](Get-GapsioProp $sched 'period') }
        $act = Get-GapsioProp $r 'detectionAction'
        $tmpl = Get-GapsioProp $act 'alertTemplate'
        $auto = Get-GapsioProp $act 'automatedActions'
        $actions = @()
        if ($auto) { $actions = @($auto.PSObject.Properties | Where-Object { $_.Name -notlike '@*' -and @($_.Value | Where-Object { $_ }).Count } | ForEach-Object { $_.Name }) }
        if (-not $actions.Count) { $actions = @(@(Get-GapsioProp $act 'responseActions') | Where-Object { $_ } | ForEach-Object { ([string](Get-GapsioProp $_ '@odata.type')) -replace '^#?microsoft\.graph\.security\.', '' -replace 'ResponseAction$', '' } | Where-Object { $_ }) }
        $scope = Get-GapsioProp $act 'organizationalScope'
        $groups = @(@(Get-GapsioProp $scope 'deviceGroups') + @(Get-GapsioProp $scope 'scopeNames') | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        $run = Get-GapsioProp $r 'lastRunDetails'
        $lastRun = if ($run -and (Get-GapsioProp $run 'status')) { [pscustomobject]@{ status = [string](Get-GapsioProp $run 'status'); at = ConvertTo-GapsioIsoUtc (Get-GapsioProp $run 'lastRunDateTime'); failureReason = [string](Get-GapsioProp $run 'failureReason'); errorCode = [string](Get-GapsioProp $run 'errorCode') } } else { $null }
        $title = [string](Get-GapsioProp $tmpl 'title')
        $hits = $null; $lastAlert = $null
        if ($null -ne $alerts -and $title -and $title -notmatch '\{\{') {
            $a = $alerts[$title.ToLowerInvariant()]
            $hits = if ($a) { [int]$a.Alerts } else { 0 }
            if ($a) { $lastAlert = ConvertTo-GapsioIsoUtc $a.Last }
        }
        $name = [string](Get-GapsioProp $r 'displayName')
        [pscustomobject]@{
            key            = Get-GapsioHash "detrule|$($r.id)"
            fp             = Get-GapsioHash "$status|$freq|$(Get-GapsioProp $tmpl 'severity')|$($actions -join ',')|$(Get-GapsioProp $r 'lastModifiedDateTime')"
            label          = New-GapsioText "Detection rule $name" "Detection-Regel $name"
            state          = "$status$(if ($actions.Count) { "; actions: $($actions -join ', ')" })"
            id             = [string]$r.id
            name           = $name
            status         = $status
            frequency      = $freq
            severity       = [string](Get-GapsioProp $tmpl 'severity')
            alertTitle     = $title
            actions        = $actions
            impactActions  = @($actions | Where-Object { $_ -in $script:GapsioDetectionImpactActions })
            deviceGroups   = $groups
            createdBy      = [string](Get-GapsioProp $r 'createdBy')
            lastModifiedBy = [string](Get-GapsioProp $r 'lastModifiedBy')
            lastModified   = ConvertTo-GapsioIsoUtc (Get-GapsioProp $r 'lastModifiedDateTime')
            lastRun        = $lastRun
            alerts30d      = $hits
            lastAlert      = $lastAlert
        }
    }
    [pscustomobject]@{ status = 'ok'; rules = @($rules | Sort-Object @{ Expression = { switch ($_.status) { 'autoDisabled' { 0 } 'disabled' { 1 } default { 2 } } } }, name) }
}

function Get-GapsioDetectionRuleFindings {
    param($Detections)
    if (-not $Detections -or $Detections.status -ne 'ok') { return @() }
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-GapsioText -En $en -De $de }
    $rules = @($Detections.rules)
    $list = { param($rows) ((@($rows | Select-Object -First 8 | ForEach-Object { $_.name })) -join ', ') + $(if (@($rows).Count -gt 8) { ' …' } else { '' }) }

    $auto = @($rules | Where-Object { $_.status -eq 'autoDisabled' })
    if ($auto.Count) {
        $f.Add((New-GapsioFinding -Severity 'High' -Category 'Detection' -Title (& $T "$($auto.Count) custom detection rule(s) were switched off automatically" "$($auto.Count) Custom-Detection-Regel(n) wurden automatisch abgeschaltet") `
                    -Detail (& $T "Defender set these rules to 'autoDisabled' – they no longer run and raise no alerts: $(& $list $auto). Nobody is notified when this happens." "Defender hat diese Regeln auf „autoDisabled“ gesetzt – sie laufen nicht mehr und erzeugen keine Alerts: $(& $list $auto). Niemand wird darüber benachrichtigt.") `
                    -Recommendation (& $T 'Open each rule in the Defender portal (Hunting › Custom detection rules), run its query, fix what fails (changed schema, time-outs, too many results) and switch the rule on again.' 'Jede Regel im Defender-Portal öffnen (Hunting › Benutzerdefinierte Erkennungsregeln), die Abfrage ausführen, den Fehler beheben (geändertes Schema, Zeitüberschreitung, zu viele Ergebnisse) und die Regel wieder einschalten.') -Subject 'detection|autodisabled' -StableKey))
    }
    $failed = @($rules | Where-Object { $_.status -eq 'enabled' -and $_.lastRun -and $_.lastRun.status -in 'failed', 'partiallyFailed' })
    if ($failed.Count) {
        $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'Detection' -Title (& $T "$($failed.Count) custom detection rule(s) failed in their last run" "$($failed.Count) Custom-Detection-Regel(n) sind im letzten Lauf fehlgeschlagen") `
                    -Detail (& $T "The last run did not complete: $((@($failed | Select-Object -First 8 | ForEach-Object { "$($_.name) ($($_.lastRun.errorCode))" })) -join ', ')." "Der letzte Lauf wurde nicht abgeschlossen: $((@($failed | Select-Object -First 8 | ForEach-Object { "$($_.name) ($($_.lastRun.errorCode))" })) -join ', ').") `
                    -Recommendation (& $T 'Run the query in Advanced Hunting and fix the reported error; rules that keep failing are switched off by Defender.' 'Die Abfrage in Advanced Hunting ausführen und den gemeldeten Fehler beheben; dauerhaft fehlschlagende Regeln schaltet Defender ab.') -Subject 'detection|failed' -StableKey))
    }
    $off = @($rules | Where-Object { $_.status -eq 'disabled' })
    if ($off.Count) {
        $f.Add((New-GapsioFinding -Severity 'Low' -Category 'Detection' -Title (& $T "$($off.Count) custom detection rule(s) are disabled" "$($off.Count) Custom-Detection-Regel(n) sind deaktiviert") `
                    -Detail (& $T "Disabled rules detect nothing: $(& $list $off). Last changed by: $((@($off | ForEach-Object lastModifiedBy | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 5)) -join ', ')." "Deaktivierte Regeln erkennen nichts: $(& $list $off). Zuletzt geändert von: $((@($off | ForEach-Object lastModifiedBy | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 5)) -join ', ').") `
                    -Recommendation (& $T 'Enable the rules that are still needed and delete the rest, so the list shows what really protects.' 'Noch benötigte Regeln aktivieren und den Rest löschen, damit die Liste zeigt, was wirklich schützt.') -Subject 'detection|disabled' -StableKey))
    }
    $impact = @($rules | Where-Object { $_.status -eq 'enabled' -and @($_.impactActions).Count })
    if ($impact.Count) {
        $f.Add((New-GapsioFinding -Severity 'Low' -Category 'Detection' -Title (& $T "$($impact.Count) custom detection rule(s) act automatically" "$($impact.Count) Custom-Detection-Regel(n) handeln automatisch") `
                    -Detail (& $T "These rules isolate devices, disable users, quarantine files or move mail without anyone approving it: $((@($impact | Select-Object -First 8 | ForEach-Object { "$($_.name) ($($_.impactActions -join ', '))" })) -join '; ')." "Diese Regeln isolieren Geräte, deaktivieren Benutzer, stellen Dateien unter Quarantäne oder verschieben Mails, ohne dass jemand zustimmt: $((@($impact | Select-Object -First 8 | ForEach-Object { "$($_.name) ($($_.impactActions -join ', '))" })) -join '; ').") `
                    -Recommendation (& $T 'Review who may change these rules (Detection tuning permission) and check their queries after schema changes – a query that matches too much acts on every match.' 'Prüfen, wer diese Regeln ändern darf (Berechtigung „Detection tuning“), und die Abfragen nach Schemaänderungen kontrollieren – eine zu breite Abfrage handelt bei jedem Treffer.') -Subject 'detection|actions' -StableKey))
    }
    @($f.ToArray())
}
#endregion
