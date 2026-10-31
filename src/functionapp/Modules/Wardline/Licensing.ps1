# Wardline – module "licensing": Defender for Endpoint licence indication.
#
# Scope (deliberately narrow): Defender for Endpoint only. The module compares
#   1. the MDE service plans a tenant owns (subscribedSkus),
#   2. the users who hold such a plan (users/assignedPlans),
#   3. the client devices actually onboarded to Defender for Endpoint and who uses them (Advanced Hunting, optional Intune).
# It produces an INDICATION, not an audit: the licence terms are per user (one user may use up to five devices), the
# device-to-user mapping is derived from logon data and can be incomplete (shared devices, kiosks, service accounts,
# devices without logons in the observation window). Servers are listed separately – server licences are usually bought
# through Defender for Servers (Azure) and are not visible in Microsoft Graph.

# Service plans that represent a Defender for Endpoint entitlement (Microsoft "Product names and service plan identifiers for licensing").
$script:WlMdePlans = [ordered]@{
    '871d91ec-ec1a-452b-a83f-bd76c7d770ef' = @{ Name = 'WINDEFATP'; Tier = 'P2'; Label = 'Defender for Endpoint Plan 2' }
    '292cc034-7b7c-4950-aaf5-943befd3f1d4' = @{ Name = 'MDE_LITE'; Tier = 'P1'; Label = 'Defender for Endpoint Plan 1' }
    'bfc1bbd9-981b-4f71-9b82-17c35fd0e2a4' = @{ Name = 'MDE_SMB'; Tier = 'MDB'; Label = 'Defender for Business' }
}
$script:WlMdePlanNames = @{ 'WINDEFATP' = 'P2'; 'MDE_LITE' = 'P1'; 'MDE_SMB' = 'MDB' }
$script:WlMdeTierRank = @{ 'P2' = 3; 'MDB' = 2; 'P1' = 1 }
# Licence terms (Microsoft Product Terms): one user licence covers up to five concurrently used devices.
# Both values can be tuned per installation (WL_LICENSING_DEVICES_PER_USER, WL_LICENSING_DAYS).
$script:WlMdeDevicesPerUser = 5
$script:WlLicensingDays = 30
function Get-WlLicensingSettings {
    $d = [string](Get-WlSetting 'WL_LICENSING_DAYS' ''); if ($d -match '^\d+$' -and [int]$d -ge 7 -and [int]$d -le 90) { $script:WlLicensingDays = [int]$d }
    $p = [string](Get-WlSetting 'WL_LICENSING_DEVICES_PER_USER' ''); if ($p -match '^\d+$' -and [int]$p -ge 1) { $script:WlMdeDevicesPerUser = [int]$p }
}

function Get-WlMdePlanTier {
    <#
    .SYNOPSIS
    'P2', 'P1', 'MDB' for an MDE service plan (by ID or name), otherwise $null.
    #>
    param($Plan)
    $id = [string](Get-WlProp $Plan 'servicePlanId'); $name = [string](Get-WlProp $Plan 'servicePlanName')
    if ($id -and $script:WlMdePlans.Contains($id.ToLowerInvariant())) { return $script:WlMdePlans[$id.ToLowerInvariant()].Tier }
    if ($name -and $script:WlMdePlanNames.ContainsKey($name.ToUpperInvariant())) { return $script:WlMdePlanNames[$name.ToUpperInvariant()] }
    $null
}

function Get-WlBestTier {
    param([string[]]$Tiers)
    $best = $null
    foreach ($t in $Tiers) { if ($t -and ($null -eq $best -or $script:WlMdeTierRank[$t] -gt $script:WlMdeTierRank[$best])) { $best = $t } }
    $best
}

function Get-WlLicenseSkus {
    <#
    .SYNOPSIS
    Subscribed SKUs that contain a Defender for Endpoint service plan, with enabled/consumed units and the MDE tier.
    Server SKUs (MDATP_Server …) are flagged so the portal can keep them apart from user licences.
    #>
    $raw = Invoke-WlGraphSafe -All -Path 'subscribedSkus' -Context 'Subscribed SKUs (Organization.Read.All)'
    if ($null -eq $raw) { return $null }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($raw)) {
        $plans = @(Get-WlProp $s 'servicePlans')
        $mde = @(foreach ($p in $plans) { $t = Get-WlMdePlanTier $p; if ($t) { [pscustomobject]@{ name = [string]$p.servicePlanName; tier = $t; status = [string]$p.provisioningStatus } } })
        if (-not $mde.Count) { continue }
        $part = [string](Get-WlProp $s 'skuPartNumber')
        $enabled = [int](Get-WlProp (Get-WlProp $s 'prepaidUnits') 'enabled'); $consumed = [int](Get-WlProp $s 'consumedUnits')
        $tier = Get-WlBestTier @($mde | ForEach-Object tier)
        $isServer = $part -match 'SERVER' -or $part -match 'MDATP_Server'
        $out.Add([pscustomobject]@{
                key = Get-WlHash "sku|$($s.skuId)"; fp = Get-WlHash "$enabled|$consumed|$tier|$([string](Get-WlProp $s 'capabilityStatus'))"
                label = "$part ($consumed/$enabled)"; state = [string](Get-WlProp $s 'capabilityStatus')
                skuId = [string]$s.skuId; skuPartNumber = $part; tier = $tier; isServer = [bool]$isServer
                enabled = $enabled; consumed = $consumed; suspended = [int](Get-WlProp (Get-WlProp $s 'prepaidUnits') 'suspended'); warning = [int](Get-WlProp (Get-WlProp $s 'prepaidUnits') 'warning')
                appliesTo = [string](Get-WlProp $s 'appliesTo'); plans = $mde
            })
    }
    @($out | Sort-Object { -$script:WlMdeTierRank[$_.tier] }, skuPartNumber)
}

function Get-WlMdeLicensedUsers {
    <#
    .SYNOPSIS
    Users with an enabled Defender for Endpoint service plan (P2, P1 or Defender for Business). The whole user list is
    read with a narrow $select and filtered locally – Graph does not filter reliably on assignedPlans.
    #>
    $raw = Invoke-WlGraphSafe -All -Path 'users?$select=id,userPrincipalName,displayName,accountEnabled,userType,assignedPlans,onPremisesSamAccountName,mailNickname&$top=999' -Context 'Users with assigned plans (User.Read.All)'
    if ($null -eq $raw) { return $null }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($u in @($raw)) {
        $tiers = @(foreach ($p in @(Get-WlProp $u 'assignedPlans')) { if ([string](Get-WlProp $p 'capabilityStatus') -eq 'Enabled') { Get-WlMdePlanTier $p } })
        $tier = Get-WlBestTier $tiers
        if (-not $tier) { continue }
        $upn = [string]$u.userPrincipalName
        $out.Add([pscustomobject]@{
                id = [string]$u.id; upn = $upn; displayName = [string]$u.displayName; tier = $tier
                accountEnabled = [bool](Get-WlProp $u 'accountEnabled'); userType = [string](Get-WlProp $u 'userType')
                names = @(@(($upn -split '@')[0], [string](Get-WlProp $u 'onPremisesSamAccountName'), [string](Get-WlProp $u 'mailNickname')) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
            })
    }
    $out.ToArray()
}

function Get-WlLicensingDevices {
    <#
    .SYNOPSIS
    Onboarded devices (last 30 days) and who used them: primary user and recent users from Intune (exact, by Entra
    device ID) plus interactive logons from DeviceLogonEvents (matched by account name – lower confidence).
    Returns @{ devices = …; logons = …; intune = … } or $null when hunting is unavailable.
    #>
    $days = $script:WlLicensingDays
    $devices = Invoke-WlHuntingSafe -NoShard -Context 'Onboarded devices (ThreatHunting.Read.All)' -Query @"
// WardlineLicensingDevices
DeviceInfo
| where Timestamp > ago(${days}d)
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, DeviceName, OSPlatform, DeviceType, AadDeviceId, MachineGroup, ExclusionReason, LoggedOnUsers) by DeviceId
| project DeviceId, DeviceName, OSPlatform, DeviceType, AadDeviceId, MachineGroup, ExclusionReason, LoggedOnUsers, LastSeen = Timestamp
"@
    if ($null -eq $devices) { return $null }
    $logons = Invoke-WlHuntingSafe -NoShard -Context 'Interactive logons (ThreatHunting.Read.All)' -Query @"
// WardlineLicensingLogons
DeviceLogonEvents
| where Timestamp > ago(${days}d)
| where ActionType == "LogonSuccess"
| where LogonType in ("Interactive", "RemoteInteractive", "CachedInteractive", "Unlock")
| where isnotempty(AccountName) and not(AccountName endswith "$") and AccountName !startswith "DWM-" and AccountName !startswith "UMFD-"
| where tolower(AccountDomain) !in ("nt authority", "window manager", "font driver host", "nt service")
| summarize Logons = count(), Last = max(Timestamp) by DeviceId, AccountName = tolower(AccountName)
"@
    $intune = $null
    if (Test-WlFeature 'coverage') {
        $intune = Invoke-WlGraphSafe -All -Path 'deviceManagement/managedDevices?$select=id,azureADDeviceId,userPrincipalName,userId,usersLoggedOn,operatingSystem,deviceName&$top=1000' -Context 'Intune devices and their users (DeviceManagementManagedDevices.Read.All)'
    }
    @{ devices = @($devices); logons = @($logons); intune = @($intune) }
}

function Test-WlServerDevice {
    param($Row)
    $t = [string](Get-WlProp $Row 'DeviceType'); $os = [string](Get-WlProp $Row 'OSPlatform')
    $t -eq 'Server' -or $os -match 'Server' -or ($os -eq 'Linux' -and $t -ne 'Workstation')
}

function Get-WlLicensingModel {
    <#
    .SYNOPSIS
    Pure computation (testable without I/O): joins SKUs, licensed users and devices into the licensing snapshot body.
    #>
    param($Skus, $Users, $Data, [string]$Detail = 'users')
    $T = { param($en, $de) New-WlText -En $en -De $de }
    $byId = @{}; $byName = @{}
    foreach ($u in @($Users)) { $byId[$u.id] = $u; foreach ($n in $u.names) { if (-not $byName.ContainsKey($n)) { $byName[$n] = [System.Collections.Generic.List[object]]::new() }; $byName[$n].Add($u) } }
    $byUpn = @{}; foreach ($u in @($Users)) { if ($u.upn) { $byUpn[$u.upn.ToLowerInvariant()] = $u } }

    # Intune: Entra device ID -> users (exact)
    $intuneUsers = @{}
    foreach ($m in @($Data.intune)) {
        $aad = [string](Get-WlProp $m 'azureADDeviceId'); if (-not $aad) { continue }
        $aad = $aad.ToLowerInvariant()
        if (-not $intuneUsers.ContainsKey($aad)) { $intuneUsers[$aad] = [System.Collections.Generic.HashSet[string]]::new() }
        $upn = [string](Get-WlProp $m 'userPrincipalName'); if ($upn) { $null = $intuneUsers[$aad].Add("upn:$($upn.ToLowerInvariant())") }
        foreach ($lo in @(Get-WlProp $m 'usersLoggedOn')) { $uid = [string](Get-WlProp $lo 'userId'); if ($uid) { $null = $intuneUsers[$aad].Add("id:$uid") } }
    }
    # Logons: DeviceId -> account names
    $logonNames = @{}
    foreach ($l in @($Data.logons)) {
        $d = [string]$l.DeviceId; if (-not $logonNames.ContainsKey($d)) { $logonNames[$d] = [System.Collections.Generic.HashSet[string]]::new() }
        $null = $logonNames[$d].Add(([string]$l.AccountName).ToLowerInvariant())
    }

    $userDevices = @{}   # user id -> HashSet deviceId (clients only)
    $devices = [System.Collections.Generic.List[object]]::new()
    $servers = [System.Collections.Generic.List[object]]::new()
    foreach ($row in @($Data.devices)) {
        if ([string](Get-WlProp $row 'ExclusionReason')) { continue }
        $id = [string]$row.DeviceId
        $isServer = Test-WlServerDevice $row
        $rec = [ordered]@{
            key = Get-WlHash "licdev|$id"; deviceId = $id; deviceName = [string]$row.DeviceName; os = [string]$row.OSPlatform; deviceType = [string]$row.DeviceType
            machineGroup = [string]$row.MachineGroup; lastSeen = ConvertTo-WlUtc $row.LastSeen; users = @(); licensedBy = $null; tier = $null; confidence = $null; state = $null
        }
        if ($isServer) { $rec.state = 'Server'; $rec.fp = Get-WlHash 'server'; $rec.label = "$($rec.deviceName): server"; $servers.Add([pscustomobject]$rec); continue }

        $found = [ordered]@{}   # user id -> confidence
        $aad = ([string](Get-WlProp $row 'AadDeviceId')).ToLowerInvariant()
        if ($aad -and $intuneUsers.ContainsKey($aad)) {
            foreach ($ref in $intuneUsers[$aad]) {
                $u = if ($ref.StartsWith('id:')) { $byId[$ref.Substring(3)] } else { $byUpn[$ref.Substring(4)] }
                if ($u) { $found[$u.id] = 'Intune' } elseif ($ref.StartsWith('upn:')) { $found[$ref] = 'Intune' }
            }
        }
        $names = [System.Collections.Generic.HashSet[string]]::new()
        if ($logonNames.ContainsKey($id)) { foreach ($n in $logonNames[$id]) { $null = $names.Add($n) } }
        $lou = [string](Get-WlProp $row 'LoggedOnUsers')
        if ($lou) { try { foreach ($x in @($lou | ConvertFrom-Json)) { $n = [string](Get-WlProp $x 'UserName'); if ($n -and $n -notmatch '\$$') { $null = $names.Add($n.ToLowerInvariant()) } } } catch { } }
        foreach ($n in $names) {
            if ($byName.ContainsKey($n)) { foreach ($u in $byName[$n]) { if (-not $found.Contains($u.id)) { $found[$u.id] = 'Logon' } } }
            elseif (-not $found.Contains("name:$n")) { $found["name:$n"] = 'Logon' }
        }
        $licensedUsers = @(foreach ($k in $found.Keys) { if ($byId.ContainsKey($k)) { $byId[$k] } })
        $anyUser = $found.Count -gt 0
        $rec.users = @(foreach ($k in $found.Keys) {
                if ($byId.ContainsKey($k)) { [pscustomobject]@{ upn = $byId[$k].upn; tier = $byId[$k].tier; confidence = $found[$k] } }
                else { [pscustomobject]@{ upn = ($k -replace '^(upn|name):', ''); tier = $null; confidence = $found[$k] } }
            })
        foreach ($u in $licensedUsers) { if (-not $userDevices.ContainsKey($u.id)) { $userDevices[$u.id] = [System.Collections.Generic.HashSet[string]]::new() }; $null = $userDevices[$u.id].Add($id) }
        if ($licensedUsers.Count) {
            $best = $licensedUsers | Sort-Object { -$script:WlMdeTierRank[$_.tier] } | Select-Object -First 1
            $rec.state = 'Licensed'; $rec.licensedBy = $best.upn; $rec.tier = $best.tier; $rec.confidence = $found[$best.id]
        }
        elseif ($anyUser) { $rec.state = 'Unlicensed'; $rec.confidence = $(if ($found.Values -contains 'Intune') { 'Intune' } else { 'Logon' }) }
        else { $rec.state = 'NoUser' }
        $rec.fp = Get-WlHash "$($rec.state)|$($rec.tier)|$($rec.licensedBy)"
        $rec.label = "$($rec.deviceName): $($rec.state)"
        $devices.Add([pscustomobject]$rec)
    }

    $userRows = [System.Collections.Generic.List[object]]::new()
    foreach ($u in @($Users)) {
        $n = if ($userDevices.ContainsKey($u.id)) { $userDevices[$u.id].Count } else { 0 }
        $state = if ($n -gt $script:WlMdeDevicesPerUser) { 'OverLimit' } elseif ($n -eq 0) { 'NoDevice' } else { 'InUse' }
        $upn = if ($Detail -eq 'aggregate') { "user-$((Get-WlHash $u.id).Substring(0, 10))" } else { $u.upn }
        $name = if ($Detail -eq 'aggregate') { $null } else { $u.displayName }
        $userRows.Add([pscustomobject]@{
                key = Get-WlHash "licuser|$($u.id)"; fp = Get-WlHash "$($u.tier)|$n|$($u.accountEnabled)"; label = "$upn ($($u.tier)): $n device(s)"; state = $state
                upn = $upn; displayName = $name; tier = $u.tier; accountEnabled = $u.accountEnabled; userType = $u.userType; deviceCount = $n
                devices = @($(if ($userDevices.ContainsKey($u.id)) { $userDevices[$u.id] } else { @() }) | ForEach-Object { $d = $_; $dev = $devices | Where-Object { $_.deviceId -eq $d } | Select-Object -First 1; if ($dev) { $dev.deviceName } else { $d } })
            })
    }

    $skuList = @($Skus | Where-Object { $_ })
    $userSkus = @($skuList | Where-Object { -not $_.isServer }); $serverSkus = @($skuList | Where-Object isServer)
    $sum = { param($list, $prop, $tier) [int](($list | Where-Object { $_.tier -eq $tier } | Measure-Object $prop -Sum).Sum) }
    $clients = @($devices)
    $licUsers = @($Users | Where-Object { $_ })
    $summary = [ordered]@{
        observedDays        = $script:WlLicensingDays
        devicesPerUser      = $script:WlMdeDevicesPerUser
        skus                = $skuList.Count
        p2Enabled           = & $sum $userSkus 'enabled' 'P2'; p2Consumed = & $sum $userSkus 'consumed' 'P2'
        p1Enabled           = & $sum $userSkus 'enabled' 'P1'; p1Consumed = & $sum $userSkus 'consumed' 'P1'
        mdbEnabled          = & $sum $userSkus 'enabled' 'MDB'; mdbConsumed = & $sum $userSkus 'consumed' 'MDB'
        serverSkuEnabled    = [int](($serverSkus | Measure-Object enabled -Sum).Sum); serverSkuConsumed = [int](($serverSkus | Measure-Object consumed -Sum).Sum)
        licensedUsers       = $licUsers.Count
        usersP2             = @($licUsers | Where-Object tier -eq 'P2').Count
        usersP1             = @($licUsers | Where-Object tier -eq 'P1').Count
        usersMdb            = @($licUsers | Where-Object tier -eq 'MDB').Count
        usersDisabled       = @($licUsers | Where-Object { -not $_.accountEnabled }).Count
        usersNoDevice       = @($userRows | Where-Object state -eq 'NoDevice').Count
        usersOverLimit      = @($userRows | Where-Object state -eq 'OverLimit').Count
        clients             = $clients.Count
        clientsLicensed     = @($clients | Where-Object state -eq 'Licensed').Count
        clientsUnlicensed   = @($clients | Where-Object state -eq 'Unlicensed').Count
        clientsNoUser       = @($clients | Where-Object state -eq 'NoUser').Count
        clientsP1Only       = @($clients | Where-Object { $_.state -eq 'Licensed' -and $_.tier -eq 'P1' }).Count
        servers             = $servers.Count
        intuneMapping       = [bool](@($Data.intune).Count)
    }

    # Findings
    $f = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $userSkus) {
        if ($s.consumed -gt $s.enabled -and $s.enabled -ge 0) {
            $f.Add((New-WlFinding -Severity 'High' -Category 'Licensing' -Subject $s.skuId -StableKey `
                        -Title (& $T "More licences assigned than purchased: $($s.skuPartNumber)" "Mehr Lizenzen zugewiesen als gekauft: $($s.skuPartNumber)") `
                        -Detail (& $T "$($s.consumed) of $($s.enabled) units are assigned. Microsoft 365 allows this temporarily; the overage is billed or blocked at the next true-up." "$($s.consumed) von $($s.enabled) Einheiten sind zugewiesen. Microsoft 365 erlaubt das vorübergehend; der Überhang wird beim nächsten True-up berechnet oder gesperrt.") `
                        -Recommendation (& $T 'Buy additional units or remove the plan from users who do not need it.' 'Zusätzliche Einheiten kaufen oder den Plan bei Benutzern entfernen, die ihn nicht benötigen.')))
        }
    }
    $unl = @($clients | Where-Object state -eq 'Unlicensed')
    if ($unl.Count) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Licensing' -Subject 'clients-unlicensed' -StableKey `
                    -Title (& $T "$($unl.Count) onboarded client(s) used only by users without a Defender for Endpoint licence" "$($unl.Count) onboardete(r) Client(s) nur von Benutzern ohne Defender-for-Endpoint-Lizenz genutzt") `
                    -Detail (& $T "In the last $($script:WlLicensingDays) days these devices were used by users who hold no MDE P1/P2 or Defender for Business plan. Indication only: the user mapping comes from Intune and interactive logons." "In den letzten $($script:WlLicensingDays) Tagen wurden diese Geräte von Benutzern genutzt, die keinen MDE-P1/P2- oder Defender-for-Business-Plan haben. Nur ein Hinweis: Die Benutzerzuordnung stammt aus Intune und interaktiven Anmeldungen.") `
                    -Recommendation (& $T 'Assign a Defender for Endpoint plan to the users (group-based licensing) or exclude the devices from onboarding.' 'Den Benutzern einen Defender-for-Endpoint-Plan zuweisen (gruppenbasierte Lizenzierung) oder die Geräte vom Onboarding ausnehmen.') |
                Add-Member -NotePropertyName deviceCount -NotePropertyValue $unl.Count -PassThru | Add-Member -NotePropertyName deviceSample -NotePropertyValue @($unl | Select-Object -First 10 | ForEach-Object deviceName) -PassThru))
    }
    $over = @($userRows | Where-Object state -eq 'OverLimit')
    if ($over.Count) {
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Licensing' -Subject 'users-overlimit' -StableKey `
                    -Title (& $T "$($over.Count) user(s) use more than $($script:WlMdeDevicesPerUser) client devices" "$($over.Count) Benutzer nutzen mehr als $($script:WlMdeDevicesPerUser) Client-Geräte") `
                    -Detail (& $T "A user licence covers up to $($script:WlMdeDevicesPerUser) devices. Shared devices, admin accounts and hot-desking inflate this number – check before acting." "Eine Benutzerlizenz deckt bis zu $($script:WlMdeDevicesPerUser) Geräte ab. Geteilte Geräte, Admin-Konten und Hot-Desking erhöhen diese Zahl – vor Maßnahmen prüfen.") `
                    -Recommendation (& $T 'Check whether the extra devices are shared devices (device licence) or whether the user really uses more than five devices.' 'Prüfen, ob die zusätzlichen Geräte geteilte Geräte sind (Gerätelizenz) oder der Benutzer tatsächlich mehr als fünf Geräte nutzt.')))
    }
    $noDev = @($userRows | Where-Object { $_.state -eq 'NoDevice' -and $_.accountEnabled })
    if ($noDev.Count -and $clients.Count) {
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Licensing' -Subject 'users-nodevice' -StableKey `
                    -Title (& $T "$($noDev.Count) licensed user(s) without an onboarded device in $($script:WlLicensingDays) days" "$($noDev.Count) lizenzierte Benutzer ohne onboardetes Gerät in $($script:WlLicensingDays) Tagen") `
                    -Detail (& $T 'Potentially unused licences – or users whose device is not onboarded, uses no interactive logon (VDI, Mac without Intune) or was inactive.' 'Potenziell ungenutzte Lizenzen – oder Benutzer, deren Gerät nicht onboardet ist, ohne interaktive Anmeldung läuft (VDI, Mac ohne Intune) oder inaktiv war.') `
                    -Recommendation (& $T 'Cross-check with the coverage page before reclaiming licences.' 'Vor der Rücknahme von Lizenzen mit der Coverage-Seite abgleichen.')))
    }
    $p1 = @($clients | Where-Object { $_.state -eq 'Licensed' -and $_.tier -eq 'P1' })
    if ($p1.Count -and $summary.usersP2 -gt 0) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Licensing' -Subject 'clients-p1' -StableKey `
                    -Title (& $T "$($p1.Count) client(s) covered only by Plan 1 in a tenant using Plan 2 features" "$($p1.Count) Client(s) nur durch Plan 1 abgedeckt in einem Tenant mit Plan-2-Funktionen") `
                    -Detail (& $T 'Plan 1 covers next-generation protection, ASR and manual response. EDR, Advanced Hunting, automated investigation and vulnerability management are Plan 2 features and apply to every onboarded device.' 'Plan 1 umfasst Next-Generation Protection, ASR und manuelle Reaktion. EDR, Advanced Hunting, automatische Untersuchung und Schwachstellenmanagement sind Plan-2-Funktionen und wirken auf jedes onboardete Gerät.') `
                    -Recommendation (& $T 'Either licence these users with Plan 2 or document why Plan 1 is sufficient for them (mixed licensing requires the P2 features to be unused for those devices).' 'Diese Benutzer entweder mit Plan 2 lizenzieren oder dokumentieren, warum Plan 1 für sie ausreicht (Mischlizenzierung setzt voraus, dass die P2-Funktionen für diese Geräte nicht genutzt werden).')))
    }
    if ($servers.Count -and -not $serverSkus.Count) {
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Licensing' -Subject 'servers' -StableKey `
                    -Title (& $T "$($servers.Count) onboarded server(s) – no server licence visible in Microsoft 365" "$($servers.Count) onboardete(r) Server – keine Serverlizenz in Microsoft 365 sichtbar") `
                    -Detail (& $T 'Servers are normally licensed through Defender for Servers (Defender for Cloud, Azure subscription) – that is not visible in Microsoft Graph. Only "Defender for Endpoint Server" SKUs show up here.' 'Server werden normalerweise über Defender for Servers (Defender for Cloud, Azure-Abonnement) lizenziert – das ist in Microsoft Graph nicht sichtbar. Nur „Defender for Endpoint Server“-SKUs erscheinen hier.') `
                    -Recommendation (& $T 'Confirm that the servers are covered by a Defender for Servers plan or a server SKU.' 'Bestätigen, dass die Server durch einen Defender-for-Servers-Plan oder eine Server-SKU abgedeckt sind.')))
    }
    $summary.findings = $f.Count

    $caveats = @(
        (& $T 'Indication, not an audit: Microsoft licenses Defender for Endpoint per user (up to five devices each); Wardline derives the device-to-user mapping from Intune and interactive logons of the last 30 days.' 'Hinweis, kein Audit: Microsoft lizenziert Defender for Endpoint pro Benutzer (bis zu fünf Geräte); Wardline leitet die Zuordnung Gerät → Benutzer aus Intune und interaktiven Anmeldungen der letzten 30 Tage ab.'),
        (& $T 'Shared devices, kiosks, VDI and service accounts produce "no user" or inflate per-user device counts.' 'Geteilte Geräte, Kiosks, VDI und Dienstkonten führen zu „kein Benutzer“ oder erhöhen die Gerätezahl pro Benutzer.'),
        (& $T 'Server licences (Defender for Servers via Azure) are not visible in Microsoft Graph; servers are listed separately.' 'Serverlizenzen (Defender for Servers über Azure) sind in Microsoft Graph nicht sichtbar; Server werden separat gezählt.'),
        (& $T 'Confidence "Intune" = exact match by Entra device ID; "Logon" = account name matched to UPN / SAM account name.' 'Konfidenz „Intune“ = exakte Zuordnung über Entra-Geräte-ID; „Logon“ = Kontoname mit UPN / SAM-Kontoname abgeglichen.')
    )
    [ordered]@{
        summary = $summary; skus = $skuList; users = @($userRows); devices = @($devices | Sort-Object { @{ Unlicensed = 0; NoUser = 1; Licensed = 2 }[$_.state] }, deviceName)
        servers = @($servers); findings = @($f); caveats = $caveats
    }
}

function Invoke-WlLicensingCollection {
    <#
    .SYNOPSIS
    Collects the Defender for Endpoint licence indication and stores it as the licensing snapshot (module "licensing").
    WL_LICENSING_DETAIL=aggregate pseudonymises user names in the stored snapshot (data-minimisation).
    #>
    Reset-WlWarnings
    Get-WlLicensingSettings
    $started = [DateTime]::UtcNow
    $detail = ([string](Get-WlSetting 'WL_LICENSING_DETAIL' 'users')).ToLowerInvariant()
    $skus = Get-WlLicenseSkus
    $users = Get-WlMdeLicensedUsers
    $data = Get-WlLicensingDevices
    if ($null -eq $data) { Add-WlWarning 'Device-to-user mapping needs the hunting feature (ThreatHunting.Read.All); only SKUs and licensed users are shown.'; $data = @{ devices = @(); logons = @(); intune = @() } }
    $m = Get-WlLicensingModel -Skus @($skus) -Users @($users) -Data $data -Detail $detail
    $r = [ordered]@{
        module = 'licensing'; version = (Get-WlVersion); generatedAt = $started.ToString('o'); tenantId = (Get-WlSetting 'WL_TENANT_ID')
        scope = 'Defender for Endpoint'; detail = $detail
        summary = $m.summary; skus = $m.skus; users = $m.users; devices = $m.devices; servers = $m.servers; findings = $m.findings; caveats = $m.caveats
        warnings = @(Get-WlWarnings)
    }
    Save-WlSnapshot -Module 'licensing' -Snapshot $r -Collections @('skus', 'users', 'devices', 'findings') -Started $started
    Write-Information "Licensing collection done: $($m.summary.licensedUsers) licensed users, $($m.summary.clients) clients ($($m.summary.clientsUnlicensed) unlicensed), $($m.summary.servers) servers, $($m.findings.Count) findings."
    $r
}
