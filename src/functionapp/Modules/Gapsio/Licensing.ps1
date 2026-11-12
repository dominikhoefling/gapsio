# Gapsio – module "licensing": Defender licence indication (Defender for Endpoint, Defender for Office 365).
#
# Scope (deliberately narrow): Defender for Endpoint with device mapping, Defender for Office 365 as purchased/assigned
# units plus plan holders (no mailbox mapping). The module compares
#   1. the MDE service plans a tenant owns (subscribedSkus),
#   2. the users who hold such a plan (users/assignedPlans),
#   3. the client devices actually onboarded to Defender for Endpoint and who uses them (Advanced Hunting, optional Intune).
# It produces an INDICATION, not an audit: the licence terms are per user (one user may use up to five devices), the
# device-to-user mapping is derived from logon data and can be incomplete (shared devices, kiosks, service accounts,
# devices without logons in the observation window). Servers are listed separately – server licences are usually bought
# through Defender for Servers (Azure) and are not visible in Microsoft Graph.

# Service plans that represent a Defender for Endpoint entitlement (Microsoft "Product names and service plan identifiers for licensing").
$script:GapsioMdePlans = [ordered]@{
    '871d91ec-ec1a-452b-a83f-bd76c7d770ef' = @{ Name = 'WINDEFATP'; Tier = 'P2'; Label = 'Defender for Endpoint Plan 2' }
    '292cc034-7b7c-4950-aaf5-943befd3f1d4' = @{ Name = 'MDE_LITE'; Tier = 'P1'; Label = 'Defender for Endpoint Plan 1' }
    'bfc1bbd9-981b-4f71-9b82-17c35fd0e2a4' = @{ Name = 'MDE_SMB'; Tier = 'MDB'; Label = 'Defender for Business' }
}
$script:GapsioMdePlanNames = @{ 'WINDEFATP' = 'P2'; 'MDE_LITE' = 'P1'; 'MDE_SMB' = 'MDB' }
$script:GapsioMdeTierRank = @{ 'P2' = 3; 'MDB' = 2; 'P1' = 1 }
# Defender for Office 365 service plans (licensed per user/mailbox; no device mapping).
$script:GapsioMdoPlans = [ordered]@{
    'f20fedf3-f3c3-43c3-8267-2bfdd51c0939' = @{ Name = 'ATP_ENTERPRISE'; Tier = 'P1'; Label = 'Defender for Office 365 Plan 1' }
    '8e0c0a52-6a6c-4d40-8370-dd62790dcd70' = @{ Name = 'THREAT_INTELLIGENCE'; Tier = 'P2'; Label = 'Defender for Office 365 Plan 2' }
    '493ff600-6a2b-4db6-ad37-a7d4eb214516' = @{ Name = 'ATP_ENTERPRISE_GOV'; Tier = 'P1'; Label = 'Defender for Office 365 Plan 1 (GCC)' }
    '900018f1-0cdb-4ecb-94d4-90281760fdc6' = @{ Name = 'THREAT_INTELLIGENCE_GOV'; Tier = 'P2'; Label = 'Defender for Office 365 Plan 2 (GCC)' }
}
$script:GapsioMdoPlanNames = @{ 'ATP_ENTERPRISE' = 'P1'; 'ATP_ENTERPRISE_GOV' = 'P1'; 'THREAT_INTELLIGENCE' = 'P2'; 'THREAT_INTELLIGENCE_GOV' = 'P2' }
$script:GapsioMdoTierRank = @{ 'P2' = 2; 'P1' = 1 }
# Licence terms (Microsoft Product Terms): one user licence covers up to five concurrently used devices.
# Both values can be tuned per installation (GAPSIO_LICENSING_DEVICES_PER_USER, GAPSIO_LICENSING_DAYS).
$script:GapsioMdeDevicesPerUser = 5
$script:GapsioLicensingDays = 30
# Usage classification: a client used by at least this many distinct people in the window counts as "shared" (GAPSIO_LICENSING_SHARED_MIN_USERS).
# Account names matching the service pattern (GAPSIO_LICENSING_SERVICE_PATTERN, regex) are treated as service/admin accounts and do not count as users.
$script:GapsioLicensingSharedMinUsers = 4
$script:GapsioLicensingServicePattern = '^(svc|srv|service|sa[_.-]|adm[_.-]|admin|administrator|kiosk|kiosque|scan|print|autologon|autopilot|defaultuser|wdagutilityaccount|test[_.-]?user|lab[_.-]|guest)'
$script:GapsioLicensingKioskPattern = '(kiosk|kiosque|shared|hotdesk|hot-desk|conference|meeting|lobby|reception|infopoint|signage|scanner|warehouse|terminal|pos[_-]|cashdesk|training|classroom|loaner)'
$script:GapsioLicensingVdiPattern = '(virtual machine|vmware|citrix|hyper-v|parallels|virtualbox|qemu|kvm|xen|nutanix ahv|azure virtual desktop|avd|wvd|vdi|w365|cloudpc|cloud pc)'
# Display names for the SKUs that carry a Defender for Endpoint plan (skuPartNumber -> product name as people say it).
# Unknown part numbers fall back to the tier of the contained MDE plan, so the portal never shows a bare code.
$script:GapsioSkuNames = @{
    'DEFENDER_ENDPOINT_P1'          = 'Defender for Endpoint P1'
    'DEFENDER_ENDPOINT_P1_EDU'      = 'Defender for Endpoint P1 (Education)'
    'WIN_DEF_ATP'                   = 'Defender for Endpoint P2'
    'MDATP_XPLAT'                   = 'Defender for Endpoint P2 (cross-platform)'
    'MDATP_SERVER'                  = 'Defender for Endpoint for Servers'
    'MDE_SMB'                       = 'Defender for Business'
    'MICROSOFT_DEFENDER_FOR_BUSINESS' = 'Defender for Business'
    'SPE_E5'                        = 'Microsoft 365 E5'
    'SPE_E5_NOPSTNCONF'             = 'Microsoft 365 E5 (without Audio Conferencing)'
    'MICROSOFT_365_E5_(NO_TEAMS)'   = 'Microsoft 365 E5 (no Teams)'
    'O365_W/O_TEAMS_BUNDLE_M5'      = 'Microsoft 365 E5 (no Teams)'
    'O365_W/O_TEAMS_BUNDLE_M3'      = 'Microsoft 365 E3 (no Teams)'
    'SPE_E5_USGOV_GCCHIGH'          = 'Microsoft 365 E5 (GCC High)'
    'SPE_E3'                        = 'Microsoft 365 E3'
    'MICROSOFT_365_E3_(NO_TEAMS)'   = 'Microsoft 365 E3 (no Teams)'
    'SPE_A5'                        = 'Microsoft 365 A5'
    'M365EDU_A5_FACULTY'            = 'Microsoft 365 A5 (faculty)'
    'M365EDU_A5_STUDENT'            = 'Microsoft 365 A5 (students)'
    'M365EDU_A3_FACULTY'            = 'Microsoft 365 A3 (faculty)'
    'M365EDU_A3_STUDENT'            = 'Microsoft 365 A3 (students)'
    'IDENTITY_THREAT_PROTECTION'    = 'Microsoft 365 E5 Security'
    'IDENTITY_THREAT_PROTECTION_FOR_EMS_E5' = 'Microsoft 365 E5 Security (for EMS E5)'
    'SPE_F5_SEC'                    = 'Microsoft 365 F5 Security'
    'SPE_F5_SECCOMP'                = 'Microsoft 365 F5 Security + Compliance'
    'SPB'                           = 'Microsoft 365 Business Premium'
    'WIN10_VDA_E5'                  = 'Windows Enterprise E5'
    'WIN_ENT_E5'                    = 'Windows Enterprise E5'
    'DEVELOPERPACK_E5'              = 'Microsoft 365 E5 Developer'
    'ATP_ENTERPRISE'                = 'Defender for Office 365 P1'
    'ATP_ENTERPRISE_FACULTY'        = 'Defender for Office 365 P1 (faculty)'
    'ATP_ENTERPRISE_GOV'            = 'Defender for Office 365 P1 (GCC)'
    'THREAT_INTELLIGENCE'           = 'Defender for Office 365 P2'
    'THREAT_INTELLIGENCE_GOV'       = 'Defender for Office 365 P2 (GCC)'
    'O365_E5'                       = 'Office 365 E5'
    'ENTERPRISEPREMIUM'             = 'Office 365 E5'
    'ENTERPRISEPREMIUM_NOPSTNCONF'  = 'Office 365 E5 (without Audio Conferencing)'
    'O365_A5'                       = 'Office 365 A5'
    'ENTERPRISEPREMIUM_FACULTY'     = 'Office 365 A5 (faculty)'
    'ENTERPRISEPREMIUM_STUDENT'     = 'Office 365 A5 (students)'
}
$script:GapsioTierNames = @{ 'P2' = 'Defender for Endpoint P2'; 'P1' = 'Defender for Endpoint P1'; 'MDB' = 'Defender for Business' }
$script:GapsioMdoTierNames = @{ 'P2' = 'Defender for Office 365 P2'; 'P1' = 'Defender for Office 365 P1' }

function Get-GapsioSkuDisplayName {
    <#
    .SYNOPSIS
    Product name for a subscribed SKU, e.g. WIN_DEF_ATP -> "Defender for Endpoint P2". Unknown suites:
    "<tier name> (in <part number>)", so the plan stays recognisable.
    #>
    param([string]$PartNumber, [string]$Tier, [bool]$IsServer, [string]$Product = 'MDE')
    $k = ([string]$PartNumber).ToUpperInvariant()
    if ($script:GapsioSkuNames.ContainsKey($k)) { return $script:GapsioSkuNames[$k] }
    if ($IsServer) { return 'Defender for Endpoint for Servers' }
    $names = if ($Product -eq 'MDO') { $script:GapsioMdoTierNames } else { $script:GapsioTierNames }
    if ($Tier -and $names.ContainsKey($Tier)) { return "$($names[$Tier]) (in $PartNumber)" }
    $PartNumber
}

function Get-GapsioLicensingSettings {
    $d = [string](Get-GapsioSetting 'GAPSIO_LICENSING_DAYS' ''); if ($d -match '^\d+$' -and [int]$d -ge 7 -and [int]$d -le 90) { $script:GapsioLicensingDays = [int]$d }
    $p = [string](Get-GapsioSetting 'GAPSIO_LICENSING_DEVICES_PER_USER' ''); if ($p -match '^\d+$' -and [int]$p -ge 1) { $script:GapsioMdeDevicesPerUser = [int]$p }
    $s = [string](Get-GapsioSetting 'GAPSIO_LICENSING_SHARED_MIN_USERS' ''); if ($s -match '^\d+$' -and [int]$s -ge 2) { $script:GapsioLicensingSharedMinUsers = [int]$s }
    $r = [string](Get-GapsioSetting 'GAPSIO_LICENSING_SERVICE_PATTERN' ''); if ($r) { try { $null = [regex]::new($r); $script:GapsioLicensingServicePattern = $r } catch { Add-GapsioWarning "GAPSIO_LICENSING_SERVICE_PATTERN is not a valid regex and was ignored: $r" } }
}

function Test-GapsioServiceAccountName {
    <#
    .SYNOPSIS
    True for account names that look like service, admin, kiosk auto-logon or built-in accounts – they are not people and must not count as licence users.
    #>
    param([string]$Name)
    if (-not $Name) { return $false }
    $n = $Name.ToLowerInvariant()
    $n -match $script:GapsioLicensingServicePattern -or $n -in @('system', 'local service', 'network service', 'defaultaccount', 'administrator', 'administrateur', 'root', 'kiosk', 'kioskuser0')
}

function Get-GapsioDeviceUsage {
    <#
    .SYNOPSIS
    Classifies how a client device is used: Personal, Shared (many distinct people), Kiosk (self-deploying / shared-PC enrolment or kiosk-style name) or VDI (virtual desktop).
    Returns @{ usage = …; reasons = @(…) } so the portal can show why.
    #>
    param($Row, $Intune, [int]$DistinctUsers)
    $reasons = [System.Collections.Generic.List[string]]::new()
    $name = [string](Get-GapsioProp $Row 'DeviceName'); $os = [string](Get-GapsioProp $Row 'OSPlatform')
    $model = ([string](Get-GapsioProp $Row 'Model') + ' ' + [string](Get-GapsioProp $Row 'Vendor') + ' ' + [string](Get-GapsioProp $Intune 'model') + ' ' + [string](Get-GapsioProp $Intune 'manufacturer')).Trim()
    $enrol = [string](Get-GapsioProp $Intune 'deviceEnrollmentType'); $enrolProfile = [string](Get-GapsioProp $Intune 'enrollmentProfileName')
    $usage = 'Personal'
    if ($os -match 'WVD$' -or $os -match 'AVD' -or $enrol -eq 'azureAdJoinUsingAzureVmExtension' -or $model -match $script:GapsioLicensingVdiPattern -or $name -match '^(avd|wvd|vdi|cpc)-') {
        $usage = 'VDI'
        if ($os -match 'WVD$') { $reasons.Add("OS platform $os (multi-session)") }
        if ($enrol -eq 'azureAdJoinUsingAzureVmExtension') { $reasons.Add('Intune: joined via Azure VM extension') }
        if ($model -match $script:GapsioLicensingVdiPattern) { $reasons.Add("Model/vendor: $model") }
    }
    elseif ($enrol -eq 'windowsAzureADJoinUsingDeviceAuth' -or $enrolProfile -match $script:GapsioLicensingKioskPattern -or $name -match $script:GapsioLicensingKioskPattern) {
        $usage = 'Kiosk'
        if ($enrol -eq 'windowsAzureADJoinUsingDeviceAuth') { $reasons.Add('Intune: self-deploying / shared-PC enrolment (device authentication)') }
        if ($enrolProfile -match $script:GapsioLicensingKioskPattern) { $reasons.Add("Enrolment profile: $enrolProfile") }
        if ($name -match $script:GapsioLicensingKioskPattern) { $reasons.Add("Device name: $name") }
    }
    if ($DistinctUsers -ge $script:GapsioLicensingSharedMinUsers) {
        if ($usage -eq 'Personal') { $usage = 'Shared' }
        $reasons.Add("$DistinctUsers distinct people signed in within the window (threshold $($script:GapsioLicensingSharedMinUsers))")
    }
    @{ usage = $usage; reasons = @($reasons) }
}

function Get-GapsioMdePlanTier {
    <#
    .SYNOPSIS
    'P2', 'P1', 'MDB' for an MDE service plan (by ID or name), otherwise $null.
    #>
    param($Plan)
    $id = [string](Get-GapsioProp $Plan 'servicePlanId'); $name = [string](Get-GapsioProp $Plan 'servicePlanName')
    if ($id -and $script:GapsioMdePlans.Contains($id.ToLowerInvariant())) { return $script:GapsioMdePlans[$id.ToLowerInvariant()].Tier }
    if ($name -and $script:GapsioMdePlanNames.ContainsKey($name.ToUpperInvariant())) { return $script:GapsioMdePlanNames[$name.ToUpperInvariant()] }
    $null
}

function Get-GapsioMdoPlanTier {
    <#
    .SYNOPSIS
    'P2' or 'P1' for a Defender for Office 365 service plan (by ID or name), otherwise $null.
    #>
    param($Plan)
    $id = [string](Get-GapsioProp $Plan 'servicePlanId'); $name = [string](Get-GapsioProp $Plan 'servicePlanName')
    if ($id -and $script:GapsioMdoPlans.Contains($id.ToLowerInvariant())) { return $script:GapsioMdoPlans[$id.ToLowerInvariant()].Tier }
    if ($name -and $script:GapsioMdoPlanNames.ContainsKey($name.ToUpperInvariant())) { return $script:GapsioMdoPlanNames[$name.ToUpperInvariant()] }
    $null
}

function Get-GapsioBestTier {
    param([string[]]$Tiers, [string]$Product = 'MDE')
    $rank = if ($Product -eq 'MDO') { $script:GapsioMdoTierRank } else { $script:GapsioMdeTierRank }
    $best = $null
    foreach ($t in $Tiers) { if ($t -and ($null -eq $best -or $rank[$t] -gt $rank[$best])) { $best = $t } }
    $best
}

function Get-GapsioLicenseSkus {
    <#
    .SYNOPSIS
    Subscribed SKUs that contain a Defender for Endpoint or Defender for Office 365 service plan, with enabled/consumed
    units and the tier. A suite with both (e.g. Microsoft 365 E5) yields one record per product.
    Server SKUs (MDATP_Server …) are flagged so the portal can keep them apart from user licences.
    #>
    $raw = Invoke-GapsioGraphSafe -All -Path 'subscribedSkus' -Context 'Subscribed SKUs (Organization.Read.All)'
    if ($null -eq $raw) { return $null }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($raw)) {
        $plans = @(Get-GapsioProp $s 'servicePlans')
        $mde = @(foreach ($p in $plans) { $t = Get-GapsioMdePlanTier $p; if ($t) { [pscustomobject]@{ name = [string]$p.servicePlanName; tier = $t; status = [string]$p.provisioningStatus } } })
        $mdo = @(foreach ($p in $plans) { $t = Get-GapsioMdoPlanTier $p; if ($t) { [pscustomobject]@{ name = [string]$p.servicePlanName; tier = $t; status = [string]$p.provisioningStatus } } })
        if (-not $mde.Count -and -not $mdo.Count) { continue }
        $part = [string](Get-GapsioProp $s 'skuPartNumber')
        $enabled = [int](Get-GapsioProp (Get-GapsioProp $s 'prepaidUnits') 'enabled'); $consumed = [int](Get-GapsioProp $s 'consumedUnits')
        foreach ($product in @('MDE', 'MDO')) {
            $planList = if ($product -eq 'MDE') { $mde } else { $mdo }
            if (-not $planList.Count) { continue }
            $tier = Get-GapsioBestTier @($planList | ForEach-Object tier) -Product $product
            $isServer = $product -eq 'MDE' -and ($part -match 'SERVER' -or $part -match 'MDATP_Server')
            $display = Get-GapsioSkuDisplayName -PartNumber $part -Tier $tier -IsServer ([bool]$isServer) -Product $product
            $out.Add([pscustomobject]@{
                    key = $(if ($product -eq 'MDE') { Get-GapsioHash "sku|$($s.skuId)" } else { Get-GapsioHash "sku|$($s.skuId)|MDO" })
                    fp = Get-GapsioHash "$enabled|$consumed|$tier|$([string](Get-GapsioProp $s 'capabilityStatus'))"
                    label = "$display ($consumed/$enabled)"; state = [string](Get-GapsioProp $s 'capabilityStatus')
                    product = $product; skuId = [string]$s.skuId; skuPartNumber = $part; skuName = $display; tier = $tier; isServer = [bool]$isServer
                    enabled = $enabled; consumed = $consumed; suspended = [int](Get-GapsioProp (Get-GapsioProp $s 'prepaidUnits') 'suspended'); warning = [int](Get-GapsioProp (Get-GapsioProp $s 'prepaidUnits') 'warning')
                    appliesTo = [string](Get-GapsioProp $s 'appliesTo'); plans = $planList
                })
        }
    }
    @($out | Sort-Object { if ($_.product -eq 'MDE') { 0 } else { 1 } }, { -$(if ($_.product -eq 'MDO') { $script:GapsioMdoTierRank[$_.tier] } else { $script:GapsioMdeTierRank[$_.tier] }) }, skuPartNumber)
}

function Get-GapsioMdeLicensedUsers {
    <#
    .SYNOPSIS
    Users with an enabled Defender for Endpoint plan (P2, P1 or Defender for Business) and/or a Defender for Office 365
    plan. The whole user list is read with a narrow $select and filtered locally – Graph does not filter reliably on
    assignedPlans. tier = MDE tier ($null when the user only holds MDO), mdoTier = Defender for Office 365 tier.
    #>
    $raw = Invoke-GapsioGraphSafe -All -Path 'users?$select=id,userPrincipalName,displayName,accountEnabled,userType,assignedPlans,onPremisesSamAccountName,mailNickname&$top=999' -Context 'Users with assigned plans (User.Read.All)'
    if ($null -eq $raw) { return $null }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($u in @($raw)) {
        $enabledPlans = @(foreach ($p in @(Get-GapsioProp $u 'assignedPlans')) { if ([string](Get-GapsioProp $p 'capabilityStatus') -eq 'Enabled') { $p } })
        $tier = Get-GapsioBestTier @(foreach ($p in $enabledPlans) { Get-GapsioMdePlanTier $p })
        $mdoTier = Get-GapsioBestTier @(foreach ($p in $enabledPlans) { Get-GapsioMdoPlanTier $p }) -Product 'MDO'
        if (-not $tier -and -not $mdoTier) { continue }
        $upn = [string]$u.userPrincipalName
        $out.Add([pscustomobject]@{
                id = [string]$u.id; upn = $upn; displayName = [string]$u.displayName; tier = $tier; mdoTier = $mdoTier
                accountEnabled = [bool](Get-GapsioProp $u 'accountEnabled'); userType = [string](Get-GapsioProp $u 'userType')
                names = @(@(($upn -split '@')[0], [string](Get-GapsioProp $u 'onPremisesSamAccountName'), [string](Get-GapsioProp $u 'mailNickname')) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
            })
    }
    $out.ToArray()
}

function Get-GapsioLicensingDevices {
    <#
    .SYNOPSIS
    Onboarded devices (last 30 days) and who used them: primary user and recent users from Intune (exact, by Entra
    device ID) plus interactive logons from DeviceLogonEvents (matched by account name – lower confidence).
    Returns @{ devices = …; logons = …; intune = … } or $null when hunting is unavailable.
    #>
    $days = $script:GapsioLicensingDays
    $devices = Invoke-GapsioHuntingSafe -NoShard -Context 'Onboarded devices (ThreatHunting.Read.All)' -Query @"
// GapsioLicensingDevices
DeviceInfo
| where Timestamp > ago(${days}d)
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, DeviceName, OSPlatform, DeviceType, AadDeviceId, MachineGroup, ExclusionReason, LoggedOnUsers), Model = take_anyif(Model, isnotempty(Model)), Vendor = take_anyif(Vendor, isnotempty(Vendor)) by DeviceId
| project DeviceId, DeviceName, OSPlatform, DeviceType, AadDeviceId, MachineGroup, ExclusionReason, LoggedOnUsers, Model, Vendor, LastSeen = Timestamp
"@
    if ($null -eq $devices) { return $null }
    $logons = Invoke-GapsioHuntingSafe -NoShard -Context 'Interactive logons (ThreatHunting.Read.All)' -Query @"
// GapsioLicensingLogons
DeviceLogonEvents
| where Timestamp > ago(${days}d)
| where ActionType == "LogonSuccess"
| where LogonType in ("Interactive", "RemoteInteractive", "CachedInteractive", "Unlock")
| where isnotempty(AccountName) and not(AccountName endswith "$") and AccountName !startswith "DWM-" and AccountName !startswith "UMFD-"
| where tolower(AccountDomain) !in ("nt authority", "window manager", "font driver host", "nt service")
| summarize Logons = count(), Last = max(Timestamp) by DeviceId, AccountName = tolower(AccountName)
"@
    $intune = $null
    if (Test-GapsioFeature 'coverage') {
        $intune = Invoke-GapsioGraphSafe -All -Path 'deviceManagement/managedDevices?$select=id,azureADDeviceId,userPrincipalName,userId,operatingSystem,deviceName,deviceEnrollmentType,enrollmentProfileName,model,manufacturer&$top=1000' -Context 'Intune devices and their users (DeviceManagementManagedDevices.Read.All)'
    }
    @{ devices = @($devices); logons = @($logons); intune = @($intune) }
}

function Test-GapsioServerDevice {
    param($Row)
    $t = [string](Get-GapsioProp $Row 'DeviceType'); $os = [string](Get-GapsioProp $Row 'OSPlatform')
    $t -eq 'Server' -or $os -match 'Server' -or ($os -eq 'Linux' -and $t -ne 'Workstation')
}

function Get-GapsioLicensingModel {
    <#
    .SYNOPSIS
    Pure computation (testable without I/O): joins SKUs, licensed users and devices into the licensing snapshot body.
    #>
    param($Skus, $Users, $Data, [string]$Detail = 'users')
    $T = { param($en, $de) New-GapsioText -En $en -De $de }
    $allUsers = @($Users | Where-Object { $_ })
    $Users = @($allUsers | Where-Object { $_.tier })          # Defender for Endpoint holders drive the device mapping
    $mdoUsers = @($allUsers | Where-Object { $_.mdoTier })
    $byId = @{}; $byName = @{}
    foreach ($u in @($Users)) { $byId[$u.id] = $u; foreach ($n in $u.names) { if (-not $byName.ContainsKey($n)) { $byName[$n] = [System.Collections.Generic.List[object]]::new() }; $byName[$n].Add($u) } }
    $byUpn = @{}; foreach ($u in @($Users)) { if ($u.upn) { $byUpn[$u.upn.ToLowerInvariant()] = $u } }

    # Intune: Entra device ID -> users (exact) and -> managed device record (enrolment type, model)
    $intuneUsers = @{}; $intuneByAad = @{}
    foreach ($m in @($Data.intune)) {
        $aad = [string](Get-GapsioProp $m 'azureADDeviceId'); if (-not $aad) { continue }
        $aad = $aad.ToLowerInvariant()
        if (-not $intuneByAad.ContainsKey($aad)) { $intuneByAad[$aad] = $m }
        if (-not $intuneUsers.ContainsKey($aad)) { $intuneUsers[$aad] = [System.Collections.Generic.HashSet[string]]::new() }
        $upn = [string](Get-GapsioProp $m 'userPrincipalName'); if ($upn) { $null = $intuneUsers[$aad].Add("upn:$($upn.ToLowerInvariant())") }
        $uid = [string](Get-GapsioProp $m 'userId'); if ($uid) { $null = $intuneUsers[$aad].Add("id:$uid") }
    }
    # Logons: DeviceId -> account names
    $logonNames = @{}
    foreach ($l in @($Data.logons)) {
        $d = [string]$l.DeviceId; if (-not $logonNames.ContainsKey($d)) { $logonNames[$d] = [System.Collections.Generic.HashSet[string]]::new() }
        $null = $logonNames[$d].Add(([string]$l.AccountName).ToLowerInvariant())
    }

    $userDevices = @{}   # user id -> HashSet deviceId (personal clients only)
    $userSharedDevices = @{}   # user id -> HashSet deviceId (shared / kiosk / VDI clients – do not count against the per-user limit)
    $serviceAccountNames = [System.Collections.Generic.HashSet[string]]::new()
    $devices = [System.Collections.Generic.List[object]]::new()
    $servers = [System.Collections.Generic.List[object]]::new()
    foreach ($row in @($Data.devices)) {
        if ([string](Get-GapsioProp $row 'ExclusionReason')) { continue }
        $id = [string]$row.DeviceId
        $isServer = Test-GapsioServerDevice $row
        $rec = [ordered]@{
            key = Get-GapsioHash "licdev|$id"; deviceId = $id; deviceName = [string]$row.DeviceName; os = [string]$row.OSPlatform; deviceType = [string]$row.DeviceType
            machineGroup = [string]$row.MachineGroup; lastSeen = ConvertTo-GapsioUtc $row.LastSeen; users = @(); licensedBy = $null; tier = $null; confidence = $null; state = $null
            usage = 'Personal'; usageReasons = @(); distinctUsers = 0; serviceAccounts = @(); model = (("$([string](Get-GapsioProp $row 'Vendor')) $([string](Get-GapsioProp $row 'Model'))").Trim())
        }
        if ($isServer) { $rec.state = 'Server'; $rec.fp = Get-GapsioHash 'server'; $rec.label = "$($rec.deviceName): server"; $servers.Add([pscustomobject]$rec); continue }

        $found = [ordered]@{}   # user id -> confidence
        $aad = ([string](Get-GapsioProp $row 'AadDeviceId')).ToLowerInvariant()
        if ($aad -and $intuneUsers.ContainsKey($aad)) {
            foreach ($ref in $intuneUsers[$aad]) {
                $u = if ($ref.StartsWith('id:')) { $byId[$ref.Substring(3)] } else { $byUpn[$ref.Substring(4)] }
                if ($u) { $found[$u.id] = 'Intune' } elseif ($ref.StartsWith('upn:')) { $found[$ref] = 'Intune' }
            }
        }
        $names = [System.Collections.Generic.HashSet[string]]::new()
        if ($logonNames.ContainsKey($id)) { foreach ($n in $logonNames[$id]) { $null = $names.Add($n) } }
        $lou = [string](Get-GapsioProp $row 'LoggedOnUsers')
        if ($lou) { try { foreach ($x in @($lou | ConvertFrom-Json)) { $n = [string](Get-GapsioProp $x 'UserName'); if ($n -and $n -notmatch '\$$') { $null = $names.Add($n.ToLowerInvariant()) } } } catch { } }
        # Service / admin / kiosk auto-logon accounts are not people: record them, but do not map them to licences.
        $svc = @(foreach ($n in @($names)) { if (Test-GapsioServiceAccountName $n) { $n } })
        foreach ($n in $svc) { $null = $names.Remove($n); $null = $serviceAccountNames.Add($n) }
        $rec.serviceAccounts = @($svc | Sort-Object)
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
        $rec.distinctUsers = $found.Count
        $cls = Get-GapsioDeviceUsage -Row $row -Intune $(if ($aad -and $intuneByAad.ContainsKey($aad)) { $intuneByAad[$aad] } else { $null }) -DistinctUsers $found.Count
        $rec.usage = $cls.usage; $rec.usageReasons = @($cls.reasons)
        $bucket = if ($rec.usage -eq 'Personal') { $userDevices } else { $userSharedDevices }
        foreach ($u in $licensedUsers) { if (-not $bucket.ContainsKey($u.id)) { $bucket[$u.id] = [System.Collections.Generic.HashSet[string]]::new() }; $null = $bucket[$u.id].Add($id) }
        if ($licensedUsers.Count) {
            $best = $licensedUsers | Sort-Object { -$script:GapsioMdeTierRank[$_.tier] } | Select-Object -First 1
            $rec.state = 'Licensed'; $rec.licensedBy = $best.upn; $rec.tier = $best.tier; $rec.confidence = $found[$best.id]
        }
        elseif ($anyUser) { $rec.state = 'Unlicensed'; $rec.confidence = $(if ($found.Values -contains 'Intune') { 'Intune' } else { 'Logon' }) }
        else { $rec.state = 'NoUser' }
        $rec.fp = Get-GapsioHash "$($rec.state)|$($rec.tier)|$($rec.licensedBy)|$($rec.usage)"
        $rec.label = "$($rec.deviceName): $($rec.state)$(if ($rec.usage -ne 'Personal') { " ($($rec.usage))" })"
        $devices.Add([pscustomobject]$rec)
    }

    $userRows = [System.Collections.Generic.List[object]]::new()
    foreach ($u in @($Users)) {
        $n = if ($userDevices.ContainsKey($u.id)) { $userDevices[$u.id].Count } else { 0 }
        $nShared = if ($userSharedDevices.ContainsKey($u.id)) { $userSharedDevices[$u.id].Count } else { 0 }
        $state = if ($n -gt $script:GapsioMdeDevicesPerUser) { 'OverLimit' } elseif ($n -eq 0 -and $nShared -eq 0) { 'NoDevice' } else { 'InUse' }
        $upn = if ($Detail -eq 'aggregate') { "user-$((Get-GapsioHash $u.id).Substring(0, 10))" } else { $u.upn }
        $name = if ($Detail -eq 'aggregate') { $null } else { $u.displayName }
        $userRows.Add([pscustomobject]@{
                key = Get-GapsioHash "licuser|$($u.id)"; fp = Get-GapsioHash "$($u.tier)|$n|$($u.accountEnabled)"; label = "$upn ($($u.tier)): $n device(s)"; state = $state
                upn = $upn; displayName = $name; tier = $u.tier; accountEnabled = $u.accountEnabled; userType = $u.userType; deviceCount = $n; sharedDeviceCount = $nShared
                devices = @($(if ($userDevices.ContainsKey($u.id)) { $userDevices[$u.id] } else { @() }) | ForEach-Object { $d = $_; $dev = $devices | Where-Object { $_.deviceId -eq $d } | Select-Object -First 1; if ($dev) { $dev.deviceName } else { $d } })
                sharedDevices = @($(if ($userSharedDevices.ContainsKey($u.id)) { $userSharedDevices[$u.id] } else { @() }) | ForEach-Object { $d = $_; $dev = $devices | Where-Object { $_.deviceId -eq $d } | Select-Object -First 1; if ($dev) { "$($dev.deviceName) ($($dev.usage))" } else { $d } })
            })
    }

    $skuList = @($Skus | Where-Object { $_ })
    $mdoSkus = @($skuList | Where-Object product -eq 'MDO')
    $skuListMde = @($skuList | Where-Object { -not $_.product -or $_.product -eq 'MDE' })
    $userSkus = @($skuListMde | Where-Object { -not $_.isServer }); $serverSkus = @($skuListMde | Where-Object isServer)
    $sum = { param($list, $prop, $tier) [int](($list | Where-Object { $_.tier -eq $tier } | Measure-Object $prop -Sum).Sum) }
    $clients = @($devices)
    $licUsers = @($Users | Where-Object { $_ })
    $mdoRows = [System.Collections.Generic.List[object]]::new()
    foreach ($u in $mdoUsers) {
        $upn = if ($Detail -eq 'aggregate') { "user-$((Get-GapsioHash $u.id).Substring(0, 10))" } else { $u.upn }
        $name = if ($Detail -eq 'aggregate') { $null } else { $u.displayName }
        $mdoRows.Add([pscustomobject]@{
                key = Get-GapsioHash "mdouser|$($u.id)"; fp = Get-GapsioHash "$($u.mdoTier)|$($u.tier)|$($u.accountEnabled)"; label = "$upn (MDO $($u.mdoTier))"
                state = $(if (-not $u.accountEnabled) { 'Disabled' } else { 'InUse' })
                upn = $upn; displayName = $name; tier = $u.mdoTier; mdeTier = $u.tier; accountEnabled = $u.accountEnabled; userType = $u.userType
            })
    }
    $summary = [ordered]@{
        observedDays        = $script:GapsioLicensingDays
        devicesPerUser      = $script:GapsioMdeDevicesPerUser
        skus                = $skuList.Count
        p2Enabled           = & $sum $userSkus 'enabled' 'P2'; p2Consumed = & $sum $userSkus 'consumed' 'P2'
        p1Enabled           = & $sum $userSkus 'enabled' 'P1'; p1Consumed = & $sum $userSkus 'consumed' 'P1'
        mdbEnabled          = & $sum $userSkus 'enabled' 'MDB'; mdbConsumed = & $sum $userSkus 'consumed' 'MDB'
        serverSkuEnabled    = [int](($serverSkus | Measure-Object enabled -Sum).Sum); serverSkuConsumed = [int](($serverSkus | Measure-Object consumed -Sum).Sum)
        mdoP2Enabled        = & $sum $mdoSkus 'enabled' 'P2'; mdoP2Consumed = & $sum $mdoSkus 'consumed' 'P2'
        mdoP1Enabled        = & $sum $mdoSkus 'enabled' 'P1'; mdoP1Consumed = & $sum $mdoSkus 'consumed' 'P1'
        mdoSkus             = $mdoSkus.Count
        mdoUsers            = $mdoUsers.Count
        mdoUsersP2          = @($mdoUsers | Where-Object mdoTier -eq 'P2').Count
        mdoUsersP1          = @($mdoUsers | Where-Object mdoTier -eq 'P1').Count
        mdoUsersDisabled    = @($mdoUsers | Where-Object { -not $_.accountEnabled }).Count
        mdoUsersWithoutMde  = @($mdoUsers | Where-Object { -not $_.tier }).Count
        mdeUsersWithoutMdo  = @($licUsers | Where-Object { -not $_.mdoTier }).Count
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
        clientsShared       = @($clients | Where-Object usage -eq 'Shared').Count
        clientsKiosk        = @($clients | Where-Object usage -eq 'Kiosk').Count
        clientsVdi          = @($clients | Where-Object usage -eq 'VDI').Count
        clientsNoUserPersonal = @($clients | Where-Object { $_.state -eq 'NoUser' -and $_.usage -eq 'Personal' }).Count
        serviceAccounts     = $serviceAccountNames.Count
        sharedMinUsers      = $script:GapsioLicensingSharedMinUsers
        servers             = $servers.Count
        intuneMapping       = [bool](@($Data.intune).Count)
    }

    # Findings
    $f = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($userSkus) + @($mdoSkus)) {
        if ($s.consumed -gt $s.enabled -and $s.enabled -ge 0) {
            $f.Add((New-GapsioFinding -Severity 'High' -Category 'Licensing' -Subject "$($s.skuId)$(if ($s.product -eq 'MDO') { '|MDO' })" -StableKey `
                        -Title (& $T "More licences assigned than purchased: $($s.skuName)" "Mehr Lizenzen zugewiesen als gekauft: $($s.skuName)") `
                        -Detail (& $T "$($s.consumed) of $($s.enabled) units are assigned. Microsoft 365 allows this temporarily; the overage is billed or blocked at the next true-up." "$($s.consumed) von $($s.enabled) Einheiten sind zugewiesen. Microsoft 365 erlaubt das vorübergehend; der Überhang wird beim nächsten True-up berechnet oder gesperrt.") `
                        -Recommendation (& $T 'Buy additional units or remove the plan from users who do not need it.' 'Zusätzliche Einheiten kaufen oder den Plan bei Benutzern entfernen, die ihn nicht benötigen.')))
        }
    }
    $unl = @($clients | Where-Object state -eq 'Unlicensed')
    if ($unl.Count) {
        $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'Licensing' -Subject 'clients-unlicensed' -StableKey `
                    -Title (& $T "$($unl.Count) onboarded client(s) used only by users without a Defender for Endpoint licence" "$($unl.Count) onboardete(r) Client(s) nur von Benutzern ohne Defender-for-Endpoint-Lizenz genutzt") `
                    -Detail (& $T "In the last $($script:GapsioLicensingDays) days these devices were used by users who hold no MDE P1/P2 or Defender for Business plan. Indication only: the user mapping comes from Intune and interactive logons." "In den letzten $($script:GapsioLicensingDays) Tagen wurden diese Geräte von Benutzern genutzt, die keinen MDE-P1/P2- oder Defender-for-Business-Plan haben. Nur ein Hinweis: Die Benutzerzuordnung stammt aus Intune und interaktiven Anmeldungen.") `
                    -Recommendation (& $T 'Assign a Defender for Endpoint plan to the users (group-based licensing) or exclude the devices from onboarding.' 'Den Benutzern einen Defender-for-Endpoint-Plan zuweisen (gruppenbasierte Lizenzierung) oder die Geräte vom Onboarding ausnehmen.') |
                Add-Member -NotePropertyName deviceCount -NotePropertyValue $unl.Count -PassThru | Add-Member -NotePropertyName deviceSample -NotePropertyValue @($unl | Select-Object -First 10 | ForEach-Object deviceName) -PassThru))
    }
    $over = @($userRows | Where-Object state -eq 'OverLimit')
    if ($over.Count) {
        $f.Add((New-GapsioFinding -Severity 'Low' -Category 'Licensing' -Subject 'users-overlimit' -StableKey `
                    -Title (& $T "$($over.Count) user(s) use more than $($script:GapsioMdeDevicesPerUser) client devices" "$($over.Count) Benutzer nutzen mehr als $($script:GapsioMdeDevicesPerUser) Client-Geräte") `
                    -Detail (& $T "A user licence covers up to $($script:GapsioMdeDevicesPerUser) devices. Devices recognised as shared, kiosk or VDI and service/admin accounts are already excluded from this count – what remains looks like genuine personal use." "Eine Benutzerlizenz deckt bis zu $($script:GapsioMdeDevicesPerUser) Geräte ab. Als geteilt, Kiosk oder VDI erkannte Geräte sowie Dienst-/Admin-Konten sind aus dieser Zahl bereits herausgerechnet – der Rest sieht nach echter persönlicher Nutzung aus.") `
                    -Recommendation (& $T 'Check whether the extra devices are shared devices (device licence) or whether the user really uses more than five devices.' 'Prüfen, ob die zusätzlichen Geräte geteilte Geräte sind (Gerätelizenz) oder der Benutzer tatsächlich mehr als fünf Geräte nutzt.')))
    }
    $noDev = @($userRows | Where-Object { $_.state -eq 'NoDevice' -and $_.accountEnabled })
    if ($noDev.Count -and $clients.Count) {
        $f.Add((New-GapsioFinding -Severity 'Low' -Category 'Licensing' -Subject 'users-nodevice' -StableKey `
                    -Title (& $T "$($noDev.Count) licensed user(s) without an onboarded device in $($script:GapsioLicensingDays) days" "$($noDev.Count) lizenzierte Benutzer ohne onboardetes Gerät in $($script:GapsioLicensingDays) Tagen") `
                    -Detail (& $T 'Potentially unused licences – or users whose device is not onboarded, uses no interactive logon (VDI, Mac without Intune) or was inactive.' 'Potenziell ungenutzte Lizenzen – oder Benutzer, deren Gerät nicht onboardet ist, ohne interaktive Anmeldung läuft (VDI, Mac ohne Intune) oder inaktiv war.') `
                    -Recommendation (& $T 'Cross-check with the coverage page before reclaiming licences.' 'Vor der Rücknahme von Lizenzen mit der Coverage-Seite abgleichen.')))
    }
    $p1 = @($clients | Where-Object { $_.state -eq 'Licensed' -and $_.tier -eq 'P1' })
    if ($p1.Count -and $summary.usersP2 -gt 0) {
        $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'Licensing' -Subject 'clients-p1' -StableKey `
                    -Title (& $T "$($p1.Count) client(s) covered only by Plan 1 in a tenant using Plan 2 features" "$($p1.Count) Client(s) nur durch Plan 1 abgedeckt in einem Tenant mit Plan-2-Funktionen") `
                    -Detail (& $T 'Plan 1 covers next-generation protection, ASR and manual response. EDR, Advanced Hunting, automated investigation and vulnerability management are Plan 2 features and apply to every onboarded device.' 'Plan 1 umfasst Next-Generation Protection, ASR und manuelle Reaktion. EDR, Advanced Hunting, automatische Untersuchung und Schwachstellenmanagement sind Plan-2-Funktionen und wirken auf jedes onboardete Gerät.') `
                    -Recommendation (& $T 'Either licence these users with Plan 2 or document why Plan 1 is sufficient for them (mixed licensing requires the P2 features to be unused for those devices).' 'Diese Benutzer entweder mit Plan 2 lizenzieren oder dokumentieren, warum Plan 1 für sie ausreicht (Mischlizenzierung setzt voraus, dass die P2-Funktionen für diese Geräte nicht genutzt werden).')))
    }
    $sharedLike = @($clients | Where-Object { $_.usage -ne 'Personal' })
    if ($sharedLike.Count) {
        $byUsage = ($sharedLike | Group-Object usage | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
        $f.Add((New-GapsioFinding -Severity 'Low' -Category 'Licensing' -Subject 'clients-shared' -StableKey `
                    -Title (& $T "$($sharedLike.Count) client(s) look like shared, kiosk or virtual desktops ($byUsage)" "$($sharedLike.Count) Client(s) sehen nach geteilten Geräten, Kiosks oder virtuellen Desktops aus ($byUsage)") `
                    -Detail (& $T "Recognised from the number of distinct people signing in (≥ $($script:GapsioLicensingSharedMinUsers)), the Intune enrolment type (self-deploying / shared PC, Azure VM extension), the hardware model and naming patterns. Microsoft licenses these per user as well: every person who uses them needs a plan, but the devices do not count against the five-device limit here." "Erkannt an der Zahl unterschiedlicher Personen, die sich anmelden (≥ $($script:GapsioLicensingSharedMinUsers)), am Intune-Registrierungstyp (Self-Deploying / Shared PC, Azure-VM-Erweiterung), am Hardwaremodell und an Namensmustern. Microsoft lizenziert auch diese pro Benutzer: Jede Person, die sie nutzt, braucht einen Plan – die Geräte zählen hier aber nicht gegen das Fünf-Geräte-Limit.") `
                    -Recommendation (& $T 'Check the usage column in the device table. If a device is misclassified, tune GAPSIO_LICENSING_SHARED_MIN_USERS or GAPSIO_LICENSING_SERVICE_PATTERN.' 'Die Spalte „Nutzung“ in der Gerätetabelle prüfen. Bei Fehlklassifizierung GAPSIO_LICENSING_SHARED_MIN_USERS oder GAPSIO_LICENSING_SERVICE_PATTERN anpassen.') |
                Add-Member -NotePropertyName deviceCount -NotePropertyValue $sharedLike.Count -PassThru | Add-Member -NotePropertyName deviceSample -NotePropertyValue @($sharedLike | Select-Object -First 10 | ForEach-Object { "$($_.deviceName) ($($_.usage))" }) -PassThru))
    }
    if ($servers.Count -and -not $serverSkus.Count) {
        $f.Add((New-GapsioFinding -Severity 'Low' -Category 'Licensing' -Subject 'servers' -StableKey `
                    -Title (& $T "$($servers.Count) onboarded server(s) – no server licence visible in Microsoft 365" "$($servers.Count) onboardete(r) Server – keine Serverlizenz in Microsoft 365 sichtbar") `
                    -Detail (& $T 'Servers are normally licensed through Defender for Servers (Defender for Cloud, Azure subscription) – that is not visible in Microsoft Graph. Only "Defender for Endpoint Server" SKUs show up here.' 'Server werden normalerweise über Defender for Servers (Defender for Cloud, Azure-Abonnement) lizenziert – das ist in Microsoft Graph nicht sichtbar. Nur „Defender for Endpoint Server“-SKUs erscheinen hier.') `
                    -Recommendation (& $T 'Confirm that the servers are covered by a Defender for Servers plan or a server SKU.' 'Bestätigen, dass die Server durch einen Defender-for-Servers-Plan oder eine Server-SKU abgedeckt sind.')))
    }
    if ($summary.mdoUsersP1 -gt 0 -and $summary.mdoUsersP2 -gt 0) {
        $f.Add((New-GapsioFinding -Severity 'Low' -Category 'Licensing' -Subject 'mdo-mixed' -StableKey `
                    -Title (& $T "Defender for Office 365: $($summary.mdoUsersP1) user(s) on Plan 1 next to $($summary.mdoUsersP2) on Plan 2" "Defender for Office 365: $($summary.mdoUsersP1) Benutzer mit Plan 1 neben $($summary.mdoUsersP2) mit Plan 2") `
                    -Detail (& $T 'Plan 2 features (Threat Explorer, automated investigation, attack simulation, campaign views) are tenant-wide once licensed. Microsoft expects every user who benefits to hold Plan 2; mixed tenants are a common compliance finding.' 'Plan-2-Funktionen (Threat Explorer, automatische Untersuchung, Angriffssimulation, Kampagnenansicht) wirken mandantenweit, sobald lizenziert. Microsoft erwartet Plan 2 für jeden Benutzer, der davon profitiert; gemischte Mandanten sind ein häufiger Compliance-Befund.') `
                    -Recommendation (& $T 'Either move the Plan 1 users to Plan 2 or document why Plan 1 is sufficient for them.' 'Die Plan-1-Benutzer auf Plan 2 heben oder dokumentieren, warum Plan 1 für sie ausreicht.')))
    }
    $mdoDisabled = @($mdoUsers | Where-Object { -not $_.accountEnabled })
    if ($mdoDisabled.Count) {
        $f.Add((New-GapsioFinding -Severity 'Low' -Category 'Licensing' -Subject 'mdo-disabled' -StableKey `
                    -Title (& $T "$($mdoDisabled.Count) disabled account(s) still hold a Defender for Office 365 plan" "$($mdoDisabled.Count) deaktivierte(s) Konto/Konten halten noch einen Defender-for-Office-365-Plan") `
                    -Detail (& $T 'Disabled accounts cannot receive mail protection benefits but still consume a licence.' 'Deaktivierte Konten profitieren nicht mehr vom E-Mail-Schutz, verbrauchen aber weiterhin eine Lizenz.') `
                    -Recommendation (& $T 'Reclaim the licence or convert the mailbox to a shared mailbox (no licence needed below 50 GB without archive).' 'Lizenz zurückholen oder das Postfach in ein freigegebenes Postfach umwandeln (unter 50 GB ohne Archiv lizenzfrei).')))
    }
    $summary.findings = $f.Count

    $caveats = @(
        (& $T 'Indication, not an audit: Microsoft licenses Defender for Endpoint per user (up to five devices each); Gapsio derives the device-to-user mapping from Intune and interactive logons of the last 30 days.' 'Hinweis, kein Audit: Microsoft lizenziert Defender for Endpoint pro Benutzer (bis zu fünf Geräte); Gapsio leitet die Zuordnung Gerät → Benutzer aus Intune und interaktiven Anmeldungen der letzten 30 Tage ab.'),
        (& $T "Shared devices, kiosks and VDI are recognised heuristically (≥ $($script:GapsioLicensingSharedMinUsers) distinct people, Intune enrolment type, hardware model, naming) and do not count against the per-user device limit; service and admin account names are ignored as users. Both can be tuned (GAPSIO_LICENSING_SHARED_MIN_USERS, GAPSIO_LICENSING_SERVICE_PATTERN)." "Geteilte Geräte, Kiosks und VDI werden heuristisch erkannt (≥ $($script:GapsioLicensingSharedMinUsers) unterschiedliche Personen, Intune-Registrierungstyp, Hardwaremodell, Namensmuster) und zählen nicht gegen das Gerätelimit pro Benutzer; Dienst- und Admin-Kontonamen werden nicht als Benutzer gewertet. Beides ist einstellbar (GAPSIO_LICENSING_SHARED_MIN_USERS, GAPSIO_LICENSING_SERVICE_PATTERN)."),
        (& $T 'Server licences (Defender for Servers via Azure) are not visible in Microsoft Graph; servers are listed separately.' 'Serverlizenzen (Defender for Servers über Azure) sind in Microsoft Graph nicht sichtbar; Server werden separat gezählt.'),
        (& $T 'Confidence "Intune" = exact match by Entra device ID; "Logon" = account name matched to UPN / SAM account name.' 'Konfidenz „Intune“ = exakte Zuordnung über Entra-Geräte-ID; „Logon“ = Kontoname mit UPN / SAM-Kontoname abgeglichen.'),
        (& $T 'Defender for Office 365 is licensed per user (mailbox); Gapsio shows purchased vs. assigned units and the users holding a plan. Shared mailboxes, unlicensed guests and the tenant-wide effect of Plan 2 features are not assessed.' 'Defender for Office 365 wird pro Benutzer (Postfach) lizenziert; Gapsio zeigt gekaufte vs. zugewiesene Einheiten und die Benutzer mit Plan. Freigegebene Postfächer, unlizenzierte Gäste und die mandantenweite Wirkung von Plan-2-Funktionen werden nicht bewertet.')
    )
    [ordered]@{
        summary = $summary; skus = $skuList; users = @($userRows); mdoUsers = @($mdoRows); devices = @($devices | Sort-Object { @{ Unlicensed = 0; NoUser = 1; Licensed = 2 }[$_.state] }, deviceName)
        servers = @($servers); findings = @($f); caveats = $caveats
    }
}

function Invoke-GapsioLicensingCollection {
    <#
    .SYNOPSIS
    Collects the Defender for Endpoint licence indication and stores it as the licensing snapshot (module "licensing").
    GAPSIO_LICENSING_DETAIL=aggregate pseudonymises user names in the stored snapshot (data-minimisation).
    #>
    Reset-GapsioWarnings
    Get-GapsioLicensingSettings
    $started = [DateTime]::UtcNow
    $detail = ([string](Get-GapsioSetting 'GAPSIO_LICENSING_DETAIL' 'users')).ToLowerInvariant()
    $skus = Get-GapsioLicenseSkus
    $users = Get-GapsioMdeLicensedUsers
    $data = Get-GapsioLicensingDevices
    if ($null -eq $data) { Add-GapsioWarning 'Device-to-user mapping needs the hunting feature (ThreatHunting.Read.All); only SKUs and licensed users are shown.'; $data = @{ devices = @(); logons = @(); intune = @() } }
    $m = Get-GapsioLicensingModel -Skus @($skus) -Users @($users) -Data $data -Detail $detail
    $r = [ordered]@{
        module = 'licensing'; version = (Get-GapsioVersion); generatedAt = $started.ToString('o'); tenantId = (Get-GapsioSetting 'GAPSIO_TENANT_ID')
        scope = 'Defender for Endpoint, Defender for Office 365'; detail = $detail
        summary = $m.summary; skus = $m.skus; users = $m.users; mdoUsers = $m.mdoUsers; devices = $m.devices; servers = $m.servers; findings = $m.findings; caveats = $m.caveats
        warnings = @(Get-GapsioWarnings)
    }
    Save-GapsioSnapshot -Module 'licensing' -Snapshot $r -Collections @('skus', 'users', 'mdoUsers', 'devices', 'findings') -Started $started
    Write-Information "Licensing collection done: $($m.summary.licensedUsers) MDE users, $($m.summary.mdoUsers) MDO users, $($m.summary.clients) clients ($($m.summary.clientsUnlicensed) unlicensed), $($m.summary.servers) servers, $($m.findings.Count) findings."
    $r
}
