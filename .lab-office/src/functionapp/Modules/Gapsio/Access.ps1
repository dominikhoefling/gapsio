# Gapsio Access (optional module, disabled by default): Microsoft Defender XDR unified RBAC
# - Roles and assignments from roleManagement/defender (unified RBAC): who holds which Defender role,
#   for which data sources (appScopeIds), through which path
# - Paths: direct, via group (transitive members), PIM for groups (eligible), access package that grants
#   such a group (requestable / assigned)
# - Usage: last sign-in to the Defender portal per person (Entra sign-in logs, carried forward across runs)
#   and last PIM-for-groups activation -> "has this permission ever been used?"
# - Entra roles that bypass unified RBAC (Global/Security Administrator, Security Operator/Reader,
#   Global Reader) are reported separately, not mixed into the table
# States: Active, Eligible, Requestable

$script:WlUsers = @{}
$script:WlGroupMembers = @{}
$script:WlGroupNames = @{}
$script:WlMaxMembers = 10000
$script:WlDefenderPortalAppId = '80ccca67-54bd-44ab-8625-4b79c4dc7775'   # Microsoft 365 Security and Compliance Center (security.microsoft.com)
$script:WlEntraBypassRoles = @{
    '62e90394-69f5-4237-9190-012177145e10' = @{ name = 'Global Administrator'; level = 'High' }
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = @{ name = 'Security Administrator'; level = 'High' }
    '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f' = @{ name = 'Security Operator'; level = 'High' }
    '5d6b6bb7-de71-4623-b4af-96380a352509' = @{ name = 'Security Reader'; level = 'Low' }
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451' = @{ name = 'Global Reader'; level = 'Low' }
}
$script:WlXdrDataSources = @{
    'Mde' = 'Defender for Endpoint'; 'Mdo' = 'Defender for Office 365'; 'Mdi' = 'Defender for Identity'; 'Mda' = 'Defender for Cloud Apps'
    'Mdc' = 'Defender for Cloud'; 'Xdr' = 'Defender XDR'; 'Msem' = 'Exposure Management'; 'Mdvm' = 'Vulnerability Management'; 'Sentinel' = 'Microsoft Sentinel'
}
# Permissions whose misuse has direct impact (response, live response, file collection, settings, authorization).
$script:WlXdrHighImpact = 'securitydata/response/manage', 'liveresponse', 'filecollection/manage', 'configuration/authorization/manage', 'configuration/security/manage', 'configuration/systemsettings/manage', 'emailadvancedactions/manage', 'emailquarantine/manage'

function ConvertTo-WlIsoUtc {
    # Any timestamp (string or DateTime, as it comes from Graph or from a stored snapshot) -> sortable ISO-8601 UTC string.
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return $null }
    try { (ConvertTo-WlUtc $Value).ToString('o') } catch { $null }
}

function Reset-WlAccessCache {
    $script:WlUsers = @{}
    $script:WlGroupMembers = @{}
    $script:WlGroupNames = @{}
    $script:WlMaxMembers = [int](Get-WlSetting -Name 'WL_MAX_GROUP_MEMBERS' -Default '10000')
}

function Get-WlGroupNameCached {
    param([string]$GroupId)
    if (-not $GroupId) { return $null }
    if (-not $script:WlGroupNames.ContainsKey($GroupId)) {
        $name = $GroupId
        try { $g = Invoke-WlGraph -Path "groups/$GroupId`?`$select=id,displayName"; if ($g.displayName) { $name = $g.displayName } } catch { }
        $script:WlGroupNames[$GroupId] = $name
    }
    $script:WlGroupNames[$GroupId]
}

function Get-WlGroupUsers {
    <#
    .SYNOPSIS
    Transitive user members of a group (cached, limited by WL_MAX_GROUP_MEMBERS).
    #>
    param([string]$GroupId)
    if ($script:WlGroupMembers.ContainsKey($GroupId)) { return $script:WlGroupMembers[$GroupId] }
    $users = [System.Collections.Generic.List[object]]::new()
    $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName,displayName,userType&`$top=999"
    try {
        while ($uri -and $users.Count -lt $script:WlMaxMembers) {
            $r = Invoke-WlGraph -Path $uri
            foreach ($u in @($r.value)) {
                if (-not $u) { continue }
                $users.Add($u)
                $script:WlUsers[[string]$u.id] = $u
            }
            $uri = if ($r.PSObject.Properties['@odata.nextLink']) { $r.'@odata.nextLink' } else { $null }
        }
        if ($uri) { Add-WlWarning "Group '$(Get-WlGroupNameCached $GroupId)': more than $($script:WlMaxMembers) members – list truncated (WL_MAX_GROUP_MEMBERS)." }
    }
    catch { Add-WlWarning "Members of group ${GroupId}: $($_.Exception.Message)" }
    $arr = $users.ToArray()
    $script:WlGroupMembers[$GroupId] = $arr
    $arr
}

function Resolve-WlPrincipalInfo {
    <#
    .SYNOPSIS
    Returns type and display information of a principal (user, group, service principal).
    #>
    param([string]$Id, $Expanded)
    if ($Expanded) {
        $t = [string](Get-WlProp $Expanded '@odata.type')
        $type = if ($t -match 'group') { 'group' } elseif ($t -match 'servicePrincipal') { 'servicePrincipal' } else { 'user' }
        if ($type -eq 'user') { $script:WlUsers[$Id] = $Expanded }
        if ($type -eq 'group') { $script:WlGroupNames[$Id] = [string](Get-WlProp $Expanded 'displayName') }
        return [pscustomobject]@{ id = $Id; type = $type; upn = [string](Get-WlProp $Expanded 'userPrincipalName'); displayName = [string](Get-WlProp $Expanded 'displayName') }
    }
    if ($script:WlUsers.ContainsKey($Id)) {
        $u = $script:WlUsers[$Id]
        return [pscustomobject]@{ id = $Id; type = 'user'; upn = [string]$u.userPrincipalName; displayName = [string]$u.displayName }
    }
    if ($script:WlGroupNames.ContainsKey($Id)) { return [pscustomobject]@{ id = $Id; type = 'group'; upn = $null; displayName = $script:WlGroupNames[$Id] } }
    try {
        $o = Invoke-WlGraph -Path "directoryObjects/$Id"
        return Resolve-WlPrincipalInfo -Id $Id -Expanded $o
    }
    catch { return [pscustomobject]@{ id = $Id; type = 'unknown'; upn = $null; displayName = $Id } }
}

function Resolve-WlPrincipalBatch {
    <#
    .SYNOPSIS
    Resolves many principal IDs at once (directoryObjects/getByIds, 1000 per call) into the caches.
    #>
    param([string[]]$Ids)
    $todo = @($Ids | Where-Object { $_ -and -not $script:WlUsers.ContainsKey($_) -and -not $script:WlGroupNames.ContainsKey($_) } | Sort-Object -Unique)
    for ($i = 0; $i -lt $todo.Count; $i += 1000) {
        $chunk = @($todo[$i..([Math]::Min($i + 999, $todo.Count - 1))])
        try {
            $r = Invoke-WlGraph -Method 'POST' -Path 'directoryObjects/getByIds' -Body @{ ids = $chunk; types = @('user', 'group', 'servicePrincipal') }
            foreach ($o in @(Get-WlProp $r 'value')) { if ($o) { Resolve-WlPrincipalInfo -Id ([string]$o.id) -Expanded $o | Out-Null } }
        }
        catch { Add-WlWarning "Resolve principals: $($_.Exception.Message)" }
    }
}

function Get-WlXdrScope {
    <#
    .SYNOPSIS
    Translates the appScopeIds / directoryScopeIds of a Defender role assignment into text.
    "/" = all data sources; "Mde" etc. = one data source; "/UserGroupId/…" = Defender for Identity scope.
    Device-group scoping for Defender for Endpoint is configured on the device groups page and is not part
    of the assignment object (no public API) – it is therefore not shown here.
    #>
    param([object[]]$AppScopeIds, [object[]]$DirectoryScopeIds)
    $ids = @(@($AppScopeIds) + @($DirectoryScopeIds) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    if (-not $ids.Count -or ($ids -contains '/')) { return [pscustomobject]@{ text = 'All data sources'; all = $true; dataSources = @('All') } }
    $parts = [System.Collections.Generic.List[string]]::new(); $ds = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $ids) {
        if ($script:WlXdrDataSources.ContainsKey($s)) { $parts.Add($script:WlXdrDataSources[$s]); $ds.Add($s) }
        elseif ($s -match '^/UserGroupId/(.+)$') { $parts.Add("Identity scope $($Matches[1])") }
        elseif ($s -match '^/DeviceGroupId/(.+)$') { $parts.Add("Device group $($Matches[1])") }
        elseif ($s -match '^/(subscriptions|resourceGroups)/') { $parts.Add("Cloud scope $s") }
        else { $parts.Add($s) }
    }
    [pscustomobject]@{ text = ($parts -join ', '); all = $false; dataSources = @($ds) }
}

function Get-WlDefenderPortalUsage {
    <#
    .SYNOPSIS
    Last sign-in to the Defender portal per user ID (Entra sign-in logs, interactive, up to 30 days).
    #>
    param([int]$Days = 30)
    $since = [DateTime]::UtcNow.AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $usage = @{}
    $rows = Invoke-WlGraphSafe -All -Context 'Defender portal sign-ins (AuditLog.Read.All)' `
        -Path "auditLogs/signIns?`$filter=appId eq '$($script:WlDefenderPortalAppId)' and createdDateTime ge $since and status/errorCode eq 0&`$select=userId,createdDateTime&`$top=999"
    foreach ($r in @($rows)) {
        if (-not $r -or -not $r.userId) { continue }
        $id = [string]$r.userId; $at = ConvertTo-WlIsoUtc $r.createdDateTime
        if ($at -and (-not $usage.ContainsKey($id) -or [string]::CompareOrdinal($at, $usage[$id]) -gt 0)) { $usage[$id] = $at }
    }
    $usage
}

function Get-WlPimGroupActivations {
    <#
    .SYNOPSIS
    Last self-activation per principal for a PIM-enabled group (assignment schedule requests, ~30 days).
    #>
    param([string]$GroupId)
    $out = @{}
    $reqs = Invoke-WlGraphSafe -All -Context "PIM for groups activations '$(Get-WlGroupNameCached $GroupId)'" `
        -Path "identityGovernance/privilegedAccess/group/assignmentScheduleRequests?`$filter=groupId eq '$GroupId'"
    foreach ($r in @($reqs)) {
        if (-not $r -or [string]$r.action -notmatch 'selfActivate' -or [string]$r.accessId -ne 'member') { continue }
        $id = [string]$r.principalId; $at = ConvertTo-WlIsoUtc $r.createdDateTime
        if ($at -and (-not $out.ContainsKey($id) -or [string]::CompareOrdinal($at, $out[$id]) -gt 0)) { $out[$id] = $at }
    }
    $out
}

function New-WlEntitlement {
    param(
        [string]$PrincipalId, [string]$PrincipalType, [string]$Upn, [string]$DisplayName,
        [string]$RoleId, [string]$Role, $Privileged, [string[]]$PermissionGroups,
        [string]$State, [string]$Via, [string]$Assignment, $Scope, [string]$End, [string]$AccessPackageId
    )
    $key = Get-WlHash "ent|$PrincipalId|$RoleId|$State|$Via|$($Scope.text)"
    [pscustomobject]@{
        key              = $key
        fp               = Get-WlHash "$End|$Assignment"
        label            = "$($DisplayName): $Role ($State, $Via)"
        state            = $State
        principalId      = $PrincipalId
        principalType    = $PrincipalType
        upn              = $Upn
        displayName      = $DisplayName
        roleId           = $RoleId
        role             = $Role
        privileged       = $Privileged
        permissionGroups = @($PermissionGroups)
        via              = $Via
        assignment       = $Assignment
        scope            = $Scope.text
        allDataSources   = [bool]$Scope.all
        dataSources      = @($Scope.dataSources)
        end              = $End
        accessPackageId  = $AccessPackageId
        lastUsed         = $null
        lastActivated    = $null
        usage            = 'Unknown'
    }
}

function Get-WlAccessFindings {
    param([object[]]$Entitlements, [object[]]$Bypass, [int]$UnusedDays)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-WlText -En $en -De $de }
    $names = { param($rows) ((@($rows) | ForEach-Object { if ($_.upn) { $_.upn } else { $_.displayName } } | Sort-Object -Unique | Select-Object -First 12) -join ', ') + $(if (@($rows | Select-Object -ExpandProperty principalId -Unique).Count -gt 12) { ', …' } else { '' }) }

    # 1) Active, high-impact permission, portal never used in the observation window
    $unused = @($Entitlements | Where-Object { $_.state -eq 'Active' -and $_.privileged -eq $true -and $_.usage -eq 'Unused' -and $_.principalType -eq 'user' })
    foreach ($g in @($unused | Group-Object principalId)) {
        $e = $g.Group[0]; $roles = @($g.Group | ForEach-Object { $_.role } | Sort-Object -Unique) -join ', '
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'LeastPrivilege' -Title (& $T "Standing Defender permission never used: $($e.displayName)" "Dauerhafte Defender-Berechtigung nie genutzt: $($e.displayName)") `
                    -Detail (& $T "$($e.upn) holds '$roles' with response or configuration permissions permanently, but has not signed in to the Defender portal for at least $UnusedDays days$(if ($e.lastUsed) { " (last: $($e.lastUsed.Substring(0,10)))" } else { ' (no sign-in observed)' }). The permission is a liability without a benefit." `
                        "$($e.upn) hat '$roles' mit Response- oder Konfigurationsrechten dauerhaft, hat sich aber seit mindestens $UnusedDays Tagen nicht am Defender-Portal angemeldet$(if ($e.lastUsed) { " (zuletzt: $($e.lastUsed.Substring(0,10)))" } else { ' (keine Anmeldung beobachtet)' }). Die Berechtigung ist ein Risiko ohne Nutzen.") `
                    -Recommendation (& $T 'Remove the assignment, or move the person into a PIM-enabled group so the role has to be activated when actually needed.' 'Zuweisung entfernen oder die Person in eine PIM-fähige Gruppe verschieben, damit die Rolle bei Bedarf aktiviert werden muss.') -Subject "acc|unused|$($e.principalId)"))
    }

    # 2) Eligible via PIM for groups but never activated
    $idle = @($Entitlements | Where-Object { $_.state -eq 'Eligible' -and $_.privileged -eq $true -and $_.usage -eq 'Unused' -and -not $_.lastActivated })
    foreach ($g in @($idle | Group-Object principalId)) {
        $e = $g.Group[0]
        $f.Add((New-WlFinding -Severity 'Low' -Category 'LeastPrivilege' -Title (& $T "Eligible Defender role never activated: $($e.displayName)" "Eligible Defender-Rolle nie aktiviert: $($e.displayName)") `
                    -Detail (& $T "$($e.upn) is eligible for '$($e.role)' through '$($e.via)' but has neither activated it nor used the Defender portal in the last $UnusedDays days." "$($e.upn) ist über '$($e.via)' für '$($e.role)' eligible, hat die Rolle aber in den letzten $UnusedDays Tagen weder aktiviert noch das Defender-Portal genutzt.") `
                    -Recommendation (& $T 'Confirm with the person or their manager whether the eligibility is still needed; remove it otherwise.' 'Mit der Person bzw. der Führungskraft klären, ob die Eligibility noch gebraucht wird; sonst entfernen.') -Subject "acc|idle|$($e.principalId)"))
    }

    # 3) Entra roles that bypass unified RBAC
    $high = @($Bypass | Where-Object { $_.level -eq 'High' }); $low = @($Bypass | Where-Object { $_.level -ne 'High' })
    if ($high.Count) {
        $f.Add((New-WlFinding -Severity 'High' -Category 'LeastPrivilege' -Title (& $T "$(@($high | Select-Object -ExpandProperty principalId -Unique).Count) person(s) with full Defender access through Entra roles" "$(@($high | Select-Object -ExpandProperty principalId -Unique).Count) Person(en) mit vollem Defender-Zugriff über Entra-Rollen") `
                    -Detail (& $T "Global Administrator, Security Administrator and Security Operator keep full access to the Defender portal even when unified RBAC is active – outside every scoped role: $(& $names $high). These accounts are not visible in the unified RBAC role list." "Global Administrator, Security Administrator und Security Operator behalten auch bei aktivem Unified RBAC vollen Zugriff auf das Defender-Portal – außerhalb jeder gescopten Rolle: $(& $names $high). Diese Konten sind in der Unified-RBAC-Rollenliste nicht sichtbar.") `
                    -Recommendation (& $T 'Keep these Entra roles PIM-eligible only and give day-to-day SOC work a scoped unified RBAC role instead.' 'Diese Entra-Rollen nur PIM-eligible halten und die tägliche SOC-Arbeit über eine gescopte Unified-RBAC-Rolle abbilden.') -Subject 'acc|bypass-high' -StableKey))
    }
    if ($low.Count) {
        $f.Add((New-WlFinding -Severity 'Low' -Category 'LeastPrivilege' -Title (& $T "$(@($low | Select-Object -ExpandProperty principalId -Unique).Count) person(s) read all Defender data through Entra reader roles" "$(@($low | Select-Object -ExpandProperty principalId -Unique).Count) Person(en) lesen alle Defender-Daten über Entra-Leserollen") `
                    -Detail (& $T "Security Reader and Global Reader grant read access to all Defender data sources, unscoped: $(& $names $low)." "Security Reader und Global Reader gewähren ungescopten Lesezugriff auf alle Defender-Datenquellen: $(& $names $low).") `
                    -Recommendation (& $T 'Replace them with a unified RBAC read-only role limited to the data sources the person needs.' 'Durch eine Unified-RBAC-Leserolle ersetzen, die auf die benötigten Datenquellen begrenzt ist.') -Subject 'acc|bypass-low' -StableKey))
    }

    # 4) Standing (non-PIM) high-impact access across all data sources
    $standing = @($Entitlements | Where-Object { $_.state -eq 'Active' -and $_.privileged -eq $true -and $_.allDataSources -and $_.principalType -eq 'user' })
    $standingUsers = @($standing | Select-Object -ExpandProperty principalId -Unique)
    if ($standingUsers.Count -ge 3) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'LeastPrivilege' -Title (& $T "$($standingUsers.Count) person(s) with permanent response permissions on all data sources" "$($standingUsers.Count) Person(en) mit dauerhaften Response-Rechten auf allen Datenquellen") `
                    -Detail (& $T "Roles with response, live response or configuration permissions are permanently active for $($standingUsers.Count) people and not limited to a data source: $(& $names $standing). Every one of these accounts can isolate devices, collect files or change settings at any time." "Rollen mit Response-, Live-Response- oder Konfigurationsrechten sind für $($standingUsers.Count) Personen dauerhaft aktiv und nicht auf eine Datenquelle begrenzt: $(& $names $standing). Jedes dieser Konten kann jederzeit Geräte isolieren, Dateien einsammeln oder Einstellungen ändern.") `
                    -Recommendation (& $T 'Assign these roles to PIM-enabled groups (eligible, time-bound, with justification) and split by data source where teams are separate.' 'Diese Rollen über PIM-fähige Gruppen vergeben (eligible, zeitlich begrenzt, mit Begründung) und nach Datenquelle trennen, wo Teams getrennt sind.') -Subject 'acc|standing' -StableKey))
    }

    # 5) Assignments to individual users instead of groups
    $direct = @($Entitlements | Where-Object { $_.state -eq 'Active' -and $_.via -eq 'direct' -and $_.principalType -eq 'user' })
    if ($direct.Count) {
        $f.Add((New-WlFinding -Severity 'Low' -Category 'LeastPrivilege' -Title (& $T "$($direct.Count) Defender role assignment(s) to individual users" "$($direct.Count) Defender-Rollenzuweisung(en) an einzelne Benutzer") `
                    -Detail (& $T "Unified RBAC assignments are made directly to users rather than groups: $(& $names $direct). Individual assignments bypass access reviews and PIM, and are forgotten when people change teams." "Unified-RBAC-Zuweisungen erfolgen direkt an Benutzer statt an Gruppen: $(& $names $direct). Einzelzuweisungen umgehen Access Reviews und PIM und werden bei Teamwechseln vergessen.") `
                    -Recommendation (& $T 'Assign roles to groups (ideally PIM-enabled) and put the groups under an access review.' 'Rollen an Gruppen (idealerweise PIM-fähig) vergeben und die Gruppen in einen Access Review nehmen.') -Subject 'acc|direct' -StableKey))
    }
    @($f)
}

#region API apps with Defender permissions, access reviews, PIM activation rules
# Resources whose application permissions reach Defender: MDE API (WindowsDefenderATP), Defender XDR API (Microsoft Threat
# Protection) and the Defender-related part of Microsoft Graph.
$script:WlApiResources = @(
    @{ appId = 'fc780465-2017-40d4-a0c5-307022471b92'; name = 'Defender for Endpoint API'; filter = $null }
    @{ appId = '8ee8fdad-f234-4243-8f3b-15c294843740'; name = 'Defender XDR API'; filter = $null }
    @{ appId = '00000003-0000-0000-c000-000000000000'; name = 'Microsoft Graph'; filter = '^(Security|ThreatHunting|ThreatIndicators|ThreatIntelligence|ThreatSubmission|CustomDetection|RoleManagement\.(Read|ReadWrite)\.Defender)' }
)
# Application permissions with direct impact on devices or detections
$script:WlApiHighImpact = 'Offboard|LiveResponse|Isolate|RestrictExecution|StopAndQuarantine|CollectForensics|Library\.Manage|Machine\.Scan|ReadWrite|SecurityActions'
$script:WlMicrosoftTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47', '33e01921-4d64-4f8c-a055-5bdaffd5e33d')

function Get-WlApiApps {
    <#
    .SYNOPSIS
    Service principals holding application permissions on the Defender APIs (appRoleAssignedTo of the resource service
    principals), with credential type and lifetime and the owners of the app registration (Directory.Read.All).
    #>
    $tenant = [string](Get-WlSetting -Name 'WL_TENANT_ID')
    $byClient = @{}
    foreach ($res in $script:WlApiResources) {
        $sp = Invoke-WlGraphSafe -Path "servicePrincipals(appId='$($res.appId)')?`$select=id,appId,displayName,appRoles" -Context "Service principal $($res.name)"
        if (-not $sp) { continue }
        $roleName = @{}; foreach ($r in @($sp.appRoles)) { if ($r) { $roleName[[string]$r.id] = [string]$r.value } }
        $assign = Invoke-WlGraphSafe -All -Path "servicePrincipals/$($sp.id)/appRoleAssignedTo?`$top=999" -Context "App role assignments $($res.name)"
        foreach ($a in @($assign)) {
            if (-not $a -or [string]$a.principalType -ne 'ServicePrincipal') { continue }
            $v = $roleName[[string]$a.appRoleId]
            if (-not $v) { continue }
            if ($res.filter -and $v -notmatch $res.filter) { continue }
            $cid = [string]$a.principalId
            if (-not $byClient.ContainsKey($cid)) { $byClient[$cid] = [ordered]@{ id = $cid; displayName = [string]$a.principalDisplayName; permissions = [System.Collections.Generic.List[string]]::new() } }
            $byClient[$cid].permissions.Add("$($res.name): $v")
        }
    }
    $now = [DateTime]::UtcNow
    $out = foreach ($c in $byClient.Values) {
        $sp = Invoke-WlGraphSafe -Path "servicePrincipals/$($c.id)?`$select=id,appId,displayName,appOwnerOrganizationId,accountEnabled" -Context "Service principal $($c.displayName)"
        $owner = [string](Get-WlProp $sp 'appOwnerOrganizationId')
        $internal = $owner -and $owner -eq $tenant
        $microsoft = $owner -in $script:WlMicrosoftTenants
        $secrets = 0; $certs = 0; $longest = $null; $expired = 0; $owners = @()
        if ($internal) {
            $app = Invoke-WlGraphSafe -Path "applications(appId='$([string](Get-WlProp $sp 'appId'))')?`$select=id,displayName,passwordCredentials,keyCredentials" -Context "App registration $($c.displayName)"
            if ($app) {
                foreach ($pc in @($app.passwordCredentials)) { if ($pc) { $secrets++ } }
                foreach ($kc in @($app.keyCredentials)) { if ($kc) { $certs++ } }
                foreach ($cr in @(@($app.passwordCredentials) + @($app.keyCredentials))) {
                    if (-not $cr) { continue }
                    try {
                        $end = ConvertTo-WlUtc ([string]$cr.endDateTime); $start = ConvertTo-WlUtc ([string]$cr.startDateTime)
                        if ($end -lt $now) { $expired++; continue }
                        $days = [int]($end - $start).TotalDays; if ($null -eq $longest -or $days -gt $longest) { $longest = $days }
                    }
                    catch { }
                }
                $o = Invoke-WlGraphSafe -All -Path "applications/$($app.id)/owners?`$select=id,displayName,userPrincipalName" -Context "Owners of $($c.displayName)"
                $owners = @(@($o) | Where-Object { $_ } | ForEach-Object { if ($_.userPrincipalName) { [string]$_.userPrincipalName } else { [string]$_.displayName } })
            }
        }
        $perms = @($c.permissions | Sort-Object -Unique)
        $high = @($perms | Where-Object { ($_ -split ': ', 2)[1] -match $script:WlApiHighImpact })
        [pscustomobject]@{
            key = Get-WlHash "api|$($c.id)"; fp = Get-WlHash "$($perms -join ';')|$secrets|$certs|$($owners -join ';')"
            label = "API app $($c.displayName)"; state = $(if ($high.Count) { 'HighImpact' } else { 'ReadOnly' })
            servicePrincipalId = $c.id; appId = [string](Get-WlProp $sp 'appId'); displayName = $c.displayName
            origin = $(if ($internal) { 'Tenant' } elseif ($microsoft) { 'Microsoft' } else { 'External' })
            enabled = [bool](Get-WlProp $sp 'accountEnabled'); permissions = $perms; highImpact = $high
            secrets = $secrets; certificates = $certs; expiredCredentials = $expired; longestCredentialDays = $longest; owners = $owners
        }
    }
    @($out | Sort-Object { -@($_.highImpact).Count }, displayName)
}

function Get-WlAccessReviewCoverage {
    <#
    .SYNOPSIS
    Which Defender-relevant groups and Entra roles are under an access review (AccessReview.Read.All).
    Returns $null when the definitions cannot be read.
    #>
    $defs = $null
    try { $defs = @(Invoke-WlGraph -All -Path 'identityGovernance/accessReviews/definitions?$select=id,displayName,status,scope,instanceEnumerationScope') }
    catch { Add-WlWarning "Access review definitions (AccessReview.Read.All): $(Get-WlErrorText -Exception $_.Exception -Context 'access reviews')"; return $null }
    $active = @(@($defs) | Where-Object { $_ -and [string]$_.status -notin 'Completed', 'Deleted' })
    [pscustomobject]@{ count = $active.Count; text = ((@($active | ForEach-Object { ($_ | ConvertTo-Json -Depth 12 -Compress) })) -join "`n").ToLowerInvariant() }
}

function Get-WlPimGroupRules {
    <#
    .SYNOPSIS
    PIM for Groups activation rules (member role) of a group: MFA / authentication context, justification, approval,
    maximum duration (RoleManagementPolicy.Read.AzureADGroup). $null when the group is not managed by PIM.
    #>
    param([string]$GroupId)
    $a = Invoke-WlGraphSafe -Path "policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$GroupId' and scopeType eq 'Group' and roleDefinitionId eq 'member'&`$expand=policy(`$expand=rules)" -Context "PIM policy for group $GroupId (RoleManagementPolicy.Read.AzureADGroup)"
    $pol = @(Get-WlProp $a 'value')[0]
    if (-not $pol) { return $null }
    $rules = @(Get-WlProp (Get-WlProp $pol 'policy') 'rules')
    $r = { param($id) $rules | Where-Object { [string]$_.id -eq $id } | Select-Object -First 1 }
    $en = & $r 'Enablement_EndUser_Assignment'; $ap = & $r 'Approval_EndUser_Assignment'; $ex = & $r 'Expiration_EndUser_Assignment'; $ac = & $r 'AuthenticationContext_EndUser_Assignment'
    $enabled = @(Get-WlProp $en 'enabledRules' | ForEach-Object { [string]$_ })
    $hours = $null
    $dur = [string](Get-WlProp $ex 'maximumDuration'); if ($dur) { try { $hours = [System.Xml.XmlConvert]::ToTimeSpan($dur).TotalHours } catch { } }
    [pscustomobject]@{
        mfa = ($enabled -contains 'MultiFactorAuthentication') -or [bool](Get-WlProp $ac 'isEnabled')
        justification = $enabled -contains 'Justification'
        approval = [bool](Get-WlProp (Get-WlProp $ap 'setting') 'isApprovalRequired')
        maxHours = $hours
    }
}

function Get-WlPlatformAccessFindings {
    <#
    .SYNOPSIS
    Findings for programmatic access (API apps) and identity governance around the Defender role groups.
    #>
    param([object[]]$ApiApps, $Reviews, [hashtable]$GroupGrants, [hashtable]$PimRules)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-WlText -En $en -De $de }
    foreach ($a in @($ApiApps | Where-Object { $_ -and @($_.highImpact).Count -and $_.enabled })) {
        $weak = [System.Collections.Generic.List[object]]::new()
        if ($a.secrets -gt 0) { $weak.Add(@("$($a.secrets) client secret(s)", "$($a.secrets) Client Secret(s)")) }
        if ($a.longestCredentialDays -gt 730) { $weak.Add(@("a credential valid for $([int]($a.longestCredentialDays / 365)) years", "ein Anmeldeinformationen-Gültigkeitszeitraum von $([int]($a.longestCredentialDays / 365)) Jahren")) }
        if ($a.origin -eq 'Tenant' -and @($a.owners).Count -eq 0) { $weak.Add(@('no owner', 'kein Besitzer')) }
        if ($a.origin -eq 'External') { $weak.Add(@('registered in another tenant', 'in einem anderen Mandanten registriert')) }
        $sev = if ($weak.Count) { 'High' } else { 'Medium' }
        $wEn = if ($weak.Count) { " Weak points: $((@($weak | ForEach-Object { $_[0] })) -join ', ')." } else { '' }
        $wDe = if ($weak.Count) { " Schwachstellen: $((@($weak | ForEach-Object { $_[1] })) -join ', ')." } else { '' }
        $f.Add((New-WlFinding -Severity $sev -Category 'Platform' -Title (& $T "API app with Defender write permissions: $($a.displayName)" "API-App mit Defender-Schreibrechten: $($a.displayName)") `
                    -Detail (& $T "The $($a.origin.ToLowerInvariant()) app '$($a.displayName)' holds application permissions that act on devices or detections without a user: $((@($a.highImpact)) -join ', ').$wEn Owners: $(if (@($a.owners).Count) { @($a.owners) -join ', ' } else { '–' }). Application permissions bypass Conditional Access, PIM and unified RBAC scoping." "Die App '$($a.displayName)' ($($a.origin)) hält Anwendungsberechtigungen, die ohne Benutzer auf Geräte oder Erkennungen wirken: $((@($a.highImpact)) -join ', ').$wDe Besitzer: $(if (@($a.owners).Count) { @($a.owners) -join ', ' } else { '–' }). Anwendungsberechtigungen umgehen Conditional Access, PIM und das Scoping von Unified RBAC.") `
                    -Recommendation (& $T 'Confirm the integration is still needed and reduce it to the permissions it uses; replace client secrets with certificates or a managed identity, keep credentials short-lived and give the app a responsible owner.' 'Prüfen, ob die Integration noch gebraucht wird, und auf die genutzten Berechtigungen reduzieren; Client Secrets durch Zertifikate oder eine Managed Identity ersetzen, Anmeldeinformationen kurzlebig halten und der App einen verantwortlichen Besitzer geben.') -Subject "api|$($a.servicePrincipalId)"))
    }
    $secretApps = @($ApiApps | Where-Object { $_ -and $_.secrets -gt 0 -and @($_.highImpact).Count -eq 0 })
    if ($secretApps.Count) {
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Platform' -Title (& $T "$($secretApps.Count) app(s) read Defender data with a client secret" "$($secretApps.Count) App(s) lesen Defender-Daten mit Client Secret") `
                    -Detail (& $T "Read-only integrations that authenticate with a shared secret: $((@($secretApps | Select-Object -First 10 | ForEach-Object displayName)) -join ', '). A leaked secret exposes alerts, devices and hunting data to anyone." "Nur-Lese-Integrationen, die sich mit einem geteilten Secret anmelden: $((@($secretApps | Select-Object -First 10 | ForEach-Object displayName)) -join ', '). Ein abgeflossenes Secret legt Alerts, Geräte und Hunting-Daten für jeden offen.") `
                    -Recommendation (& $T 'Switch to certificate credentials or managed identities and rotate the remaining secrets.' 'Auf Zertifikate oder Managed Identities umstellen und verbleibende Secrets rotieren.') -Subject 'api|secrets' -StableKey))
    }

    if ($Reviews -and $GroupGrants.Count) {
        $unreviewed = @(foreach ($gid in @($GroupGrants.Keys)) {
                if ($Reviews.text -notmatch [regex]::Escape(([string]$gid).ToLowerInvariant())) {
                    [pscustomobject]@{ id = $gid; name = (Get-WlGroupNameCached $gid); privileged = [bool]@($GroupGrants[$gid] | Where-Object { $_.privileged }).Count }
                }
            })
        if ($unreviewed.Count) {
            $priv = @($unreviewed | Where-Object { $_.privileged })
            $f.Add((New-WlFinding -Severity $(if ($priv.Count) { 'Medium' } else { 'Low' }) -Category 'LeastPrivilege' -Title (& $T "$($unreviewed.Count) Defender role group(s) without an access review" "$($unreviewed.Count) Defender-Rollengruppe(n) ohne Access Review") `
                        -Detail (& $T "These groups grant unified RBAC roles but no active access review covers them: $((@($unreviewed | Select-Object -First 12 | ForEach-Object name)) -join ', ')$(if ($priv.Count) { " – $($priv.Count) of them grant response, live response or settings permissions" }). Membership that is never re-attested only grows." "Diese Gruppen vergeben Unified-RBAC-Rollen, aber kein aktiver Access Review deckt sie ab: $((@($unreviewed | Select-Object -First 12 | ForEach-Object name)) -join ', ')$(if ($priv.Count) { " – $($priv.Count) davon vergeben Response-, Live-Response- oder Einstellungsrechte" }). Mitgliedschaften, die nie neu bestätigt werden, wachsen nur.") `
                        -Recommendation (& $T 'Create a recurring access review (quarterly for privileged groups) with automatic removal when reviewers do not respond.' 'Einen wiederkehrenden Access Review anlegen (quartalsweise für privilegierte Gruppen) mit automatischer Entfernung, wenn Prüfer nicht antworten.') -Subject 'acc|noreview' -StableKey))
        }
    }

    foreach ($gid in @($PimRules.Keys)) {
        $r = $PimRules[$gid]; if (-not $r) { continue }
        $privileged = [bool]@($GroupGrants[$gid] | Where-Object { $_.privileged }).Count
        if (-not $privileged) { continue }
        $gaps = [System.Collections.Generic.List[object]]::new()
        if (-not $r.mfa) { $gaps.Add(@('no MFA or authentication context on activation', 'keine MFA bzw. kein Authentifizierungskontext bei Aktivierung')) }
        if (-not $r.justification) { $gaps.Add(@('no justification required', 'keine Begründung erforderlich')) }
        if ($r.maxHours -gt 8) { $gaps.Add(@("activation lasts up to $($r.maxHours) hours", "Aktivierung bis zu $($r.maxHours) Stunden")) }
        if (-not $gaps.Count) { continue }
        $name = Get-WlGroupNameCached $gid
        $f.Add((New-WlFinding -Severity $(if (-not $r.mfa) { 'Medium' } else { 'Low' }) -Category 'LeastPrivilege' -Title (& $T "Weak PIM activation for Defender group: $name" "Schwache PIM-Aktivierung für Defender-Gruppe: $name") `
                    -Detail (& $T "The group grants privileged Defender permissions through PIM for Groups, but activation has gaps: $((@($gaps | ForEach-Object { $_[0] })) -join ', ')$(if (-not $r.approval) { '; no approval' })." "Die Gruppe vergibt privilegierte Defender-Rechte über PIM for Groups, die Aktivierung hat aber Lücken: $((@($gaps | ForEach-Object { $_[1] })) -join ', ')$(if (-not $r.approval) { '; keine Genehmigung' }).") `
                    -Recommendation (& $T 'Require MFA (ideally an authentication context with phishing-resistant MFA) and a justification on activation, limit the duration to a working shift, and add approval for live response.' 'Bei Aktivierung MFA (idealerweise Authentifizierungskontext mit phishing-resistenter MFA) und Begründung verlangen, die Dauer auf eine Schicht begrenzen und für Live Response eine Genehmigung einführen.') -Subject "acc|pim|$gid"))
    }
    @($f.ToArray())
}
#endregion

#region Purview audit (unified audit log) for Defender for Endpoint – optional feature "audit"
function Get-WlDefenderAuditFacts {
    <#
    .SYNOPSIS
    Feature "audit" (AuditLogsQuery.Read.All): Defender for Endpoint portal activity from the unified audit log
    (record type mdatpAudit) via the Graph audit log query API. Queries run asynchronously: each run reads the query
    started by the previous run and starts the next one, so a run never waits for Purview.
    #>
    param($Previous)
    if (-not ((Get-WlSetting -Name 'WL_FEATURES' -Default '') -split '[,; ]+' -contains 'audit')) { return $null }
    $records = $null; $queryAt = $null
    $prevId = [string](Get-WlProp (Get-WlProp $Previous 'auditQuery') 'id')
    if ($prevId) {
        $q = Invoke-WlGraphSafe -Beta -Path "security/auditLog/queries/$prevId" -Context 'Audit log query status (AuditLogsQuery.Read.All)'
        if ([string](Get-WlProp $q 'status') -eq 'succeeded') {
            $records = @(Invoke-WlGraphSafe -Beta -All -Path "security/auditLog/queries/$prevId/records" -Context 'Audit log records')
            $queryAt = [string](Get-WlProp (Get-WlProp $Previous 'auditQuery') 'createdAt')
        }
        elseif ($q -and [string](Get-WlProp $q 'status') -in 'notStarted', 'running') {
            return [pscustomobject]@{ query = (Get-WlProp $Previous 'auditQuery'); records = $null; summary = (Get-WlProp $Previous 'auditSummary') }
        }
    }
    $now = [DateTime]::UtcNow
    $body = @{ displayName = "Gapsio Defender audit $($now.ToString('yyyy-MM-dd'))"; filterStartDateTime = $now.AddDays(-30).ToString('o'); filterEndDateTime = $now.ToString('o'); recordTypeFilters = @('mdatpAudit') }
    $new = $null
    try { $new = Invoke-WlGraph -Beta -Path 'security/auditLog/queries' -Method POST -Body $body } catch { Add-WlWarning "Audit log query (AuditLogsQuery.Read.All): $(Get-WlErrorText -Exception $_.Exception -Context 'audit')" }
    $summary = $null
    if ($null -ne $records) {
        $rows = @(foreach ($r in $records) {
                if (-not $r) { continue }
                $op = [string](Get-WlProp $r 'operation')
                $kind = switch -Regex ($op.ToLowerInvariant()) { 'offboard' { 'Offboarding'; break } 'onboard' { 'Onboarding'; break } 'live ?response' { 'LiveResponse'; break } 'advancedfeature|setting|tamper|indicator|exclusion|rule' { 'Settings'; break } default { $null } }
                if ($kind) { [pscustomobject]@{ kind = $kind; operation = $op; user = [string](Get-WlProp $r 'userPrincipalName'); at = [string](Get-WlProp $r 'createdDateTime') } }
            })
        $summary = [pscustomobject]@{ since = $queryAt; total = @($records).Count; events = @($rows | Sort-Object at -Descending | Select-Object -First 200) }
    }
    elseif ($Previous) { $summary = Get-WlProp $Previous 'auditSummary' }
    [pscustomobject]@{ query = $(if ($new) { [pscustomobject]@{ id = [string]$new.id; createdAt = $now.ToString('o') } } else { $null }); records = $records; summary = $summary }
}

function Get-WlDefenderAuditFindings {
    param($Audit)
    $f = [System.Collections.Generic.List[object]]::new()
    $ev = @(Get-WlProp (Get-WlProp $Audit 'summary') 'events')
    if (-not $ev.Count) { return @() }
    $T = { param($en, $de) New-WlText -En $en -De $de }
    $list = { param($rows) (@($rows | Select-Object -First 8 | ForEach-Object { "$($_.user) ($($_.at))" })) -join ', ' }
    $off = @($ev | Where-Object { $_.kind -eq 'Offboarding' })
    if ($off.Count) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'Platform' -Title (& $T "Offboarding package downloaded $($off.Count) time(s) in 30 days" "Offboarding-Paket in 30 Tagen $($off.Count)-mal heruntergeladen") `
                    -Detail (& $T "Downloads by: $(& $list $off). An offboarding script silently removes a device from Defender – attackers use it to blind devices before moving laterally." "Downloads durch: $(& $list $off). Ein Offboarding-Skript entfernt ein Gerät still aus Defender – Angreifer nutzen das, um Geräte vor der lateralen Bewegung blind zu machen.") `
                    -Recommendation (& $T 'Confirm each download against a decommissioning ticket; restrict the permission to download offboarding packages to a small, PIM-protected role.' 'Jeden Download mit einem Außerbetriebnahme-Ticket abgleichen; das Recht zum Herunterladen von Offboarding-Paketen auf eine kleine, PIM-geschützte Rolle beschränken.') -Subject 'audit|offboard' -StableKey))
    }
    $lr = @($ev | Where-Object { $_.kind -eq 'LiveResponse' })
    if ($lr.Count) {
        $people = @($lr | Select-Object -ExpandProperty user -Unique)
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Platform' -Title (& $T "$($lr.Count) live response action(s) by $($people.Count) person(s) in 30 days" "$($lr.Count) Live-Response-Aktion(en) durch $($people.Count) Person(en) in 30 Tagen") `
                    -Detail (& $T "Live response runs as SYSTEM on the device. Recent use: $(& $list $lr)." "Live Response läuft auf dem Gerät als SYSTEM. Jüngste Nutzung: $(& $list $lr).") `
                    -Recommendation (& $T 'Check that every session belongs to an incident or ticket and that the people hold live response only through PIM.' 'Prüfen, dass jede Sitzung zu einem Incident oder Ticket gehört und die Personen Live Response nur über PIM halten.') -Subject 'audit|lr' -StableKey))
    }
    $set = @($ev | Where-Object { $_.kind -eq 'Settings' })
    if ($set.Count) {
        $ops = (@($set | Group-Object operation | Sort-Object Count -Descending | Select-Object -First 6 | ForEach-Object { "$($_.Name) ($($_.Count))" })) -join ', '
        $f.Add((New-WlFinding -Severity 'Low' -Category 'Platform' -Title (& $T "$($set.Count) Defender setting change(s) in the portal in 30 days" "$($set.Count) Defender-Einstellungsänderung(en) im Portal in 30 Tagen") `
                    -Detail (& $T "Changes: $ops. Last by: $(& $list $set). Portal changes (advanced features, indicators, rules) do not appear in any device timeline." "Änderungen: $ops. Zuletzt durch: $(& $list $set). Portal-Änderungen (erweiterte Features, Indikatoren, Regeln) erscheinen in keiner Geräte-Timeline.") `
                    -Recommendation (& $T 'Match the changes against change tickets; forward the unified audit log to the SIEM and alert on tamper protection, EDR in block mode and indicator changes.' 'Änderungen mit Change-Tickets abgleichen; das Unified Audit Log ins SIEM leiten und bei Änderungen an Tamper Protection, EDR im Block-Modus und Indikatoren alarmieren.') -Subject 'audit|settings' -StableKey))
    }
    @($f.ToArray())
}
#endregion

function Invoke-WlAccessCollection {
    <#
    .SYNOPSIS
    Full run of the access module; writes the snapshot and drift to storage.
    #>
    Reset-WlWarnings
    Reset-WlAccessCache
    $started = [DateTime]::UtcNow
    Write-Information "Gapsio access: start $($started.ToString('o'))" -InformationAction Continue
    $signInDays = 30
    $unusedDays = [int](Get-WlSetting -Name 'WL_ACCESS_UNUSED_DAYS' -Default '30')
    $prev = Get-WlBlob -Container 'state' -Name 'access-latest.json'

    $rows = [System.Collections.Generic.List[object]]::new()
    $audiences = [System.Collections.Generic.List[object]]::new()
    $groupGrants = @{}   # groupId -> list of rights the group grants

    #region Unified RBAC roles
    $roleById = @{}
    $roles = [System.Collections.Generic.List[object]]::new()
    $defs = Invoke-WlGraphSafe -Beta -All -Context 'Defender unified RBAC role definitions (RoleManagement.Read.Defender)' -Path 'roleManagement/defender/roleDefinitions'
    foreach ($d in @($defs)) {
        if (-not $d) { continue }
        $actions = @(foreach ($rp in @($d.rolePermissions)) { if ($rp) { @($rp.allowedResourceActions) } }) | Where-Object { $_ } | ForEach-Object { [string]$_ }
        $groups = @($actions | ForEach-Object { if ($_ -match '^microsoft\.xdr/([^/]+)/') { $Matches[1] } } | Sort-Object -Unique)
        $priv = [bool]@($actions | Where-Object { $a = $_; @($script:WlXdrHighImpact | Where-Object { $a -like "*$_*" }).Count -gt 0 }).Count
        $r = [pscustomobject]@{
            platform = 'Defender'; id = [string]$d.id; name = [string]$d.displayName; description = [string](Get-WlProp $d 'description')
            builtIn = [bool](Get-WlProp $d 'isBuiltIn'); privileged = $priv; actions = @($actions); permissionGroups = @($groups)
        }
        $roleById[[string]$d.id] = $r
        if ($d.templateId) { $roleById[[string]$d.templateId] = $r }
        $roles.Add($r)
    }
    $roleOf = { param($id) if ($roleById.ContainsKey([string]$id)) { $roleById[[string]$id] } else { [pscustomobject]@{ id = [string]$id; name = [string]$id; privileged = $null; permissionGroups = @() } } }
    #endregion

    #region Unified RBAC assignments
    $assignments = @(Invoke-WlGraphSafe -Beta -All -Context 'Defender unified RBAC role assignments (RoleManagement.Read.Defender)' -Path 'roleManagement/defender/roleAssignments')
    Resolve-WlPrincipalBatch -Ids @($assignments | ForEach-Object { @(Get-WlProp $_ 'principalIds') } | ForEach-Object { [string]$_ })
    foreach ($a in $assignments) {
        if (-not $a) { continue }
        $role = & $roleOf $a.roleDefinitionId
        $scope = Get-WlXdrScope -AppScopeIds @(Get-WlProp $a 'appScopeIds') -DirectoryScopeIds @(Get-WlProp $a 'directoryScopeIds')
        $aName = [string](Get-WlProp $a 'displayName')
        foreach ($pid in @(Get-WlProp $a 'principalIds')) {
            if (-not $pid) { continue }
            $p = Resolve-WlPrincipalInfo -Id ([string]$pid) -Expanded $null
            if ($p.type -eq 'group') {
                if (-not $groupGrants.ContainsKey($p.id)) { $groupGrants[$p.id] = [System.Collections.Generic.List[object]]::new() }
                $groupGrants[$p.id].Add([pscustomobject]@{ roleId = $role.id; role = $role.name; privileged = $role.privileged; permissionGroups = $role.permissionGroups; scope = $scope; assignment = $aName })
            }
            else {
                $rows.Add((New-WlEntitlement -PrincipalId $p.id -PrincipalType $p.type -Upn $p.upn -DisplayName $p.displayName -RoleId $role.id -Role $role.name `
                            -Privileged $role.privileged -PermissionGroups $role.permissionGroups -State 'Active' -Via 'direct' -Assignment $aName -Scope $scope))
            }
        }
    }
    #endregion

    #region Groups -> users (active via group) and PIM for groups (eligible)
    $activations = @{}
    foreach ($gid in @($groupGrants.Keys)) {
        $gname = Get-WlGroupNameCached $gid
        foreach ($u in @(Get-WlGroupUsers -GroupId $gid)) {
            if (-not $u) { continue }
            foreach ($g in $groupGrants[$gid]) {
                $rows.Add((New-WlEntitlement -PrincipalId ([string]$u.id) -PrincipalType 'user' -Upn ([string]$u.userPrincipalName) -DisplayName ([string]$u.displayName) `
                            -RoleId $g.roleId -Role $g.role -Privileged $g.privileged -PermissionGroups $g.permissionGroups -State 'Active' -Via "Group: $gname" -Assignment $g.assignment -Scope $g.scope))
            }
        }
        $inst = Invoke-WlGraphSafe -All -Context "PIM for groups '$gname'" -Path "identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$gid'"
        if (-not @($inst).Count) { continue }
        $activations[$gid] = Get-WlPimGroupActivations -GroupId $gid
        foreach ($i in @($inst)) {
            if (-not $i -or [string]$i.accessId -ne 'member') { continue }
            $p = Resolve-WlPrincipalInfo -Id ([string]$i.principalId) -Expanded $null
            $targets = if ($p.type -eq 'group') { @(Get-WlGroupUsers -GroupId $p.id | ForEach-Object { [pscustomobject]@{ id = $_.id; upn = $_.userPrincipalName; displayName = $_.displayName } }) } else { @($p) }
            foreach ($t in $targets) {
                foreach ($g in $groupGrants[$gid]) {
                    $e = New-WlEntitlement -PrincipalId ([string]$t.id) -PrincipalType 'user' -Upn ([string]$t.upn) -DisplayName ([string]$t.displayName) `
                        -RoleId $g.roleId -Role $g.role -Privileged $g.privileged -PermissionGroups $g.permissionGroups -State 'Eligible' `
                        -Via "PIM for groups: $gname" -Assignment $g.assignment -Scope $g.scope -End ([string]$i.endDateTime)
                    if ($activations[$gid].ContainsKey([string]$t.id)) { $e.lastActivated = $activations[$gid][[string]$t.id] }
                    $rows.Add($e)
                }
            }
        }
    }
    #endregion

    #region Access packages that grant a role-holding group
    if ($groupGrants.Count -gt 0) {
        $aps = Invoke-WlGraphSafe -All -Context 'Access Packages' -Path 'identityGovernance/entitlementManagement/accessPackages?$expand=assignmentPolicies'
        $apGrants = @{}
        foreach ($ap in @($aps)) {
            if (-not $ap) { continue }
            $detail = $null
            try { $detail = Invoke-WlGraph -Path "identityGovernance/entitlementManagement/accessPackages/$($ap.id)?`$expand=resourceRoleScopes(`$expand=role(`$expand=resource),scope)" }
            catch { $detail = Invoke-WlGraphSafe -Context "Resources of access package '$($ap.displayName)'" -Path "identityGovernance/entitlementManagement/accessPackages/$($ap.id)?`$expand=resourceRoleScopes(`$expand=role,scope)" }
            $grants = [System.Collections.Generic.List[object]]::new()
            foreach ($rrs in @(Get-WlProp $detail 'resourceRoleScopes')) {
                if (-not $rrs) { continue }
                $role = Get-WlProp $rrs 'role'; $scopeObj = Get-WlProp $rrs 'scope'
                if ([string](Get-WlProp $role 'originSystem') -ne 'AadGroup' -or [string](Get-WlProp $role 'originId') -notmatch '^Member') { continue }
                $resOrigin = [string](Get-WlProp (Get-WlProp $role 'resource') 'originId')
                $gid = if ($resOrigin) { $resOrigin } else { [string](Get-WlProp $scopeObj 'originId') }
                if (-not $groupGrants.ContainsKey($gid)) { continue }
                foreach ($g in $groupGrants[$gid]) { $grants.Add([pscustomobject]@{ roleId = $g.roleId; role = $g.role; privileged = $g.privileged; permissionGroups = $g.permissionGroups; scope = $g.scope; assignment = $g.assignment; via = "via group $(Get-WlGroupNameCached $gid)" }) }
            }
            if ($grants.Count -eq 0) { continue }
            $apGrants[[string]$ap.id] = $grants

            foreach ($pol in @($ap.assignmentPolicies)) {
                if (-not $pol) { continue }
                if (-not [bool](Get-WlProp (Get-WlProp $pol 'requestorSettings') 'enableTargetsToSelfAddAccess')) { continue }
                $scopeKind = [string](Get-WlProp $pol 'allowedTargetScope')
                if ($scopeKind -in 'allMemberUsers', 'allDirectoryUsers', 'allExternalUsers', 'allConfiguredConnectedOrganizationUsers') {
                    $audiences.Add([pscustomobject]@{
                            key = Get-WlHash "aud|$($ap.id)|$($pol.id)"; fp = Get-WlHash ((@($grants | ForEach-Object { $_.roleId }) -join ';') + $scopeKind)
                            label = "Access package '$($ap.displayName)' requestable by $scopeKind"; state = $scopeKind
                            audience = $scopeKind; accessPackageId = [string]$ap.id; accessPackage = [string]$ap.displayName; policy = [string]$pol.displayName
                            grants = @($grants | ForEach-Object { [pscustomobject]@{ role = $_.role; state = 'Active'; scope = $_.scope.text } })
                        })
                    continue
                }
                foreach ($tgt in @(Get-WlProp $pol 'specificAllowedTargets')) {
                    if (-not $tgt) { continue }
                    $tt = [string](Get-WlProp $tgt '@odata.type')
                    $users = @()
                    if ($tt -match 'singleUser') { $users = @(Resolve-WlPrincipalInfo -Id ([string]$tgt.userId) -Expanded $null) }
                    elseif ($tt -match 'groupMembers') { $users = @(Get-WlGroupUsers -GroupId ([string]$tgt.groupId) | ForEach-Object { [pscustomobject]@{ id = $_.id; upn = $_.userPrincipalName; displayName = $_.displayName } }) }
                    foreach ($u in $users) {
                        foreach ($g in $grants) {
                            $rows.Add((New-WlEntitlement -PrincipalId ([string]$u.id) -PrincipalType 'user' -Upn ([string]$u.upn) -DisplayName ([string]$u.displayName) `
                                        -RoleId $g.roleId -Role $g.role -Privileged $g.privileged -PermissionGroups $g.permissionGroups -State 'Requestable' `
                                        -Via "Access package: $($ap.displayName) ($($g.via))" -Assignment $g.assignment -Scope $g.scope -AccessPackageId ([string]$ap.id)))
                        }
                    }
                }
            }
        }
        if ($apGrants.Count -gt 0) {
            $apAssign = Invoke-WlGraphSafe -All -Context 'Access package assignments' -Path "identityGovernance/entitlementManagement/assignments?`$filter=state eq 'delivered'&`$expand=target,accessPackage"
            foreach ($as in @($apAssign)) {
                if (-not $as) { continue }
                $apId = [string](Get-WlProp (Get-WlProp $as 'accessPackage') 'id')
                if (-not $apGrants.ContainsKey($apId)) { continue }
                $tgt = Get-WlProp $as 'target'; $oid = [string](Get-WlProp $tgt 'objectId')
                if (-not $oid) { continue }
                foreach ($g in $apGrants[$apId]) {
                    $rows.Add((New-WlEntitlement -PrincipalId $oid -PrincipalType 'user' -Upn ([string](Get-WlProp $tgt 'principalName')) -DisplayName ([string](Get-WlProp $tgt 'displayName')) `
                                -RoleId $g.roleId -Role $g.role -Privileged $g.privileged -PermissionGroups $g.permissionGroups -State 'Active' `
                                -Via "Access package: $(Get-WlProp (Get-WlProp $as 'accessPackage') 'displayName') (assigned, $($g.via))" -Assignment $g.assignment -Scope $g.scope `
                                -End ([string](Get-WlProp (Get-WlProp (Get-WlProp $as 'schedule') 'expiration') 'endDateTime')) -AccessPackageId $apId))
                }
            }
        }
    }
    #endregion

    #region Entra roles that bypass unified RBAC
    $bypass = [System.Collections.Generic.List[object]]::new()
    # Graph rejects 'roleDefinitionId in (...)' with several IDs – query each role separately
    $entra = @(foreach ($rid in ($script:WlEntraBypassRoles.Keys | Sort-Object)) {
            Invoke-WlGraphSafe -All -Context 'Entra role assignments (RoleManagement.Read.Directory)' -Path "roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$rid'&`$expand=principal"
        })
    foreach ($a in @($entra)) {
        if (-not $a -or -not $script:WlEntraBypassRoles.ContainsKey([string]$a.roleDefinitionId)) { continue }
        $info = $script:WlEntraBypassRoles[[string]$a.roleDefinitionId]
        $p = Resolve-WlPrincipalInfo -Id ([string]$a.principalId) -Expanded (Get-WlProp $a 'principal')
        $targets = if ($p.type -eq 'group') { @(Get-WlGroupUsers -GroupId $p.id | ForEach-Object { [pscustomobject]@{ id = $_.id; type = 'user'; upn = $_.userPrincipalName; displayName = $_.displayName } }) } else { @($p) }
        foreach ($t in $targets) {
            $bypass.Add([pscustomobject]@{
                    key = Get-WlHash "byp|$($t.id)|$($a.roleDefinitionId)"; fp = Get-WlHash $p.type; label = "$($t.displayName): $($info.name) (Entra)"; state = 'Active'
                    principalId = [string]$t.id; principalType = $t.type; upn = $t.upn; displayName = $t.displayName; role = $info.name; level = $info.level
                    via = $(if ($p.type -eq 'group') { "Group: $($p.displayName)" } else { 'direct' }); lastUsed = $null
                })
        }
    }
    #endregion

    #region Usage: portal sign-ins (carried forward) and usage verdict
    $seen = @{}
    $ents = @(foreach ($r in $rows) { if (-not $seen.ContainsKey($r.key)) { $seen[$r.key] = $true; $r } })
    $usage = @{}
    foreach ($pu in @(Get-WlProp $prev 'principalUsage')) {
        if (-not $pu) { continue }
        foreach ($prop in $pu.PSObject.Properties) { $v = ConvertTo-WlIsoUtc $prop.Value; if ($v) { $usage[[string]$prop.Name] = $v } }
    }
    $fresh = Get-WlDefenderPortalUsage -Days $signInDays
    foreach ($k in $fresh.Keys) { if (-not $usage.ContainsKey($k) -or [string]::CompareOrdinal($fresh[$k], $usage[$k]) -gt 0) { $usage[$k] = $fresh[$k] } }
    $now = [DateTime]::UtcNow
    $observedSince = $now.AddDays(-$signInDays)
    $prevSince = [string](Get-WlProp $prev 'usageObservedSince')
    if ($prevSince) { try { $ps = ConvertTo-WlUtc $prevSince; if ($ps -lt $observedSince) { $observedSince = $ps } } catch { } }
    $observedDays = [int][math]::Floor(($now - $observedSince).TotalDays)
    $verdict = {
        param($last)
        if ($last) { try { if (($now - (ConvertTo-WlUtc $last)).TotalDays -le $unusedDays) { return 'Used' } else { return 'Unused' } } catch { return 'Unknown' } }
        if ($observedDays -ge $unusedDays) { 'Unused' } else { 'Unknown' }
    }
    foreach ($e in $ents) {
        if ($usage.ContainsKey($e.principalId)) { $e.lastUsed = $usage[$e.principalId] }
        $e.usage = & $verdict $e.lastUsed
    }
    foreach ($b in $bypass) { if ($usage.ContainsKey($b.principalId)) { $b.lastUsed = $usage[$b.principalId] } }
    #endregion

    #region Programmatic access and governance
    $apiApps = @(Get-WlApiApps)
    $reviews = Get-WlAccessReviewCoverage
    $pimRules = @{}
    foreach ($gid in @($groupGrants.Keys)) { if (@($groupGrants[$gid] | Where-Object { $_.privileged }).Count) { $pimRules[$gid] = Get-WlPimGroupRules -GroupId $gid } }
    $audit = Get-WlDefenderAuditFacts -Previous $prev
    #endregion

    $findings = @(Get-WlAccessFindings -Entitlements $ents -Bypass @($bypass) -UnusedDays $unusedDays) + @(Get-WlPlatformAccessFindings -ApiApps $apiApps -Reviews $reviews -GroupGrants $groupGrants -PimRules $pimRules) + @(Get-WlDefenderAuditFindings -Audit $audit)
    $principals = @($ents | Select-Object -ExpandProperty principalId -Unique)
    $activeEnts = @($ents | Where-Object { $_.state -eq 'Active' })
    $snapshot = [ordered]@{
        module             = 'access'
        version            = (Get-WlVersion)
        generatedAt        = $now.ToString('o')
        tenantId           = Get-WlSetting -Name 'WL_TENANT_ID'
        summary            = [ordered]@{
            principals         = $principals.Count
            entitlements       = $ents.Count
            roles              = $roles.Count
            customRoles        = @($roles | Where-Object { -not $_.builtIn }).Count
            active             = $activeEnts.Count
            eligible           = @($ents | Where-Object { $_.state -eq 'Eligible' }).Count
            requestable        = @($ents | Where-Object { $_.state -eq 'Requestable' }).Count
            privilegedActive   = @($activeEnts | Where-Object { $_.privileged -eq $true } | Select-Object -ExpandProperty principalId -Unique).Count
            standingPrivileged = @($activeEnts | Where-Object { $_.privileged -eq $true -and $_.allDataSources } | Select-Object -ExpandProperty principalId -Unique).Count
            unusedActive       = @($activeEnts | Where-Object { $_.usage -eq 'Unused' } | Select-Object -ExpandProperty principalId -Unique).Count
            bypassUsers        = @($bypass | Select-Object -ExpandProperty principalId -Unique).Count
            openAudiences      = $audiences.Count
            roleGrantingGroups = $groupGrants.Count
            apiApps            = $apiApps.Count
            apiAppsHighImpact  = @($apiApps | Where-Object { @($_.highImpact).Count }).Count
            accessReviews      = $(if ($reviews) { $reviews.count } else { $null })
            findings           = $findings.Count
        }
        unusedDays         = $unusedDays
        usageObservedSince = $observedSince.ToString('o')
        principalUsage     = [ordered]@{}
        roles              = @($roles)
        bypassRoles        = @($script:WlEntraBypassRoles.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ id = $_; name = $script:WlEntraBypassRoles[$_].name; level = $script:WlEntraBypassRoles[$_].level } })
        entitlements       = $ents
        bypass             = @($bypass)
        audiences          = @($audiences)
        apiApps            = $apiApps
        auditQuery         = $(if ($audit) { $audit.query } else { $null })
        auditSummary       = $(if ($audit) { $audit.summary } else { $null })
        findings           = $findings
        warnings           = @(Get-WlWarnings)
    }
    foreach ($k in ($usage.Keys | Sort-Object)) { $snapshot.principalUsage[$k] = $usage[$k] }
    $r = Save-WlSnapshot -Module 'access' -Snapshot $snapshot -Collections @('entitlements', 'bypass', 'audiences', 'apiApps', 'findings') -Started $started
    Write-Information "Gapsio access: done, $($r.changes) change(s), $($r.warnings) warning(s)." -InformationAction Continue
    $r
}
