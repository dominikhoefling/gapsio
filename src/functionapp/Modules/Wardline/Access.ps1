# Wardline Access (optional module, disabled by default): Microsoft Defender XDR unified RBAC
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

function Invoke-WlAccessCollection {
    <#
    .SYNOPSIS
    Full run of the access module; writes the snapshot and drift to storage.
    #>
    Reset-WlWarnings
    Reset-WlAccessCache
    $started = [DateTime]::UtcNow
    Write-Information "Wardline access: start $($started.ToString('o'))" -InformationAction Continue
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
    $ids = "'" + (($script:WlEntraBypassRoles.Keys | Sort-Object) -join "','") + "'"
    $entra = Invoke-WlGraphSafe -All -Context 'Entra role assignments (RoleManagement.Read.Directory)' -Path "roleManagement/directory/roleAssignments?`$filter=roleDefinitionId in ($ids)&`$expand=principal"
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

    $findings = @(Get-WlAccessFindings -Entitlements $ents -Bypass @($bypass) -UnusedDays $unusedDays)
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
            findings           = $findings.Count
        }
        unusedDays         = $unusedDays
        usageObservedSince = $observedSince.ToString('o')
        principalUsage     = [ordered]@{}
        roles              = @($roles)
        entitlements       = $ents
        bypass             = @($bypass)
        audiences          = @($audiences)
        findings           = $findings
        warnings           = @(Get-WlWarnings)
    }
    foreach ($k in ($usage.Keys | Sort-Object)) { $snapshot.principalUsage[$k] = $usage[$k] }
    $r = Save-WlSnapshot -Module 'access' -Snapshot $snapshot -Collections @('entitlements', 'bypass', 'audiences', 'findings') -Started $started
    Write-Information "Wardline access: done, $($r.changes) change(s), $($r.warnings) warning(s)." -InformationAction Continue
    $r
}
