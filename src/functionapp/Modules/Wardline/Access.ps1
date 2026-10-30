# Wardline Access (optional module, disabled by default): unified RBAC overview
# - Entra roles: active (permanent/activated) and eligible (PIM)
# - PIM for groups: eligible group membership -> the group's roles are eligible
# - Access packages: assigned or requestable (incl. roles granted through groups in the package)
# - Intune RBAC
# States: Active, Activated, Eligible, Requestable

$script:WlUsers = @{}
$script:WlGroupMembers = @{}
$script:WlGroupNames = @{}
$script:WlMaxMembers = 10000

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
    try {
        $o = Invoke-WlGraph -Path "directoryObjects/$Id"
        return Resolve-WlPrincipalInfo -Id $Id -Expanded $o
    }
    catch { return [pscustomobject]@{ id = $Id; type = 'unknown'; upn = $null; displayName = $Id } }
}

function New-WlEntitlement {
    param(
        [string]$PrincipalId, [string]$PrincipalType, [string]$Upn, [string]$DisplayName,
        [string]$Platform, [string]$RoleId, [string]$Role, $Privileged,
        [string]$State, [string]$Via, [string]$Scope, [string]$End, [string]$AccessPackageId
    )
    $key = Get-WlHash "ent|$PrincipalId|$Platform|$RoleId|$State|$Via|$Scope"
    [pscustomobject]@{
        key             = $key
        fp              = Get-WlHash "$End"
        label           = "$($DisplayName): $Role ($State, $Via)"
        state           = $State
        principalId     = $PrincipalId
        principalType   = $PrincipalType
        upn             = $Upn
        displayName     = $DisplayName
        platform        = $Platform
        roleId          = $RoleId
        role            = $Role
        privileged      = $Privileged
        via             = $Via
        scope           = $Scope
        end             = $End
        accessPackageId = $AccessPackageId
    }
}

function Get-WlScopeText {
    param([string]$DirectoryScopeId)
    if (-not $DirectoryScopeId -or $DirectoryScopeId -eq '/') { return 'Tenant' }
    if ($DirectoryScopeId -match '^/administrativeUnits/(.+)$') { return "Administrative unit $($Matches[1])" }
    "Object $DirectoryScopeId"
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

    $rows = [System.Collections.Generic.List[object]]::new()
    $audiences = [System.Collections.Generic.List[object]]::new()
    $groupGrants = @{}   # groupId -> list of rights the group grants

    #region Role definitions
    $roleById = @{}
    $roles = [System.Collections.Generic.List[object]]::new()
    $defs = Invoke-WlGraphSafe -Beta -All -Context 'Entra role definitions' -Path 'roleManagement/directory/roleDefinitions?$select=id,displayName,description,isBuiltIn,isPrivileged,templateId,rolePermissions'
    foreach ($d in @($defs)) {
        if (-not $d) { continue }
        $actions = @(foreach ($rp in @($d.rolePermissions)) { if ($rp) { @($rp.allowedResourceActions) } }) | Where-Object { $_ }
        $r = [pscustomobject]@{ platform = 'Entra'; id = [string]$d.id; name = [string]$d.displayName; description = [string]$d.description; builtIn = [bool]$d.isBuiltIn; privileged = (Get-WlProp $d 'isPrivileged'); actions = @($actions) }
        $roleById[[string]$d.id] = $r
        if ($d.templateId) { $roleById[[string]$d.templateId] = $r }
        $roles.Add($r)
    }
    #endregion

    #region Entra: active and eligible
    $roleOf = { param($id) if ($roleById.ContainsKey([string]$id)) { $roleById[[string]$id] } else { [pscustomobject]@{ name = [string]$id; privileged = $null } } }

    $active = $null
    try { $active = Invoke-WlGraph -All -Path 'roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal' }
    catch {
        Add-WlWarning "PIM assignments not readable (licence/permissions?), using roleAssignments: $($_.Exception.Message)"
        $active = Invoke-WlGraphSafe -All -Context 'Entra role assignments' -Path 'roleManagement/directory/roleAssignments?$expand=principal'
    }
    $eligible = Invoke-WlGraphSafe -All -Context 'PIM eligibilities (Entra roles)' -Path 'roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal'

    foreach ($set in @(@{ items = $active; state = 'Active' }, @{ items = $eligible; state = 'Eligible' })) {
        foreach ($a in @($set.items)) {
            if (-not $a) { continue }
            $memberType = [string](Get-WlProp $a 'memberType')
            if ($memberType -eq 'Group') { continue }  # resolved via the group
            $p = Resolve-WlPrincipalInfo -Id ([string]$a.principalId) -Expanded (Get-WlProp $a 'principal')
            $role = & $roleOf $a.roleDefinitionId
            $scope = Get-WlScopeText ([string]$a.directoryScopeId)
            $end = [string](Get-WlProp $a 'endDateTime')
            $state = $set.state
            if ($state -eq 'Active' -and [string](Get-WlProp $a 'assignmentType') -eq 'Activated') { $state = 'Activated' }

            if ($p.type -eq 'group') {
                if (-not $groupGrants.ContainsKey($p.id)) { $groupGrants[$p.id] = [System.Collections.Generic.List[object]]::new() }
                $groupGrants[$p.id].Add([pscustomobject]@{ platform = 'Entra'; roleId = [string]$a.roleDefinitionId; role = $role.name; privileged = $role.privileged; state = $set.state; scope = $scope; end = $end })
            }
            else {
                $rows.Add((New-WlEntitlement -PrincipalId $p.id -PrincipalType $p.type -Upn $p.upn -DisplayName $p.displayName -Platform 'Entra' `
                            -RoleId ([string]$a.roleDefinitionId) -Role $role.name -Privileged $role.privileged -State $state -Via 'direct' -Scope $scope -End $end))
            }
        }
    }
    #endregion

    #region Intune RBAC
    $intuneDefs = Invoke-WlGraphSafe -Beta -All -Context 'Intune role definitions' -Path 'deviceManagement/roleDefinitions?$select=id,displayName,description,isBuiltIn'
    foreach ($idf in @($intuneDefs)) {
        if (-not $idf) { continue }
        $roles.Add([pscustomobject]@{ platform = 'Intune'; id = [string]$idf.id; name = [string]$idf.displayName; description = [string]$idf.description; builtIn = [bool]$idf.isBuiltIn; privileged = $null; actions = @() })
        $ras = Invoke-WlGraphSafe -Beta -All -Context "Intune role assignments '$($idf.displayName)'" -Path "deviceManagement/roleDefinitions/$($idf.id)/roleAssignments"
        foreach ($ra in @($ras)) {
            if (-not $ra) { continue }
            $detail = Invoke-WlGraphSafe -Beta -Context "Intune role assignment '$($ra.displayName)'" -Path "deviceManagement/roleAssignments/$($ra.id)"
            if (-not $detail) { continue }
            $scopeType = [string](Get-WlProp $detail 'scopeType')
            $scopeMembers = @(Get-WlProp $detail 'scopeMembers') | Where-Object { $_ }
            $scope = if ($scopeType -match 'all') { "Intune: $scopeType" } elseif ($scopeMembers.Count) { "Intune: $($scopeMembers.Count) scope group(s)" } else { 'Intune' }
            foreach ($gid in @(Get-WlProp $detail 'members')) {
                if (-not $gid) { continue }
                if (-not $groupGrants.ContainsKey([string]$gid)) { $groupGrants[[string]$gid] = [System.Collections.Generic.List[object]]::new() }
                $groupGrants[[string]$gid].Add([pscustomobject]@{ platform = 'Intune'; roleId = [string]$idf.id; role = [string]$idf.displayName; privileged = $null; state = 'Active'; scope = $scope; end = $null })
            }
        }
    }
    #endregion

    #region Groups -> users (active/eligible via group)
    foreach ($gid in @($groupGrants.Keys)) {
        $gname = Get-WlGroupNameCached $gid
        $members = Get-WlGroupUsers -GroupId $gid
        foreach ($u in @($members)) {
            if (-not $u) { continue }
            foreach ($g in $groupGrants[$gid]) {
                $rows.Add((New-WlEntitlement -PrincipalId ([string]$u.id) -PrincipalType 'user' -Upn ([string]$u.userPrincipalName) -DisplayName ([string]$u.displayName) `
                            -Platform $g.platform -RoleId $g.roleId -Role $g.role -Privileged $g.privileged -State $g.state -Via "Group: $gname" -Scope $g.scope -End $g.end))
            }
        }
    }
    #endregion

    #region PIM for groups (eligible membership in role-granting groups)
    foreach ($gid in @($groupGrants.Keys)) {
        $gname = Get-WlGroupNameCached $gid
        $inst = Invoke-WlGraphSafe -All -Context "PIM for groups '$gname'" -Path "identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$gid'"
        foreach ($i in @($inst)) {
            if (-not $i -or [string]$i.accessId -ne 'member') { continue }
            $p = Resolve-WlPrincipalInfo -Id ([string]$i.principalId) -Expanded $null
            $targets = if ($p.type -eq 'group') { @(Get-WlGroupUsers -GroupId $p.id | ForEach-Object { [pscustomobject]@{ id = $_.id; upn = $_.userPrincipalName; displayName = $_.displayName } }) } else { @($p) }
            foreach ($t in $targets) {
                foreach ($g in $groupGrants[$gid]) {
                    $rows.Add((New-WlEntitlement -PrincipalId ([string]$t.id) -PrincipalType 'user' -Upn ([string]$t.upn) -DisplayName ([string]$t.displayName) `
                                -Platform $g.platform -RoleId $g.roleId -Role $g.role -Privileged $g.privileged -State 'Eligible' `
                                -Via "PIM for groups: $gname" -Scope $g.scope -End ([string]$i.endDateTime)))
                }
            }
        }
    }
    #endregion

    #region Access Packages
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
            $origin = [string](Get-WlProp $role 'originSystem')
            $resOrigin = [string](Get-WlProp (Get-WlProp $role 'resource') 'originId')
            if ($origin -eq 'DirectoryRole') {
                $rid = if ($resOrigin) { $resOrigin } else { [string](Get-WlProp $scopeObj 'originId') }
                $rdef = & $roleOf $rid
                $st = if ([string](Get-WlProp $role 'originId') -match 'Eligible') { 'Eligible' } else { 'Active' }
                $grants.Add([pscustomobject]@{ platform = 'Entra'; roleId = $rid; role = $rdef.name; privileged = $rdef.privileged; state = $st; scope = 'Tenant'; via = 'in package' })
            }
            elseif ($origin -eq 'AadGroup') {
                $gid = if ($resOrigin) { $resOrigin } else { [string](Get-WlProp $scopeObj 'originId') }
                if ([string](Get-WlProp $role 'originId') -notmatch '^Member') { continue }
                if ($groupGrants.ContainsKey($gid)) {
                    foreach ($g in $groupGrants[$gid]) {
                        $grants.Add([pscustomobject]@{ platform = $g.platform; roleId = $g.roleId; role = $g.role; privileged = $g.privileged; state = $g.state; scope = $g.scope; via = "via group $(Get-WlGroupNameCached $gid)" })
                    }
                }
            }
        }
        if ($grants.Count -eq 0) { continue }
        $apGrants[[string]$ap.id] = $grants

        # Requestable
        foreach ($pol in @($ap.assignmentPolicies)) {
            if (-not $pol) { continue }
            $req = Get-WlProp $pol 'requestorSettings'
            if (-not [bool](Get-WlProp $req 'enableTargetsToSelfAddAccess')) { continue }
            $scopeKind = [string](Get-WlProp $pol 'allowedTargetScope')
            $polName = [string]$pol.displayName
            if ($scopeKind -in 'allMemberUsers', 'allDirectoryUsers', 'allExternalUsers', 'allConfiguredConnectedOrganizationUsers') {
                $audiences.Add([pscustomobject]@{
                        key = Get-WlHash "aud|$($ap.id)|$($pol.id)"; fp = Get-WlHash ((@($grants | ForEach-Object { "$($_.roleId)|$($_.state)" }) -join ';') + $scopeKind)
                        label = "Access package '$($ap.displayName)' requestable by $scopeKind"; state = $scopeKind
                        audience = $scopeKind; accessPackageId = [string]$ap.id; accessPackage = [string]$ap.displayName; policy = $polName; grants = @($grants)
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
                                    -Platform $g.platform -RoleId $g.roleId -Role $g.role -Privileged $g.privileged -State 'Requestable' `
                                    -Via "Access package: $($ap.displayName) ($($g.state), $($g.via))" -Scope $g.scope -AccessPackageId ([string]$ap.id)))
                    }
                }
            }
        }
    }

    # Assigned packages (show where rights come from)
    if ($apGrants.Count -gt 0) {
        $assignments = Invoke-WlGraphSafe -All -Context 'Access package assignments' -Path "identityGovernance/entitlementManagement/assignments?`$filter=state eq 'delivered'&`$expand=target,accessPackage"
        foreach ($as in @($assignments)) {
            if (-not $as) { continue }
            $apId = [string](Get-WlProp (Get-WlProp $as 'accessPackage') 'id')
            if (-not $apGrants.ContainsKey($apId)) { continue }
            $tgt = Get-WlProp $as 'target'
            $oid = [string](Get-WlProp $tgt 'objectId')
            if (-not $oid) { continue }
            foreach ($g in $apGrants[$apId]) {
                $end = [string](Get-WlProp (Get-WlProp $as 'schedule') 'expiration')
                $rows.Add((New-WlEntitlement -PrincipalId $oid -PrincipalType 'user' -Upn ([string](Get-WlProp $tgt 'principalName')) -DisplayName ([string](Get-WlProp $tgt 'displayName')) `
                            -Platform $g.platform -RoleId $g.roleId -Role $g.role -Privileged $g.privileged -State $g.state `
                            -Via "Access package: $(Get-WlProp (Get-WlProp $as 'accessPackage') 'displayName') (assigned, $($g.via))" -Scope $g.scope -AccessPackageId $apId))
            }
        }
    }
    #endregion

    # Remove duplicates
    $seen = @{}
    $ents = foreach ($r in $rows) { if (-not $seen.ContainsKey($r.key)) { $seen[$r.key] = $true; $r } }
    $ents = @($ents)

    $principals = @($ents | Select-Object -ExpandProperty principalId -Unique)
    $snapshot = [ordered]@{
        module       = 'access'
        version      = (Get-WlVersion)
        generatedAt  = [DateTime]::UtcNow.ToString('o')
        tenantId     = Get-WlSetting -Name 'WL_TENANT_ID'
        summary      = [ordered]@{
            principals        = $principals.Count
            entitlements      = $ents.Count
            active            = @($ents | Where-Object { $_.state -in 'Active', 'Activated' }).Count
            eligible          = @($ents | Where-Object { $_.state -eq 'Eligible' }).Count
            requestable       = @($ents | Where-Object { $_.state -eq 'Requestable' }).Count
            privilegedActive  = @($ents | Where-Object { $_.state -in 'Active', 'Activated' -and $_.privileged -eq $true }).Count
            openAudiences     = $audiences.Count
            roleGrantingGroups = $groupGrants.Count
        }
        roles        = @($roles)
        entitlements = $ents
        audiences    = @($audiences)
        warnings     = @(Get-WlWarnings)
    }
    $r = Save-WlSnapshot -Module 'access' -Snapshot $snapshot -Collections @('entitlements', 'audiences') -Started $started
    Write-Information "Wardline access: done, $($r.changes) change(s), $($r.warnings) warning(s)." -InformationAction Continue
    $r
}
