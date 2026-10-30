#Requires -Version 7.2
<#
.SYNOPSIS
    Removes all test data created by New-WardlineTestData.ps1 (objects with the prefix "Wardline-Test").
    Users and groups go to the Entra ID recycle bin (restorable for 30 days).
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][string]$TenantId)
$ErrorActionPreference = 'Stop'
$Prefix = 'Wardline-Test'
$beta = 'https://graph.microsoft.com/beta'
$v1 = 'https://graph.microsoft.com/v1.0'

function Invoke-WlG {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body)
    $p = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 20 -Compress); $p.ContentType = 'application/json' }
    Invoke-MgGraphRequest @p
}
function Get-WlGAll { param([string]$Uri) $items = @(); while ($Uri) { $r = Invoke-WlG -Uri $Uri; $items += @($r.value); $Uri = $r.'@odata.nextLink' }; $items }
function Invoke-WlStep {
    param([string]$Label, [scriptblock]$Action)
    if (-not $PSCmdlet.ShouldProcess($Label, 'Remove')) { return }
    try { & $Action; Write-Host "  ✓ $Label" -ForegroundColor Green }
    catch { $m = $_.Exception.Message; if ($_.ErrorDetails.Message) { $m = $_.ErrorDetails.Message }; Write-Host "  ! $Label – $($m -replace '\s+', ' ')" -ForegroundColor Yellow }
}

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes @(
    'User.ReadWrite.All', 'Group.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'RoleEligibilitySchedule.ReadWrite.Directory',
    'RoleAssignmentSchedule.ReadWrite.Directory', 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup', 'PrivilegedAccess.ReadWrite.AzureADGroup',
    'EntitlementManagement.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementRBAC.ReadWrite.All')
$me = Invoke-WlG -Uri "$v1/me?`$select=id"
$em = "$v1/identityGovernance/entitlementManagement"

Write-Host "`n▶ AI agents and Conditional Access" -ForegroundColor Cyan
try {
    Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes @('Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'AgentIdentityBlueprint.ReadWrite.All', 'AgentIdUser.ReadWrite.All', 'Application.ReadWrite.All', 'User.ReadWrite.All', 'Group.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'RoleEligibilitySchedule.ReadWrite.Directory', 'RoleAssignmentSchedule.ReadWrite.Directory', 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup', 'PrivilegedAccess.ReadWrite.AzureADGroup', 'EntitlementManagement.ReadWrite.All', 'DeviceManagementRBAC.ReadWrite.All')
    foreach ($cp in @(Get-WlGAll -Uri "$beta/identity/conditionalAccess/policies?`$select=id,displayName") | Where-Object { $_.displayName -like "$Prefix*" }) {
        Invoke-WlStep "CA policy $($cp.displayName)" { Invoke-WlG -Method DELETE -Uri "$beta/identity/conditionalAccess/policies/$($cp.id)" | Out-Null }
    }
    foreach ($u in @(Get-WlGAll -Uri "$beta/users/microsoft.graph.agentUser?`$filter=startswith(userPrincipalName,'wardline-test-agent')&`$select=id,userPrincipalName")) {
        Invoke-WlStep "Agent user $($u.userPrincipalName)" { Invoke-WlG -Method DELETE -Uri "$beta/users/$($u.id)" | Out-Null }
    }
    foreach ($bp in @(Get-WlGAll -Uri "$beta/applications/microsoft.graph.agentIdentityBlueprint?`$filter=startswith(displayName,'$Prefix')&`$select=id,appId,displayName")) {
        foreach ($ai in @(Get-WlGAll -Uri "$beta/servicePrincipals/microsoft.graph.agentIdentity?`$filter=agentIdentityBlueprintId eq '$($bp.appId)'&`$select=id,displayName")) {
            Invoke-WlStep "Agent identity $($ai.displayName)" { Invoke-WlG -Method DELETE -Uri "$beta/servicePrincipals/$($ai.id)" | Out-Null }
        }
        foreach ($sp in @(Get-WlGAll -Uri "$beta/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?`$filter=appId eq '$($bp.appId)'&`$select=id")) {
            Invoke-WlStep "Blueprint principal $($bp.displayName)" { Invoke-WlG -Method DELETE -Uri "$beta/servicePrincipals/$($sp.id)" | Out-Null }
        }
        Invoke-WlStep "Blueprint $($bp.displayName)" { Invoke-WlG -Method DELETE -Uri "$beta/applications/$($bp.id)" | Out-Null }
    }
}
catch { Write-Host "  ! AI agents: $($_.Exception.Message)" -ForegroundColor Yellow }

Write-Host "`n▶ Intune" -ForegroundColor Cyan
foreach ($pol in @(Get-WlGAll -Uri "$beta/deviceManagement/configurationPolicies?`$select=id,name") | Where-Object { $_.name -like "$Prefix*" }) {
    Invoke-WlStep "Policy $($pol.name)" { Invoke-WlG -Method DELETE -Uri "$beta/deviceManagement/configurationPolicies('$($pol.id)')" | Out-Null }
}
foreach ($ra in @(Get-WlGAll -Uri "$beta/deviceManagement/roleAssignments") | Where-Object { $_.displayName -like "$Prefix*" }) {
    Invoke-WlStep "Intune role assignment $($ra.displayName)" { Invoke-WlG -Method DELETE -Uri "$beta/deviceManagement/roleAssignments/$($ra.id)" | Out-Null }
}

Write-Host "`n▶ Entitlement Management" -ForegroundColor Cyan
foreach ($cat in @(Get-WlGAll -Uri "$em/catalogs?`$filter=displayName eq '$Prefix'")) {
    foreach ($ap in @(Get-WlGAll -Uri "$em/accessPackages?`$filter=catalog/id eq '$($cat.id)'")) {
        foreach ($as in @(Get-WlGAll -Uri "$em/assignments?`$filter=accessPackage/id eq '$($ap.id)' and state eq 'delivered'")) {
            Invoke-WlStep "Assignment $($as.id)" { Invoke-WlG -Method POST -Uri "$em/assignmentRequests" -Body @{ requestType = 'adminRemove'; assignment = @{ id = $as.id } } | Out-Null }
        }
        $full = Invoke-WlG -Uri "$em/accessPackages/$($ap.id)?`$expand=assignmentPolicies,resourceRoleScopes"
        foreach ($pol in @($full.assignmentPolicies)) { Invoke-WlStep "Policy $($pol.displayName)" { Invoke-WlG -Method DELETE -Uri "$em/assignmentPolicies/$($pol.id)" | Out-Null } }
        foreach ($rrs in @($full.resourceRoleScopes)) { Invoke-WlStep "Resource role in the package" { Invoke-WlG -Method DELETE -Uri "$em/accessPackages/$($ap.id)/resourceRoleScopes/$($rrs.id)" | Out-Null } }
        Invoke-WlStep "Access Package $($ap.displayName)" { Invoke-WlG -Method DELETE -Uri "$em/accessPackages/$($ap.id)" | Out-Null }
    }
    foreach ($res in @(Get-WlGAll -Uri "$em/catalogs/$($cat.id)/resources")) {
        Invoke-WlStep "Catalog resource $($res.displayName)" { Invoke-WlG -Method POST -Uri "$em/resourceRequests" -Body @{ requestType = 'adminRemove'; resource = @{ originId = $res.originId; originSystem = $res.originSystem }; catalog = @{ id = $cat.id } } | Out-Null }
    }
    Start-Sleep -Seconds 10
    Invoke-WlStep "Catalog $($cat.displayName)" { Invoke-WlG -Method DELETE -Uri "$em/catalogs/$($cat.id)" | Out-Null }
}

Write-Host "`n▶ PIM and roles" -ForegroundColor Cyan
$users = @(Get-WlGAll -Uri "$v1/users?`$filter=startswith(userPrincipalName,'wardline-test-')&`$select=id,userPrincipalName")
$groups = @(Get-WlGAll -Uri "$v1/groups?`$filter=startswith(displayName,'$Prefix')&`$select=id,displayName,isAssignableToRole")
foreach ($g in $groups | Where-Object { $_.isAssignableToRole }) {
    foreach ($e in @(Get-WlGAll -Uri "$v1/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$($g.id)'")) {
        Invoke-WlStep "PIM for groups: $($e.principalId) in $($g.displayName)" {
            Invoke-WlG -Method POST -Uri "$v1/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" -Body @{ accessId = $e.accessId; principalId = $e.principalId; groupId = $g.id; action = 'adminRemove'; justification = 'Remove Wardline test' } | Out-Null
        }
    }
    foreach ($a in @(Get-WlGAll -Uri "$v1/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$($g.id)'")) {
        Invoke-WlStep "Role assignment of group $($g.displayName)" {
            Invoke-WlG -Method POST -Uri "$v1/roleManagement/directory/roleAssignmentScheduleRequests" -Body @{ action = 'adminRemove'; roleDefinitionId = $a.roleDefinitionId; directoryScopeId = $a.directoryScopeId; principalId = $g.id; justification = 'Remove Wardline test' } | Out-Null
        }
    }
}
foreach ($u in $users) {
    foreach ($e in @(Get-WlGAll -Uri "$v1/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$($u.id)'")) {
        Invoke-WlStep "Eligibility of $($u.userPrincipalName)" {
            Invoke-WlG -Method POST -Uri "$v1/roleManagement/directory/roleEligibilityScheduleRequests" -Body @{ action = 'adminRemove'; roleDefinitionId = $e.roleDefinitionId; directoryScopeId = $e.directoryScopeId; principalId = $u.id; justification = 'Remove Wardline test' } | Out-Null
        }
    }
}

Write-Host "`n▶ Groups and users" -ForegroundColor Cyan
foreach ($g in $groups) { Invoke-WlStep "Group $($g.displayName)" { Invoke-WlG -Method DELETE -Uri "$v1/groups/$($g.id)" | Out-Null } }
foreach ($u in $users) { Invoke-WlStep "User $($u.userPrincipalName)" { Invoke-WlG -Method DELETE -Uri "$v1/users/$($u.id)" | Out-Null } }

Write-Host "`n▶ Allow indicators" -ForegroundColor Cyan
$token = $null
if (Get-Command az -ErrorAction SilentlyContinue) { $token = & az account get-access-token --tenant $TenantId --resource https://api.securitycenter.microsoft.com --query accessToken -o tsv 2>$null }
if ($token) {
    try {
        $ind = (Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/indicators?`$filter=startswith(title,'$Prefix')" -Headers @{ Authorization = "Bearer $token" }).value
        foreach ($i in @($ind)) { Invoke-WlStep "Indicator $($i.title)" { Invoke-RestMethod -Method Delete -Uri "https://api.securitycenter.microsoft.com/api/indicators/$($i.id)" -Headers @{ Authorization = "Bearer $token" } | Out-Null } }
    }
    catch { Write-Host "  ! Please delete the indicators in the Defender portal (title starts with '$Prefix'); otherwise they expire after 30 days." -ForegroundColor Yellow }
}
else { Write-Host "  ! Please delete the indicators in the Defender portal (title starts with '$Prefix'); otherwise they expire after 30 days." -ForegroundColor Yellow }
Write-Host "`nDone." -ForegroundColor Green
