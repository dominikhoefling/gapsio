#Requires -Version 7.2
<#
.SYNOPSIS
    Creates the Wardline app registrations up front – for the identity team, before the Azure team installs Wardline.

.DESCRIPTION
    Typical in large organisations: app registrations and admin consent are owned by the identity team, Azure resources by
    the platform team. This script creates (idempotently):

      Portal app   "Wardline Portal"       sign-in to the portal, app role Wardline.Admin, delegated openid/profile/email/User.Read
                                           with admin consent. No client secret, no application permissions.
      Data app     "Wardline Data Access"  read-only application permissions for the selected features (least privilege) with
                                           admin consent. No secret: the Wardline managed identity signs in to it via workload
                                           identity federation. The federated credential is added once the managed identity
                                           exists (-ManagedIdentityPrincipalId, or by Install-Wardline.ps1 if allowed).

    Hand over both app IDs to the Azure team:
      ./setup/Install-Wardline.ps1 -ResourceGroup <rg> -PortalAppId <portal appId> -DataAppId <data appId> -Features <same features>

    Requires: Azure CLI signed in ("az login") as Application Administrator (apps) and Privileged Role Administrator (consent).

.EXAMPLE
    ./setup/New-WardlineAppRegistrations.ps1 -Features Hunting,Indicators,Coverage,Agents -AdminGroupId <objectId>

.EXAMPLE
    # Later, after the installation: allow the managed identity to sign in to the data app
    ./setup/New-WardlineAppRegistrations.ps1 -DataAppId <appId> -ManagedIdentityPrincipalId <objectId>

.EXAMPLE
    # Redirect URI once the Function App exists (if the Azure team cannot change the app)
    ./setup/New-WardlineAppRegistrations.ps1 -PortalAppId <appId> -PortalHostName wardline-abc123.azurewebsites.net
#>
[CmdletBinding()]
param(
    [string[]]$Features = @('Hunting', 'Indicators', 'Coverage', 'Agents'),
    [string]$AdminGroupId,
    [string]$PortalName = 'Wardline Portal',
    [string]$DataName = 'Wardline Data Access',
    [string]$PortalAppId,
    [string]$DataAppId,
    [string]$PortalHostName,
    [string]$ManagedIdentityPrincipalId,
    [switch]$SkipPortalApp,
    [switch]$SkipDataApp
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'WardlineSetup.ps1')

$featureList = Resolve-WardlineFeatures -Features $Features
$acct = (Invoke-Az -Arguments @('account', 'show', '-o', 'json')) | ConvertFrom-Json
$tenantId = $acct.tenantId
$me = Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'
Write-Ok "Tenant: $tenantId, signed in as $($me.userPrincipalName)"
$graphAppId = '00000003-0000-0000-c000-000000000000'
$graphSp = Get-ServicePrincipalByAppId -AppId $graphAppId -Select 'id,appId,displayName,appRoles'

function Get-AppByAppIdOrName {
    param([string]$AppId, [string]$Name)
    if ($AppId) { return @((Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$AppId'").value) | Select-Object -First 1 }
    @((Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$([uri]::EscapeDataString($Name.Replace("'", "''")))'").value) | Select-Object -First 1
}
function Get-OrCreateSp {
    param([string]$AppId)
    $sp = Get-ServicePrincipalByAppId -AppId $AppId -Select 'id,appId,displayName,appRoles'
    if (-not $sp) { Start-Sleep -Seconds 5; $sp = Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body @{ appId = $AppId; tags = @('WindowsAzureActiveDirectoryIntegratedApp') } }
    $sp
}

# ---------------------------------------------------------------- Portal app
if (-not $SkipPortalApp) {
    Write-Step "Portal app registration '$PortalName'"
    $scopeIds = @{ openid = '37f7f235-527c-4136-accd-4a02d197296e'; profile = '14dad69e-099b-42c9-810b-d002981feec1'; email = '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0'; UserRead = 'e1fe6dd8-ba31-4d61-89e7-88639da4683d' }
    $app = Get-AppByAppIdOrName -AppId $PortalAppId -Name $PortalName
    $redirects = @($(if ($PortalHostName) { "https://$PortalHostName/.auth/login/aad/callback" }))
    if (-not $app) {
        $app = Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body @{
            displayName = $PortalName; signInAudience = 'AzureADMyOrg'
            web = @{ redirectUris = $redirects; implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } }
            appRoles = @(@{ id = [guid]::NewGuid().ToString(); allowedMemberTypes = @('User'); value = 'Wardline.Admin'; isEnabled = $true; displayName = 'Wardline Administrator'; description = 'Sees all Wardline reports and can start runs.' })
            requiredResourceAccess = @(@{ resourceAppId = $graphAppId; resourceAccess = @($scopeIds.Values | ForEach-Object { @{ id = $_; type = 'Scope' } }) })
            notes = 'Wardline: sign-in to the self-hosted portal. No client secret, no application permissions.'
        }
        Write-Ok "Created: $($app.appId)"
    }
    else {
        Write-Ok "Present: $($app.appId)"
        if ($redirects) {
            $uris = @($app.web.redirectUris) + $redirects | Select-Object -Unique
            Invoke-Graph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" -Body @{ web = @{ redirectUris = @($uris); implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } } } | Out-Null
            Write-Ok "Redirect URI: $($redirects -join ', ')"
        }
    }
    $sp = Get-OrCreateSp -AppId $app.appId
    $grants = @((Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)'").value)
    if (-not ($grants | Where-Object { $_.resourceId -eq $graphSp.id -and $_.consentType -eq 'AllPrincipals' })) {
        Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Body @{ clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $graphSp.id; scope = 'openid profile email User.Read' } | Out-Null
    }
    Write-Ok 'Admin consent for sign-in granted'
    $roleId = (@($app.appRoles) + @($sp.appRoles) | Where-Object { $_.value -eq 'Wardline.Admin' } | Select-Object -First 1).id
    if ($AdminGroupId -and $roleId) {
        $existing = @(Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo")
        if (-not ($existing | Where-Object { $_.principalId -eq $AdminGroupId -and $_.appRoleId -eq $roleId })) {
            Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" -Body @{ principalId = $AdminGroupId; resourceId = $sp.id; appRoleId = $roleId } | Out-Null
        }
        Write-Ok "Wardline.Admin assigned to group $AdminGroupId"
    }
    $PortalAppId = $app.appId
}

# ---------------------------------------------------------------- Data app
if (-not $SkipDataApp) {
    Write-Step "Data-access app registration '$DataName' (features: $($featureList -join ', '))"
    Show-WardlinePermissions -Features $featureList
    $model = Get-WardlinePermissionModel
    $data = Get-AppByAppIdOrName -AppId $DataAppId -Name $DataName
    # requiredResourceAccess documents the permissions on the app registration (as in the Entra admin center)
    $rra = foreach ($g in (Get-WardlinePermissionSet -Features $featureList | Group-Object Resource)) {
        $resSp = Get-ServicePrincipalByAppId -AppId $model.resources.($g.Name).appId
        if (-not $resSp) { continue }
        $ids = foreach ($v in ($g.Group | ForEach-Object Value | Sort-Object -Unique)) { $r = @($resSp.appRoles) | Where-Object { $_.value -eq $v } | Select-Object -First 1; if ($r) { @{ id = $r.id; type = 'Role' } } }
        @{ resourceAppId = $resSp.appId; resourceAccess = @($ids) }
    }
    if (-not $data) {
        $data = Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body @{
            displayName = $DataName; signInAudience = 'AzureADMyOrg'; requiredResourceAccess = @($rra)
            notes = 'Wardline: read-only data access. No secret – the Wardline managed identity signs in via a federated credential.'
        }
        Write-Ok "Created: $($data.appId)"
    }
    else {
        Invoke-Graph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($data.id)" -Body @{ requiredResourceAccess = @($rra) } | Out-Null
        Write-Ok "Present: $($data.appId) (permissions updated)"
    }
    $dsp = Get-OrCreateSp -AppId $data.appId
    $r = Grant-WardlinePermissions -PrincipalId $dsp.id -Features $featureList -Prune
    Write-Ok "Admin consent: $($r.granted) granted, $($r.present) present, $($r.removed) removed"
    if ($ManagedIdentityPrincipalId) {
        $fic = Set-WardlineFederatedCredential -AppObjectId $data.id -TenantId $tenantId -ManagedIdentityPrincipalId $ManagedIdentityPrincipalId
        Write-Ok "Federated credential for managed identity $ManagedIdentityPrincipalId $fic"
    }
    $DataAppId = $data.appId
}

Write-Host ''
Write-Host '──────────────────────────────────────────────────────────────' -ForegroundColor DarkGray
Write-Host ' Hand over to the Azure team:' -ForegroundColor Green
Write-Host "   ./setup/Install-Wardline.ps1 -ResourceGroup <rg> -Location <region> -Features $($featureList -join ',')$(if ($PortalAppId) { " -PortalAppId $PortalAppId" })$(if ($DataAppId) { " -DataAppId $DataAppId" })"
if (-not $ManagedIdentityPrincipalId -and $DataAppId) {
    Write-Host ' After the installation (if the Azure team cannot add the federated credential):'
    Write-Host "   ./setup/New-WardlineAppRegistrations.ps1 -SkipPortalApp -DataAppId $DataAppId -ManagedIdentityPrincipalId <objectId of id-wardline-runner>"
}
if ($PortalAppId -and -not $PortalHostName) {
    Write-Host ' Redirect URI (the install script adds it if allowed, otherwise):'
    Write-Host "   ./setup/New-WardlineAppRegistrations.ps1 -SkipDataApp -PortalAppId $PortalAppId -PortalHostName <function app>.azurewebsites.net"
}
Write-Host ''
