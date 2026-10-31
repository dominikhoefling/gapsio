#Requires -Version 7.2
<#
.SYNOPSIS
    Installs or updates Wardline in your own Azure subscription and Entra tenant.

.DESCRIPTION
    Runs in Azure Cloud Shell (PowerShell), on Windows, macOS and Linux.
    Requirements: PowerShell 7.2+ and the Azure CLI (az), signed in with "az login".
    macOS: brew install powershell azure-cli

    Steps (idempotent – the script can be run again at any time):
      1. Deploy the resource group and Azure resources (Bicep/ARM)
      2. Portal app registration for sign-in (no client secret, app role Wardline.Admin) – or attach an existing one
      3. Enable sign-in to the portal (App Service Authentication)
      4. Read-only permissions for the selected features (least privilege) – or attach an existing data-access app
      5. Deploy the function code and start the first run

    Features (-Features) – each feature only adds the permissions it needs (see setup/permissions.json):
      Core        always     Intune policies: exclusions, ASR configuration, MDAV baseline
      Hunting     default    Advanced Hunting: device state, local exclusions, effective ASR mode, local AI agents
      Indicators  default    Allow indicators from Defender for Endpoint
      Coverage    default    Defender coverage gaps: Intune-managed devices not onboarded to Defender
      Agents      default    AI agents: Entra Agent ID, Agent 365 registry, Conditional Access coverage
      Access      optional   Admin roles: active, eligible via PIM, requestable via access packages
      Licensing   optional   Defender for Endpoint licence indication: SKUs, licensed users, onboarded devices without a licensed user
      Inventory   optional   Device inventory via Intune Remediations (use -DeviceInventory, deploys a detection script)
    Show the exact permissions without installing:  ./setup/Install-Wardline.ps1 -ShowPermissions -Features Hunting,Agents

    Separation of duties (large organisations):
      The identity team can create the app registrations up front with setup/New-WardlineAppRegistrations.ps1 and hand
      over the app IDs. The Azure team then only attaches them:
        -PortalAppId   existing portal (sign-in) app registration
        -DataAppId     existing data-access app registration with the permissions already granted; Wardline's managed
                       identity signs in to it via workload identity federation (no secret)
      Alternatively -SkipPermissionGrant deploys everything and prints the command the identity team runs
      (setup/Grant-WardlinePermissions.ps1).

    Roles needed to run this script:
      - Azure: Owner, or Contributor + User Access Administrator, on the subscription or resource group
      - Entra (only for what the script creates itself): Application Administrator for the portal app registration,
        Privileged Role Administrator for granting the permissions. Not needed with -PortalAppId/-DataAppId/-SkipPermissionGrant.

.EXAMPLE
    ./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -Location westeurope

.EXAMPLE
    ./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -Location germanywestcentral -Features Hunting,Indicators,Coverage,Response,Agents,Access -EnableImmutability -SnapshotRetentionDays 730 -ChangeRetentionDays 365

.EXAMPLE
    ./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -PortalAppId <appId> -DataAppId <appId>

.EXAMPLE
    ./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -DeviceInventory -DeviceInventoryGroupId <device group objectId>

.EXAMPLE
    ./setup/Install-Wardline.ps1 -ResourceGroup rg-security -Location germanywestcentral -NamingMode Customized -FunctionAppName sec-wardline-fa-gwc-prd -StorageAccountName secwardlinegwcprd01 -RunnerIdentityName sec-wardline-mi-runner-gwc-prd -PlanName sec-wardline-plan-gwc-prd
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup,
    [string]$Location = 'westeurope',
    [string]$SubscriptionId,
    [ValidateSet('Default', 'Customized')][string]$NamingMode = 'Default',
    [ValidatePattern('^[a-z0-9]{3,10}$')][string]$NamePrefix = 'wardline',
    [string]$FunctionAppName,
    [ValidatePattern('^[a-z0-9]{3,24}$')][string]$StorageAccountName,
    [string]$RunnerIdentityName,
    [string]$DeployIdentityName,
    [string]$PlanName,
    [string]$LogWorkspaceName,
    [string]$AppInsightsName,
    [ValidateRange(30, 3650)][int]$RetentionDays = 365,
    [ValidateRange(30, 3650)][int]$SnapshotRetentionDays,
    [ValidateRange(30, 3650)][int]$ChangeRetentionDays,
    [switch]$EnableImmutability,
    [ValidateSet('Standard_LRS', 'Standard_ZRS', 'Standard_GRS')][string]$StorageSku = 'Standard_LRS',
    [string[]]$Features = @('Hunting', 'Indicators', 'Coverage', 'Response', 'Agents'),
    [string]$AdminGroupId,
    [switch]$RestrictToAssignedUsers,
    [string]$PortalAppId,
    [string]$DataAppId,
    [switch]$SkipPermissionGrant,
    [switch]$ShowPermissions,
    [string]$PackagePath,
    [switch]$SkipCode,
    [switch]$SkipFirstRun,
    [string]$NotifyWebhookUrl,
    [ValidateSet('Critical', 'High', 'Medium', 'Low')][string]$NotifyMinSeverity = 'High',
    [ValidatePattern('^(WL1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)?$')][string]$LicenseKey,
    [switch]$DeviceInventory,
    [string]$DeviceInventoryGroupId,
    [switch]$RemoveDeviceInventory
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'WardlineSetup.ps1')

if ($DeviceInventory -and $RemoveDeviceInventory) { throw '-DeviceInventory and -RemoveDeviceInventory cannot be combined.' }
$featureList = @($Features) + $(if ($DeviceInventory) { 'Inventory' })
$featureList = @($featureList | Where-Object { -not ($RemoveDeviceInventory -and $_ -eq 'Inventory') })
$featureList = Resolve-WardlineFeatures -Features $featureList
$modules = @('endpoint') + $(if ($featureList -contains 'Agents') { 'agents' }) + $(if ($featureList -contains 'Access') { 'access' }) + $(if ($featureList -contains 'Licensing') { 'licensing' })
$endpointFeatures = @($featureList | Where-Object { $_ -in 'Hunting', 'Indicators', 'Coverage', 'Inventory', 'Response' } | ForEach-Object { $_.ToLowerInvariant() })

if ($ShowPermissions) {
    Write-Host "`nWardline features: $($featureList -join ', ')" -ForegroundColor Cyan
    Write-Host 'Application permissions (read-only) required for these features:'
    Show-WardlinePermissions -Features $featureList
    return
}
if (-not $ResourceGroup) { throw 'Parameter -ResourceGroup is required.' }

$hasCustomNames = @(
    $FunctionAppName,
    $StorageAccountName,
    $RunnerIdentityName,
    $DeployIdentityName,
    $PlanName,
    $LogWorkspaceName,
    $AppInsightsName
).Where({ $_ }).Count -gt 0
if ($NamingMode -eq 'Default' -and $hasCustomNames) {
    throw 'Custom names were provided, but -NamingMode is Default. Use -NamingMode Customized when setting custom resource names.'
}
if ($NamingMode -eq 'Customized' -and -not $hasCustomNames) {
    Write-Note 'NamingMode is Customized, but no custom names were provided. Default generated names will be used.'
}

# ---------------------------------------------------------------- Prerequisites
Write-Step 'Checking prerequisites'
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI (az) not found. macOS: brew install azure-cli · Windows: winget install Microsoft.AzureCLI · or use Azure Cloud Shell.' }
$acct = Invoke-Az -Arguments @('account', 'show', '-o', 'json') -AllowFailure
if (-not $acct) { throw 'Not signed in. Run "az login" first.' }
if ($SubscriptionId) { Invoke-Az -Arguments @('account', 'set', '--subscription', $SubscriptionId) | Out-Null; $acct = Invoke-Az -Arguments @('account', 'show', '-o', 'json') }
$acct = $acct | ConvertFrom-Json
$tenantId = $acct.tenantId
Write-Ok "Subscription: $($acct.name) ($($acct.id))"
Write-Ok "Tenant:       $tenantId"
$me = Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'
Write-Ok "Signed in:    $($me.userPrincipalName)"
Write-Ok "Features:     $($featureList -join ', ')"
Write-Ok "Naming mode:  $NamingMode"

# Updates: keep the region of an existing installation unless -Location is given explicitly
if (-not $PSBoundParameters.ContainsKey('Location')) {
    $rgLocation = Invoke-Az -Arguments @('group', 'show', '-n', $ResourceGroup, '--query', 'location', '-o', 'tsv') -AllowFailure
    if ($rgLocation -and $rgLocation.Trim()) { $Location = $rgLocation.Trim(); Write-Ok "Region:       $Location (existing resource group)" }
}

# The compiled template (kept in sync with main.bicep by CI) needs no Bicep CLI and its hash lets Update-Wardline.ps1
# detect infrastructure changes.
$template = Join-Path $root 'deploy/azuredeploy.json'
if (-not (Test-Path $template)) { $template = Join-Path $root 'deploy/main.bicep' }

# Re-runs: adopt the names of an existing installation (tag wardline-component), so an update without the naming
# parameters never creates a second set of resources next to custom-named ones.
$existingRaw = Invoke-Az -Arguments @('resource', 'list', '-g', $ResourceGroup, '--query', "[?tags.""wardline-component""!=null].{name:name, component:tags.""wardline-component""}", '-o', 'json') -AllowFailure
$existing = @{}
if ($existingRaw) { foreach ($r in @($existingRaw | ConvertFrom-Json)) { if (-not $existing.ContainsKey($r.component)) { $existing[$r.component] = $r.name } } }
$adopt = [ordered]@{ functionapp = 'FunctionAppName'; storage = 'StorageAccountName'; runner = 'RunnerIdentityName'; deployer = 'DeployIdentityName'; plan = 'PlanName'; logs = 'LogWorkspaceName'; appinsights = 'AppInsightsName' }
$adopted = @()
foreach ($c in $adopt.Keys) {
    $var = $adopt[$c]
    $given = Get-Variable -Name $var -ValueOnly
    if ($existing.ContainsKey($c)) {
        if ($given -and $given -ne $existing[$c]) { throw "The resource group already contains a Wardline $c named '$($existing[$c])'. Renaming is not supported – use -$var $($existing[$c]) or a new resource group." }
        if (-not $given) { Set-Variable -Name $var -Value $existing[$c]; $adopted += "$c=$($existing[$c])" }
    }
}
if ($adopted.Count) { $NamingMode = 'Customized'; Write-Ok "Existing names: $($adopted -join ', ')" }

# Re-runs: keep the notification and retention settings unless they are passed explicitly (app settings are rewritten by the template)
if ($existing.ContainsKey('functionapp')) {
    $cur = Invoke-Az -Arguments @('functionapp', 'config', 'appsettings', 'list', '-g', $ResourceGroup, '-n', $existing['functionapp'], '-o', 'json') -AllowFailure
    if ($cur) {
        $curMap = @{}; foreach ($x in @($cur | ConvertFrom-Json)) { $curMap[$x.name] = $x.value }
        if (-not $PSBoundParameters.ContainsKey('NotifyWebhookUrl') -and $curMap['WL_NOTIFY_WEBHOOK']) { $NotifyWebhookUrl = $curMap['WL_NOTIFY_WEBHOOK']; Write-Ok 'Notification webhook: kept' }
        if (-not $PSBoundParameters.ContainsKey('NotifyMinSeverity') -and $curMap['WL_NOTIFY_MIN_SEVERITY']) { $NotifyMinSeverity = $curMap['WL_NOTIFY_MIN_SEVERITY'] }
        if (-not $PSBoundParameters.ContainsKey('LicenseKey') -and $curMap['WL_LICENSE_KEY']) { $LicenseKey = $curMap['WL_LICENSE_KEY'] }
        if (-not $PSBoundParameters.ContainsKey('RetentionDays')) {
            if (-not $SnapshotRetentionDays -and $curMap['WL_SNAPSHOT_RETENTION_DAYS']) { $SnapshotRetentionDays = [int]$curMap['WL_SNAPSHOT_RETENTION_DAYS'] }
            if (-not $ChangeRetentionDays -and $curMap['WL_CHANGE_RETENTION_DAYS']) { $ChangeRetentionDays = [int]$curMap['WL_CHANGE_RETENTION_DAYS'] }
        }
    }
}
# -RetentionDays sets both; the specific parameters win.
if (-not $SnapshotRetentionDays) { $SnapshotRetentionDays = $RetentionDays }
if (-not $ChangeRetentionDays) { $ChangeRetentionDays = $RetentionDays }
if ($NotifyWebhookUrl -and $NotifyWebhookUrl -notmatch '^https://') { throw '-NotifyWebhookUrl must be an https URL.' }

function Deploy-Infrastructure {
    param([string]$SsoClientId = '')
    $name = "wardline-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $params = @(
        "namePrefix=$NamePrefix", "retentionDays=$RetentionDays", "snapshotRetentionDays=$SnapshotRetentionDays", "changeRetentionDays=$ChangeRetentionDays", "enableImmutability=$($EnableImmutability.IsPresent.ToString().ToLower())",
        "storageSku=$StorageSku", "ssoClientId=$SsoClientId", "location=$Location", "deviceInventory=$(($featureList -contains 'Inventory').ToString().ToLower())",
        "enableAgents=$(($modules -contains 'agents').ToString().ToLower())", "enableAccess=$(($modules -contains 'access').ToString().ToLower())", "enableLicensing=$(($modules -contains 'licensing').ToString().ToLower())",
        "features=$($endpointFeatures -join ',')", "dataAppId=$DataAppId", "notifyMinSeverity=$NotifyMinSeverity"
    )
    if ($NotifyWebhookUrl) { $params += "notifyWebhook=$NotifyWebhookUrl" }
    if ($LicenseKey) { $params += "licenseKey=$LicenseKey" }
    if ($NamingMode -eq 'Customized') {
        if ($FunctionAppName) { $params += "customFunctionAppName=$FunctionAppName" }
        if ($StorageAccountName) { $params += "customStorageAccountName=$StorageAccountName" }
        if ($RunnerIdentityName) { $params += "customRunnerIdentityName=$RunnerIdentityName" }
        if ($DeployIdentityName) { $params += "customDeployIdentityName=$DeployIdentityName" }
        if ($PlanName) { $params += "customPlanName=$PlanName" }
        if ($LogWorkspaceName) { $params += "customLogWorkspaceName=$LogWorkspaceName" }
        if ($AppInsightsName) { $params += "customAppInsightsName=$AppInsightsName" }
    }
    $out = Invoke-Az -Arguments (@('deployment', 'group', 'create', '-g', $ResourceGroup, '-n', $name, '--template-file', $template, '--query', 'properties.outputs', '-o', 'json', '--parameters') + $params)
    $o = $out | ConvertFrom-Json
    [pscustomobject]@{
        FunctionAppName   = $o.functionAppName.value
        HostName          = $o.defaultHostName.value
        PortalUrl         = $o.portalUrl.value
        RunnerPrincipalId = $o.runnerPrincipalId.value
        StorageAccount    = $o.storageAccountName.value
    }
}

# ---------------------------------------------------------------- 1. Azure resources
Write-Step "Resource group '$ResourceGroup' in $Location"
Invoke-Az -Arguments @('group', 'create', '-n', $ResourceGroup, '-l', $Location, '--tags', 'product=Wardline', '-o', 'none') | Out-Null
Write-Ok 'Resource group ready'

Write-Step 'Deploying Azure resources (storage, Function App, monitoring, managed identity)'
$infra = Deploy-Infrastructure
Write-Ok "Function App: $($infra.FunctionAppName)"
Write-Ok "Storage:      $($infra.StorageAccount) (Entra authentication only, no keys)"
$redirect = "https://$($infra.HostName)/.auth/login/aad/callback"

# ---------------------------------------------------------------- 2. Portal app registration
$graphAppId = '00000003-0000-0000-c000-000000000000'
$graphSp = Get-ServicePrincipalByAppId -AppId $graphAppId -Select 'id,appId,displayName'
$appName = "Wardline Portal ($($infra.FunctionAppName))"
if ($PortalAppId) {
    Write-Step "Attaching the existing portal app registration ($PortalAppId)"
    $app = @((Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$PortalAppId'" -AllowFailure).value) | Select-Object -First 1
    if ($app) {
        $appName = $app.displayName
        if (@($app.web.redirectUris) -notcontains $redirect) {
            $uris = @($app.web.redirectUris) + $redirect | Select-Object -Unique
            $ok = Invoke-Graph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" -Body @{ web = @{ redirectUris = @($uris); implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } } } -AllowFailure
            if ($ok -ne $false) { Write-Ok "Redirect URI added: $redirect" }
            else { Write-Note "No permission to change the app registration. Ask the identity team to add the redirect URI: $redirect (Web platform, ID tokens enabled)" }
        }
        else { Write-Ok 'Redirect URI present' }
        if (-not (@($app.appRoles) | Where-Object { $_.value -eq 'Wardline.Admin' })) { Write-Note "The app registration has no app role 'Wardline.Admin'. Create it with setup/New-WardlineAppRegistrations.ps1 or add it manually." }
    }
    else {
        Write-Note "The app registration could not be read (missing directory permission?). Make sure it has the redirect URI: $redirect"
    }
    $sp = Get-ServicePrincipalByAppId -AppId $PortalAppId -Select 'id,appId,displayName,appRoles'
}
else {
    Write-Step 'Portal app registration (sign-in to the portal)'
    $scopeIds = @{
        openid   = '37f7f235-527c-4136-accd-4a02d197296e'
        profile  = '14dad69e-099b-42c9-810b-d002981feec1'
        email    = '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0'
        UserRead = 'e1fe6dd8-ba31-4d61-89e7-88639da4683d'
    }
    $encodedName = [uri]::EscapeDataString($appName.Replace("'", "''"))
    $app = @(Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$encodedName'").value | Select-Object -First 1
    if (-not $app) {
        $app = Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body @{
            displayName            = $appName
            signInAudience         = 'AzureADMyOrg'
            web                    = @{ redirectUris = @($redirect); implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } }
            appRoles               = @(@{
                    id = [guid]::NewGuid().ToString(); allowedMemberTypes = @('User'); value = 'Wardline.Admin'; isEnabled = $true
                    displayName = 'Wardline Administrator'; description = 'Sees all Wardline reports and can start runs.'
                })
            requiredResourceAccess = @(@{ resourceAppId = $graphAppId; resourceAccess = @($scopeIds.Values | ForEach-Object { @{ id = $_; type = 'Scope' } }) })
            notes                  = 'Wardline: sign-in to the self-hosted portal. No client secret, no Graph application permissions.'
        }
        Write-Ok "App registration created: $($app.appId)"
    }
    else {
        $uris = @($app.web.redirectUris) + $redirect | Select-Object -Unique
        Invoke-Graph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" -Body @{ web = @{ redirectUris = @($uris); implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } } } | Out-Null
        Write-Ok "App registration present: $($app.appId)"
    }
    $PortalAppId = $app.appId
    $sp = Get-ServicePrincipalByAppId -AppId $PortalAppId -Select 'id,appId,displayName,appRoles'
    if (-not $sp) {
        Start-Sleep -Seconds 5
        $sp = Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body @{ appId = $PortalAppId; tags = @('WindowsAzureActiveDirectoryIntegratedApp') }
    }
}

if ($sp) {
    $null = Invoke-Graph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)" -Body @{ appRoleAssignmentRequired = $RestrictToAssignedUsers.IsPresent } -AllowFailure
    $grants = @((Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)'" -AllowFailure).value)
    if (-not ($grants | Where-Object { $_.resourceId -eq $graphSp.id -and $_.consentType -eq 'AllPrincipals' })) {
        $r = Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Body @{ clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $graphSp.id; scope = 'openid profile email User.Read' } -AllowFailure
        if ($r -eq $false) { Write-Note 'Admin consent for sign-in (openid profile email User.Read) could not be granted – ask the identity team.' } else { Write-Ok 'Admin consent for sign-in (openid profile email User.Read) granted' }
    }
    else { Write-Ok 'Admin consent for sign-in present' }

    $adminRoleId = (@($sp.appRoles) | Where-Object { $_.value -eq 'Wardline.Admin' } | Select-Object -First 1).id
    if ($adminRoleId) {
        $principals = @(@{ id = $me.id; label = $me.userPrincipalName })
        if ($AdminGroupId) { $principals += @{ id = $AdminGroupId; label = "group $AdminGroupId" } }
        $existing = @(Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo")
        foreach ($p in $principals) {
            if ($existing | Where-Object { $_.principalId -eq $p.id -and $_.appRoleId -eq $adminRoleId }) { Write-Ok "Wardline.Admin already assigned: $($p.label)"; continue }
            $r = Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" -Body @{ principalId = $p.id; resourceId = $sp.id; appRoleId = $adminRoleId } -AllowFailure
            if ($r -eq $false) { Write-Note "Could not assign Wardline.Admin to $($p.label) – ask the identity team." } else { Write-Ok "Wardline.Admin assigned: $($p.label)" }
        }
    }
}
else { Write-Note 'The enterprise application (service principal) of the portal app does not exist yet. The identity team must create it and assign the Wardline.Admin role.' }

# ---------------------------------------------------------------- Optional: device inventory (Intune Remediations)
$inventoryName = 'Wardline – local Defender exclusions (read-only)'
if ($DeviceInventory -or $RemoveDeviceInventory) {
    Write-Step $(if ($DeviceInventory) { 'Setting up the device inventory (Intune Remediations, detection script only)' } else { 'Removing the device inventory' })
    if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) { throw 'The device inventory needs the module: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' }
    Import-Module Microsoft.Graph.Authentication
    try { Connect-MgGraph -TenantId $tenantId -NoWelcome -Scopes 'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementScripts.ReadWrite.All' }
    catch { Connect-MgGraph -TenantId $tenantId -NoWelcome -Scopes 'DeviceManagementConfiguration.ReadWrite.All' }
    $hsBase = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'
    $existingHs = @((Invoke-MgGraphRequest -Uri "$hsBase`?`$select=id,displayName" -OutputType PSObject).value) | Where-Object { $_.displayName -like 'Wardline*' }

    if ($RemoveDeviceInventory) {
        foreach ($h in $existingHs) { Invoke-MgGraphRequest -Method DELETE -Uri "$hsBase/$($h.id)" | Out-Null; Write-Ok "Removed: $($h.displayName)" }
        if (-not $existingHs) { Write-Ok 'No detection script present' }
    }
    else {
        $content = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $root 'setup/assets/Get-WardlineLocalExclusions.ps1')))
        $body = @{
            displayName = $inventoryName; publisher = 'Wardline'; version = '1'
            description = 'Wardline: reads local Microsoft Defender exclusions, DisableLocalAdminMerge, Tamper Protection and running mode. Changes nothing (no remediation script).'
            detectionScriptContent = $content; runAsAccount = 'system'; enforceSignatureCheck = $false; runAs32Bit = $false; roleScopeTagIds = @('0')
        }
        $hs = $existingHs | Select-Object -First 1
        if ($hs) {
            Invoke-MgGraphRequest -Method PATCH -Uri "$hsBase/$($hs.id)" -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' | Out-Null
            Write-Ok "Detection script updated ($($hs.id))"
        }
        else {
            $body['@odata.type'] = '#microsoft.graph.deviceHealthScript'
            $hs = Invoke-MgGraphRequest -Method POST -Uri $hsBase -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -OutputType PSObject
            Write-Ok "Detection script created ($($hs.id))"
        }
        $target = if ($DeviceInventoryGroupId) { @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $DeviceInventoryGroupId } } else { @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
        $assign = @{ deviceHealthScriptAssignments = @(@{
                    target = $target; runRemediationScript = $false
                    runSchedule = @{ '@odata.type' = '#microsoft.graph.deviceHealthScriptDailySchedule'; interval = 1; useUtc = $true; time = '01:00:00' }
                }) }
        Invoke-MgGraphRequest -Method POST -Uri "$hsBase/$($hs.id)/assign" -Body ($assign | ConvertTo-Json -Depth 6) -ContentType 'application/json' | Out-Null
        Write-Ok ('Assigned to ' + $(if ($DeviceInventoryGroupId) { "group $DeviceInventoryGroupId" } else { 'all devices' }) + ', daily at 01:00 UTC')
    }
    Disconnect-MgGraph | Out-Null
}

# ---------------------------------------------------------------- 3. Enable sign-in
Write-Step 'Enabling sign-in to the portal'
$infra = Deploy-Infrastructure -SsoClientId $PortalAppId
Write-Ok 'App Service Authentication enabled (Entra ID, no client secret)'

# ---------------------------------------------------------------- 4. Read permissions (least privilege)
$grantCmd = "./setup/Grant-WardlinePermissions.ps1 -PrincipalId $($infra.RunnerPrincipalId) -Features $($featureList -join ',')"
if ($DataAppId) {
    Write-Step "Attaching the data-access app registration ($DataAppId)"
    $dataApp = @((Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$DataAppId'" -AllowFailure).value) | Select-Object -First 1
    $fic = $null
    if ($dataApp) { try { $fic = Set-WardlineFederatedCredential -AppObjectId $dataApp.id -TenantId $tenantId -ManagedIdentityPrincipalId $infra.RunnerPrincipalId } catch { $fic = $null } }
    if ($fic) { Write-Ok "Federated credential for the managed identity $fic (no secret)" }
    else {
        Write-Note 'Could not add the federated credential. Ask the identity team to add it to the app registration:'
        Write-Host "     Issuer:   https://login.microsoftonline.com/$tenantId/v2.0"
        Write-Host "     Subject:  $($infra.RunnerPrincipalId)   (object ID of the managed identity id-$NamePrefix-runner)"
        Write-Host '     Audience: api://AzureADTokenExchange'
        Write-Host "     or run:   ./setup/New-WardlineAppRegistrations.ps1 -DataAppId $DataAppId -ManagedIdentityPrincipalId $($infra.RunnerPrincipalId)"
    }
    $dataSp = Get-ServicePrincipalByAppId -AppId $DataAppId -Select 'id,appId,displayName'
    if ($dataSp) {
        $missing = Get-WardlineMissingPermissions -PrincipalId $dataSp.id -Features $featureList
        if ($missing.Count) { Write-Note "The data-access app is missing permissions for the selected features: $($missing -join ', ')" } else { Write-Ok 'The data-access app has all permissions for the selected features' }
    }
}
elseif ($SkipPermissionGrant) {
    Write-Step 'Read permissions'
    Write-Note 'Skipped (-SkipPermissionGrant). Ask a Privileged Role Administrator to run:'
    Write-Host "     $grantCmd"
    Write-Host '     Show the permissions:'
    Write-Host "     ./setup/Install-Wardline.ps1 -ShowPermissions -Features $($featureList -join ',')"
}
else {
    Write-Step 'Read permissions of the managed identity (least privilege for the selected features)'
    $r = Grant-WardlinePermissions -PrincipalId $infra.RunnerPrincipalId -Features $featureList -Prune
    if ($r.removed) { Write-Ok "$($r.removed) permission(s) removed that the selected features no longer need" }
}

# ---------------------------------------------------------------- 5. Deploy code
if (-not $SkipCode) {
    Write-Step 'Deploying the function code'
    if (-not $PackagePath) {
        $PackagePath = Join-Path $root 'dist/wardline-functionapp.zip'
        if (-not (Test-Path $PackagePath)) { & (Join-Path $root 'build/New-WardlinePackage.ps1') | Out-Null }
    }
    $deployed = $false
    for ($i = 1; $i -le 6 -and -not $deployed; $i++) {
        $r = Invoke-Az -Arguments @('functionapp', 'deployment', 'source', 'config-zip', '-g', $ResourceGroup, '-n', $infra.FunctionAppName, '--src', $PackagePath, '-o', 'none') -AllowFailure
        if ($null -ne $r) { $deployed = $true } else { Write-Note "Deployment attempt $i failed (role assignments may still be propagating), waiting 30 s …"; Start-Sleep -Seconds 30 }
    }
    if (-not $deployed) { throw 'The code could not be deployed. Run the script again in a few minutes.' }
    Write-Ok "Package deployed: $(Split-Path $PackagePath -Leaf)"
    $pkgVersion = Get-WardlinePackageVersion -Path $PackagePath
    $templateHash = if ($template -like '*.json') { (Get-FileHash -Algorithm SHA256 $template).Hash.ToLowerInvariant() } else { $null }
    Set-WardlineVersionTags -ResourceGroup $ResourceGroup -FunctionAppName $infra.FunctionAppName -Version $pkgVersion -TemplateSha256 $templateHash
    if ($pkgVersion) { Write-Ok "Version $pkgVersion" }
}

# ---------------------------------------------------------------- First run
if (-not $SkipFirstRun -and -not $SkipCode) {
    Write-Step 'Starting the first run'
    Write-Note 'New Graph permissions take effect with the next token of the managed identity (usually within an hour, at most 24 hours). Until then the portal shows HTTP 403 notices.'
    try {
        $keys = Invoke-Az -Arguments @('functionapp', 'keys', 'list', '-g', $ResourceGroup, '-n', $infra.FunctionAppName, '-o', 'json') | ConvertFrom-Json
        $fns = @('CollectEndpoint') + $(if ($modules -contains 'agents') { 'CollectAgents' }) + $(if ($modules -contains 'access') { 'CollectAccess' }) + $(if ($modules -contains 'licensing') { 'CollectLicensing' })
        foreach ($fn in $fns) {
            Invoke-RestMethod -Method Post -Uri "https://$($infra.HostName)/admin/functions/$fn" -Headers @{ 'x-functions-key' = $keys.masterKey } -ContentType 'application/json' -Body '{"input":""}' | Out-Null
        }
        Write-Ok "Runs started ($(($fns -replace '^Collect', '') -join ', ')). Results appear in the portal within a few minutes."
    }
    catch { Write-Note "Could not start the run directly ($($_.Exception.Message)). Click “Collect now” in the portal." }
}

# ---------------------------------------------------------------- Summary
Write-Host ''
Write-Host '──────────────────────────────────────────────────────────────' -ForegroundColor DarkGray
Write-Host " Wardline is ready: $($infra.PortalUrl)" -ForegroundColor Green
Write-Host '──────────────────────────────────────────────────────────────' -ForegroundColor DarkGray
Write-Host " Administrators:   enterprise app '$appName' > Users and groups > role 'Wardline Administrator'"
Write-Host " Features:         $($featureList -join ', ')"
Write-Host " Data access:      $(if ($DataAppId) { "app registration $DataAppId (federated, no secret)" } else { 'managed identity (no secret)' })"
if ($modules -contains 'access') { Write-Host " Everyone else:    sees 'My permissions' only$(if ($RestrictToAssignedUsers) { ' (only assigned users can sign in)' })" }
Write-Host " Data:             storage account $($infra.StorageAccount) in $ResourceGroup – snapshots $SnapshotRetentionDays days$(if ($EnableImmutability) { ' (immutable)' }), change history $ChangeRetentionDays days"
Write-Host ''
