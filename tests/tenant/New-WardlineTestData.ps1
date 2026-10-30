#Requires -Version 7.2
<#
.SYNOPSIS
    Creates Wardline test data in a TEST tenant. Do not use in production environments.

.DESCRIPTION
    All objects start with "Wardline-Test" and can be removed again with Remove-WardlineTestData.ps1.

    1. ID check: verifies every Settings Catalog ID of the Wardline baseline against the tenant
       and writes the result to wardline-setting-check.txt
    2. Intune: Windows and macOS test policies with exclusions at every risk level and deliberate
       baseline deviations. Assigned to an EMPTY group – nothing changes on any device.
    3. Access (optional module): two disabled test users, a role-assignable group with Helpdesk Administrator,
       PIM eligibility (Security Reader), PIM for groups (you as eligible member), Intune role
       Help Desk Operator for the group, access package with approval by you
    4. Allow indicators in Defender for Endpoint (made-up values, expire after 30 days)
    5. Intune: ASR test policies (different modes, a per-rule exclusion, a deliberate conflict) and a
       Linux test policy (passive mode, exclusions incl. global scope) – also assigned to the empty group only
    6. AI agents (Entra Agent ID): a test blueprint, three agent identities, two agent users and two
       Conditional Access policies in report-only mode (not enforced). Requires the Agent ID licence/preview.

    Prerequisites: PowerShell 7.2+, module Microsoft.Graph.Authentication
      Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
    Optional for indicators: Azure CLI signed in to the same tenant (az login)
    Roles: Global Administrator in the test tenant

.EXAMPLE
    ./tests/tenant/New-WardlineTestData.ps1 -TenantId contoso.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [switch]$SkipIntune,
    [switch]$SkipAccess,
    [switch]$SkipIndicators,
    [switch]$SkipAgents,
    [string]$ReportPath = (Join-Path (Get-Location) 'wardline-setting-check.txt')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $PSScriptRoot 'SettingsCatalog.ps1')

$Prefix = 'Wardline-Test'
$beta = 'https://graph.microsoft.com/beta'
$v1 = 'https://graph.microsoft.com/v1.0'

function Write-Step { param([string]$Text) Write-Host "`n▶ $Text" -ForegroundColor Cyan }
function Write-Ok { param([string]$Text) Write-Host "  ✓ $Text" -ForegroundColor Green }
function Write-Note { param([string]$Text) Write-Host "  ! $Text" -ForegroundColor Yellow }

function Invoke-WlG {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body)
    $p = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 40 -Compress); $p.ContentType = 'application/json' }
    Invoke-MgGraphRequest @p
}
function Get-WlGAll {
    param([Parameter(Mandatory)][string]$Uri)
    $items = @()
    while ($Uri) { $r = Invoke-WlG -Uri $Uri; $items += @($r.value); $Uri = $r.'@odata.nextLink' }
    $items
}
function Get-ErrText {
    param($E)
    $m = $E.Exception.Message
    if ($E.ErrorDetails -and $E.ErrorDetails.Message) { $m = $E.ErrorDetails.Message }
    # Extract only the actual error messages from the Graph response (instead of headers)
    $msgs = [regex]::Matches($m, '"message"\s*:\s*"((?:[^"\\]|\\.)*)"') | ForEach-Object { $_.Groups[1].Value -replace '\\"', '"' }
    if ($msgs) { $m = ($msgs | Select-Object -Unique) -join ' | ' }
    $m = $m -replace '\s+', ' '
    $m.Substring(0, [Math]::Min(800, $m.Length))
}
function New-RandomPassword {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+-_=?'
    $bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(28)
    'Aa1!' + (-join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] }))
}
$schedule = { @{ startDateTime = [DateTime]::UtcNow.ToString('o'); expiration = @{ type = 'afterDuration'; duration = 'P30D' } } }

# ---------------------------------------------------------------- Sign-in
Write-Step 'Signing in to Microsoft Graph'
if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) { throw 'Module missing: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' }
Import-Module Microsoft.Graph.Authentication
$scopes = @(
    'User.ReadWrite.All', 'Group.ReadWrite.All', 'Directory.Read.All',
    'RoleManagement.ReadWrite.Directory', 'RoleEligibilitySchedule.ReadWrite.Directory', 'RoleAssignmentSchedule.ReadWrite.Directory',
    'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup', 'PrivilegedAccess.ReadWrite.AzureADGroup',
    'EntitlementManagement.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementRBAC.ReadWrite.All'
)
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome
$me = Invoke-WlG -Uri "$v1/me?`$select=id,userPrincipalName"
$org = (Invoke-WlG -Uri "$v1/organization?`$select=id,displayName,verifiedDomains").value[0]
$domain = ($org.verifiedDomains | Where-Object { $_.isInitial } | Select-Object -First 1).name
Write-Ok "Tenant: $($org.displayName) ($domain), signed in as $($me.userPrincipalName)"

$fetch = { param($id) Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings('$([uri]::EscapeDataString($id))')" }
$report = [System.Collections.Generic.List[string]]::new()
$report.Add("Wardline setting check – $($org.displayName) – $([DateTime]::UtcNow.ToString('u'))")

# ---------------------------------------------------------------- 1. ID check
if (-not $SkipIntune) {
    Write-Step 'Checking the Wardline baseline IDs'
    $baseline = Get-Content -Raw (Join-Path $root 'src/functionapp/config/mdav-baseline.json') | ConvertFrom-Json
    $report.Add(''); $report.Add('== Baseline: exact IDs')
    $missing = 0
    foreach ($c in @($baseline.checks | Where-Object { $_.definitionId } | Sort-Object definitionId -Unique)) {
        $d = Get-WlDefinition -Id $c.definitionId -Fetch $fetch
        if ($d) { $report.Add("ok      $($c.definitionId)   [$((@($d.options) | ForEach-Object { $_.itemId -replace '^.*_', '_' }) -join ' ')]") }
        else { $missing++; $report.Add("MISSING $($c.definitionId)   (check '$($c.id)')") }
    }
    if ($missing) { Write-Note "$missing baseline ID(s) not found in the tenant – see report" } else { Write-Ok 'All exact baseline IDs present' }

    # Linux: IDs are matched by pattern (definitionIdPattern) because Microsoft does not document them
    $script:LinuxIds = @()
    try { $script:LinuxIds = @(Get-WlGAll -Uri "$beta/deviceManagement/configurationSettings?`$filter=startswith(id,'linux_')&`$select=id" | ForEach-Object { $_.id }) } catch { }
    $report.Add(''); $report.Add("== Baseline: patterns (Linux) – $($script:LinuxIds.Count) Linux definitions in the tenant")
    foreach ($c in @($baseline.checks | Where-Object { $_.definitionIdPattern })) {
        $hit = @($script:LinuxIds | Where-Object { $_ -match $c.definitionIdPattern })
        $report.Add($(if ($hit) { "ok      $($c.id) -> $($hit -join ', ')" } else { "MISSING $($c.id) ($($c.definitionIdPattern))" }))
    }
    $report.Add(''); $report.Add('== Linux settings (Defender-related)')
    $script:LinuxIds | Where-Object { $_ -match 'exclu|enforcement|merge|tamper|behavio|cloud|threattype|sample|passive|scope|network' } | Sort-Object | ForEach-Object { $report.Add("   $_") }

    $report.Add(''); $report.Add('== Defender settings in the Settings Catalog (search)')
    foreach ($q in @("startswith(id,'com.apple.managedclient.preferences_')", "startswith(id,'device_vendor_msft_defender_configuration_')")) {
        try {
            $ids = @(Get-WlGAll -Uri "$beta/deviceManagement/configurationSettings?`$filter=$q&`$select=id") | ForEach-Object { $_.id }
            $hits = @($ids | Where-Object { $_ -match 'tamper|enforcement|exclu|merge|cloud|behavio|threattype|sample|passive|hide|disablelocal' })
            $report.Add("-- $q : $($ids.Count) found, relevant: $($hits.Count)")
            $hits | Sort-Object | ForEach-Object { $report.Add("   $_") }
        }
        catch { $report.Add("-- $q : search not possible ($(Get-ErrText $_))") }
    }
}

# ---------------------------------------------------------------- 2. Intune-Testrichtlinien
if (-not $SkipIntune) {
    Write-Step 'Empty target group for the test policies'
    $devGroupName = "$Prefix Devices (empty)"
    $devGroup = @(Get-WlGAll -Uri "$v1/groups?`$filter=displayName eq '$devGroupName'") | Select-Object -First 1
    if (-not $devGroup) {
        $devGroup = Invoke-WlG -Method POST -Uri "$v1/groups" -Body @{ displayName = $devGroupName; mailEnabled = $false; mailNickname = 'wardline-test-devices'; securityEnabled = $true; description = 'Wardline test: deliberately empty – the test policies apply to no device.' }
    }
    Write-Ok "$devGroupName ($($devGroup.id))"

    $p = 'device_vendor_msft_policy_config_defender_'
    $policies = @(
        @{
            name = "$Prefix Windows exclusions and deviations"; platforms = 'windows10'
            spec = [ordered]@{
                "${p}allowrealtimemonitoring"     = '1'
                "${p}allowbehaviormonitoring"     = '1'
                "${p}allowcloudprotection"        = '1'
                "${p}enablenetworkprotection"     = '1'
                "${p}puaprotection"               = '2'       # Audit -> deviation
                "${p}cloudblocklevel"             = '0'       # Default -> deviation
                "${p}cloudextendedtimeout"        = 10        # < 50 -> deviation
                "${p}submitsamplesconsent"        = '0'       # Always prompt -> deviation
                "${p}excludedpaths"               = @('C:\Users\*\AppData\Local\Temp\WardlineTest\', 'D:\WardlineTest\db.mdf', 'C:\Program Files\Contoso\Agent\agent.exe\:{PathType:file,ScanTrigger:OnAccess}')
                "${p}excludedprocesses"           = @('powershell.exe', 'C:\Program Files\Contoso\Agent\svc.exe')
                "${p}excludedextensions"          = @('.ps1', '.wltest')
                "${p}attacksurfacereductionrules" = @([ordered]@{ blockexecutionofpotentiallyobfuscatedscripts = 'audit'; blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem = 'block' })
            }
        },
        @{
            name = "$Prefix macOS exclusions and deviations"; platforms = 'macOS'
            spec = [ordered]@{
                'com.apple.managedclient.preferences_enforcementlevel_tamperprotection' = '1'          # audit -> deviation
                'com.apple.managedclient.preferences_enforcementlevel_antivirusengine'  = '2'          # real_time -> OK
                'com.apple.managedclient.preferences_exclusionsmergepolicy'             = '0'          # merge -> deviation
                'com.apple.managedclient.preferences_cloudblocklevel'                   = '0'          # normal -> deviation
                'com.apple.managedclient.preferences_behaviormonitoring'                = '0'          # enabled -> OK
                'com.apple.managedclient.preferences_exclusions'                        = @(
                    [ordered]@{ 'item_$type' = '0'; 'item_path' = '/Users/Shared/WardlineTest'; 'item_isdirectory' = 'true' },
                    [ordered]@{ 'item_$type' = '2'; 'item_name' = 'python3' })
                'com.apple.managedclient.preferences_threattypesettings'                = @([ordered]@{ 'item_key' = '0'; 'item_value' = '0' })   # PUA audit -> deviation
                'com.apple.managedclient.preferences_allowedthreats'                    = @('EICAR-Test-File (not a virus)')
            }
        },
        @{
            name = "$Prefix ASR Clients"; platforms = 'windows10'
            spec = [ordered]@{
                "${p}attacksurfacereductionrules" = @([ordered]@{
                        blockallofficeapplicationsfromcreatingchildprocesses                    = 'warn'
                        blockallofficeapplicationsfromcreatingchildprocesses_perruleexclusions = @('C:\Program Files\Contoso\Addin\addin.exe')
                        blockprocesscreationsfrompsexecandwmicommands                           = 'audit'
                        blockabuseofexploitedvulnerablesigneddrivers                            = 'block'
                        blockpersistencethroughwmieventsubscription                             = 'off'
                    })
                "${p}attacksurfacereductiononlyexclusions" = @('C:\WardlineTest\ASR\')
            }
        },
        @{
            name = "$Prefix ASR pilot (conflict)"; platforms = 'windows10'
            spec = [ordered]@{
                "${p}attacksurfacereductionrules" = @([ordered]@{ blockallofficeapplicationsfromcreatingchildprocesses = 'block' })
            }
        }
    )

    # Linux: build the IDs from the search above (candidate patterns) so the policy is created even if the IDs differ
    $lx = { param($pattern) @($script:LinuxIds | Where-Object { $_ -match $pattern -and $_ -notmatch '_item_' }) | Select-Object -First 1 }
    $linuxSpec = [ordered]@{}
    $id = & $lx '^linux_.*antivirusengine_enforcementlevel$'; if ($id) { $linuxSpec[$id] = 'passive' }            # -> deviation
    $id = & $lx '^linux_.*exclusion.*mergepolicy$'; if ($id) { $linuxSpec[$id] = 'merge|0' }                      # -> deviation
    $id = & $lx '^linux_.*behaviormonitoring$'; if ($id) { $linuxSpec[$id] = 'enabled|1' }                         # -> OK
    $id = & $lx '^linux_.*(exclusionsettings_exclusions|antivirusengine_exclusions)$'
    if ($id) {
        $linuxSpec[$id] = @(
            [ordered]@{ '$type' = 'excludedpath|0'; 'path' = '/opt/wardline-test'; 'isdirectory' = 'true'; 'scopes' = @('epp', 'global') },
            [ordered]@{ '$type' = 'excludedpath|0'; 'path' = '/tmp/wardline-test'; 'isdirectory' = 'true'; 'scopes' = @('epp') },
            [ordered]@{ '$type' = 'excludedfilename|2'; 'name' = 'python3' })
    }
    if ($linuxSpec.Count) { $policies += @{ name = "$Prefix Linux exclusions and deviations"; platforms = 'linux'; technologies = @('linuxMdm', 'microsoftSense', 'mdm,microsoftSense'); spec = $linuxSpec } }
    else { Write-Note 'No Linux Defender settings found in the Settings Catalog – Linux test policy skipped' }

    foreach ($pol in $policies) {
        Write-Step "Intune policy: $($pol.name)"
        $report.Add(''); $report.Add("== Policy: $($pol.name)")
        $existing = @(Get-WlGAll -Uri "$beta/deviceManagement/configurationPolicies?`$select=id,name") | Where-Object { $_.name -eq $pol.name } | Select-Object -First 1
        if ($existing) { Write-Ok "already present ($($existing.id)) – skipped"; continue }
        $log = [System.Collections.Generic.List[string]]::new()
        $settings = New-WlSettingsList -Spec $pol.spec -Fetch $fetch -Log $log
        $log | ForEach-Object { $report.Add("   $_") }
        if (-not $settings.Count) { Write-Note 'No setting could be resolved – policy not created (see report)'; continue }
        try {
            # Linux: "linuxMdm" (Intune) or "microsoftSense" (Security Settings Management), depending on the tenant
            $created = $null; $lastErr = $null
            foreach ($tech in @($(if ($pol.technologies) { $pol.technologies } else { 'mdm' }))) {
                try {
                    $created = Invoke-WlG -Method POST -Uri "$beta/deviceManagement/configurationPolicies" -Body @{
                        name = $pol.name; description = 'Wardline test: deliberate weaknesses, assigned to an empty group only.'
                        platforms = $pol.platforms; technologies = $tech; roleScopeTagIds = @('0'); settings = $settings
                    }
                    break
                }
                catch { $lastErr = $_ }
            }
            if (-not $created) { throw $lastErr }
            Invoke-WlG -Method POST -Uri "$beta/deviceManagement/configurationPolicies('$($created.id)')/assign" -Body @{ assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $devGroup.id } }) } | Out-Null
            Write-Ok "created with $($settings.Count) setting(s), assigned to '$devGroupName'"
            $report.Add("   -> created: $($created.id)")
        }
        catch {
            $msg = Get-ErrText $_
            Write-Note "Creation failed: $msg"
            $report.Add("   -> ERROR while creating: $msg")
        }
        $bad = @($log | Where-Object { $_ -notlike 'ok*' })
        if ($bad.Count) { Write-Note "$($bad.Count) setting(s) could not be resolved – see report" }
    }
}

# ---------------------------------------------------------------- 3. Access
if (-not $SkipAccess) {
    Write-Step 'Test users (disabled, sign-in not possible)'
    $users = @{}
    foreach ($n in 'anna', 'ben') {
        $upn = "wardline-test-$n@$domain"
        $u = @(Get-WlGAll -Uri "$v1/users?`$filter=userPrincipalName eq '$upn'&`$select=id,userPrincipalName") | Select-Object -First 1
        if (-not $u) {
            $u = Invoke-WlG -Method POST -Uri "$v1/users" -Body @{
                accountEnabled = $false; displayName = "$Prefix $((Get-Culture).TextInfo.ToTitleCase($n))"; mailNickname = "wardline-test-$n"; userPrincipalName = $upn
                passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = (New-RandomPassword) }
            }
        }
        $users[$n] = $u
        Write-Ok "$upn ($($u.id))"
    }

    Write-Step 'Role-assignable group'
    $rgName = "$Prefix Helpdesk"
    $rg = @(Get-WlGAll -Uri "$v1/groups?`$filter=displayName eq '$rgName'") | Select-Object -First 1
    if (-not $rg) {
        $rg = Invoke-WlG -Method POST -Uri "$v1/groups" -Body @{ displayName = $rgName; mailEnabled = $false; mailNickname = 'wardline-test-helpdesk'; securityEnabled = $true; isAssignableToRole = $true; description = 'Wardline test: grants Helpdesk Administrator and an Intune role.' }
        Start-Sleep -Seconds 10
    }
    try { Invoke-WlG -Method POST -Uri "$v1/groups/$($rg.id)/members/`$ref" -Body @{ '@odata.id' = "$v1/directoryObjects/$($users['anna'].id)" } | Out-Null } catch { if ((Get-ErrText $_) -notmatch 'already exist') { Write-Note "Mitglied: $(Get-ErrText $_)" } }
    Write-Ok "$rgName ($($rg.id)), Mitglied: wardline-test-anna"

    $roles = @{ Helpdesk = '729827e3-9c14-49f7-bb1b-9608f156bbb8'; SecurityReader = '5d6b6bb7-de71-4623-b4af-96380a352509' }

    Write-Step 'PIM: active and eligible Entra roles'
    try {
        Invoke-WlG -Method POST -Uri "$v1/roleManagement/directory/roleAssignmentScheduleRequests" -Body @{
            action = 'adminAssign'; justification = 'Wardline-Test'; roleDefinitionId = $roles.Helpdesk; directoryScopeId = '/'; principalId = $rg.id; scheduleInfo = (& $schedule)
        } | Out-Null
        Write-Ok "Helpdesk Administrator active for group '$rgName' (30 days)"
    }
    catch { $m = Get-ErrText $_; if ($m -match 'Exists') { Write-Ok 'Helpdesk Administrator for the group already present' } else { Write-Note "Active assignment: $m" } }
    try {
        Invoke-WlG -Method POST -Uri "$v1/roleManagement/directory/roleEligibilityScheduleRequests" -Body @{
            action = 'adminAssign'; justification = 'Wardline-Test'; roleDefinitionId = $roles.SecurityReader; directoryScopeId = '/'; principalId = $users['ben'].id; scheduleInfo = (& $schedule)
        } | Out-Null
        Write-Ok 'Security Reader eligible for wardline-test-ben (30 days)'
    }
    catch { $m = Get-ErrText $_; if ($m -match 'Exists') { Write-Ok 'Eligibility for Ben already present' } else { Write-Note "Eligibility: $m" } }

    Write-Step 'PIM for groups: you as eligible member of the helpdesk group'
    try {
        Invoke-WlG -Method POST -Uri "$v1/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" -Body @{
            accessId = 'member'; principalId = $me.id; groupId = $rg.id; action = 'adminAssign'; justification = 'Wardline-Test'; scheduleInfo = (& $schedule)
        } | Out-Null
        Write-Ok "$($me.userPrincipalName) eligible for '$rgName' (30 days) – shows up under 'My access'"
    }
    catch { $m = Get-ErrText $_; if ($m -match 'Exists') { Write-Ok 'already present' } else { Write-Note "PIM for groups: $m" } }

    Write-Step 'Intune RBAC: Help Desk Operator for the group'
    try {
        $ir = @(Get-WlGAll -Uri "$beta/deviceManagement/roleDefinitions") | Where-Object { $_.displayName -eq 'Help Desk Operator' } | Select-Object -First 1
        $iaName = "$Prefix Helpdesk"
        $ia = @(Get-WlGAll -Uri "$beta/deviceManagement/roleAssignments") | Where-Object { $_.displayName -eq $iaName } | Select-Object -First 1
        if (-not $ia -and $ir) {
            Invoke-WlG -Method POST -Uri "$beta/deviceManagement/roleAssignments" -Body @{
                '@odata.type' = '#microsoft.graph.deviceAndAppManagementRoleAssignment'; displayName = $iaName; description = 'Wardline-Test'
                members = @($rg.id); scopeMembers = @(); scopeType = 'allDevicesAndLicensedUsers'
                'roleDefinition@odata.bind' = "$beta/deviceManagement/roleDefinitions('$($ir.id)')"
            } | Out-Null
        }
        Write-Ok 'Intune role assigned'
    }
    catch { Write-Note "Intune RBAC: $(Get-ErrText $_)" }

    Write-Step 'Entitlement Management: catalog and access package'
    try {
        $em = "$v1/identityGovernance/entitlementManagement"
        $cat = @(Get-WlGAll -Uri "$em/catalogs?`$filter=displayName eq '$Prefix'") | Select-Object -First 1
        if (-not $cat) { $cat = Invoke-WlG -Method POST -Uri "$em/catalogs" -Body @{ displayName = $Prefix; description = 'Wardline-Test'; isExternallyVisible = $false } }

        $res = @(Get-WlGAll -Uri "$em/catalogs/$($cat.id)/resources?`$filter=originId eq '$($rg.id)'") | Select-Object -First 1
        if (-not $res) {
            Invoke-WlG -Method POST -Uri "$em/resourceRequests" -Body @{ requestType = 'adminAdd'; resource = @{ originId = $rg.id; originSystem = 'AadGroup' }; catalog = @{ id = $cat.id } } | Out-Null
            for ($i = 0; $i -lt 12 -and -not $res; $i++) { Start-Sleep -Seconds 5; $res = @(Get-WlGAll -Uri "$em/catalogs/$($cat.id)/resources?`$filter=originId eq '$($rg.id)'") | Select-Object -First 1 }
        }
        if (-not $res) { throw 'The group has not arrived in the catalog after 60 s. Please run the script again.' }
        $role = @(Get-WlGAll -Uri "$em/catalogs/$($cat.id)/resourceRoles?`$filter=(originSystem eq 'AadGroup' and resource/id eq '$($res.id)')&`$expand=resource") | Where-Object { $_.originId -like 'Member_*' } | Select-Object -First 1

        $apName = "$Prefix Helpdesk access"
        $ap = @(Get-WlGAll -Uri "$em/accessPackages?`$filter=displayName eq '$apName'") | Select-Object -First 1
        if (-not $ap) { $ap = Invoke-WlG -Method POST -Uri "$em/accessPackages" -Body @{ displayName = $apName; description = 'Wardline test: grants Helpdesk Administrator via the group.'; isHidden = $false; catalog = @{ id = $cat.id } } }
        $apFull = Invoke-WlG -Uri "$em/accessPackages/$($ap.id)?`$expand=resourceRoleScopes,assignmentPolicies"
        if (-not @($apFull.resourceRoleScopes).Count) {
            Invoke-WlG -Method POST -Uri "$em/accessPackages/$($ap.id)/resourceRoleScopes" -Body @{
                role  = @{ id = $role.id; originId = $role.originId; originSystem = 'AadGroup'; resource = @{ id = $res.id; originId = $rg.id; originSystem = 'AadGroup' } }
                scope = @{ originId = $rg.id; originSystem = 'AadGroup'; isRootScope = $true }
            } | Out-Null
        }
        $approval = @{
            isApprovalRequiredForAdd = $true; isApprovalRequiredForUpdate = $false
            stages = @(@{ durationBeforeAutomaticDenial = 'P2D'; isApproverJustificationRequired = $false; isEscalationEnabled = $false; durationBeforeEscalation = 'PT0S'
                    primaryApprovers = @(@{ '@odata.type' = '#microsoft.graph.singleUser'; userId = $me.id; description = 'Wardline test approver' })
                    fallbackPrimaryApprovers = @(); escalationApprovers = @(); fallbackEscalationApprovers = @() })
        }
        $requestor = @{ enableTargetsToSelfAddAccess = $true; enableTargetsToSelfUpdateAccess = $false; enableTargetsToSelfRemoveAccess = $true; allowCustomAssignmentSchedule = $false
            enableOnBehalfRequestorsToAddAccess = $false; enableOnBehalfRequestorsToUpdateAccess = $false; enableOnBehalfRequestorsToRemoveAccess = $false; onBehalfRequestors = @() }
        $existingPolicies = @($apFull.assignmentPolicies | ForEach-Object { $_.displayName })
        foreach ($pd in @(
                @{ displayName = "$Prefix Ben only"; allowedTargetScope = 'specificDirectoryUsers'; specificAllowedTargets = @(@{ '@odata.type' = '#microsoft.graph.singleUser'; userId = $users['ben'].id; description = 'Ben' }) },
                @{ displayName = "$Prefix all members"; allowedTargetScope = 'allMemberUsers'; specificAllowedTargets = @() })) {
            if ($existingPolicies -contains $pd.displayName) { continue }
            Invoke-WlG -Method POST -Uri "$em/assignmentPolicies" -Body (@{
                    displayName = $pd.displayName; description = 'Wardline-Test'; allowedTargetScope = $pd.allowedTargetScope; specificAllowedTargets = $pd.specificAllowedTargets
                    expiration = @{ type = 'afterDuration'; duration = 'P30D' }; requestorSettings = $requestor; requestApprovalSettings = $approval
                    accessPackage = @{ id = $ap.id }
                }) | Out-Null
        }
        Write-Ok "Access Package '$apName': requestable by Ben and by all members, approval by you"
    }
    catch { Write-Note "Entitlement Management: $(Get-ErrText $_)" }
}

# ---------------------------------------------------------------- 4. Allow indicators
if (-not $SkipIndicators) {
    Write-Step 'Allow indicators in Defender for Endpoint'
    $indicators = @(
        @{ indicatorValue = '0123456789abcdef0123456789abcdef01234567'; indicatorType = 'CertificateThumbprint'; title = "$Prefix certificate (made up)" },
        @{ indicatorValue = 'aa0f5c2b3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4'; indicatorType = 'FileSha256'; title = "$Prefix file (made up)" }
    )
    $token = $null
    if (Get-Command az -ErrorAction SilentlyContinue) {
        $token = & az account get-access-token --tenant $TenantId --resource https://api.securitycenter.microsoft.com --query accessToken -o tsv 2>$null
    }
    $done = 0
    if ($token) {
        foreach ($i in $indicators) {
            try {
                Invoke-RestMethod -Method Post -Uri 'https://api.securitycenter.microsoft.com/api/indicators' -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body (@{
                        indicatorValue = $i.indicatorValue; indicatorType = $i.indicatorType; action = 'Allowed'; title = $i.title; description = 'Wardline-Test'
                        severity = 'Informational'; generateAlert = $false; expirationTime = [DateTime]::UtcNow.AddDays(30).ToString('o')
                    } | ConvertTo-Json) | Out-Null
                $done++
            }
            catch { Write-Note "$($i.title): $(Get-ErrText $_)"; break }
        }
    }
    if ($done -eq $indicators.Count) { Write-Ok 'Two allow indicators created (expire after 30 days)' }
    else {
        Write-Note 'Please create the indicators manually (Defender portal › Settings › Endpoints › Indicators):'
        foreach ($i in $indicators) { Write-Host "     $($i.indicatorType): $($i.indicatorValue)  Action: Allow  Title: $($i.title)  Expires: in 30 days" }
    }
}

# ---------------------------------------------------------------- 6. AI agents (Entra Agent ID)
if (-not $SkipAgents) {
    Write-Step 'AI agents: blueprint, agent identities, agent users, Conditional Access (report-only)'
    $agentScopes = @('AgentIdentityBlueprint.Create', 'AgentIdentityBlueprint.ReadWrite.All', 'AgentIdentityBlueprint.AddRemoveCreds.All', 'AgentIdentityBlueprintPrincipal.Create',
        'AgentIdUser.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Application.Read.All')
    $ok = $true
    try { Connect-MgGraph -TenantId $TenantId -Scopes ($scopes + $agentScopes) -NoWelcome }
    catch { Write-Note "Sign-in with Agent ID permissions not possible: $(Get-ErrText $_)"; $ok = $false }
    $odata = @{ 'OData-Version' = '4.0' }
    if ($ok) {
        try {
            $bpName = "$Prefix Blueprint"
            $bp = @(Get-WlGAll -Uri "$beta/applications/microsoft.graph.agentIdentityBlueprint?`$filter=displayName eq '$bpName'") | Select-Object -First 1
            if (-not $bp) {
                $bp = Invoke-MgGraphRequest -Method POST -Uri "$beta/applications" -OutputType PSObject -Headers $odata -ContentType 'application/json' -Body (@{
                        '@odata.type' = 'Microsoft.Graph.AgentIdentityBlueprint'; displayName = $bpName
                        'sponsors@odata.bind' = @("https://graph.microsoft.com/v1.0/users/$($me.id)"); 'owners@odata.bind' = @("https://graph.microsoft.com/v1.0/users/$($me.id)")
                    } | ConvertTo-Json)
                Start-Sleep -Seconds 10
            }
            Write-Ok "Blueprint: $($bp.displayName) (app ID $($bp.appId))"
            $bpp = @(Get-WlGAll -Uri "$beta/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?`$filter=appId eq '$($bp.appId)'") | Select-Object -First 1
            if (-not $bpp) { $bpp = Invoke-MgGraphRequest -Method POST -Uri "$beta/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal" -OutputType PSObject -Headers $odata -ContentType 'application/json' -Body (@{ appId = $bp.appId } | ConvertTo-Json) }
            Write-Ok 'Blueprint principal present'

            # Agent identities are created by the blueprint itself (blueprint token, short-lived secret that is removed afterwards)
            $existingIds = @(Get-WlGAll -Uri "$beta/servicePrincipals/microsoft.graph.agentIdentity?`$filter=agentIdentityBlueprintId eq '$($bp.appId)'&`$select=id,displayName")
            $wanted = @(
                @{ name = "$Prefix Agent protected"; sponsor = $true; user = 'wardline-test-agent-a' },
                @{ name = "$Prefix Agent unprotected"; sponsor = $true; user = 'wardline-test-agent-b' },
                @{ name = "$Prefix Agent without sponsor"; sponsor = $false; user = $null })
            $agentIds = @{}
            foreach ($e in $existingIds) { $agentIds[$e.displayName] = $e.id }
            $missingAgents = @($wanted | Where-Object { -not $agentIds.ContainsKey($_.name) })
            $bpToken = $null; $secretId = $null
            if ($missingAgents.Count) {
                $pw = Invoke-MgGraphRequest -Method POST -Uri "$beta/applications/$($bp.id)/addPassword" -OutputType PSObject -ContentType 'application/json' -Body (@{ passwordCredential = @{ displayName = 'Wardline test (temporary)'; endDateTime = [DateTime]::UtcNow.AddHours(2).ToString('o') } } | ConvertTo-Json)
                $secretId = $pw.keyId
                Start-Sleep -Seconds 20
                for ($i = 1; $i -le 6 -and -not $bpToken; $i++) {
                    try { $bpToken = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$($org.id)/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{ grant_type = 'client_credentials'; client_id = $bp.appId; client_secret = $pw.secretText; scope = 'https://graph.microsoft.com/.default' }).access_token }
                    catch { Start-Sleep -Seconds 15 }
                }
                if (-not $bpToken) { throw 'No token received for the blueprint.' }
                foreach ($w in $missingAgents) {
                    $body = @{ displayName = $w.name; agentIdentityBlueprintId = $bp.appId }
                    if ($w.sponsor) { $body['sponsors@odata.bind'] = @("https://graph.microsoft.com/v1.0/users/$($me.id)") }
                    $ai = Invoke-RestMethod -Method Post -Uri "$beta/servicePrincipals/Microsoft.Graph.AgentIdentity" -Headers @{ Authorization = "Bearer $bpToken"; 'OData-Version' = '4.0' } -ContentType 'application/json' -Body ($body | ConvertTo-Json)
                    $agentIds[$w.name] = $ai.id
                }
            }
            Write-Ok "Agent identities: $(($wanted | ForEach-Object { $_.name -replace "^$Prefix ", '' }) -join ', ')"

            $agentUsers = @{}
            foreach ($w in @($wanted | Where-Object { $_.user })) {
                $upn = "$($w.user)@$domain"
                $u = @(Get-WlGAll -Uri "$beta/users/microsoft.graph.agentUser?`$filter=userPrincipalName eq '$upn'&`$select=id") | Select-Object -First 1
                if (-not $u) {
                    $ubody = @{ accountEnabled = $true; displayName = "$($w.name) (User)"; mailNickname = $w.user; userPrincipalName = $upn; identityParentId = $agentIds[$w.name] } | ConvertTo-Json
                    try { $u = Invoke-MgGraphRequest -Method POST -Uri "$beta/users/microsoft.graph.agentUser" -OutputType PSObject -Headers $odata -ContentType 'application/json' -Body $ubody }
                    catch {
                        if (-not $bpToken) { throw }
                        $u = Invoke-RestMethod -Method Post -Uri "$beta/users/microsoft.graph.agentUser" -Headers @{ Authorization = "Bearer $bpToken"; 'OData-Version' = '4.0' } -ContentType 'application/json' -Body $ubody
                    }
                }
                $agentUsers[$w.name] = $u.id
            }
            Write-Ok "Agent users: $($agentUsers.Count)"
            if ($secretId) { try { Invoke-MgGraphRequest -Method POST -Uri "$beta/applications/$($bp.id)/removePassword" -Body (@{ keyId = $secretId } | ConvertTo-Json) -ContentType 'application/json' | Out-Null; Write-Ok 'Temporary blueprint secret removed' } catch { Write-Note "Please remove the secret manually: $(Get-ErrText $_)" } }

            # Conditional Access – report-only exclusively
            $caExisting = @(Get-WlGAll -Uri "$beta/identity/conditionalAccess/policies?`$select=id,displayName") | ForEach-Object { $_.displayName }
            $caPolicies = @(
                @{ displayName = "$Prefix CA block agent (report-only)"; state = 'enabledForReportingButNotEnforced'
                    conditions = @{ clientApplications = @{ includeAgentIdServicePrincipals = @($agentIds["$Prefix Agent protected"]) }; applications = @{ includeApplications = @('All') } }
                    grantControls = @{ operator = 'OR'; builtInControls = @('block') } },
                @{ displayName = "$Prefix CA agent users (report-only)"; state = 'enabledForReportingButNotEnforced'
                    conditions = @{ users = @{ includeUsers = @('AllAgentIdUsers'); excludeUsers = @($agentUsers["$Prefix Agent unprotected"] | Where-Object { $_ }) }; applications = @{ includeApplications = @('All') } }
                    grantControls = @{ operator = 'OR'; builtInControls = @('block') } })
            foreach ($cp in $caPolicies) {
                if ($caExisting -contains $cp.displayName) { continue }
                try { Invoke-WlG -Method POST -Uri "$beta/identity/conditionalAccess/policies" -Body $cp | Out-Null }
                catch { Write-Note "CA '$($cp.displayName)': $(Get-ErrText $_)" }
            }
            Write-Ok 'Conditional Access: two report-only policies (they block nothing)'
        }
        catch { Write-Note "AI agents: $(Get-ErrText $_)" }
    }
}

$report | Set-Content -Path $ReportPath -Encoding utf8
Write-Host ''
Write-Host "Done. ID check report: $ReportPath" -ForegroundColor Green
Write-Host 'Then click "Collect now" in the Wardline portal. Remove: ./tests/tenant/Remove-WardlineTestData.ps1'
