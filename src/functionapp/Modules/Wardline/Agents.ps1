# Wardline Agents: inventory of AI agents and their protection.
#
# Cloud agents (Copilot Studio, Azure AI Foundry, custom) – sources: Microsoft Entra Agent ID, the Agent 365 registry and
# Defender AgentsInfo. Rated by Conditional Access coverage, separately for the agent identity and the agent user.
# Local agents (e.g. coding assistants and IDE extensions on endpoints) – source: Defender AgentsInfo
# (RawAgentInfo.localAgentMetadata). They run in the signed-in user's context; rated by device and configuration
# (auto-approve, MCP servers, trusted process) and combined with the endpoint module's device state.
#
# Conditional Access rules (product documentation, 10/2026):
# - Agent identities are targeted via conditions.clientApplications.includeAgentIdServicePrincipals
#   ('All', object IDs of agent identities or blueprints) or agentIdServicePrincipalFilter (custom security attributes).
# - Agent users are targeted via conditions.users.includeUsers = 'AllAgentIdUsers' or their object ID.
#   Policies for "All users" and group assignments do NOT apply to agent users.
# - A policy for the agent identity does not apply to its agent user and vice versa.
# - With security defaults enabled, Conditional Access is not evaluated at all.

function Get-WlGraphListExpand {
    # Load a list with $expand=sponsors; if that fails (older API versions), retry without expand.
    param([string]$Path, [string]$Context)
    try { return @(Invoke-WlGraph -All -Path "$Path&`$expand=sponsors(`$select=id,displayName,userPrincipalName)") }
    catch { return @(Invoke-WlGraphSafe -All -Path $Path -Context $Context) }
}

function Get-WlAgentDirectory {
    $bp = Invoke-WlGraphSafe -All -Context 'Agent identity blueprints (AgentIdentityBlueprint.Read.All)' `
        -Path 'applications/microsoft.graph.agentIdentityBlueprint?$select=id,appId,displayName,createdDateTime,publisherDomain,signInAudience'
    $bpp = Invoke-WlGraphSafe -All -Context 'Blueprint principals (AgentIdentityBlueprintPrincipal.Read.All)' `
        -Path 'servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?$select=id,appId,displayName,accountEnabled,appOwnerOrganizationId,createdDateTime'
    $ids = Get-WlGraphListExpand -Context 'Agent identities (AgentIdentity.Read.All)' `
        -Path 'servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,displayName,accountEnabled,agentIdentityBlueprintId,createdByAppId,createdDateTime,disabledByMicrosoftStatus'
    $users = Get-WlGraphListExpand -Context 'Agent users' `
        -Path 'users/microsoft.graph.agentUser?$select=id,displayName,userPrincipalName,accountEnabled,identityParentId,createdDateTime'
    [pscustomobject]@{
        Blueprints          = @($bp | Where-Object { $_ })
        BlueprintPrincipals = @($bpp | Where-Object { $_ })
        Identities          = @($ids | Where-Object { $_ })
        Users               = @($users | Where-Object { $_ })
    }
}

function Get-WlAgentRegistry {
    # Agent 365 registry (Graph beta). Optional – without licence or permission the run only adds a warning.
    @(Invoke-WlGraphSafe -Beta -All -Context 'Agent 365 registry (AgentInstance.Read.All)' -Path 'agentRegistry/agentInstances' | Where-Object { $_ })
}

function Get-WlAgentsInfo {
    # Defender XDR Advanced Hunting: AgentsInfo (Copilot Studio, Foundry, local agents on endpoints, ...).
    $q = @"
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| extend m = RawAgentInfo.localAgentMetadata
| project AgentId = tostring(AgentId), Name, Platform, Version, EntraAgentID, EntraBlueprintID, SourceAgentId, PublishedStatus, LifecycleStatus, Availability,
          InstanceCount, Model, CreatedDateTime, LastUpdatedDateTime,
          IsLocal = isnotempty(m) or Platform has "Local",
          Vendor = tostring(m.vendor), LocalDeviceId = tostring(m.machineId), LocalDeviceName = tostring(m.deviceName), LocalOs = tostring(m.osPlatform),
          LocalUser = tostring(m.upn), AutoApprove = tostring(m.autoApprove), TrustedProcess = tostring(m.trustedProcess), Process = tostring(m.relatedProcess),
          LocalMcps = tostring(m.localMcps), McpServers = tostring(RawAgentInfo.mcpServers)
"@
    @(Invoke-WlHuntingSafe -Query $q -Context 'Advanced Hunting AgentsInfo' | Where-Object { $_ })
}

function Get-WlCaPolicies {
    $pol = Invoke-WlGraphSafe -All -Context 'Conditional Access policies (Policy.Read.All)' -Path 'identity/conditionalAccess/policies'
    $sd = $null
    try { $sd = Invoke-WlGraph -Path 'policies/identitySecurityDefaultsEnforcementPolicy' } catch { }
    [pscustomobject]@{ Policies = @($pol | Where-Object { $_ }); SecurityDefaults = [bool](Get-WlProp $sd 'isEnabled') }
}

function Get-WlCaControls {
    # Grant controls as codes (block, mfa, compliantDevice, ...) plus operator and agent risk levels; the portal renders them.
    param($Policy)
    $g = Get-WlProp $Policy 'grantControls'
    [pscustomobject]@{
        controls   = @(@(Get-WlProp $g 'builtInControls') | Where-Object { $_ } | ForEach-Object { [string]$_ })
        operator   = [string](Get-WlProp $g 'operator')
        riskLevels = @(@(Get-WlProp (Get-WlProp $Policy 'conditions') 'agentIdRiskLevels') | Where-Object { $_ } | ForEach-Object { [string]$_ })
    }
}

function Test-WlCaAgentScope {
    <#
    .SYNOPSIS
    Checks whether a CA policy covers a subject.
      -Kind Identity: subject IDs = agent identity, blueprint (object ID / app ID), blueprint principal
      -Kind User:     subject IDs = agent user
    Returns $null (not affected) or an object with applies/excluded/uncertain/via/filter.
    via codes: AllAgentIdentities, Direct, Blueprint, AttributeFilter, AllAgentUsers
    #>
    param($Policy, [ValidateSet('Identity', 'User')][string]$Kind, [string[]]$Ids, [string]$DirectId)
    $c = Get-WlProp $Policy 'conditions'
    $idSet = @($Ids | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    if ($Kind -eq 'Identity') {
        $ca = Get-WlProp $c 'clientApplications'
        if (-not $ca) { return $null }
        $inc = @(@(Get-WlProp $ca 'includeAgentIdServicePrincipals') | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $exc = @(@(Get-WlProp $ca 'excludeAgentIdServicePrincipals') | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $flt = Get-WlProp $ca 'agentIdServicePrincipalFilter'
        $rule = [string](Get-WlProp $flt 'rule'); $mode = [string](Get-WlProp $flt 'mode')
        $via = $null
        if ($inc -contains 'all') { $via = 'AllAgentIdentities' }
        elseif ($DirectId -and $inc -contains $DirectId.ToLowerInvariant()) { $via = 'Direct' }
        elseif (@($inc | Where-Object { $idSet -contains $_ }).Count) { $via = 'Blueprint' }
        $excluded = @($exc | Where-Object { $idSet -contains $_ }).Count -gt 0
        if (-not $via -and $rule -and $mode -ne 'exclude') { return [pscustomobject]@{ applies = $false; excluded = $false; uncertain = $true; via = 'AttributeFilter'; filter = $rule } }
        if (-not $via) { return $null }
        $uncertain = [bool]($rule -and $mode -eq 'exclude')
        return [pscustomobject]@{ applies = (-not $excluded); excluded = $excluded; uncertain = $uncertain; via = $via; filter = $(if ($uncertain) { $rule } else { $null }) }
    }
    $u = Get-WlProp $c 'users'
    if (-not $u) { return $null }
    $inc = @(@(Get-WlProp $u 'includeUsers') | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $exc = @(@(Get-WlProp $u 'excludeUsers') | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $via = $null
    if ($inc -contains 'allagentidusers') { $via = 'AllAgentUsers' }
    elseif (@($inc | Where-Object { $idSet -contains $_ }).Count) { $via = 'Direct' }
    if (-not $via) { return $null }
    $excluded = @($exc | Where-Object { $idSet -contains $_ }).Count -gt 0
    [pscustomobject]@{ applies = (-not $excluded); excluded = $excluded; uncertain = $false; via = $via; filter = $null }
}

function Get-WlAgentCaCoverage {
    # Status codes: Protected, ReportOnly, Excluded, Unclear, NotCovered, SecurityDefaults
    param([object[]]$Policies, [ValidateSet('Identity', 'User')][string]$Kind, [string[]]$Ids, [string]$DirectId, [bool]$SecurityDefaults)
    $hits = foreach ($p in @($Policies)) {
        $state = [string](Get-WlProp $p 'state')
        if ($state -eq 'disabled') { continue }
        $r = Test-WlCaAgentScope -Policy $p -Kind $Kind -Ids $Ids -DirectId $DirectId
        if (-not $r) { continue }
        $ctl = Get-WlCaControls -Policy $p
        [pscustomobject]@{
            id = [string]$p.id; name = [string]$p.displayName
            state = $(if ($state -eq 'enabled') { 'Enabled' } else { 'ReportOnly' })
            via = $r.via; filter = $r.filter; applies = $r.applies; excluded = $r.excluded; uncertain = $r.uncertain
            controls = $ctl.controls; operator = $ctl.operator; riskLevels = $ctl.riskLevels
        }
    }
    $hits = @($hits)
    $status = if ($SecurityDefaults) { 'SecurityDefaults' }
    elseif (@($hits | Where-Object { $_.applies -and $_.state -eq 'Enabled' }).Count) { 'Protected' }
    elseif (@($hits | Where-Object { $_.applies }).Count) { 'ReportOnly' }
    elseif (@($hits | Where-Object { $_.excluded -and $_.state -eq 'Enabled' }).Count) { 'Excluded' }
    elseif (@($hits | Where-Object { $_.uncertain }).Count) { 'Unclear' }
    else { 'NotCovered' }
    [pscustomobject]@{ status = $status; policies = $hits }
}

function Get-WlSponsorText {
    param($Object)
    @(@(Get-WlProp $Object 'sponsors') | Where-Object { $_ } | ForEach-Object { $n = [string](Get-WlProp $_ 'displayName'); $u = [string](Get-WlProp $_ 'userPrincipalName'); if ($u) { "$n ($u)" } elseif ($n) { $n } else { [string](Get-WlProp $_ 'id') } })
}

function ConvertFrom-WlJsonSafe {
    param([string]$Text)
    if (-not $Text -or $Text -in 'null', '[]', '{}') { return @() }
    try { @($Text | ConvertFrom-Json -Depth 10) } catch { @() }
}

function Get-WlLocalMcpInfo {
    # Normalises the MCP servers of a local agent: name, command and whether it is loaded unpinned from a public registry.
    param([string]$LocalMcps, [string]$McpServers)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($m in (ConvertFrom-WlJsonSafe $LocalMcps)) {
        if (-not $m) { continue }
        $cmd = [string](Get-WlProp $m 'commandName')
        $cmdArgs = @(Get-WlProp $m 'commandArgs') | ForEach-Object { [string]$_ }
        $line = (@($cmd) + $cmdArgs) -join ' '
        $unpinned = ($cmd -match '^(npx|uvx|pipx|bunx|pnpm|dlx)(\.cmd|\.exe)?$' -and ($line -match '@latest\b' -or $line -match '(^|\s)-y(\s|$)' -or $line -notmatch '@\d'))
        $out.Add([pscustomobject]@{ name = [string](Get-WlProp $m 'name'); kind = 'local'; command = $line; unpinned = [bool]$unpinned; endpoint = $null })
    }
    foreach ($m in (ConvertFrom-WlJsonSafe $McpServers)) {
        if (-not $m) { continue }
        $out.Add([pscustomobject]@{ name = [string](Get-WlProp $m 'name'); kind = [string](Get-WlProp $m 'type'); command = $null; unpinned = $false; endpoint = [string](Get-WlProp $m 'endpoint') })
    }
    $out.ToArray()
}

function Get-WlAgentInventory {
    <#
    .SYNOPSIS
    Merges Entra Agent ID, the Agent 365 registry and Defender AgentsInfo into one agent inventory and rates the
    Conditional Access coverage per agent identity and agent user. Local agents get device context instead.
    #>
    param($Directory, [object[]]$Registry, [object[]]$AgentsInfo, $Ca, [hashtable]$EndpointDevices = @{})
    $bpByApp = @{}; $bpById = @{}
    foreach ($b in $Directory.Blueprints) { $bpByApp[([string]$b.appId).ToLowerInvariant()] = $b; $bpById[([string]$b.id).ToLowerInvariant()] = $b }
    $bppByApp = @{}; foreach ($b in $Directory.BlueprintPrincipals) { $bppByApp[([string]$b.appId).ToLowerInvariant()] = $b }
    $userByParent = @{}; foreach ($u in $Directory.Users) { $k = ([string](Get-WlProp $u 'identityParentId')).ToLowerInvariant(); if ($k) { $userByParent[$k] = $u } }
    $regByIdentity = @{}; foreach ($r in @($Registry)) { $k = ([string](Get-WlProp $r 'agentIdentityId')).ToLowerInvariant(); if ($k) { $regByIdentity[$k] = $r } }
    $aiByEntra = @{}
    foreach ($a in @($AgentsInfo)) { $k = ([string](Get-WlProp $a 'EntraAgentID')).ToLowerInvariant(); if ($k) { $aiByEntra[$k] = $a } }

    $usedReg = @{}; $usedAi = @{}; $usedUsers = @{}
    $agents = [System.Collections.Generic.List[object]]::new()

    $newAgent = {
        param([string]$Name, [string]$Type)
        [ordered]@{
            name = $Name; agentType = $Type; sources = [System.Collections.Generic.List[string]]::new(); platform = $null
            blueprintAppId = $null; blueprintId = $null; blueprintName = $null; blueprintPrincipalId = $null; blueprintPublisher = $null
            agentId = $null; agentAppId = $null; agentEnabled = $null; disabledByMicrosoft = $null
            agentUserId = $null; agentUserUpn = $null; agentUserEnabled = $null
            sponsors = @(); owners = @(); created = $null; publishedStatus = $null; lifecycle = $null; registryId = $null; defenderAgentId = $null
            vendor = $null; version = $null; device = $null; user = $null; autoApprove = $null; trustedProcess = $null; process = $null; mcpServers = @()
            caIdentity = $null; caUser = $null
        }
    }

    foreach ($i in $Directory.Identities) {
        $a = & $newAgent ([string]$i.displayName) 'Cloud'
        $a.sources.Add('EntraAgentId')
        $a.agentId = [string]$i.id; $a.agentAppId = [string]$i.appId; $a.agentEnabled = [bool](Get-WlProp $i 'accountEnabled')
        $a.disabledByMicrosoft = [string](Get-WlProp $i 'disabledByMicrosoftStatus')
        $a.created = [string](Get-WlProp $i 'createdDateTime')
        $a.sponsors = @(Get-WlSponsorText $i)
        $bpApp = ([string](Get-WlProp $i 'agentIdentityBlueprintId')).ToLowerInvariant()
        $a.blueprintAppId = [string](Get-WlProp $i 'agentIdentityBlueprintId')
        if ($bpApp -and $bpByApp.ContainsKey($bpApp)) { $b = $bpByApp[$bpApp]; $a.blueprintId = [string]$b.id; $a.blueprintName = [string]$b.displayName; $a.blueprintPublisher = [string](Get-WlProp $b 'publisherDomain') }
        if ($bpApp -and $bppByApp.ContainsKey($bpApp)) { $bp = $bppByApp[$bpApp]; $a.blueprintPrincipalId = [string]$bp.id; if (-not $a.blueprintName) { $a.blueprintName = [string]$bp.displayName } }
        $u = $userByParent[([string]$i.id).ToLowerInvariant()]
        if ($u) { $usedUsers[[string]$u.id] = $true; $a.agentUserId = [string]$u.id; $a.agentUserUpn = [string]$u.userPrincipalName; $a.agentUserEnabled = [bool](Get-WlProp $u 'accountEnabled') }
        $r = $regByIdentity[([string]$i.id).ToLowerInvariant()]
        if ($r) { $usedReg[[string]$r.id] = $true; $a.sources.Add('Agent365Registry'); $a.registryId = [string]$r.id; $a.platform = [string](Get-WlProp $r 'originatingStore'); $a.owners = @(Get-WlProp $r 'ownerIds') }
        $ai = $aiByEntra[([string]$i.id).ToLowerInvariant()]
        if (-not $ai) { $ai = $aiByEntra[([string]$i.appId).ToLowerInvariant()] }
        if ($ai) { $usedAi[[string]$ai.AgentId] = $true; $a.sources.Add('DefenderAgentsInfo'); $a.defenderAgentId = [string]$ai.AgentId; if (-not $a.platform) { $a.platform = [string]$ai.Platform }; $a.publishedStatus = [string]$ai.PublishedStatus; $a.lifecycle = [string]$ai.LifecycleStatus }
        if (-not $a.platform) { $a.platform = 'Entra Agent ID' }
        $agents.Add($a)
    }

    # Registry entries without an Entra agent identity
    foreach ($r in @($Registry)) {
        if (-not $r -or $usedReg.ContainsKey([string]$r.id)) { continue }
        $a = & $newAgent ([string]$r.displayName) 'Cloud'
        $a.sources.Add('Agent365Registry'); $a.registryId = [string]$r.id; $a.platform = [string](Get-WlProp $r 'originatingStore')
        $a.owners = @(Get-WlProp $r 'ownerIds'); $a.created = [string](Get-WlProp $r 'createdDateTime')
        $bpObj = ([string](Get-WlProp $r 'agentIdentityBlueprintId')).ToLowerInvariant()
        if ($bpObj -and $bpById.ContainsKey($bpObj)) { $b = $bpById[$bpObj]; $a.blueprintId = [string]$b.id; $a.blueprintAppId = [string]$b.appId; $a.blueprintName = [string]$b.displayName }
        $uid = [string](Get-WlProp $r 'agentUserId')
        if ($uid) { $a.agentUserId = $uid; $u = @($Directory.Users | Where-Object { $_.id -eq $uid })[0]; if ($u) { $usedUsers[$uid] = $true; $a.agentUserUpn = [string]$u.userPrincipalName; $a.agentUserEnabled = [bool](Get-WlProp $u 'accountEnabled') } }
        $ai = @($AgentsInfo | Where-Object { $_ -and ([string]$_.AgentId -eq [string]$r.id -or ([string]$_.SourceAgentId -and [string]$_.SourceAgentId -eq [string](Get-WlProp $r 'sourceAgentId'))) })[0]
        if ($ai) { $usedAi[[string]$ai.AgentId] = $true; $a.sources.Add('DefenderAgentsInfo'); $a.defenderAgentId = [string]$ai.AgentId; $a.publishedStatus = [string]$ai.PublishedStatus; $a.lifecycle = [string]$ai.LifecycleStatus }
        $agents.Add($a)
    }

    # Defender inventory without an Entra agent identity: cloud agents and local agents on endpoints
    foreach ($ai in @($AgentsInfo)) {
        if (-not $ai -or $usedAi.ContainsKey([string]$ai.AgentId)) { continue }
        $isLocal = [string](Get-WlProp $ai 'IsLocal') -match '^(true|1)$'
        $a = & $newAgent ([string]$ai.Name) $(if ($isLocal) { 'Local' } else { 'Cloud' })
        $a.sources.Add('DefenderAgentsInfo'); $a.defenderAgentId = [string]$ai.AgentId; $a.platform = [string]$ai.Platform
        $a.publishedStatus = [string]$ai.PublishedStatus; $a.lifecycle = [string]$ai.LifecycleStatus; $a.created = [string]$ai.CreatedDateTime
        $a.version = [string](Get-WlProp $ai 'Version')
        if ([string]$ai.EntraBlueprintID) { $a.blueprintAppId = [string]$ai.EntraBlueprintID }
        if ($isLocal) {
            $devId = [string](Get-WlProp $ai 'LocalDeviceId')
            $ep = if ($devId -and $EndpointDevices.ContainsKey($devId)) { $EndpointDevices[$devId] } else { $null }
            $a.vendor = [string](Get-WlProp $ai 'Vendor')
            $a.user = [string](Get-WlProp $ai 'LocalUser')
            $a.autoApprove = ([string](Get-WlProp $ai 'AutoApprove')) -match '^(true|1)$'
            $tp = [string](Get-WlProp $ai 'TrustedProcess')
            $a.trustedProcess = if ($tp) { $tp -match '^(true|1)$' } else { $null }
            $a.process = [string](Get-WlProp $ai 'Process')
            $a.mcpServers = @(Get-WlLocalMcpInfo -LocalMcps ([string](Get-WlProp $ai 'LocalMcps')) -McpServers ([string](Get-WlProp $ai 'McpServers')))
            $a.device = [ordered]@{
                id = $devId; name = [string](Get-WlProp $ai 'LocalDeviceName'); os = [string](Get-WlProp $ai 'LocalOs')
                group = $(if ($ep) { [string]$ep.deviceGroup } else { $null })
                tamper = $(if ($ep) { [string](Get-WlProp $ep.checks 'TamperProtection') } else { $null })
                localExclusions = $(if ($ep) { [int]$ep.localExclusions } else { $null })
                asrBelowMinimum = $(if ($ep) { $ep.asrBelowMinimum } else { $null })
                avMode = $(if ($ep) { [string]$ep.avModeText } else { $null })
            }
        }
        $agents.Add($a)
    }

    # Agent users without an agent identity (orphaned)
    foreach ($u in $Directory.Users) {
        if ($usedUsers.ContainsKey([string]$u.id)) { continue }
        $a = & $newAgent ([string]$u.displayName) 'Cloud'
        $a.sources.Add('EntraAgentId'); $a.platform = 'Entra Agent ID'
        $a.agentUserId = [string]$u.id; $a.agentUserUpn = [string]$u.userPrincipalName; $a.agentUserEnabled = [bool](Get-WlProp $u 'accountEnabled')
        $a.sponsors = @(Get-WlSponsorText $u); $a.created = [string](Get-WlProp $u 'createdDateTime')
        $agents.Add($a)
    }

    # Conditional Access and drift keys
    foreach ($a in $agents) {
        if ($a.agentType -eq 'Local') { $a.caIdentity = [pscustomobject]@{ status = 'UserContext'; policies = @() } }
        elseif ($a.agentId) {
            $ids = @($a.agentId, $a.blueprintId, $a.blueprintAppId, $a.blueprintPrincipalId)
            $a.caIdentity = Get-WlAgentCaCoverage -Policies $Ca.Policies -Kind Identity -Ids $ids -DirectId $a.agentId -SecurityDefaults $Ca.SecurityDefaults
        }
        elseif ($a.agentUserId) { $a.caIdentity = [pscustomobject]@{ status = 'IdentityMissing'; policies = @() } }
        else { $a.caIdentity = [pscustomobject]@{ status = 'NoAgentId'; policies = @() } }
        if ($a.agentUserId) { $a.caUser = Get-WlAgentCaCoverage -Policies $Ca.Policies -Kind User -Ids @($a.agentUserId) -DirectId $a.agentUserId -SecurityDefaults $Ca.SecurityDefaults }

        $a.key = Get-WlHash "agent|$(if ($a.agentId) { $a.agentId } elseif ($a.registryId) { "reg:$($a.registryId)" } elseif ($a.defenderAgentId) { "mde:$($a.defenderAgentId)" } else { "user:$($a.agentUserId)" })"
        $where = if ($a.device) { " @ $($a.device.name)" } else { '' }
        $a.label = New-WlText "$($a.agentType) agent $($a.name)$where" "$(if ($a.agentType -eq 'Local') { 'Lokaler' } else { 'Cloud-' })Agent $($a.name)$where"
        $a.state = if ($a.agentType -eq 'Local') { "autoApprove=$($a.autoApprove); mcp=$(@($a.mcpServers).Count)" } else { "agent=$($a.caIdentity.status)$(if ($a.caUser) { "; agentUser=$($a.caUser.status)" })" }
        $a.fp = Get-WlHash "$($a.state)|$($a.agentEnabled)|$($a.agentUserEnabled)|$(@($a.sponsors) -join ',')|$($a.blueprintAppId)|$($a.version)"
        $a.sources = @($a.sources | Select-Object -Unique)
    }
    @($agents | ForEach-Object { [pscustomobject]$_ })
}

function Get-WlAgentPolicySummary {
    # CA policies that target agents – with target, effect and the number of agents they actually cover.
    param([object[]]$Policies, [object[]]$Agents)
    $out = foreach ($p in @($Policies)) {
        $c = Get-WlProp $p 'conditions'
        $ca = Get-WlProp $c 'clientApplications'; $u = Get-WlProp $c 'users'
        $inc = @(Get-WlProp $ca 'includeAgentIdServicePrincipals') | Where-Object { $_ }
        $exc = @(Get-WlProp $ca 'excludeAgentIdServicePrincipals') | Where-Object { $_ }
        $flt = [string](Get-WlProp (Get-WlProp $ca 'agentIdServicePrincipalFilter') 'rule')
        $incU = @(Get-WlProp $u 'includeUsers') | Where-Object { $_ }
        $someUsers = @($incU | Where-Object { $id = $_; @($Agents | Where-Object { $_.agentUserId -eq $id }).Count }).Count
        if (-not $inc -and -not $flt -and -not ($incU -contains 'AllAgentIdUsers') -and -not $someUsers) { continue }
        # Targets as codes: AllAgentIdentities | SomeAgentIdentities(count) | AttributeFilter(rule) | AllAgentUsers | SomeAgentUsers(count)
        $targets = @()
        if ($inc -contains 'All') { $targets += [pscustomobject]@{ code = 'AllAgentIdentities' } } elseif ($inc) { $targets += [pscustomobject]@{ code = 'SomeAgentIdentities'; count = @($inc).Count } }
        if ($flt) { $targets += [pscustomobject]@{ code = 'AttributeFilter'; rule = $flt } }
        if ($incU -contains 'AllAgentIdUsers') { $targets += [pscustomobject]@{ code = 'AllAgentUsers' } } elseif ($someUsers) { $targets += [pscustomobject]@{ code = 'SomeAgentUsers'; count = $someUsers } }
        $apps = Get-WlProp $c 'applications'
        $incApps = @(Get-WlProp $apps 'includeApplications') | Where-Object { $_ }
        $resources = if ($incApps -contains 'All') { 'All' } elseif ($incApps -contains 'AllAgentIdResources') { 'AllAgentResources' } elseif ($incApps) { "$(@($incApps).Count)" } else { $null }
        $state = switch ([string]$p.state) { 'enabled' { 'Enabled' } 'enabledForReportingButNotEnforced' { 'ReportOnly' } default { 'Disabled' } }
        $ctl = Get-WlCaControls -Policy $p
        $covId = @($Agents | Where-Object { $_.caIdentity -and @($_.caIdentity.policies | Where-Object { $_.id -eq $p.id -and $_.applies }).Count }).Count
        $covUser = @($Agents | Where-Object { $_.caUser -and @($_.caUser.policies | Where-Object { $_.id -eq $p.id -and $_.applies }).Count }).Count
        [pscustomobject]@{
            key = Get-WlHash "capol|$($p.id)"
            fp = Get-WlHash "$state|$(@($inc) -join ',')|$(@($exc) -join ',')|$flt|$(@($incU) -join ',')|$($ctl.controls -join ',')|$($ctl.riskLevels -join ',')"
            label = New-WlText "CA policy $($p.displayName)" "CA-Richtlinie $($p.displayName)"
            state = $state
            id = [string]$p.id; name = [string]$p.displayName
            targets = $targets; excludes = @($exc).Count; resources = $resources
            controls = $ctl.controls; operator = $ctl.operator; riskLevels = $ctl.riskLevels
            coveredIdentities = $covId; coveredUsers = $covUser
            modified = [string](Get-WlProp $p 'modifiedDateTime')
        }
    }
    @($out)
}

function Get-WlAgentFindings {
    param([object[]]$Agents, [object[]]$PolicySummary, [bool]$SecurityDefaults)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-WlText -En $en -De $de }
    $cloud = @($Agents | Where-Object { $_.agentType -ne 'Local' })
    $withId = @($cloud | Where-Object { $_.agentId })
    $withUser = @($cloud | Where-Object { $_.agentUserId })
    $names = { param($pols, $filter) (@($pols | Where-Object $filter | ForEach-Object { $_.name }) -join ', ') }

    if ($SecurityDefaults -and ($withId.Count -or $withUser.Count)) {
        $f.Add((New-WlFinding -Severity 'Medium' -Category 'ConditionalAccess' -Title (& $T 'Security defaults enabled – Conditional Access is not evaluated' 'Sicherheitsstandards aktiv – Conditional Access greift nicht') `
                    -Detail (& $T 'While security defaults are enabled, no Conditional Access policies are evaluated – not for agents either.' 'Solange die Sicherheitsstandards (Security Defaults) aktiv sind, werden keine Conditional-Access-Richtlinien ausgewertet – auch nicht für Agents.') `
                    -Recommendation (& $T 'Move to Conditional Access and create policies for agent identities and agent users.' 'Auf Conditional Access umstellen und Richtlinien für Agent-Identitäten und Agent-User anlegen.') -Subject 'secdefaults'))
    }
    $activeId = @($PolicySummary | Where-Object { $_.state -eq 'Enabled' -and @($_.targets | Where-Object { $_.code -in 'AllAgentIdentities', 'SomeAgentIdentities', 'AttributeFilter' }).Count })
    $activeUser = @($PolicySummary | Where-Object { $_.state -eq 'Enabled' -and @($_.targets | Where-Object { $_.code -in 'AllAgentUsers', 'SomeAgentUsers' }).Count })
    if ($withId.Count -and -not $activeId.Count -and -not $SecurityDefaults) {
        $f.Add((New-WlFinding -Severity 'High' -Category 'ConditionalAccess' -Title (& $T 'No enabled Conditional Access policy for agent identities' 'Keine aktive Conditional-Access-Richtlinie für Agent-Identitäten') `
                    -Detail (& $T "The tenant has $($withId.Count) agent identit(ies) but no enabled policy targets agent identities. Policies for users or workload identities do not apply to agents." "Im Mandanten gibt es $($withId.Count) Agent-Identität(en), aber keine aktive Richtlinie, die Agent-Identitäten adressiert. Richtlinien für Benutzer oder Workload-Identitäten gelten nicht für Agents.") `
                    -Recommendation (& $T 'At minimum: block "All agent identities" except approved blueprints/agents (via custom security attributes) and block high-risk agents.' 'Mindestens: „Alle Agent-Identitäten“ blockieren außer freigegebenen Blueprints/Agents (per Custom Security Attribute) und Agents mit hohem Risiko blockieren.') -Subject 'no-ca-identity'))
    }
    if ($withUser.Count -and -not $activeUser.Count -and -not $SecurityDefaults) {
        $f.Add((New-WlFinding -Severity 'High' -Category 'ConditionalAccess' -Title (& $T 'No enabled Conditional Access policy for agent users' 'Keine aktive Conditional-Access-Richtlinie für Agent-User') `
                    -Detail (& $T "The tenant has $($withUser.Count) agent user(s). Policies for ""All users"" and group assignments do not apply to agent users – they must be targeted via ""All agent users"" or individually." "Im Mandanten gibt es $($withUser.Count) Agent-User. Richtlinien für „Alle Benutzer“ und Gruppen-Zuweisungen gelten für Agent-User nicht – sie müssen über „Alle Agent-User“ bzw. einzeln adressiert werden.") `
                    -Recommendation (& $T 'Create a policy for "All agent users" (e.g. block risky agent users, require a compliant device/network).' 'Richtlinie für „Alle Agent-User“ anlegen (z. B. riskante Agent-User blockieren, konformes Gerät/Netzwerk verlangen).') -Subject 'no-ca-user'))
    }

    foreach ($a in $cloud) {
        $id = if ($a.agentId) { $a.agentId } elseif ($a.registryId) { $a.registryId } else { $a.defenderAgentId }
        if ($a.agentId -and $a.agentEnabled) {
            switch ($a.caIdentity.status) {
                'NotCovered' { if ($activeId.Count) { $f.Add((New-WlFinding -Severity 'High' -Category 'ConditionalAccess' -Title (& $T "Agent without Conditional Access: $($a.name)" "Agent ohne Conditional Access: $($a.name)") -Detail (& $T "Agent identity $($a.agentId) (blueprint $($a.blueprintAppId)) is not covered by any Conditional Access policy." "Die Agent-Identität $($a.agentId) (Blueprint $($a.blueprintAppId)) wird von keiner Conditional-Access-Richtlinie erfasst.") -Recommendation (& $T 'Add the agent or its blueprint to an agent policy, or classify it with a custom security attribute.' 'Agent bzw. Blueprint in eine Agent-Richtlinie aufnehmen oder per Custom Security Attribute klassifizieren.') -Subject "ca-id|$id")) } }
                'ReportOnly' { $n = & $names $a.caIdentity.policies { $_.applies }; $f.Add((New-WlFinding -Severity 'Medium' -Category 'ConditionalAccess' -Title (& $T "Agent covered by report-only policies only: $($a.name)" "Agent nur durch Report-only-Richtlinien erfasst: $($a.name)") -Detail (& $T "Policies: $n. Report-only only logs." "Richtlinien: $n. Report-only protokolliert nur.") -Recommendation (& $T 'Review the sign-in logs of the agent identity and enable the policy.' 'Sign-in-Logs der Agent-Identität prüfen und Richtlinie aktivieren.') -Subject "ca-ro|$id")) }
                'Excluded' { $n = & $names $a.caIdentity.policies { $_.excluded }; $f.Add((New-WlFinding -Severity 'Medium' -Category 'ConditionalAccess' -Title (& $T "Agent excluded from Conditional Access: $($a.name)" "Agent von Conditional Access ausgenommen: $($a.name)") -Detail (& $T "Excluded in: $n." "Ausgenommen in: $n.") -Recommendation (& $T 'Justify and document the exclusion or remove it.' 'Ausnahme begründen und dokumentieren oder entfernen.') -Subject "ca-ex|$id")) }
                'Unclear' { $n = & $names $a.caIdentity.policies { $true }; $f.Add((New-WlFinding -Severity 'Low' -Category 'ConditionalAccess' -Title (& $T "Coverage by attribute filter cannot be verified: $($a.name)" "Abdeckung per Attributfilter nicht prüfbar: $($a.name)") -Detail (& $T "The policies $n select agents by custom security attributes. Whether this agent is covered depends on its attributes." "Die Richtlinien $n wählen Agents über Custom Security Attributes aus. Ob dieser Agent erfasst wird, hängt von seinen Attributen ab.") -Recommendation (& $T "Check the agent's custom security attributes." 'Custom Security Attributes des Agents prüfen.') -Subject "ca-flt|$id")) }
            }
        }
        if ($a.agentUserId -and $a.agentUserEnabled -and $a.caUser) {
            switch ($a.caUser.status) {
                'NotCovered' { if ($activeUser.Count) { $f.Add((New-WlFinding -Severity 'High' -Category 'ConditionalAccess' -Title (& $T "Agent user without Conditional Access: $($a.agentUserUpn)" "Agent-User ohne Conditional Access: $($a.agentUserUpn)") -Detail (& $T "The agent user of '$($a.name)' is not covered by any policy. ""All users"" does not include agent users." "Der Agent-User von '$($a.name)' wird von keiner Richtlinie erfasst. „Alle Benutzer“ schließt Agent-User nicht ein.") -Recommendation (& $T 'Include agent users via "All agent users" or individually.' 'Agent-User über „Alle Agent-User“ oder einzeln in eine Richtlinie aufnehmen.') -Subject "ca-user|$($a.agentUserId)")) } }
                'ReportOnly' { $n = & $names $a.caUser.policies { $_.applies }; $f.Add((New-WlFinding -Severity 'Medium' -Category 'ConditionalAccess' -Title (& $T "Agent user covered by report-only policies only: $($a.agentUserUpn)" "Agent-User nur durch Report-only-Richtlinien erfasst: $($a.agentUserUpn)") -Detail (& $T "Policies: $n." "Richtlinien: $n.") -Recommendation (& $T 'Enable the policy after evaluation.' 'Richtlinie nach Auswertung aktivieren.') -Subject "ca-user-ro|$($a.agentUserId)")) }
                'Excluded' { $n = & $names $a.caUser.policies { $_.excluded }; $f.Add((New-WlFinding -Severity 'Medium' -Category 'ConditionalAccess' -Title (& $T "Agent user excluded from Conditional Access: $($a.agentUserUpn)" "Agent-User von Conditional Access ausgenommen: $($a.agentUserUpn)") -Detail (& $T "Excluded in: $n." "Ausgenommen in: $n.") -Recommendation (& $T 'Justify the exclusion or remove it.' 'Ausnahme begründen oder entfernen.') -Subject "ca-user-ex|$($a.agentUserId)")) }
            }
        }
        if ($a.agentId -and -not @($a.sponsors).Count) {
            $f.Add((New-WlFinding -Severity 'Medium' -Category 'Accountability' -Title (& $T "Agent without sponsor: $($a.name)" "Agent ohne Sponsor: $($a.name)") -Detail (& $T 'No sponsor (accountable person or group) is set for the agent identity. Without a sponsor there is no recertification and no contact.' 'Für die Agent-Identität ist kein Sponsor (verantwortliche Person oder Gruppe) hinterlegt. Ohne Sponsor fehlen Rezertifizierung und Ansprechpartner.') -Recommendation (& $T 'Set a sponsor in Entra (Agent ID).' 'Sponsor in Entra (Agent ID) setzen.') -Subject "sponsor|$id"))
        }
        if ($a.disabledByMicrosoft -and $a.disabledByMicrosoft -ne 'NotDisabled') {
            $f.Add((New-WlFinding -Severity 'High' -Category 'Agent' -Title (& $T "Agent disabled by Microsoft: $($a.name)" "Agent von Microsoft deaktiviert: $($a.name)") -Detail (& $T "Status: $($a.disabledByMicrosoft)." "Status: $($a.disabledByMicrosoft).") -Recommendation (& $T 'Investigate the agent and inform the owners.' 'Agent untersuchen und Verantwortliche informieren.') -Subject "msdisabled|$id"))
        }
        if ($a.agentId -and $a.blueprintAppId -and -not $a.blueprintName) {
            $f.Add((New-WlFinding -Severity 'Low' -Category 'Agent' -Title (& $T "Blueprint unknown in this tenant: $($a.name)" "Blueprint im Mandanten unbekannt: $($a.name)") -Detail (& $T "The agent identity references blueprint $($a.blueprintAppId), which is visible neither as a blueprint nor as a blueprint principal." "Die Agent-Identität verweist auf Blueprint $($a.blueprintAppId), der weder als Blueprint noch als Blueprint-Principal sichtbar ist.") -Recommendation (& $T 'Check where the agent comes from (third-party blueprint?).' 'Herkunft des Agents prüfen (Drittanbieter-Blueprint?).') -Subject "bp|$id"))
        }
        if (-not $a.agentId -and $a.agentUserId) {
            $f.Add((New-WlFinding -Severity 'Medium' -Category 'Agent' -Title (& $T "Orphaned agent user: $($a.agentUserUpn)" "Verwaister Agent-User: $($a.agentUserUpn)") -Detail (& $T 'There is no (longer an) agent identity for this agent user. Orphaned accounts keep their permissions and licences.' 'Zu diesem Agent-User gibt es keine Agent-Identität (mehr). Verwaiste Konten behalten ihre Rechte und Lizenzen.') -Recommendation (& $T 'Disable or delete the agent user if the agent no longer exists.' 'Agent-User deaktivieren bzw. löschen, wenn der Agent nicht mehr existiert.') -Subject "orphan|$($a.agentUserId)"))
        }
        if (-not $a.agentId -and -not $a.agentUserId) {
            $f.Add((New-WlFinding -Severity 'Low' -Category 'Agent' -Title (& $T "Cloud agent without Entra Agent ID: $($a.name)" "Cloud-Agent ohne Entra Agent ID: $($a.name)") -Detail (& $T "Platform: $($a.platform). Without an agent identity neither Conditional Access nor Identity Protection applies to this agent; it uses the user's identity or its own credentials." "Plattform: $($a.platform). Ohne Agent-Identität greifen weder Conditional Access noch Identity Protection für diesen Agent; er nutzt die Identität des Benutzers oder eigene Anmeldedaten.") -Recommendation (& $T 'Check whether the agent can be moved to Entra Agent ID.' 'Prüfen, ob der Agent auf Entra Agent ID umgestellt werden kann.') -Subject "noid|$id"))
        }
    }

    # Local agents (endpoints)
    foreach ($a in @($Agents | Where-Object { $_.agentType -eq 'Local' })) {
        $dev = if ($a.device) { $a.device.name } else { '?' }
        $subj = "local|$($a.defenderAgentId)"
        if ($a.autoApprove) {
            $f.Add((New-WlFinding -Severity 'High' -Category 'LocalAgent' -Title (& $T "Local agent runs actions without confirmation: $($a.name)" "Lokaler Agent führt Aktionen ohne Bestätigung aus: $($a.name)") `
                        -Detail (& $T "$($a.name) on $dev ($($a.user)) has auto-approve enabled: tool calls, shell commands and file changes run without the user confirming them." "$($a.name) auf $dev ($($a.user)) hat Auto-Approve aktiviert: Tool-Aufrufe, Shell-Befehle und Dateiänderungen laufen ohne Bestätigung durch den Benutzer.") `
                        -Recommendation (& $T 'Disable auto-approve or restrict it to read-only tools; enforce this through the vendor''s managed settings.' 'Auto-Approve abschalten oder auf lesende Werkzeuge beschränken; über die verwalteten Einstellungen des Herstellers erzwingen.') -Subject "$subj|auto" -DeviceId $a.device.id -DeviceName $dev))
        }
        $unpinned = @($a.mcpServers | Where-Object { $_.unpinned })
        if ($unpinned.Count) {
            $list = ($unpinned | ForEach-Object { "$($_.name) ($($_.command))" }) -join '; '
            $f.Add((New-WlFinding -Severity 'Medium' -Category 'LocalAgent' -Title (& $T "MCP server loaded unpinned from a public registry: $($a.name)" "MCP-Server ohne feste Version aus öffentlicher Paketquelle: $($a.name)") `
                        -Detail (& $T "On $dev the agent starts MCP servers that are downloaded at run time without a pinned version: $list. A compromised package update runs immediately with the user's rights." "Auf $dev startet der Agent MCP-Server, die zur Laufzeit ohne feste Version geladen werden: $list. Ein kompromittiertes Paket-Update läuft sofort mit den Rechten des Benutzers.") `
                        -Recommendation (& $T 'Pin MCP servers to a version (or install them from an internal registry) and allow-list approved servers.' 'MCP-Server auf eine Version festlegen (bzw. aus interner Paketquelle installieren) und freigegebene Server per Allow-List erzwingen.') -Subject "$subj|mcp" -DeviceId $a.device.id -DeviceName $dev))
        }
        if ($a.trustedProcess -eq $false) {
            $f.Add((New-WlFinding -Severity 'Medium' -Category 'LocalAgent' -Title (& $T "Local agent from an untrusted process: $($a.name)" "Lokaler Agent aus nicht vertrauenswürdigem Prozess: $($a.name)") `
                        -Detail (& $T "Defender does not classify the process '$($a.process)' on $dev as trusted." "Defender stuft den Prozess '$($a.process)' auf $dev nicht als vertrauenswürdig ein.") `
                        -Recommendation (& $T 'Verify the origin and signature of the agent; block it if it is not approved.' 'Herkunft und Signatur des Agents prüfen; nicht freigegebene Agents blockieren.') -Subject "$subj|trust" -DeviceId $a.device.id -DeviceName $dev))
        }
        $d = $a.device
        if ($d -and ($d.tamper -eq 'BAD' -or [int]$d.localExclusions -gt 0)) {
            $why = @()
            if ($d.tamper -eq 'BAD') { $why += , @('Tamper Protection off', 'Tamper Protection aus') }
            if ([int]$d.localExclusions -gt 0) { $why += , @("$($d.localExclusions) local exclusion(s)", "$($d.localExclusions) lokale Exclusion(s)") }
            $f.Add((New-WlFinding -Severity $(if ($a.autoApprove) { 'Critical' } else { 'High' }) -Category 'Combined' -Title (& $T "Local agent on a weakened device: $($a.name)" "Lokaler Agent auf geschwächtem Gerät: $($a.name)") `
                        -Detail (& $T "$($a.name) runs on $dev, which has: $(($why | ForEach-Object { $_[0] }) -join ', ')$(if ($a.autoApprove) { ', and the agent runs actions without confirmation' }). Whatever the agent downloads or executes may not be detected." `
                            "$($a.name) läuft auf $dev mit: $(($why | ForEach-Object { $_[1] }) -join ', ')$(if ($a.autoApprove) { ', und der Agent führt Aktionen ohne Bestätigung aus' }). Was der Agent lädt oder ausführt, wird unter Umständen nicht erkannt.") `
                        -Recommendation (& $T 'Fix the device first (Tamper Protection, remove local exclusions), then allow the agent again.' 'Zuerst das Gerät absichern (Tamper Protection, lokale Exclusions entfernen), dann den Agent wieder zulassen.') -Subject "$subj|device" -DeviceId $d.id -DeviceName $dev))
        }
    }
    @($f | Sort-Object { $script:WlSeverityOrder[$_.severity] }, category, { Get-WlProp $_.title 'en' })
}

function Invoke-WlAgentsCollection {
    <#
    .SYNOPSIS
    Full run of the agents module; writes the snapshot and drift to storage.
    #>
    Reset-WlWarnings
    $started = [DateTime]::UtcNow
    Write-Information "Wardline agents: start $($started.ToString('o'))" -InformationAction Continue

    $dir = Get-WlAgentDirectory
    $reg = Get-WlAgentRegistry
    $ai = Get-WlAgentsInfo
    $ca = Get-WlCaPolicies

    # Device state from the endpoint module (latest snapshot) for local agents
    $epDevices = @{}
    try {
        $ep = Get-WlBlob -Container 'state' -Name 'endpoint-latest.json'
        foreach ($d in @(Get-WlProp $ep 'devices')) { if ($d -and $d.deviceId) { $epDevices[[string]$d.deviceId] = $d } }
    }
    catch { }

    $agents = Get-WlAgentInventory -Directory $dir -Registry $reg -AgentsInfo $ai -Ca $ca -EndpointDevices $epDevices
    $policies = Get-WlAgentPolicySummary -Policies $ca.Policies -Agents $agents
    $findings = Get-WlAgentFindings -Agents $agents -PolicySummary $policies -SecurityDefaults $ca.SecurityDefaults

    $blueprints = foreach ($b in $dir.Blueprints) {
        $n = @($agents | Where-Object { $_.blueprintAppId -eq $b.appId }).Count
        [pscustomobject]@{ key = Get-WlHash "bp|$($b.id)"; fp = Get-WlHash "$($b.displayName)|$n"; label = New-WlText "Blueprint $($b.displayName)" "Blueprint $($b.displayName)"; state = "$n agent(s)"
            id = [string]$b.id; appId = [string]$b.appId; name = [string]$b.displayName; publisher = [string](Get-WlProp $b 'publisherDomain'); agents = $n
            hasPrincipal = [bool]$(@($dir.BlueprintPrincipals | Where-Object { $_.appId -eq $b.appId }).Count); created = [string](Get-WlProp $b 'createdDateTime') }
    }
    $sevCount = [ordered]@{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $sevCount[$s] = @($findings | Where-Object { $_.severity -eq $s }).Count }
    $cloud = @($agents | Where-Object { $_.agentType -ne 'Local' })
    $local = @($agents | Where-Object { $_.agentType -eq 'Local' })
    $snapshot = [ordered]@{
        module           = 'agents'
        version          = (Get-WlVersion)
        generatedAt      = [DateTime]::UtcNow.ToString('o')
        tenantId         = Get-WlSetting -Name 'WL_TENANT_ID'
        securityDefaults = $ca.SecurityDefaults
        summary          = [ordered]@{
            agents            = @($agents).Count
            cloudAgents       = $cloud.Count
            localAgents       = $local.Count
            localDevices      = @($local | ForEach-Object { $_.device.id } | Where-Object { $_ } | Select-Object -Unique).Count
            localAutoApprove  = @($local | Where-Object { $_.autoApprove }).Count
            withEntraId       = @($cloud | Where-Object { $_.agentId }).Count
            agentUsers        = @($cloud | Where-Object { $_.agentUserId }).Count
            blueprints        = @($dir.Blueprints).Count
            identitiesCovered = @($cloud | Where-Object { $_.caIdentity.status -eq 'Protected' }).Count
            identitiesOpen    = @($cloud | Where-Object { $_.agentId -and $_.caIdentity.status -ne 'Protected' }).Count
            usersCovered      = @($cloud | Where-Object { $_.caUser -and $_.caUser.status -eq 'Protected' }).Count
            usersOpen         = @($cloud | Where-Object { $_.caUser -and $_.caUser.status -ne 'Protected' }).Count
            withoutEntraId    = @($cloud | Where-Object { -not $_.agentId -and -not $_.agentUserId }).Count
            caPolicies        = @($policies).Count
            findings          = $sevCount
        }
        agents           = @($agents)
        blueprints       = @($blueprints)
        policies         = @($policies)
        findings         = @($findings)
        warnings         = @(Get-WlWarnings)
    }
    $r = Save-WlSnapshot -Module 'agents' -Snapshot $snapshot -Collections @('agents', 'blueprints', 'policies', 'findings') -Started $started
    Write-Information "Wardline agents: done, $($r.changes) change(s), $($r.warnings) warning(s)." -InformationAction Continue
    $r
}
