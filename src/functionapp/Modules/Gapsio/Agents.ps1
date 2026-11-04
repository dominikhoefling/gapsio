# Gapsio Agents: inventory of AI agents and their protection.
#
# Cloud agents (Copilot Studio, Azure AI Foundry, custom) – sources: Microsoft Entra Agent ID, the Agent 365 package catalog
# (Package Management API, v1.0 copilot/admin/catalog/packages; legacy beta agentRegistry as fallback) and Defender AgentsInfo.
# Rated by Conditional Access coverage, separately for the agent identity and the agent user.
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

function Get-GapsioGraphListExpand {
    # Load a list with $expand=sponsors; if that fails (older API versions), retry without expand.
    param([string]$Path, [string]$Context)
    $expand = "$Path&`$expand=sponsors(`$select=id,displayName,userPrincipalName)"
    try { return @(Invoke-GapsioGraph -All -Path $expand) } catch { }
    try { return @(Invoke-GapsioGraph -Beta -All -Path $expand) } catch { }
    @(Invoke-GapsioGraphV1First -All -Path $Path -Context $Context)
}

function Get-GapsioAgentDirectory {
    $bp = Invoke-GapsioGraphV1First -All -Context 'Agent identity blueprints (AgentIdentityBlueprint.Read.All)' `
        -Path 'applications/microsoft.graph.agentIdentityBlueprint?$select=id,appId,displayName,createdDateTime,publisherDomain,signInAudience'
    $bpp = Invoke-GapsioGraphV1First -All -Context 'Blueprint principals (AgentIdentityBlueprintPrincipal.Read.All)' `
        -Path 'servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?$select=id,appId,displayName,accountEnabled,appOwnerOrganizationId,createdDateTime'
    $ids = Get-GapsioGraphListExpand -Context 'Agent identities (AgentIdentity.Read.All)' `
        -Path 'servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,displayName,accountEnabled,agentIdentityBlueprintId,createdByAppId,createdDateTime,disabledByMicrosoftStatus'
    $users = Get-GapsioGraphListExpand -Context 'Agent users' `
        -Path 'users/microsoft.graph.agentUser?$select=id,displayName,userPrincipalName,accountEnabled,identityParentId,createdDateTime'
    [pscustomobject]@{
        Blueprints          = @($bp | Where-Object { $_ })
        BlueprintPrincipals = @($bpp | Where-Object { $_ })
        Identities          = @($ids | Where-Object { $_ })
        Users               = @($users | Where-Object { $_ })
    }
}

$script:GapsioAgentRegistryStatus = 'Unknown'
$script:GapsioAgentRegistrySource = $null
$script:GapsioAgentRegistryNote = $null

function Test-GapsioHttpStatus {
    param($ErrorRecord, [string[]]$Status)
    $s = [string]$ErrorRecord.Exception.Data['Status']
    if ($s -and $Status -contains $s) { return $true }
    foreach ($x in $Status) { if ($ErrorRecord.Exception.Message -match "\b$x\b") { return $true } }
    $false
}

function ConvertFrom-GapsioAgentPackage {
    <#
    .SYNOPSIS
    Normalises a copilotPackage (Agent 365 Package Management API) into the shape the inventory expects from the
    legacy registry: id, displayName, agentIdentityId, originatingStore, ownerIds, createdDateTime, plus package details.
    #>
    param($Package)
    $owner = [string](Get-GapsioProp $Package 'ownerId')
    [pscustomobject]@{
        gapsioSource         = 'Agent365Packages'
        id               = [string](Get-GapsioProp $Package 'id')
        displayName      = [string](Get-GapsioProp $Package 'displayName')
        agentIdentityId  = [string](Get-GapsioProp $Package 'agentIdentityId')
        agentIdentityBlueprintId = $null
        agentUserId      = $null
        sourceAgentId    = [string](Get-GapsioProp $Package 'manifestId')
        appId            = [string](Get-GapsioProp $Package 'appId')
        originatingStore = $(if ([string](Get-GapsioProp $Package 'platform')) { [string](Get-GapsioProp $Package 'platform') } else { [string](Get-GapsioProp $Package 'type') })
        publisher        = [string](Get-GapsioProp $Package 'publisher')
        ownerIds         = @(@($owner) | Where-Object { $_ })
        createdDateTime  = [string](Get-GapsioProp $Package 'lastModifiedDateTime')
        packageType      = [string](Get-GapsioProp $Package 'type')
        elementTypes     = @(@(Get-GapsioProp $Package 'elementTypes') | Where-Object { $_ } | ForEach-Object { [string]$_ })
        supportedHosts   = @(@(Get-GapsioProp $Package 'supportedHosts') | Where-Object { $_ } | ForEach-Object { [string]$_ })
        isBlocked        = [bool](Get-GapsioProp $Package 'isBlocked')
        availableTo      = [string](Get-GapsioProp $Package 'availableTo')
        deployedTo       = [string](Get-GapsioProp $Package 'deployedTo')
    }
}

function Test-GapsioAgentPackageIsAgent {
    # Package catalog also lists Office add-ins and Teams apps; keep agents only.
    param($Package)
    $hosts = @(@(Get-GapsioProp $Package 'supportedHosts') | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $els = @(@(Get-GapsioProp $Package 'elementTypes') | ForEach-Object { ([string]$_).ToLowerInvariant() })
    if ($hosts -contains 'copilot') { return $true }
    foreach ($e in $els) { if ($e -match 'agent|bot') { return $true } }
    [bool][string](Get-GapsioProp $Package 'agentIdentityId')
}

function Get-GapsioAgentPackages {
    <#
    .SYNOPSIS
    Agent 365 Package Management API (Graph v1.0, CopilotPackages.Read.All, needs an Agent 365 licence).
    Server-side filter for agents (supportedHosts contains Copilot); falls back to the unfiltered list with a
    client-side filter if the filter is rejected.
    #>
    $base = 'copilot/admin/catalog/packages'
    $list = $null
    try { $list = @(Invoke-GapsioGraph -All -Path "$base`?`$filter=supportedHosts/any(h:h eq 'Copilot')" | Where-Object { $_ }) }
    catch {
        if (Test-GapsioHttpStatus $_ @('400')) { $list = @(Invoke-GapsioGraph -All -Path $base | Where-Object { $_ -and (Test-GapsioAgentPackageIsAgent $_) }) }
        else { throw }
    }
    @($list | ForEach-Object { ConvertFrom-GapsioAgentPackage $_ })
}

function Add-GapsioPackageDetails {
    # Copies package-level details (Agent 365 Package Management API) onto an inventory entry; no-op for legacy registry rows.
    param($Agent, $Row)
    if ([string](Get-GapsioProp $Row 'gapsioSource') -ne 'Agent365Packages') { return }
    $Agent.publisher = [string](Get-GapsioProp $Row 'publisher')
    $Agent.blocked = [bool](Get-GapsioProp $Row 'isBlocked')
    $Agent.availableTo = [string](Get-GapsioProp $Row 'availableTo')
    $Agent.deployedTo = [string](Get-GapsioProp $Row 'deployedTo')
    if (-not $Agent.agentAppId -and [string](Get-GapsioProp $Row 'appId')) { $Agent.agentAppId = [string](Get-GapsioProp $Row 'appId') }
}

function Get-GapsioAgentRegistry {
    <#
    .SYNOPSIS
    Agent inventory from Microsoft Agent 365. Order:
      1. Agent 365 Package Management API (v1.0 copilot/admin/catalog/packages, CopilotPackages.Read.All) – the
         successor API. 403 = permission not granted or no Agent 365 licence, 404 = not available: both fall through.
      2. Legacy registry (beta agentRegistry/agentInstances, AgentInstance.Read.All), retired from May 2026.
    Both are optional sources: if neither exists the status is NotAvailable (a note, not a warning). Any other
    error on the last attempted source is a warning.
    #>
    $script:GapsioAgentRegistrySource = $null; $script:GapsioAgentRegistryNote = $null
    try {
        $r = Get-GapsioAgentPackages
        $script:GapsioAgentRegistryStatus = 'Available'; $script:GapsioAgentRegistrySource = 'Agent365Packages'
        return @($r)
    }
    catch {
        $msg = $_.Exception.Message
        if (Test-GapsioHttpStatus $_ @('403')) { $script:GapsioAgentRegistryNote = 'Agent 365 Package Management API: CopilotPackages.Read.All not granted or no Agent 365 licence' }
        elseif (Test-GapsioHttpStatus $_ @('404')) { $script:GapsioAgentRegistryNote = 'Agent 365 Package Management API not available in this tenant' }
        else { $script:GapsioAgentRegistryNote = "Agent 365 Package Management API: $msg" }
    }
    try {
        $r = @(Invoke-GapsioGraph -Beta -All -Path 'agentRegistry/agentInstances' | Where-Object { $_ })
        $script:GapsioAgentRegistryStatus = 'Available'; $script:GapsioAgentRegistrySource = 'AgentRegistry'
        return $r
    }
    catch {
        if (Test-GapsioHttpStatus $_ @('404')) { $script:GapsioAgentRegistryStatus = 'NotAvailable' }
        else { $script:GapsioAgentRegistryStatus = 'Error'; Add-GapsioWarning "Agent 365 registry (AgentInstance.Read.All): $($_.Exception.Message)" }
        return @()
    }
}

function Get-GapsioAgentsInfo {
    <#
    .SYNOPSIS
    Defender XDR Advanced Hunting: AgentsInfo (Copilot Studio, Foundry, Agent 365, local agents on endpoints, ...).
    .NOTES
    Column names follow the documented schema (learn.microsoft.com/defender-xdr/advanced-hunting-agentsinfo-table):
    AgentId, AgentName, Platform, AgentDescription, Version, SourceAgentId, EntraAgentId, EntraBlueprintId, PublishedStatus,
    LifecycleStatus, Availability, CreatedDateTime, LastPublishedDateTime, LastUpdatedDateTime, InstanceCount, Model and the
    dynamic columns Owners, SharedWith, Permissions, Guardrails, Endpoints, McpServers, ConnectedAgents, DeclaredTools,
    DeclaredDataSources, Channels, RawAgentInfo. KQL column names are case-sensitive.
    The inner structure of the dynamic columns is NOT documented; they are passed through as JSON text and evaluated
    defensively in PowerShell (counts, obvious flags). RawAgentInfo.localAgentMetadata (local agents on endpoints) is
    not documented either – treated as optional.
    #>
    $q = @"
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| extend m = RawAgentInfo.localAgentMetadata
| project AgentId = tostring(AgentId), Name = AgentName, Platform, Description = AgentDescription, Version, EntraAgentId, EntraBlueprintId, SourceAgentId,
          PublishedStatus, LifecycleStatus, Availability, InstanceCount, Model, CreatedDateTime, LastUpdatedDateTime, LastPublishedDateTime,
          Owners = tostring(Owners), SharedWith = tostring(SharedWith), Permissions = tostring(Permissions), Guardrails = tostring(Guardrails),
          Endpoints = tostring(Endpoints), ConnectedAgents = tostring(ConnectedAgents), DeclaredTools = tostring(DeclaredTools),
          DeclaredDataSources = tostring(DeclaredDataSources), Channels = tostring(Channels),
          McpServers = tostring(McpServers), RawMcpServers = tostring(RawAgentInfo.mcpServers),
          IsLocal = isnotempty(m) or Platform has "Local",
          Vendor = tostring(m.vendor), LocalDeviceId = tostring(m.machineId), LocalDeviceName = tostring(m.deviceName), LocalOs = tostring(m.osPlatform),
          LocalUser = tostring(m.upn), AutoApprove = tostring(m.autoApprove), TrustedProcess = tostring(m.trustedProcess), Process = tostring(m.relatedProcess),
          LocalMcps = tostring(m.localMcps)
"@
    @(Invoke-GapsioHuntingSafe -Query $q -Context 'Advanced Hunting AgentsInfo' -ShardColumn 'AgentId' | Where-Object { $_ })
}

function Get-GapsioJsonCount {
    <#
    .SYNOPSIS
    Number of entries in a dynamic AgentsInfo column passed as JSON text.
    Returns $null when the value is unknown (null/empty text), the element count for arrays, and for objects the number
    of keys (0 for {}), so that "explicitly empty" can be told apart from "not provided".
    #>
    param([string]$Text)
    if (-not $Text -or $Text -eq 'null') { return $null }
    $v = $null
    try { $v = $Text | ConvertFrom-Json -Depth 10 -NoEnumerate } catch { return $null }
    if ($null -eq $v) { return $null }
    if ($v -is [System.Array]) { return @($v).Count }
    if ($v -is [string]) { return $(if ($v) { 1 } else { 0 }) }
    @($v.PSObject.Properties).Count
}

function Get-GapsioJsonNames {
    # Display names from a dynamic list (strings or objects with displayName/userPrincipalName/name/id).
    param([string]$Text)
    $out = foreach ($e in (ConvertFrom-GapsioJsonSafe $Text)) {
        if ($null -eq $e) { continue }
        if ($e -is [string]) { $e; continue }
        $n = [string](Get-GapsioProp $e 'displayName'); $u = [string](Get-GapsioProp $e 'userPrincipalName')
        if ($u -and $n) { "$n ($u)" } elseif ($u) { $u } elseif ($n) { $n }
        else { $s = [string](Get-GapsioProp $e 'name'); if ($s) { $s } else { [string](Get-GapsioProp $e 'id') } }
    }
    @($out | Where-Object { $_ })
}

function Get-GapsioAgentEndpoints {
    # Endpoints of an agent (URL, transport, external connectivity flag). Property names inside the dynamic value are not
    # documented, so url/transport/external are looked up by name pattern.
    param([string]$Text)
    $out = foreach ($e in (ConvertFrom-GapsioJsonSafe $Text)) {
        if ($null -eq $e) { continue }
        if ($e -is [string]) { [pscustomobject]@{ url = $e; transport = $null; external = $null }; continue }
        $url = $null; $transport = $null; $external = $null
        foreach ($p in $e.PSObject.Properties) {
            if ($p.Name -match '^(url|uri|endpoint|address)$' -and -not $url) { $url = [string]$p.Value }
            elseif ($p.Name -match 'transport|protocol' -and -not $transport) { $transport = [string]$p.Value }
            elseif ($p.Name -match 'external|public|internet' -and $null -eq $external) { $external = ([string]$p.Value) -match '^(true|1|yes)$' }
        }
        [pscustomobject]@{ url = $url; transport = $transport; external = $external }
    }
    @($out)
}

function Get-GapsioCaPolicies {
    $pol = Invoke-GapsioGraphV1First -All -Context 'Conditional Access policies (Policy.Read.All)' -Path 'identity/conditionalAccess/policies'
    $sd = $null
    try { $sd = Invoke-GapsioGraph -Path 'policies/identitySecurityDefaultsEnforcementPolicy' } catch { }
    [pscustomobject]@{ Policies = @($pol | Where-Object { $_ }); SecurityDefaults = [bool](Get-GapsioProp $sd 'isEnabled') }
}

function Get-GapsioCaControls {
    # Grant controls as codes (block, mfa, compliantDevice, ...) plus operator and agent risk levels; the portal renders them.
    param($Policy)
    $g = Get-GapsioProp $Policy 'grantControls'
    [pscustomobject]@{
        controls   = @(@(Get-GapsioProp $g 'builtInControls') | Where-Object { $_ } | ForEach-Object { [string]$_ })
        operator   = [string](Get-GapsioProp $g 'operator')
        riskLevels = @(@(Get-GapsioProp (Get-GapsioProp $Policy 'conditions') 'agentIdRiskLevels') | Where-Object { $_ } | ForEach-Object { [string]$_ })
    }
}

function Test-GapsioCaAgentScope {
    <#
    .SYNOPSIS
    Checks whether a CA policy covers a subject.
      -Kind Identity: subject IDs = agent identity, blueprint (object ID / app ID), blueprint principal
      -Kind User:     subject IDs = agent user
    Returns $null (not affected) or an object with applies/excluded/uncertain/via/filter.
    via codes: AllAgentIdentities, Direct, Blueprint, AttributeFilter, AllAgentUsers
    #>
    param($Policy, [ValidateSet('Identity', 'User')][string]$Kind, [string[]]$Ids, [string]$DirectId)
    $c = Get-GapsioProp $Policy 'conditions'
    $idSet = @($Ids | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    if ($Kind -eq 'Identity') {
        $ca = Get-GapsioProp $c 'clientApplications'
        if (-not $ca) { return $null }
        $inc = @(@(Get-GapsioProp $ca 'includeAgentIdServicePrincipals') | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $exc = @(@(Get-GapsioProp $ca 'excludeAgentIdServicePrincipals') | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $flt = Get-GapsioProp $ca 'agentIdServicePrincipalFilter'
        $rule = [string](Get-GapsioProp $flt 'rule'); $mode = [string](Get-GapsioProp $flt 'mode')
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
    $u = Get-GapsioProp $c 'users'
    if (-not $u) { return $null }
    $inc = @(@(Get-GapsioProp $u 'includeUsers') | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $exc = @(@(Get-GapsioProp $u 'excludeUsers') | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $via = $null
    if ($inc -contains 'allagentidusers') { $via = 'AllAgentUsers' }
    elseif (@($inc | Where-Object { $idSet -contains $_ }).Count) { $via = 'Direct' }
    if (-not $via) { return $null }
    $excluded = @($exc | Where-Object { $idSet -contains $_ }).Count -gt 0
    [pscustomobject]@{ applies = (-not $excluded); excluded = $excluded; uncertain = $false; via = $via; filter = $null }
}

function Get-GapsioAgentCaCoverage {
    # Status codes: Protected, ReportOnly, Excluded, Unclear, NotCovered, SecurityDefaults
    param([object[]]$Policies, [ValidateSet('Identity', 'User')][string]$Kind, [string[]]$Ids, [string]$DirectId, [bool]$SecurityDefaults)
    $hits = foreach ($p in @($Policies)) {
        $state = [string](Get-GapsioProp $p 'state')
        if ($state -eq 'disabled') { continue }
        $r = Test-GapsioCaAgentScope -Policy $p -Kind $Kind -Ids $Ids -DirectId $DirectId
        if (-not $r) { continue }
        $ctl = Get-GapsioCaControls -Policy $p
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

function Get-GapsioSponsorText {
    param($Object)
    @(@(Get-GapsioProp $Object 'sponsors') | Where-Object { $_ } | ForEach-Object { $n = [string](Get-GapsioProp $_ 'displayName'); $u = [string](Get-GapsioProp $_ 'userPrincipalName'); if ($u) { "$n ($u)" } elseif ($n) { $n } else { [string](Get-GapsioProp $_ 'id') } })
}

function ConvertFrom-GapsioJsonSafe {
    param([string]$Text)
    if (-not $Text -or $Text -in 'null', '[]', '{}') { return @() }
    try { @($Text | ConvertFrom-Json -Depth 10) } catch { @() }
}

function Get-GapsioLocalMcpInfo {
    # Normalises the MCP servers of a local agent: name, command and whether it is loaded unpinned from a public registry.
    param([string]$LocalMcps, [string]$McpServers)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($m in (ConvertFrom-GapsioJsonSafe $LocalMcps)) {
        if (-not $m) { continue }
        $cmd = [string](Get-GapsioProp $m 'commandName')
        $cmdArgs = @(Get-GapsioProp $m 'commandArgs') | ForEach-Object { [string]$_ }
        $line = (@($cmd) + $cmdArgs) -join ' '
        $unpinned = ($cmd -match '^(npx|uvx|pipx|bunx|pnpm|dlx)(\.cmd|\.exe)?$' -and ($line -match '@latest\b' -or $line -match '(^|\s)-y(\s|$)' -or $line -notmatch '@\d'))
        $out.Add([pscustomobject]@{ name = [string](Get-GapsioProp $m 'name'); kind = 'local'; command = $line; unpinned = [bool]$unpinned; endpoint = $null })
    }
    foreach ($m in (ConvertFrom-GapsioJsonSafe $McpServers)) {
        if (-not $m) { continue }
        if ($m -is [string]) { $out.Add([pscustomobject]@{ name = $m; kind = 'remote'; command = $null; unpinned = $false; endpoint = $m }); continue }
        # Structure of AgentsInfo.McpServers is not documented ("server URLs and credential configuration") – look up by common names.
        $name = $null; $kind = $null; $ep = $null
        foreach ($p in $m.PSObject.Properties) {
            if ($p.Name -match '^(name|displayName|serverName)$' -and -not $name) { $name = [string]$p.Value }
            elseif ($p.Name -match '^(type|transport|kind)$' -and -not $kind) { $kind = [string]$p.Value }
            elseif ($p.Name -match '^(endpoint|url|uri|serverUrl|address)$' -and -not $ep) { $ep = [string]$p.Value }
        }
        if (-not $name) { $name = $ep }
        $out.Add([pscustomobject]@{ name = $name; kind = $(if ($kind) { $kind } else { 'remote' }); command = $null; unpinned = $false; endpoint = $ep })
    }
    $out.ToArray()
}

function Add-GapsioAgentsInfoDetails {
    # Copies the documented AgentsInfo properties of a matched row into an inventory entry.
    param($Agent, $Row)
    $Agent.defenderAgentId = [string]$Row.AgentId
    if (-not $Agent.platform) { $Agent.platform = [string](Get-GapsioProp $Row 'Platform') }
    $Agent.publishedStatus = [string](Get-GapsioProp $Row 'PublishedStatus'); $Agent.lifecycle = [string](Get-GapsioProp $Row 'LifecycleStatus')
    if (-not $Agent.version) { $Agent.version = [string](Get-GapsioProp $Row 'Version') }
    if (-not $Agent.created) { $Agent.created = [string](Get-GapsioProp $Row 'CreatedDateTime') }
    $Agent.description = [string](Get-GapsioProp $Row 'Description')
    $Agent.model = [string](Get-GapsioProp $Row 'Model')
    $Agent.availability = [string](Get-GapsioProp $Row 'Availability')
    $Agent.lastPublished = [string](Get-GapsioProp $Row 'LastPublishedDateTime')
    $ic = Get-GapsioProp $Row 'InstanceCount'; if ($null -ne $ic -and "$ic" -ne '') { $Agent.instanceCount = [int]$ic }
    if (-not @($Agent.owners).Count) { $Agent.owners = @(Get-GapsioJsonNames ([string](Get-GapsioProp $Row 'Owners'))) }
    $Agent.sharedWith = Get-GapsioJsonCount ([string](Get-GapsioProp $Row 'SharedWith'))
    $Agent.permissions = Get-GapsioJsonCount ([string](Get-GapsioProp $Row 'Permissions'))
    $Agent.guardrails = Get-GapsioJsonCount ([string](Get-GapsioProp $Row 'Guardrails'))
    $Agent.tools = Get-GapsioJsonCount ([string](Get-GapsioProp $Row 'DeclaredTools'))
    $Agent.dataSources = Get-GapsioJsonCount ([string](Get-GapsioProp $Row 'DeclaredDataSources'))
    $Agent.connectedAgents = @(Get-GapsioJsonNames ([string](Get-GapsioProp $Row 'ConnectedAgents')))
    $Agent.channels = @(Get-GapsioJsonNames ([string](Get-GapsioProp $Row 'Channels')))
    $Agent.endpoints = @(Get-GapsioAgentEndpoints ([string](Get-GapsioProp $Row 'Endpoints')))
    $mcp = [string](Get-GapsioProp $Row 'McpServers'); if (-not $mcp -or $mcp -in 'null', '[]') { $mcp = [string](Get-GapsioProp $Row 'RawMcpServers') }
    if (-not @($Agent.mcpServers).Count) { $Agent.mcpServers = @(Get-GapsioLocalMcpInfo -LocalMcps ([string](Get-GapsioProp $Row 'LocalMcps')) -McpServers $mcp) }
}

function Get-GapsioAgentInventory {
    <#
    .SYNOPSIS
    Merges Entra Agent ID, the Agent 365 registry and Defender AgentsInfo into one agent inventory and rates the
    Conditional Access coverage per agent identity and agent user. Local agents get device context instead.
    #>
    param($Directory, [object[]]$Registry, [object[]]$AgentsInfo, $Ca, [hashtable]$EndpointDevices = @{})
    $bpByApp = @{}; $bpById = @{}
    foreach ($b in $Directory.Blueprints) { $bpByApp[([string]$b.appId).ToLowerInvariant()] = $b; $bpById[([string]$b.id).ToLowerInvariant()] = $b }
    $bppByApp = @{}; foreach ($b in $Directory.BlueprintPrincipals) { $bppByApp[([string]$b.appId).ToLowerInvariant()] = $b }
    $userByParent = @{}; foreach ($u in $Directory.Users) { $k = ([string](Get-GapsioProp $u 'identityParentId')).ToLowerInvariant(); if ($k) { $userByParent[$k] = $u } }
    $regByIdentity = @{}; foreach ($r in @($Registry)) { $k = ([string](Get-GapsioProp $r 'agentIdentityId')).ToLowerInvariant(); if ($k) { $regByIdentity[$k] = $r } }
    $regSource = { param($r) $s = [string](Get-GapsioProp $r 'gapsioSource'); if ($s) { $s } else { 'Agent365Registry' } }
    $aiByEntra = @{}
    foreach ($a in @($AgentsInfo)) { $k = ([string](Get-GapsioProp $a 'EntraAgentId')).ToLowerInvariant(); if ($k) { $aiByEntra[$k] = $a } }

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
            publisher = $null; blocked = $null; availableTo = $null; deployedTo = $null
            vendor = $null; version = $null; device = $null; user = $null; autoApprove = $null; trustedProcess = $null; process = $null; mcpServers = @()
            description = $null; model = $null; availability = $null; lastPublished = $null; instanceCount = $null
            sharedWith = $null; permissions = $null; guardrails = $null; tools = $null; dataSources = $null; connectedAgents = @(); channels = @(); endpoints = @()
            caIdentity = $null; caUser = $null
        }
    }

    foreach ($i in $Directory.Identities) {
        $a = & $newAgent ([string]$i.displayName) 'Cloud'
        $a.sources.Add('EntraAgentId')
        $a.agentId = [string]$i.id; $a.agentAppId = [string]$i.appId; $a.agentEnabled = [bool](Get-GapsioProp $i 'accountEnabled')
        $a.disabledByMicrosoft = [string](Get-GapsioProp $i 'disabledByMicrosoftStatus')
        $a.created = [string](Get-GapsioProp $i 'createdDateTime')
        $a.sponsors = @(Get-GapsioSponsorText $i)
        $bpApp = ([string](Get-GapsioProp $i 'agentIdentityBlueprintId')).ToLowerInvariant()
        $a.blueprintAppId = [string](Get-GapsioProp $i 'agentIdentityBlueprintId')
        if ($bpApp -and $bpByApp.ContainsKey($bpApp)) { $b = $bpByApp[$bpApp]; $a.blueprintId = [string]$b.id; $a.blueprintName = [string]$b.displayName; $a.blueprintPublisher = [string](Get-GapsioProp $b 'publisherDomain') }
        if ($bpApp -and $bppByApp.ContainsKey($bpApp)) { $bp = $bppByApp[$bpApp]; $a.blueprintPrincipalId = [string]$bp.id; if (-not $a.blueprintName) { $a.blueprintName = [string]$bp.displayName } }
        $u = $userByParent[([string]$i.id).ToLowerInvariant()]
        if ($u) { $usedUsers[[string]$u.id] = $true; $a.agentUserId = [string]$u.id; $a.agentUserUpn = [string]$u.userPrincipalName; $a.agentUserEnabled = [bool](Get-GapsioProp $u 'accountEnabled') }
        $r = $regByIdentity[([string]$i.id).ToLowerInvariant()]
        if ($r) { $usedReg[[string]$r.id] = $true; $a.sources.Add((& $regSource $r)); $a.registryId = [string]$r.id; $a.platform = [string](Get-GapsioProp $r 'originatingStore'); $a.owners = @(Get-GapsioProp $r 'ownerIds'); Add-GapsioPackageDetails $a $r }
        $ai = $aiByEntra[([string]$i.id).ToLowerInvariant()]
        if (-not $ai) { $ai = $aiByEntra[([string]$i.appId).ToLowerInvariant()] }
        if ($ai) { $usedAi[[string]$ai.AgentId] = $true; $a.sources.Add('DefenderAgentsInfo'); Add-GapsioAgentsInfoDetails $a $ai }
        if (-not $a.platform) { $a.platform = 'Entra Agent ID' }
        $agents.Add($a)
    }

    # Registry entries without an Entra agent identity
    foreach ($r in @($Registry)) {
        if (-not $r -or $usedReg.ContainsKey([string]$r.id)) { continue }
        $a = & $newAgent ([string]$r.displayName) 'Cloud'
        $a.sources.Add((& $regSource $r)); $a.registryId = [string]$r.id; $a.platform = [string](Get-GapsioProp $r 'originatingStore')
        $a.owners = @(Get-GapsioProp $r 'ownerIds'); $a.created = [string](Get-GapsioProp $r 'createdDateTime')
        Add-GapsioPackageDetails $a $r
        $bpObj = ([string](Get-GapsioProp $r 'agentIdentityBlueprintId')).ToLowerInvariant()
        if ($bpObj -and $bpById.ContainsKey($bpObj)) { $b = $bpById[$bpObj]; $a.blueprintId = [string]$b.id; $a.blueprintAppId = [string]$b.appId; $a.blueprintName = [string]$b.displayName }
        $uid = [string](Get-GapsioProp $r 'agentUserId')
        if ($uid) { $a.agentUserId = $uid; $u = @($Directory.Users | Where-Object { $_.id -eq $uid })[0]; if ($u) { $usedUsers[$uid] = $true; $a.agentUserUpn = [string]$u.userPrincipalName; $a.agentUserEnabled = [bool](Get-GapsioProp $u 'accountEnabled') } }
        $rApp = [string](Get-GapsioProp $r 'appId')
        $ai = @($AgentsInfo | Where-Object { $_ -and ([string]$_.AgentId -eq [string]$r.id -or ([string]$_.SourceAgentId -and [string]$_.SourceAgentId -eq [string](Get-GapsioProp $r 'sourceAgentId')) -or ($rApp -and [string](Get-GapsioProp $_ 'EntraAgentId') -eq $rApp)) })[0]
        if ($ai) { $usedAi[[string]$ai.AgentId] = $true; $a.sources.Add('DefenderAgentsInfo'); Add-GapsioAgentsInfoDetails $a $ai }
        $agents.Add($a)
    }

    # Defender inventory without an Entra agent identity: cloud agents and local agents on endpoints
    foreach ($ai in @($AgentsInfo)) {
        if (-not $ai -or $usedAi.ContainsKey([string]$ai.AgentId)) { continue }
        $isLocal = [string](Get-GapsioProp $ai 'IsLocal') -match '^(true|1)$'
        $a = & $newAgent ([string]$ai.Name) $(if ($isLocal) { 'Local' } else { 'Cloud' })
        $a.sources.Add('DefenderAgentsInfo')
        if ([string](Get-GapsioProp $ai 'EntraBlueprintId')) { $a.blueprintAppId = [string](Get-GapsioProp $ai 'EntraBlueprintId') }
        if ($isLocal) {
            $devId = [string](Get-GapsioProp $ai 'LocalDeviceId')
            $ep = if ($devId -and $EndpointDevices.ContainsKey($devId)) { $EndpointDevices[$devId] } else { $null }
            $a.vendor = [string](Get-GapsioProp $ai 'Vendor')
            $a.user = [string](Get-GapsioProp $ai 'LocalUser')
            $a.autoApprove = ([string](Get-GapsioProp $ai 'AutoApprove')) -match '^(true|1)$'
            $tp = [string](Get-GapsioProp $ai 'TrustedProcess')
            $a.trustedProcess = if ($tp) { $tp -match '^(true|1)$' } else { $null }
            $a.process = [string](Get-GapsioProp $ai 'Process')
            $a.device = [ordered]@{
                id = $devId; name = [string](Get-GapsioProp $ai 'LocalDeviceName'); os = [string](Get-GapsioProp $ai 'LocalOs')
                group = $(if ($ep) { [string]$ep.deviceGroup } else { $null })
                tamper = $(if ($ep) { [string](Get-GapsioProp $ep.checks 'TamperProtection') } else { $null })
                localExclusions = $(if ($ep) { [int]$ep.localExclusions } else { $null })
                asrBelowMinimum = $(if ($ep) { $ep.asrBelowMinimum } else { $null })
                avMode = $(if ($ep) { [string]$ep.avModeText } else { $null })
            }
        }
        Add-GapsioAgentsInfoDetails $a $ai
        $agents.Add($a)
    }

    # Agent users without an agent identity (orphaned)
    foreach ($u in $Directory.Users) {
        if ($usedUsers.ContainsKey([string]$u.id)) { continue }
        $a = & $newAgent ([string]$u.displayName) 'Cloud'
        $a.sources.Add('EntraAgentId'); $a.platform = 'Entra Agent ID'
        $a.agentUserId = [string]$u.id; $a.agentUserUpn = [string]$u.userPrincipalName; $a.agentUserEnabled = [bool](Get-GapsioProp $u 'accountEnabled')
        $a.sponsors = @(Get-GapsioSponsorText $u); $a.created = [string](Get-GapsioProp $u 'createdDateTime')
        $agents.Add($a)
    }

    # Conditional Access and drift keys
    foreach ($a in $agents) {
        if ($a.agentType -eq 'Local') { $a.caIdentity = [pscustomobject]@{ status = 'UserContext'; policies = @() } }
        elseif ($a.agentId) {
            $ids = @($a.agentId, $a.blueprintId, $a.blueprintAppId, $a.blueprintPrincipalId)
            $a.caIdentity = Get-GapsioAgentCaCoverage -Policies $Ca.Policies -Kind Identity -Ids $ids -DirectId $a.agentId -SecurityDefaults $Ca.SecurityDefaults
        }
        elseif ($a.agentUserId) { $a.caIdentity = [pscustomobject]@{ status = 'IdentityMissing'; policies = @() } }
        else { $a.caIdentity = [pscustomobject]@{ status = 'NoAgentId'; policies = @() } }
        if ($a.agentUserId) { $a.caUser = Get-GapsioAgentCaCoverage -Policies $Ca.Policies -Kind User -Ids @($a.agentUserId) -DirectId $a.agentUserId -SecurityDefaults $Ca.SecurityDefaults }

        $a.key = Get-GapsioHash "agent|$(if ($a.agentId) { $a.agentId } elseif ($a.registryId) { "reg:$($a.registryId)" } elseif ($a.defenderAgentId) { "mde:$($a.defenderAgentId)" } else { "user:$($a.agentUserId)" })"
        $where = if ($a.device) { " @ $($a.device.name)" } else { '' }
        $a.label = New-GapsioText "$($a.agentType) agent $($a.name)$where" "$(if ($a.agentType -eq 'Local') { 'Lokaler' } else { 'Cloud-' })Agent $($a.name)$where"
        $a.state = if ($a.agentType -eq 'Local') { "autoApprove=$($a.autoApprove); mcp=$(@($a.mcpServers).Count)" } else { "agent=$($a.caIdentity.status)$(if ($a.caUser) { "; agentUser=$($a.caUser.status)" })" }
        $a.fp = Get-GapsioHash "$($a.state)|$($a.agentEnabled)|$($a.agentUserEnabled)|$(@($a.sponsors) -join ',')|$($a.blueprintAppId)|$($a.version)|$($a.guardrails)|$(@($a.endpoints | Where-Object { $_.external }).Count)|$(@($a.mcpServers).Count)"
        $a.sources = @($a.sources | Select-Object -Unique)
    }
    @($agents | ForEach-Object { [pscustomobject]$_ })
}

function Get-GapsioAgentPolicySummary {
    # CA policies that target agents – with target, effect and the number of agents they actually cover.
    param([object[]]$Policies, [object[]]$Agents)
    $out = foreach ($p in @($Policies)) {
        $c = Get-GapsioProp $p 'conditions'
        $ca = Get-GapsioProp $c 'clientApplications'; $u = Get-GapsioProp $c 'users'
        $inc = @(Get-GapsioProp $ca 'includeAgentIdServicePrincipals') | Where-Object { $_ }
        $exc = @(Get-GapsioProp $ca 'excludeAgentIdServicePrincipals') | Where-Object { $_ }
        $flt = [string](Get-GapsioProp (Get-GapsioProp $ca 'agentIdServicePrincipalFilter') 'rule')
        $incU = @(Get-GapsioProp $u 'includeUsers') | Where-Object { $_ }
        $someUsers = @($incU | Where-Object { $id = $_; @($Agents | Where-Object { $_.agentUserId -eq $id }).Count }).Count
        if (-not $inc -and -not $flt -and -not ($incU -contains 'AllAgentIdUsers') -and -not $someUsers) { continue }
        # Targets as codes: AllAgentIdentities | SomeAgentIdentities(count) | AttributeFilter(rule) | AllAgentUsers | SomeAgentUsers(count)
        $targets = @()
        if ($inc -contains 'All') { $targets += [pscustomobject]@{ code = 'AllAgentIdentities' } } elseif ($inc) { $targets += [pscustomobject]@{ code = 'SomeAgentIdentities'; count = @($inc).Count } }
        if ($flt) { $targets += [pscustomobject]@{ code = 'AttributeFilter'; rule = $flt } }
        if ($incU -contains 'AllAgentIdUsers') { $targets += [pscustomobject]@{ code = 'AllAgentUsers' } } elseif ($someUsers) { $targets += [pscustomobject]@{ code = 'SomeAgentUsers'; count = $someUsers } }
        $apps = Get-GapsioProp $c 'applications'
        $incApps = @(Get-GapsioProp $apps 'includeApplications') | Where-Object { $_ }
        $resources = if ($incApps -contains 'All') { 'All' } elseif ($incApps -contains 'AllAgentIdResources') { 'AllAgentResources' } elseif ($incApps) { "$(@($incApps).Count)" } else { $null }
        $state = switch ([string]$p.state) { 'enabled' { 'Enabled' } 'enabledForReportingButNotEnforced' { 'ReportOnly' } default { 'Disabled' } }
        $ctl = Get-GapsioCaControls -Policy $p
        $covId = @($Agents | Where-Object { $_.caIdentity -and @($_.caIdentity.policies | Where-Object { $_.id -eq $p.id -and $_.applies }).Count }).Count
        $covUser = @($Agents | Where-Object { $_.caUser -and @($_.caUser.policies | Where-Object { $_.id -eq $p.id -and $_.applies }).Count }).Count
        [pscustomobject]@{
            key = Get-GapsioHash "capol|$($p.id)"
            fp = Get-GapsioHash "$state|$(@($inc) -join ',')|$(@($exc) -join ',')|$flt|$(@($incU) -join ',')|$($ctl.controls -join ',')|$($ctl.riskLevels -join ',')"
            label = New-GapsioText "CA policy $($p.displayName)" "CA-Richtlinie $($p.displayName)"
            state = $state
            id = [string]$p.id; name = [string]$p.displayName
            targets = $targets; excludes = @($exc).Count; resources = $resources
            controls = $ctl.controls; operator = $ctl.operator; riskLevels = $ctl.riskLevels
            coveredIdentities = $covId; coveredUsers = $covUser
            modified = [string](Get-GapsioProp $p 'modifiedDateTime')
        }
    }
    @($out)
}

function Get-GapsioAgentFindings {
    param([object[]]$Agents, [object[]]$PolicySummary, [bool]$SecurityDefaults)
    $f = [System.Collections.Generic.List[object]]::new()
    $T = { param($en, $de) New-GapsioText -En $en -De $de }
    $cloud = @($Agents | Where-Object { $_.agentType -ne 'Local' })
    $withId = @($cloud | Where-Object { $_.agentId })
    $withUser = @($cloud | Where-Object { $_.agentUserId })
    $names = { param($pols, $filter) (@($pols | Where-Object $filter | ForEach-Object { $_.name }) -join ', ') }

    if ($SecurityDefaults -and ($withId.Count -or $withUser.Count)) {
        $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'ConditionalAccess' -Title (& $T 'Security defaults enabled – Conditional Access is not evaluated' 'Sicherheitsstandards aktiv – Conditional Access greift nicht') `
                    -Detail (& $T 'While security defaults are enabled, no Conditional Access policies are evaluated – not for agents either.' 'Solange die Sicherheitsstandards (Security Defaults) aktiv sind, werden keine Conditional-Access-Richtlinien ausgewertet – auch nicht für Agents.') `
                    -Recommendation (& $T 'Move to Conditional Access and create policies for agent identities and agent users.' 'Auf Conditional Access umstellen und Richtlinien für Agent-Identitäten und Agent-User anlegen.') -Subject 'secdefaults'))
    }
    $activeId = @($PolicySummary | Where-Object { $_.state -eq 'Enabled' -and @($_.targets | Where-Object { $_.code -in 'AllAgentIdentities', 'SomeAgentIdentities', 'AttributeFilter' }).Count })
    $activeUser = @($PolicySummary | Where-Object { $_.state -eq 'Enabled' -and @($_.targets | Where-Object { $_.code -in 'AllAgentUsers', 'SomeAgentUsers' }).Count })
    if ($withId.Count -and -not $activeId.Count -and -not $SecurityDefaults) {
        $f.Add((New-GapsioFinding -Severity 'High' -Category 'ConditionalAccess' -Title (& $T 'No enabled Conditional Access policy for agent identities' 'Keine aktive Conditional-Access-Richtlinie für Agent-Identitäten') `
                    -Detail (& $T "The tenant has $($withId.Count) agent identit(ies) but no enabled policy targets agent identities. Policies for users or workload identities do not apply to agents." "Im Mandanten gibt es $($withId.Count) Agent-Identität(en), aber keine aktive Richtlinie, die Agent-Identitäten adressiert. Richtlinien für Benutzer oder Workload-Identitäten gelten nicht für Agents.") `
                    -Recommendation (& $T 'At minimum: block "All agent identities" except approved blueprints/agents (via custom security attributes) and block high-risk agents.' 'Mindestens: „Alle Agent-Identitäten“ blockieren außer freigegebenen Blueprints/Agents (per Custom Security Attribute) und Agents mit hohem Risiko blockieren.') -Subject 'no-ca-identity'))
    }
    if ($withUser.Count -and -not $activeUser.Count -and -not $SecurityDefaults) {
        $f.Add((New-GapsioFinding -Severity 'High' -Category 'ConditionalAccess' -Title (& $T 'No enabled Conditional Access policy for agent users' 'Keine aktive Conditional-Access-Richtlinie für Agent-User') `
                    -Detail (& $T "The tenant has $($withUser.Count) agent user(s). Policies for ""All users"" and group assignments do not apply to agent users – they must be targeted via ""All agent users"" or individually." "Im Mandanten gibt es $($withUser.Count) Agent-User. Richtlinien für „Alle Benutzer“ und Gruppen-Zuweisungen gelten für Agent-User nicht – sie müssen über „Alle Agent-User“ bzw. einzeln adressiert werden.") `
                    -Recommendation (& $T 'Create a policy for "All agent users" (e.g. block risky agent users, require a compliant device/network).' 'Richtlinie für „Alle Agent-User“ anlegen (z. B. riskante Agent-User blockieren, konformes Gerät/Netzwerk verlangen).') -Subject 'no-ca-user'))
    }

    foreach ($a in $cloud) {
        $id = if ($a.agentId) { $a.agentId } elseif ($a.registryId) { $a.registryId } else { $a.defenderAgentId }
        if ($a.agentId -and $a.agentEnabled) {
            switch ($a.caIdentity.status) {
                'NotCovered' { if ($activeId.Count) { $f.Add((New-GapsioFinding -Severity 'High' -Category 'ConditionalAccess' -Title (& $T "Agent without Conditional Access: $($a.name)" "Agent ohne Conditional Access: $($a.name)") -Detail (& $T "Agent identity $($a.agentId) (blueprint $($a.blueprintAppId)) is not covered by any Conditional Access policy." "Die Agent-Identität $($a.agentId) (Blueprint $($a.blueprintAppId)) wird von keiner Conditional-Access-Richtlinie erfasst.") -Recommendation (& $T 'Add the agent or its blueprint to an agent policy, or classify it with a custom security attribute.' 'Agent bzw. Blueprint in eine Agent-Richtlinie aufnehmen oder per Custom Security Attribute klassifizieren.') -Subject "ca-id|$id")) } }
                'ReportOnly' { $n = & $names $a.caIdentity.policies { $_.applies }; $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'ConditionalAccess' -Title (& $T "Agent covered by report-only policies only: $($a.name)" "Agent nur durch Report-only-Richtlinien erfasst: $($a.name)") -Detail (& $T "Policies: $n. Report-only only logs." "Richtlinien: $n. Report-only protokolliert nur.") -Recommendation (& $T 'Review the sign-in logs of the agent identity and enable the policy.' 'Sign-in-Logs der Agent-Identität prüfen und Richtlinie aktivieren.') -Subject "ca-ro|$id")) }
                'Excluded' { $n = & $names $a.caIdentity.policies { $_.excluded }; $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'ConditionalAccess' -Title (& $T "Agent excluded from Conditional Access: $($a.name)" "Agent von Conditional Access ausgenommen: $($a.name)") -Detail (& $T "Excluded in: $n." "Ausgenommen in: $n.") -Recommendation (& $T 'Justify and document the exclusion or remove it.' 'Ausnahme begründen und dokumentieren oder entfernen.') -Subject "ca-ex|$id")) }
                'Unclear' { $n = & $names $a.caIdentity.policies { $true }; $f.Add((New-GapsioFinding -Severity 'Low' -Category 'ConditionalAccess' -Title (& $T "Coverage by attribute filter cannot be verified: $($a.name)" "Abdeckung per Attributfilter nicht prüfbar: $($a.name)") -Detail (& $T "The policies $n select agents by custom security attributes. Whether this agent is covered depends on its attributes." "Die Richtlinien $n wählen Agents über Custom Security Attributes aus. Ob dieser Agent erfasst wird, hängt von seinen Attributen ab.") -Recommendation (& $T "Check the agent's custom security attributes." 'Custom Security Attributes des Agents prüfen.') -Subject "ca-flt|$id")) }
            }
        }
        if ($a.agentUserId -and $a.agentUserEnabled -and $a.caUser) {
            switch ($a.caUser.status) {
                'NotCovered' { if ($activeUser.Count) { $f.Add((New-GapsioFinding -Severity 'High' -Category 'ConditionalAccess' -Title (& $T "Agent user without Conditional Access: $($a.agentUserUpn)" "Agent-User ohne Conditional Access: $($a.agentUserUpn)") -Detail (& $T "The agent user of '$($a.name)' is not covered by any policy. ""All users"" does not include agent users." "Der Agent-User von '$($a.name)' wird von keiner Richtlinie erfasst. „Alle Benutzer“ schließt Agent-User nicht ein.") -Recommendation (& $T 'Include agent users via "All agent users" or individually.' 'Agent-User über „Alle Agent-User“ oder einzeln in eine Richtlinie aufnehmen.') -Subject "ca-user|$($a.agentUserId)")) } }
                'ReportOnly' { $n = & $names $a.caUser.policies { $_.applies }; $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'ConditionalAccess' -Title (& $T "Agent user covered by report-only policies only: $($a.agentUserUpn)" "Agent-User nur durch Report-only-Richtlinien erfasst: $($a.agentUserUpn)") -Detail (& $T "Policies: $n." "Richtlinien: $n.") -Recommendation (& $T 'Enable the policy after evaluation.' 'Richtlinie nach Auswertung aktivieren.') -Subject "ca-user-ro|$($a.agentUserId)")) }
                'Excluded' { $n = & $names $a.caUser.policies { $_.excluded }; $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'ConditionalAccess' -Title (& $T "Agent user excluded from Conditional Access: $($a.agentUserUpn)" "Agent-User von Conditional Access ausgenommen: $($a.agentUserUpn)") -Detail (& $T "Excluded in: $n." "Ausgenommen in: $n.") -Recommendation (& $T 'Justify the exclusion or remove it.' 'Ausnahme begründen oder entfernen.') -Subject "ca-user-ex|$($a.agentUserId)")) }
            }
        }
        if ($a.agentId -and -not @($a.sponsors).Count) {
            $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'Accountability' -Title (& $T "Agent without sponsor: $($a.name)" "Agent ohne Sponsor: $($a.name)") -Detail (& $T 'No sponsor (accountable person or group) is set for the agent identity. Without a sponsor there is no recertification and no contact.' 'Für die Agent-Identität ist kein Sponsor (verantwortliche Person oder Gruppe) hinterlegt. Ohne Sponsor fehlen Rezertifizierung und Ansprechpartner.') -Recommendation (& $T 'Set a sponsor in Entra (Agent ID).' 'Sponsor in Entra (Agent ID) setzen.') -Subject "sponsor|$id"))
        }
        if ($a.disabledByMicrosoft -and $a.disabledByMicrosoft -ne 'NotDisabled') {
            $f.Add((New-GapsioFinding -Severity 'High' -Category 'Agent' -Title (& $T "Agent disabled by Microsoft: $($a.name)" "Agent von Microsoft deaktiviert: $($a.name)") -Detail (& $T "Status: $($a.disabledByMicrosoft)." "Status: $($a.disabledByMicrosoft).") -Recommendation (& $T 'Investigate the agent and inform the owners.' 'Agent untersuchen und Verantwortliche informieren.') -Subject "msdisabled|$id"))
        }
        if ($a.agentId -and $a.blueprintAppId -and -not $a.blueprintName) {
            $f.Add((New-GapsioFinding -Severity 'Low' -Category 'Agent' -Title (& $T "Blueprint unknown in this tenant: $($a.name)" "Blueprint im Mandanten unbekannt: $($a.name)") -Detail (& $T "The agent identity references blueprint $($a.blueprintAppId), which is visible neither as a blueprint nor as a blueprint principal." "Die Agent-Identität verweist auf Blueprint $($a.blueprintAppId), der weder als Blueprint noch als Blueprint-Principal sichtbar ist.") -Recommendation (& $T 'Check where the agent comes from (third-party blueprint?).' 'Herkunft des Agents prüfen (Drittanbieter-Blueprint?).') -Subject "bp|$id"))
        }
        if (-not $a.agentId -and $a.agentUserId) {
            $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'Agent' -Title (& $T "Orphaned agent user: $($a.agentUserUpn)" "Verwaister Agent-User: $($a.agentUserUpn)") -Detail (& $T 'There is no (longer an) agent identity for this agent user. Orphaned accounts keep their permissions and licences.' 'Zu diesem Agent-User gibt es keine Agent-Identität (mehr). Verwaiste Konten behalten ihre Rechte und Lizenzen.') -Recommendation (& $T 'Disable or delete the agent user if the agent no longer exists.' 'Agent-User deaktivieren bzw. löschen, wenn der Agent nicht mehr existiert.') -Subject "orphan|$($a.agentUserId)"))
        }
        if (-not $a.agentId -and -not $a.agentUserId) {
            $f.Add((New-GapsioFinding -Severity 'Low' -Category 'Agent' -Title (& $T "Cloud agent without Entra Agent ID: $($a.name)" "Cloud-Agent ohne Entra Agent ID: $($a.name)") -Detail (& $T "Platform: $($a.platform). Without an agent identity neither Conditional Access nor Identity Protection applies to this agent; it uses the user's identity or its own credentials." "Plattform: $($a.platform). Ohne Agent-Identität greifen weder Conditional Access noch Identity Protection für diesen Agent; er nutzt die Identität des Benutzers oder eigene Anmeldedaten.") -Recommendation (& $T 'Check whether the agent can be moved to Entra Agent ID.' 'Prüfen, ob der Agent auf Entra Agent ID umgestellt werden kann.') -Subject "noid|$id"))
        }
        # Defender AgentsInfo: Guardrails is documented as "guardrails attached to the agent and their coverage" – an explicitly empty
        # value (not null) means none are attached. Only published, active agents are rated.
        if ($a.defenderAgentId -and $a.guardrails -eq 0 -and $a.lifecycle -ne 'Blocked' -and $a.lifecycle -ne 'Uninstalled' -and $a.lifecycle -ne 'Deleted' -and $a.publishedStatus -ne 'Draft') {
            $f.Add((New-GapsioFinding -Severity 'Low' -Category 'Agent' -Title (& $T "Agent without guardrails: $($a.name)" "Agent ohne Guardrails: $($a.name)") -Detail (& $T "Defender reports no guardrails for this agent ($($a.platform)). Tools: $(if ($null -ne $a.tools) { $a.tools } else { '?' }), data sources: $(if ($null -ne $a.dataSources) { $a.dataSources } else { '?' }), MCP servers: $(@($a.mcpServers).Count)." "Defender meldet für diesen Agent ($($a.platform)) keine Guardrails. Tools: $(if ($null -ne $a.tools) { $a.tools } else { '?' }), Datenquellen: $(if ($null -ne $a.dataSources) { $a.dataSources } else { '?' }), MCP-Server: $(@($a.mcpServers).Count).") -Recommendation (& $T 'Attach guardrails (content/prompt filters, tool restrictions) on the agent platform, at least for agents with tools or external data sources.' 'Guardrails (Inhalts-/Prompt-Filter, Tool-Einschränkungen) auf der Agent-Plattform hinterlegen, mindestens für Agents mit Tools oder externen Datenquellen.') -Subject "guard|$id"))
        }
        $ext = @($a.endpoints | Where-Object { $_.external -eq $true })
        if ($ext.Count) {
            $urls = (@($ext | ForEach-Object { $_.url } | Where-Object { $_ }) -join ', ')
            $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'Agent' -Title (& $T "Agent endpoint reachable from outside: $($a.name)" "Agent-Endpoint von außen erreichbar: $($a.name)") -Detail (& $T "Defender flags $($ext.Count) runtime endpoint(s) of this agent as externally connected$(if ($urls) { ": $urls" }). Conditional Access: $($a.caIdentity.status)." "Defender markiert $($ext.Count) Laufzeit-Endpoint(s) dieses Agents als extern erreichbar$(if ($urls) { ": $urls" }). Conditional Access: $($a.caIdentity.status).") -Recommendation (& $T 'Verify that the endpoint requires authentication and is covered by Conditional Access; remove endpoints that are not needed.' 'Prüfen, ob der Endpoint Authentifizierung verlangt und von Conditional Access erfasst ist; nicht benötigte Endpoints entfernen.') -Subject "ext|$id"))
        }
    }

    # Local agents (endpoints)
    foreach ($a in @($Agents | Where-Object { $_.agentType -eq 'Local' })) {
        $dev = if ($a.device) { $a.device.name } else { '?' }
        $subj = "local|$($a.defenderAgentId)"
        if ($a.autoApprove) {
            $f.Add((New-GapsioFinding -Severity 'High' -Category 'LocalAgent' -Title (& $T "Local agent runs actions without confirmation: $($a.name)" "Lokaler Agent führt Aktionen ohne Bestätigung aus: $($a.name)") `
                        -Detail (& $T "$($a.name) on $dev ($($a.user)) has auto-approve enabled: tool calls, shell commands and file changes run without the user confirming them." "$($a.name) auf $dev ($($a.user)) hat Auto-Approve aktiviert: Tool-Aufrufe, Shell-Befehle und Dateiänderungen laufen ohne Bestätigung durch den Benutzer.") `
                        -Recommendation (& $T 'Disable auto-approve or restrict it to read-only tools; enforce this through the vendor''s managed settings.' 'Auto-Approve abschalten oder auf lesende Werkzeuge beschränken; über die verwalteten Einstellungen des Herstellers erzwingen.') -Subject "$subj|auto" -DeviceId $a.device.id -DeviceName $dev))
        }
        $unpinned = @($a.mcpServers | Where-Object { $_.unpinned })
        if ($unpinned.Count) {
            $list = ($unpinned | ForEach-Object { "$($_.name) ($($_.command))" }) -join '; '
            $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'LocalAgent' -Title (& $T "MCP server loaded unpinned from a public registry: $($a.name)" "MCP-Server ohne feste Version aus öffentlicher Paketquelle: $($a.name)") `
                        -Detail (& $T "On $dev the agent starts MCP servers that are downloaded at run time without a pinned version: $list. A compromised package update runs immediately with the user's rights." "Auf $dev startet der Agent MCP-Server, die zur Laufzeit ohne feste Version geladen werden: $list. Ein kompromittiertes Paket-Update läuft sofort mit den Rechten des Benutzers.") `
                        -Recommendation (& $T 'Pin MCP servers to a version (or install them from an internal registry) and allow-list approved servers.' 'MCP-Server auf eine Version festlegen (bzw. aus interner Paketquelle installieren) und freigegebene Server per Allow-List erzwingen.') -Subject "$subj|mcp" -DeviceId $a.device.id -DeviceName $dev))
        }
        if ($a.trustedProcess -eq $false) {
            $f.Add((New-GapsioFinding -Severity 'Medium' -Category 'LocalAgent' -Title (& $T "Local agent from an untrusted process: $($a.name)" "Lokaler Agent aus nicht vertrauenswürdigem Prozess: $($a.name)") `
                        -Detail (& $T "Defender does not classify the process '$($a.process)' on $dev as trusted." "Defender stuft den Prozess '$($a.process)' auf $dev nicht als vertrauenswürdig ein.") `
                        -Recommendation (& $T 'Verify the origin and signature of the agent; block it if it is not approved.' 'Herkunft und Signatur des Agents prüfen; nicht freigegebene Agents blockieren.') -Subject "$subj|trust" -DeviceId $a.device.id -DeviceName $dev))
        }
        $d = $a.device
        if ($d -and ($d.tamper -eq 'BAD' -or [int]$d.localExclusions -gt 0)) {
            $why = @()
            if ($d.tamper -eq 'BAD') { $why += , @('Tamper Protection off', 'Tamper Protection aus') }
            if ([int]$d.localExclusions -gt 0) { $why += , @("$($d.localExclusions) local exclusion(s)", "$($d.localExclusions) lokale Exclusion(s)") }
            $f.Add((New-GapsioFinding -Severity $(if ($a.autoApprove) { 'Critical' } else { 'High' }) -Category 'Combined' -Title (& $T "Local agent on a weakened device: $($a.name)" "Lokaler Agent auf geschwächtem Gerät: $($a.name)") `
                        -Detail (& $T "$($a.name) runs on $dev, which has: $(($why | ForEach-Object { $_[0] }) -join ', ')$(if ($a.autoApprove) { ', and the agent runs actions without confirmation' }). Whatever the agent downloads or executes may not be detected." `
                            "$($a.name) läuft auf $dev mit: $(($why | ForEach-Object { $_[1] }) -join ', ')$(if ($a.autoApprove) { ', und der Agent führt Aktionen ohne Bestätigung aus' }). Was der Agent lädt oder ausführt, wird unter Umständen nicht erkannt.") `
                        -Recommendation (& $T 'Fix the device first (Tamper Protection, remove local exclusions), then allow the agent again.' 'Zuerst das Gerät absichern (Tamper Protection, lokale Exclusions entfernen), dann den Agent wieder zulassen.') -Subject "$subj|device" -DeviceId $d.id -DeviceName $dev))
        }
    }
    @($f | Sort-Object { $script:GapsioSeverityOrder[$_.severity] }, category, { Get-GapsioProp $_.title 'en' })
}

function Invoke-GapsioAgentsCollection {
    <#
    .SYNOPSIS
    Full run of the agents module; writes the snapshot and drift to storage.
    #>
    Reset-GapsioWarnings
    $started = [DateTime]::UtcNow
    Write-Information "Gapsio agents: start $($started.ToString('o'))" -InformationAction Continue

    $dir = Get-GapsioAgentDirectory
    $reg = Get-GapsioAgentRegistry
    $ai = Get-GapsioAgentsInfo
    $ca = Get-GapsioCaPolicies

    # Device state from the endpoint module (paged device collection) – only for the devices that host local agents
    $epDevices = @{}
    try {
        $ep = Get-GapsioBlob -Container 'state' -Name 'endpoint-latest.json'
        foreach ($d in @(Get-GapsioProp $ep 'devices')) { if ($d -and $d.deviceId) { $epDevices[[string]$d.deviceId] = $d } }   # snapshots of older versions
        $ids = @($ai | ForEach-Object { [string]$_.LocalDeviceId } | Where-Object { $_ } | Sort-Object -Unique)
        if ($ids.Count -and -not $epDevices.Count -and (Get-GapsioPagedMeta -Module 'endpoint' -Name 'devices')) {
            $ix = Get-GapsioPagedIndexRaw -Module 'endpoint' -Name 'devices'
            $idx = @{}; $ciId = $ix.cols['deviceId']; $ciPage = $ix.cols['page']
            if ($null -ne $ciId) { foreach ($r in $ix.rows) { $idx[$r[$ciId]] = [int]$r[$ciPage] } }
            $pages = @{}
            foreach ($id in $ids) {
                if (-not $idx.ContainsKey($id)) { continue }
                $p = $idx[$id]; if (-not $pages.ContainsKey($p)) { $pages[$p] = @(Get-GapsioPage -Module 'endpoint' -Name 'devices' -Page $p) }
                foreach ($d in $pages[$p]) { if ([string]$d.deviceId -eq $id) { $epDevices[$id] = $d } }
            }
        }
    }
    catch { }

    $agents = Get-GapsioAgentInventory -Directory $dir -Registry $reg -AgentsInfo $ai -Ca $ca -EndpointDevices $epDevices
    $policies = Get-GapsioAgentPolicySummary -Policies $ca.Policies -Agents $agents
    $findings = Get-GapsioAgentFindings -Agents $agents -PolicySummary $policies -SecurityDefaults $ca.SecurityDefaults

    $blueprints = foreach ($b in $dir.Blueprints) {
        $n = @($agents | Where-Object { $_.blueprintAppId -eq $b.appId }).Count
        [pscustomobject]@{ key = Get-GapsioHash "bp|$($b.id)"; fp = Get-GapsioHash "$($b.displayName)|$n"; label = New-GapsioText "Blueprint $($b.displayName)" "Blueprint $($b.displayName)"; state = "$n agent(s)"
            id = [string]$b.id; appId = [string]$b.appId; name = [string]$b.displayName; publisher = [string](Get-GapsioProp $b 'publisherDomain'); agents = $n
            hasPrincipal = [bool]$(@($dir.BlueprintPrincipals | Where-Object { $_.appId -eq $b.appId }).Count); created = [string](Get-GapsioProp $b 'createdDateTime') }
    }
    $sevCount = [ordered]@{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low') { $sevCount[$s] = @($findings | Where-Object { $_.severity -eq $s }).Count }
    $cloud = @($agents | Where-Object { $_.agentType -ne 'Local' })
    $local = @($agents | Where-Object { $_.agentType -eq 'Local' })
    $snapshot = [ordered]@{
        module           = 'agents'
        version          = (Get-GapsioVersion)
        generatedAt      = [DateTime]::UtcNow.ToString('o')
        tenantId         = Get-GapsioSetting -Name 'GAPSIO_TENANT_ID'
        securityDefaults = $ca.SecurityDefaults
        registryStatus   = $script:GapsioAgentRegistryStatus
        registrySource   = $script:GapsioAgentRegistrySource
        registryNote     = $script:GapsioAgentRegistryNote
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
        warnings         = @(Get-GapsioWarnings)
    }
    $r = Save-GapsioSnapshot -Module 'agents' -Snapshot $snapshot -Collections @('agents', 'blueprints', 'policies', 'findings') -Started $started
    Write-Information "Gapsio agents: done, $($r.changes) change(s), $($r.warnings) warning(s)." -InformationAction Continue
    $r
}
