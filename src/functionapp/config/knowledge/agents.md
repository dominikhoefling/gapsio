# AI agents

Feature `Agents` (on by default). Local agents additionally need the `Hunting` feature.

## Cloud agents

Inventory from **Microsoft Entra Agent ID**, the **Agent 365 package catalog** and Defender (**AgentsInfo**), per agent:

- **Blueprint ID** (app ID of the agent identity blueprint), **agent ID** (agent identity), **agent user ID**
- Sponsors, platform (Copilot Studio, Microsoft Foundry, custom …), sources
- From the Agent 365 package catalog: publisher, blocked state, availability/deployment
- Blueprints with their principals and agent count

Agent 365 data is read from the **Package Management API** (`GET /v1.0/copilot/admin/catalog/packages`, application
permission `CopilotPackages.Read.All`, requires an Agent 365 licence). If that is denied or unavailable, Gapsio falls
back to the legacy registry (`/beta/agentRegistry/agentInstances`, `AgentInstance.Read.All`, retired from May 2026) and
says so on the page. When the retired registry answers "not found" or a server error, the Agent 365 source is shown as
*not available* – a note, not a notice on every run. The snapshot exposes `registryStatus`, `registrySource` and `registryNote`.

### Defender AgentsInfo

Gapsio reads the Advanced Hunting table
[`AgentsInfo`](https://learn.microsoft.com/defender-xdr/advanced-hunting-agentsinfo-table) (one row per `AgentId`,
latest `Timestamp`): name, platform, description, version, Entra agent ID, Entra blueprint ID, `SourceAgentId`,
`PublishedStatus`, `LifecycleStatus`, `Availability`, `InstanceCount`, `Model`, the timestamps and the dynamic columns
`Owners`, `SharedWith`, `Permissions`, `Guardrails`, `Endpoints`, `McpServers`, `ConnectedAgents`, `DeclaredTools`,
`DeclaredDataSources`, `Channels`.

The table is in preview and its real columns differ from the schema reference: tenants have `Name`, `Description`,
`EntraAgentID` and `EntraBlueprintID` where the reference says `AgentName`, `AgentDescription`, `EntraAgentId` and
`EntraBlueprintId` (KQL is case-sensitive, so a query on the documented names fails). Gapsio therefore reads the
column list of the tenant's table first and builds the query from the columns that exist, under either name. A column
that exists under neither name gives an empty value and one notice that lists the missing columns and the columns
present.

The **inner structure of the dynamic columns is not documented**. Gapsio therefore only derives counts (tools, data
sources, permissions, shared-with entries), display names (owners, connected agents, channels) and looks up obvious
property names inside `Endpoints`/`McpServers` (`url`, `transport`, `external…`). Values that are missing are shown as
unknown, never as zero. Local agents on endpoints are read from `RawAgentInfo.localAgentMetadata`; if it is absent,
only cloud agents are listed. Microsoft documents the device of a local agent there as `aadDeviceId` and `deviceName`
and the user as `accountName`/`accountDomain`; Gapsio reads these next to the fields of earlier previews (`machineId`,
`upn`) and finds the endpoint device by Defender device ID, Entra device ID or name – in that order.

!!! warning "Column names verified against a tenant, contents not"
    The query runs against the column list of a real tenant (November 2026). The contents of the rows – above all the
    dynamic columns and `RawAgentInfo` – are not verified: the test tenant has no agents. If Microsoft changes the
    table again, the run reports a notice and the agent inventory falls back to Entra and the catalog. Please report
    deviations.

## Conditional Access coverage

Rated **separately for the agent identity and the agent user**, because a policy for one does not apply to the other:

| Status | Meaning |
|---|---|
| Protected | An enabled policy applies (directly, via the blueprint, or "All agent identities") |
| Report-only | Only report-only policies apply – nothing is enforced |
| Excluded | The agent is explicitly excluded |
| Unclear | Policies select agents by custom security attributes; Gapsio does not read the attributes |
| Not covered | No policy applies |
| Security defaults | Security defaults are on – Conditional Access is not evaluated at all |

Gapsio accounts for the fact that **"All users" does not include agent users**; they must be targeted via
"All agent users" or individually.

## Local agents

AI agents running on endpoints (coding assistants, IDE extensions …) from Defender AgentsInfo: vendor, device, user,
**auto-approve**, trusted and related processes and **local MCP servers** – including unpinned `npx`/`uvx` packages.
Each local agent is combined with the device's protection state (tamper protection, local exclusions, ASR below the
minimum, passive mode).

### Runtime protection for local agents

Defender for Endpoint can inspect the prompts and tool results of supported local agents and stop a detected prompt
injection (Defender Antivirus setting `AiAgentProtection`: off by default, audit or block; Windows, Defender for
Endpoint Plan 2). Gapsio shows for every local agent which mode the **assigned policies** set for its device – the
Intune antivirus profile *Microsoft Defender AI agent runtime protection* or the same template in the Defender portal:

| Value | Meaning |
|---|---|
| Block | A policy that reaches the device sets block mode |
| Audit only | Detected injections are reported, the agent action continues |
| Off / Not configured | A policy switches it off, or no assigned policy reaches the device |
| Policy conflict | Policies with different modes reach the device – Intune then applies none |
| Windows only | The device is not a Windows device |

Devices that host local agents without protection are one finding (High when an agent there runs without
confirmation, otherwise Medium); audit-only devices are a separate Low finding. The MDAV baseline has the matching
check for the whole fleet.

!!! warning "Configured, not effective"
    Defender does not report the effective value per device through Advanced Hunting (checked November 2026). A value
    set locally with `Set-MpPreference` or a script is therefore not visible, and Gapsio cannot confirm that a device
    has applied the policy. The setting ID was derived from the Defender CSP (`…/Defender/Configuration/AiAgentProtection`)
    and has not been confirmed against a tenant with such a policy yet. The second setting, `AiAgentNetworkInspection`
    (network inspection for agents without their own event interface), is not rated: the Intune profile did not
    offer it in every tenant at the time of writing.

## Findings

Agents without Conditional Access or sponsor, orphaned agent users, unknown blueprints, cloud agents without Entra
Agent ID, agents without guardrails (Defender reports an explicitly empty `Guardrails` value for a published, active
agent), agent endpoints flagged as externally connected, local agents with auto-approve, unpinned MCP servers, local
agents on weakened devices, devices with local agents and no (or audit-only) Defender runtime protection, security
defaults enabled.

!!! note "Licences"
    Entra Agent ID and Agent 365 require the corresponding licences. The agent APIs are in Microsoft Graph *beta*.
