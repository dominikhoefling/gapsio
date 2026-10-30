# AI agents

Feature `Agents` (on by default). Local agents additionally need the `Hunting` feature.

## Cloud agents

Inventory from **Microsoft Entra Agent ID**, the **Agent 365 package catalog** and Defender (**AgentsInfo**), per agent:

- **Blueprint ID** (app ID of the agent identity blueprint), **agent ID** (agent identity), **agent user ID**
- Sponsors, platform (Copilot Studio, Microsoft Foundry, custom …), sources
- From the Agent 365 package catalog: publisher, blocked state, availability/deployment
- Blueprints with their principals and agent count

Agent 365 data is read from the **Package Management API** (`GET /v1.0/copilot/admin/catalog/packages`, application
permission `CopilotPackages.Read.All`, requires an Agent 365 licence). If that is denied or unavailable, Wardline falls
back to the legacy registry (`/beta/agentRegistry/agentInstances`, `AgentInstance.Read.All`, retired from May 2026) and
says so on the page. The snapshot exposes `registryStatus`, `registrySource` and `registryNote`.

## Conditional Access coverage

Rated **separately for the agent identity and the agent user**, because a policy for one does not apply to the other:

| Status | Meaning |
|---|---|
| Protected | An enabled policy applies (directly, via the blueprint, or "All agent identities") |
| Report-only | Only report-only policies apply – nothing is enforced |
| Excluded | The agent is explicitly excluded |
| Unclear | Policies select agents by custom security attributes; Wardline does not read the attributes |
| Not covered | No policy applies |
| Security defaults | Security defaults are on – Conditional Access is not evaluated at all |

Wardline accounts for the fact that **"All users" does not include agent users**; they must be targeted via
"All agent users" or individually.

## Local agents

AI agents running on endpoints (coding assistants, IDE extensions …) from Defender AgentsInfo: vendor, device, user,
**auto-approve**, trusted and related processes and **local MCP servers** – including unpinned `npx`/`uvx` packages.
Each local agent is combined with the device's protection state (tamper protection, local exclusions, ASR below the
minimum, passive mode).

## Findings

Agents without Conditional Access or sponsor, orphaned agent users, unknown blueprints, cloud agents without Entra
Agent ID, local agents with auto-approve, unpinned MCP servers, local agents on weakened devices, security defaults enabled.

!!! note "Licences"
    Entra Agent ID and Agent 365 require the corresponding licences. The agent APIs are in Microsoft Graph *beta*.
