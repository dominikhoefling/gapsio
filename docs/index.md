# Wardline

Wardline shows where protection in Microsoft Defender and for AI agents **actually** has gaps – not just what is configured.
It runs entirely in your own Azure subscription: no data leaves your tenant, there are no secrets or storage keys, and
it uses read-only permissions only, granted per feature.

<div class="grid cards" markdown>

- **Endpoint** – exclusions from every source (Windows, macOS, Linux), local exclusions on devices, EDR exclusions,
  ASR rules per device and device group, MDAV baseline with drift. [More](modules/endpoint.md)
- **AI agents** – cloud agents from Entra Agent ID and Agent 365 with blueprint, agent and agent user IDs, Conditional
  Access coverage, and local AI agents on endpoints. [More](modules/agents.md)
- **Access** (optional) – who holds which admin role: active, eligible via PIM or requestable via access packages.
  [More](modules/access.md)
- **History** – dated snapshots in your storage account, drift between runs, CSV export of every table.

</div>

## How it works

```
Your subscription / resource group
┌──────────────────────────────────────────────────────────────────────┐
│  Function App (Flex Consumption, PowerShell 7.4)                     │
│   ├─ daily collection ──► Microsoft Graph, Advanced Hunting,         │
│   │                       Defender for Endpoint API (read-only)      │
│   ├─ API + portal  ◄── Entra ID sign-in (no client secret)           │
│   └─ managed identity ──► storage account (Entra auth only)          │
└──────────────────────────────────────────────────────────────────────┘
```

1. An administrator installs Wardline with one script (Azure Cloud Shell is enough) – see the [quick start](getting-started.md).
2. Wardline collects once a day and on demand ("Collect now" in the portal).
3. Administrators see findings, exclusions, ASR, baseline, agents and changes in the portal – in English or German.
4. New releases are announced in the portal; you update with one command – see [updates](updates.md).

## Principles

- **Self-hosted** – everything runs and stays in your subscription and region.
- **Least privilege** – each feature adds only the read-only permissions it needs ([details](permissions.md)).
- **No secrets** – managed identity, workload identity federation, App Service Authentication without a client secret.
- **Fits large organisations** – the identity team can create the app registrations up front, the Azure team only
  attaches them ([separation of duties](separation-of-duties.md)).
- **You stay in control of updates** – Wardline never updates itself.
