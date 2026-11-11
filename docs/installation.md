# Installation

`setup/Install-Gapsio.ps1` deploys and configures everything. It is **idempotent**: run it again at any time to change
features or settings – data and history are kept.

For the full script surface (including less common switches), use the source and inline help on GitHub:

- [`setup/Install-Gapsio.ps1`](https://github.com/dominikhoefling/gapsio/blob/main/setup/Install-Gapsio.ps1)
- [`setup/Grant-GapsioPermissions.ps1`](https://github.com/dominikhoefling/gapsio/blob/main/setup/Grant-GapsioPermissions.ps1)
- [`setup/Update-Gapsio.ps1`](https://github.com/dominikhoefling/gapsio/blob/main/setup/Update-Gapsio.ps1)
- [`setup/Uninstall-Gapsio.ps1`](https://github.com/dominikhoefling/gapsio/blob/main/setup/Uninstall-Gapsio.ps1)

Tip: run `Get-Help ./setup/Install-Gapsio.ps1 -Detailed` (or `-Full`) in PowerShell for the current release package.

What the script does:

1. Deploys the resource group and Azure resources (storage, Function App, monitoring, managed identity) from `deploy/azuredeploy.json` (compiled from `deploy/main.bicep`)
2. Creates the portal app registration for sign-in (no client secret, app role `Gapsio.Admin`) – or attaches an existing one
3. Enables sign-in to the portal (App Service Authentication with Entra ID)
4. Grants the read-only permissions of the selected features – or attaches an existing data-access app
5. Deploys the function code and starts the first run

## Parameters

> The table below covers the common parameters. The complete and always up-to-date list is in the script help and GitHub source links above.

| Parameter | Meaning |
|---|---|
| `-ResourceGroup` | Resource group (created if it does not exist) |
| `-Location westeurope` | Azure region |
| `-Features Hunting,Indicators,Coverage,Response,Agents` | Features to enable (default shown; `Core` is always included). See [features and permissions](permissions.md). |
| `-AdminGroupId <objectId>` | Group that additionally receives the *Gapsio Administrator* role |
| `-RestrictToAssignedUsers` | Only assigned users may sign in (otherwise all users of the tenant can open "My access" when the Access feature is on) |
| `-SnapshotRetentionDays 730` | Retention of the dated snapshots (storage lifecycle and, with `-EnableImmutability`, the WORM period; default 365) |
| `-ChangeRetentionDays 180` | Retention of the change history shown in the portal (default 365) |
| `-RetentionDays 730` | Sets both at once; the two parameters above win. Re-runs keep the current values. |
| `-EnableImmutability` | Store snapshots immutably (WORM). The policy is not locked initially; locking is a deliberate decision in the Azure portal. |
| `-StorageSku Standard_ZRS` | Zone-redundant storage |
| `-NamePrefix gapsio` | Prefix for resource names (3–10 lower-case letters/digits) |
| `-NamingMode Default` / `-NamingMode Customized` | Default = generated names from `NamePrefix`; Customized = use explicit resource names below |
| `-FunctionAppName`, `-StorageAccountName`, `-RunnerIdentityName`, `-DeployIdentityName`, `-PlanName`, `-LogWorkspaceName`, `-AppInsightsName` | Optional custom Azure resource names (used when `-NamingMode Customized`) |

Re-runs and updates find an existing installation by the tag `gapsio-component` on its resources and keep its names automatically – you do not have to repeat the naming parameters. Renaming an existing installation is not supported.
| `-PortalAppId`, `-DataAppId` | Attach app registrations created by the identity team ([separation of duties](separation-of-duties.md)) |
| `-NotifyWebhookUrl`, `-NotifyMinSeverity High` | Notifications about new findings to Teams or Power Automate ([operations](operations.md#notifications)) |
| `-SkipPermissionGrant` | Deploy everything but print the grant command for the identity team |
| `-ShowPermissions` | Only show the permissions of the selected features, change nothing |
| `-DeviceInventory`, `-DeviceInventoryGroupId`, `-RemoveDeviceInventory` | Optional device inventory, see below |
| `-Assistant`, `-AssistantEndpoint`, `-AssistantDeployment`, `-AssistantEmbeddingDeployment`, `-AssistantLocation` | Optional portal assistant (Azure OpenAI in your subscription), see below |
| `-SubscriptionId` | Subscription, if not the current one of `az` |

### Which modules exist (and how they are enabled)

`GAPSIO_MODULES` is derived from `-Features` on every install/update run:

| Module (`GAPSIO_MODULES`) | Enabled by feature(s) |
|---|---|
| `endpoint` | always (`Core`) |
| `agents` | `Agents` |
| `access` | `Access` |
| `licensing` | `Licensing` |
| `officepreview` | `OfficePreview` (private preview) |
| `purviewpreview` | `PurviewPreview` (private preview) |

Example: enable the Office preview module in addition to the defaults:

```powershell
./setup/Install-Gapsio.ps1 -ResourceGroup rg-gapsio -Features Hunting,Indicators,Coverage,Response,Agents,OfficePreview
```

## Optional: portal assistant

`-Assistant` adds a chat helper to the portal (admins only). It explains findings in plain language, answers “what should I fix first?” and points to the right view – it never changes anything and never replaces the tables.

- **Where it runs:** an Azure OpenAI resource with a `gpt-4.1-mini` chat deployment and a `text-embedding-3-small` embedding deployment **in your own subscription**, created by the installer (`-AssistantLocation` picks the region, default = installation region; `swedencentral` has the broadest model availability). Or point to an existing resource with `-AssistantEndpoint https://<name>.openai.azure.com/` and grant Gapsio's runner identity the role *Cognitive Services OpenAI User* on it (`-AssistantEmbeddingDeployment ''` if that resource has no embedding model – doc search then falls back to keywords).
- **Authentication:** managed identity only; key-based access on the created resource is disabled.
- **How it answers:** the model gets a compact server-built summary (enabled modules, view list, per-module counts, the devices your question names, and the most severe findings as far as they fit) and a set of **read-only tools** it can call: search the stored findings and devices of the last run, fetch one device record, query **Microsoft Defender Advanced Hunting live** (last seen, sensor health, alerts of the last 7 days, failed secure-configuration checks – only if the *hunting* feature is enabled), and a semantic search over the Gapsio documentation and the MDAV baseline rationale. Answers show which tools were used and which doc sections were cited. A live query that fails is reported as failed, never as "nothing found"; a device that no longer reports is described as *last known state*; links only point to views and devices that exist. Never full lists, never tokens or settings; Azure OpenAI does not use your prompts for training. Abuse monitoring can be switched off per subscription via Microsoft's *Modified Abuse Monitoring* form (https://aka.ms/oai/modifiedabusemonitoring).
- **Knowledge index:** the documentation pages shipped with the Function App (`config/knowledge/*.md`: modules, permissions, operations, installation, compliance …) and every check of `mdav-baseline.json` with its rationale and fix – about 200 sections. Built with the regular endpoint run (or on first use), stored as `state/assistant-index.json` and kept in memory; rebuilt when the pages or the embedding deployment change. If embedding fails – no embedding deployment, rate limit – the search falls back to keywords and embedding is tried again later. No Azure AI Search and no other service is involved; the index never contains tenant data.
- **Cost:** pay-as-you-go tokens; a typical question with one or two tool calls is 6–12k tokens (around a cent). Advanced Hunting calls count against the tenant's API quota like the collectors.
- **Capacity:** the installer creates the chat deployment with 50,000 tokens per minute. Capacity is a rate limit, not a price – billing is per token. Installations created before version 0.8.2 have 10,000, which is too small for a question with tool calls; see [operations](operations.md#notices-after-a-run) for the one command that raises it.
- **Turn off:** re-run the installer with `-Assistant:$false` and delete the `oai-*` resource if it was created for you.

## Local exclusions: Advanced Hunting only, or device inventory as well

| | Default (Advanced Hunting only) | `-DeviceInventory` (additionally) |
|---|---|---|
| Component on devices | none | detection script via Intune Remediations (read-only, no remediation script) |
| Visible | changes from the last 30 days before installation and everything afterwards (incl. drift) | additionally **all** local exclusions currently present, including older ones |
| DisableLocalAdminMerge | derived from policies (tenant-wide) | actually effective value **per device** |
| Requirements | Defender for Endpoint P2 / Defender XDR | additionally Intune and Windows Enterprise E3/E5 (or Education/VDA), module `Microsoft.Graph.Authentication` |
| Platforms | Windows, macOS, Linux | Windows only (macOS/Linux still via Advanced Hunting) |

```powershell
./setup/Install-Gapsio.ps1 -ResourceGroup rg-gapsio -DeviceInventory                                # all devices
./setup/Install-Gapsio.ps1 -ResourceGroup rg-gapsio -DeviceInventory -DeviceInventoryGroupId <id>   # one device group only
./setup/Install-Gapsio.ps1 -ResourceGroup rg-gapsio -RemoveDeviceInventory                          # back to Advanced Hunting only
```

The detection script (`setup/assets/Get-GapsioLocalExclusions.ps1`) runs daily at 01:00 UTC as SYSTEM, reads the
exclusion registry keys plus tamper protection and running mode, and returns compact JSON. Devices with local
exclusions show up in Intune as "with issues".

## Deploy to Azure button

1. Use the release assets `azuredeploy.json` and `gapsio-functionapp.zip`.
2. Button link: `https://portal.azure.com/#create/Microsoft.Template/uri/<URL-encoded link to azuredeploy.json>`
3. Set `packageUri` in the form to the URL of `gapsio-functionapp.zip` – the code is deployed as well.
4. Afterwards run `setup/Install-Gapsio.ps1` once with the same resource group. The Entra steps (app registration,
   permissions) need admin rights in the tenant and cannot be done safely in an ARM template. Until then the portal stays locked.

## Uninstall

```powershell
./setup/Uninstall-Gapsio.ps1 -ResourceGroup rg-gapsio
```

Deletes the resource group (including all snapshots) and the portal app registration created by the install script.
App registrations created up front by the identity team are not deleted. If immutability is enabled and locked, Azure
only allows deleting the storage account after the retention period.
