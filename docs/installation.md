# Installation

`setup/Install-Wardline.ps1` deploys and configures everything. It is **idempotent**: run it again at any time to change
features or settings – data and history are kept.

What the script does:

1. Deploys the resource group and Azure resources (storage, Function App, monitoring, managed identity) from `deploy/azuredeploy.json` (compiled from `deploy/main.bicep`)
2. Creates the portal app registration for sign-in (no client secret, app role `Wardline.Admin`) – or attaches an existing one
3. Enables sign-in to the portal (App Service Authentication with Entra ID)
4. Grants the read-only permissions of the selected features – or attaches an existing data-access app
5. Deploys the function code and starts the first run

## Parameters

| Parameter | Meaning |
|---|---|
| `-ResourceGroup` | Resource group (created if it does not exist) |
| `-Location westeurope` | Azure region |
| `-Features Hunting,Indicators,Coverage,Response,Agents` | Features to enable (default shown; `Core` is always included). See [features and permissions](permissions.md). |
| `-AdminGroupId <objectId>` | Group that additionally receives the *Wardline Administrator* role |
| `-RestrictToAssignedUsers` | Only assigned users may sign in (otherwise all users of the tenant can open "My access" when the Access feature is on) |
| `-SnapshotRetentionDays 730` | Retention of the dated snapshots (storage lifecycle and, with `-EnableImmutability`, the WORM period; default 365) |
| `-ChangeRetentionDays 180` | Retention of the change history shown in the portal (default 365) |
| `-RetentionDays 730` | Sets both at once; the two parameters above win. Re-runs keep the current values. |
| `-EnableImmutability` | Store snapshots immutably (WORM). The policy is not locked initially; locking is a deliberate decision in the Azure portal. |
| `-StorageSku Standard_ZRS` | Zone-redundant storage |
| `-NamePrefix wardline` | Prefix for resource names (3–10 lower-case letters/digits) |
| `-NamingMode Default` / `-NamingMode Customized` | Default = generated names from `NamePrefix`; Customized = use explicit resource names below |
| `-FunctionAppName`, `-StorageAccountName`, `-RunnerIdentityName`, `-DeployIdentityName`, `-PlanName`, `-LogWorkspaceName`, `-AppInsightsName` | Optional custom Azure resource names (used when `-NamingMode Customized`) |

Re-runs and updates find an existing installation by the tag `wardline-component` on its resources and keep its names automatically – you do not have to repeat the naming parameters. Renaming an existing installation is not supported.
| `-PortalAppId`, `-DataAppId` | Attach app registrations created by the identity team ([separation of duties](separation-of-duties.md)) |
| `-NotifyWebhookUrl`, `-NotifyMinSeverity High` | Notifications about new findings to Teams or Power Automate ([operations](operations.md#notifications)) |
| `-SkipPermissionGrant` | Deploy everything but print the grant command for the identity team |
| `-ShowPermissions` | Only show the permissions of the selected features, change nothing |
| `-DeviceInventory`, `-DeviceInventoryGroupId`, `-RemoveDeviceInventory` | Optional device inventory, see below |
| `-Assistant`, `-AssistantEndpoint`, `-AssistantDeployment`, `-AssistantEmbeddingDeployment`, `-AssistantLocation` | Optional portal assistant (Azure OpenAI in your subscription), see below |
| `-SubscriptionId` | Subscription, if not the current one of `az` |

## Optional: portal assistant

`-Assistant` adds a chat helper to the portal (admins only, **Enterprise licence required** – Community installations see the entry point with an upgrade hint). It explains findings in plain language, answers “what should I fix first?” and points to the right view – it never changes anything and never replaces the tables.

- **Where it runs:** an Azure OpenAI resource with a `gpt-4.1-mini` chat deployment and a `text-embedding-3-small` embedding deployment **in your own subscription**, created by the installer (`-AssistantLocation` picks the region, default = installation region; `swedencentral` has the broadest model availability). Or point to an existing resource with `-AssistantEndpoint https://<name>.openai.azure.com/` and grant Wardline's runner identity the role *Cognitive Services OpenAI User* on it (`-AssistantEmbeddingDeployment ''` if that resource has no embedding model – doc search then falls back to keywords).
- **Authentication:** managed identity only; key-based access on the created resource is disabled.
- **How it answers:** the model gets a compact server-built summary (enabled modules, view list, per-module counts, top 40 findings) and a set of **read-only tools** it can call: search the stored findings and devices of the last run, fetch one device record, query **Microsoft Defender Advanced Hunting live** (last seen, sensor health, alerts of the last 7 days, failed secure-configuration checks – only if the *hunting* feature is enabled), and a semantic search over the Wardline documentation and the MDAV baseline rationale. Answers show which tools were used and which doc sections were cited. Never full lists, never tokens or settings; Azure OpenAI does not use your prompts for training. Abuse monitoring can be switched off per subscription via Microsoft's *Modified Abuse Monitoring* form (https://aka.ms/oai/modifiedabusemonitoring).
- **Knowledge index:** built on first use from `config/knowledge/*.md` and `mdav-baseline.json` and stored as `state/assistant-index.json`; rebuilt automatically when the docs or the embedding deployment change.
- **Cost:** pay-as-you-go tokens; a typical question with one or two tool calls is 6–12k tokens (around a cent). Advanced Hunting calls count against the tenant's API quota like the collectors.
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
./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -DeviceInventory                                # all devices
./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -DeviceInventory -DeviceInventoryGroupId <id>   # one device group only
./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -RemoveDeviceInventory                          # back to Advanced Hunting only
```

The detection script (`setup/assets/Get-WardlineLocalExclusions.ps1`) runs daily at 01:00 UTC as SYSTEM, reads the
exclusion registry keys plus tamper protection and running mode, and returns compact JSON. Devices with local
exclusions show up in Intune as "with issues".

## Deploy to Azure button

1. Use the release assets `azuredeploy.json` and `wardline-functionapp.zip`.
2. Button link: `https://portal.azure.com/#create/Microsoft.Template/uri/<URL-encoded link to azuredeploy.json>`
3. Set `packageUri` in the form to the URL of `wardline-functionapp.zip` – the code is deployed as well.
4. Afterwards run `setup/Install-Wardline.ps1` once with the same resource group. The Entra steps (app registration,
   permissions) need admin rights in the tenant and cannot be done safely in an ARM template. Until then the portal stays locked.

## Uninstall

```powershell
./setup/Uninstall-Wardline.ps1 -ResourceGroup rg-wardline
```

Deletes the resource group (including all snapshots) and the portal app registration created by the install script.
App registrations created up front by the identity team are not deleted. If immutability is enabled and locked, Azure
only allows deleting the storage account after the retention period.
