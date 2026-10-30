# Installation

`setup/Install-Wardline.ps1` deploys and configures everything. It is **idempotent**: run it again at any time to change
features or settings – data and history are kept.

What the script does:

1. Deploys the resource group and Azure resources (storage, Function App, monitoring, managed identity) from `deploy/main.bicep` (fallback: `deploy/azuredeploy.json`)
2. Creates the portal app registration for sign-in (no client secret, app role `Wardline.Admin`) – or attaches an existing one
3. Enables sign-in to the portal (App Service Authentication with Entra ID)
4. Grants the read-only permissions of the selected features – or attaches an existing data-access app
5. Deploys the function code and starts the first run

## Parameters

| Parameter | Meaning |
|---|---|
| `-ResourceGroup` | Resource group (created if it does not exist) |
| `-Location westeurope` | Azure region |
| `-Features Hunting,Indicators,Agents` | Features to enable (default shown; `Core` is always included). See [features and permissions](permissions.md). |
| `-AdminGroupId <objectId>` | Group that additionally receives the *Wardline Administrator* role |
| `-RestrictToAssignedUsers` | Only assigned users may sign in (otherwise all users of the tenant can open "My access" when the Access feature is on) |
| `-RetentionDays 730` | Retention of snapshots and change history (default 365) |
| `-EnableImmutability` | Store snapshots immutably (WORM). The policy is not locked initially; locking is a deliberate decision in the Azure portal. |
| `-StorageSku Standard_ZRS` | Zone-redundant storage |
| `-NamePrefix wardline` | Prefix for resource names (3–10 lower-case letters/digits) |
| `-NamingMode Default` / `-NamingMode Customized` | Default = generated names from `NamePrefix`; Customized = use explicit resource names below |
| `-FunctionAppName`, `-StorageAccountName`, `-RunnerIdentityName`, `-DeployIdentityName`, `-PlanName`, `-LogWorkspaceName`, `-AppInsightsName` | Optional custom Azure resource names (used when `-NamingMode Customized`) |
| `-PortalAppId`, `-DataAppId` | Attach app registrations created by the identity team ([separation of duties](separation-of-duties.md)) |
| `-SkipPermissionGrant` | Deploy everything but print the grant command for the identity team |
| `-ShowPermissions` | Only show the permissions of the selected features, change nothing |
| `-DeviceInventory`, `-DeviceInventoryGroupId`, `-RemoveDeviceInventory` | Optional device inventory, see below |
| `-SubscriptionId` | Subscription, if not the current one of `az` |

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
