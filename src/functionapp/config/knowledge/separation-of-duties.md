# Separation of duties

In large organisations app registrations and admin consent are usually owned by the identity team, Azure resources by
the platform team. Gapsio supports this without any secrets: the identity team prepares the app registrations, the
Azure team only attaches them.

## 1. Identity team: create the app registrations

Roles: Application Administrator (apps) and Privileged Role Administrator (consent).

```powershell
az login
./setup/New-GapsioAppRegistrations.ps1 -Features Hunting,Indicators,Coverage,Response,Agents -AdminGroupId <objectId>
```

This creates (idempotently):

| App | Purpose | Permissions |
|---|---|---|
| **Gapsio Portal** | Sign-in to the portal, app role `Gapsio.Admin` | delegated `openid profile email User.Read` (admin consent), no secret |
| **Gapsio Data Access** | Read-only data access for the selected features | application permissions per feature (admin consent), no secret |

Hand over both app IDs to the Azure team.

## 2. Azure team: install and attach

No Entra admin role needed.

```powershell
./setup/Install-Gapsio.ps1 -ResourceGroup rg-gapsio -PortalAppId <portal appId> -DataAppId <data appId> -Features Hunting,Indicators,Coverage,Response,Agents
```

The script adds the redirect URI to the portal app and the federated credential to the data app if it is allowed to.
Otherwise it prints what the identity team has to add.

## 3. Identity team (only if the Azure team may not edit the apps)

```powershell
# Allow the Gapsio managed identity to sign in as the data-access app (workload identity federation)
./setup/New-GapsioAppRegistrations.ps1 -SkipPortalApp -DataAppId <data appId> -ManagedIdentityPrincipalId <objectId of id-gapsio-runner>

# Redirect URI of the portal
./setup/New-GapsioAppRegistrations.ps1 -SkipDataApp -PortalAppId <portal appId> -PortalHostName <function app>.azurewebsites.net
```

The federated credential uses issuer `https://login.microsoftonline.com/<tenant>/v2.0`, subject = object ID of the
managed identity and audience `api://AzureADTokenExchange`. Storage access always uses the managed identity directly.

## Alternative: grant to the managed identity

Install with `-SkipPermissionGrant`. The script prints the command for the identity team:

```powershell
./setup/Grant-GapsioPermissions.ps1 -PrincipalId <objectId of the managed identity> -Features Hunting,Indicators,Coverage,Response,Agents -Prune
./setup/Grant-GapsioPermissions.ps1 -Features Hunting,Agents -ShowOnly     # preview
```
