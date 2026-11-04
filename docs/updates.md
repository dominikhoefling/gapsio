# Updates

Gapsio **never updates itself**. You decide when a new version goes into your tenant.

## How you learn about a new release

- Once a day the Function App asks the GitHub releases API for the latest Gapsio release. It is an anonymous GET
  request – **no tenant data is sent**. The result is stored in your storage account.
- Administrators see **"Update available: x.y.z"** in the portal sidebar, linked to the release notes.
- Turn the check off with the app setting `GAPSIO_UPDATE_CHECK=false` (or the Bicep parameter `updateCheck=false`).
- You can also watch the GitHub repository (**Watch › Custom › Releases**) to get an e-mail for every release.

## Updating

```powershell
az login
./setup/Update-Gapsio.ps1 -ResourceGroup rg-gapsio -CheckOnly   # what would change
./setup/Update-Gapsio.ps1 -ResourceGroup rg-gapsio              # update to the latest release
./setup/Update-Gapsio.ps1 -ResourceGroup rg-gapsio -Version 0.6.0
```

Role needed: Contributor (or Website Contributor) on the resource group. The script

1. finds the Gapsio Function App and reads the installed version and features,
2. downloads the release assets from GitHub,
3. verifies the **SHA256 checksums** – and the **build provenance attestation** if the GitHub CLI (`gh`) is installed,
4. checks whether the release needs **additional permissions** for your features (reported; granted only with
   `-GrantPermissions`, which needs Privileged Role Administrator),
5. checks whether the release **changes the Azure resources** – if so, it tells you to run `Install-Gapsio.ps1` from
   the new release with your usual parameters (idempotent, keeps data and settings),
6. deploys the new function package. Data, history, settings and permissions stay as they are.

If the deployment fails, the previous version keeps running.

## Offline / air-gapped

Download `gapsio-functionapp.zip`, `SHA256SUMS`, `permissions.json` and `release.json` from the release into one
folder and run:

```powershell
./setup/Update-Gapsio.ps1 -ResourceGroup rg-gapsio -PackagePath ./release/gapsio-functionapp.zip
```

## Verify a release yourself

```powershell
gh attestation verify gapsio-functionapp.zip --repo dominikhoefling/gapsio
Get-FileHash -Algorithm SHA256 gapsio-functionapp.zip   # compare with SHA256SUMS
```

## Versioning

Gapsio uses [semantic versioning](https://semver.org/):

| Change | Example | What to expect |
|---|---|---|
| Patch | 0.4.0 → 0.4.1 | Bug fixes only. No new permissions, no template changes. |
| Minor | 0.4.x → 0.5.0 | New features. May need new permissions or a template update – the update script tells you. |
| Major | 0.x → 1.0 | Breaking changes, described in the release notes. |

Release assets (same names in every release, so `releases/latest/download/<name>` always works):

| Asset | Used for |
|---|---|
| `gapsio.zip` | New installation (setup scripts, template, function package) |
| `gapsio-functionapp.zip` | Code update, Deploy to Azure button |
| `azuredeploy.json` | Deploy to Azure button, template change detection |
| `permissions.json` | Permission check of the update script |
| `release.json` | Version and template hash |
| `SHA256SUMS` | Checksums of all assets |

## API stability and Graph versions

- Endpoints that exist in Microsoft Graph **v1.0** with the same data (Agent ID, Conditional Access, Entra and Intune role
  management) are called **v1.0 first**, with an automatic fallback to **beta**.
- Intune endpoints that only exist in **beta** (Settings Catalog, endpoint security templates, Remediations, legacy
  device configuration properties) are called in beta directly – a v1.0 attempt would only add failing calls or miss properties.
- Agent 365: the Package Management API (`/v1.0/copilot/admin/catalog/packages`) is used first; the legacy registry (`/beta/agentRegistry/agentInstances`) is only a fallback until its retirement.
