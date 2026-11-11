# Quick start

This installs Gapsio with the default features (Endpoint with Advanced Hunting, allow indicators and coverage gaps, AI agents) into a
new resource group. It takes about 10 minutes.

## What you need

- Azure: **Owner** (or Contributor + User Access Administrator) on the subscription or resource group
- Entra ID: **Application Administrator** and **Privileged Role Administrator** – or let your identity team prepare
  the app registrations ([separation of duties](separation-of-duties.md))
- Microsoft Defender for Endpoint P2 / Defender XDR (for Advanced Hunting) and Intune
- **Azure Cloud Shell (PowerShell)** – PowerShell 7 and the Azure CLI are already there. Locally you need
  PowerShell 7.2+ and the Azure CLI (`brew install powershell azure-cli` or `winget install Microsoft.PowerShell Microsoft.AzureCLI`).

## Install

```powershell
# 1. Download and extract the latest release
Invoke-WebRequest https://github.com/dominikhoefling/gapsio/releases/latest/download/gapsio.zip -OutFile gapsio.zip
Expand-Archive gapsio.zip -DestinationPath . -Force
cd gapsio

# 2. Optional: see exactly which permissions will be granted
./setup/Install-Gapsio.ps1 -ShowPermissions

# 3. Install
az login            # not needed in Cloud Shell
./setup/Install-Gapsio.ps1 -ResourceGroup rg-gapsio -Location westeurope
```

At the end the script prints the portal URL. Sign in with an account that has the **Gapsio Administrator** app role
(the installing account gets it automatically; add more with `-AdminGroupId`).

!!! note "First run"
    New Graph permissions take effect with the managed identity's next token – usually within an hour, at most 24 hours.
    Missing data in the first run shows up as notices (HTTP 403) in the portal – click **Collect now** later. Device state from Defender (tamper protection, running mode) is refreshed
    by Defender every few hours, so the full picture is available by the next day.

## Next steps

- Choose features: [features and permissions](permissions.md)
- All installation options, device inventory, Deploy to Azure: [installation](installation.md)
- Keep Gapsio current: [updates](updates.md)

## Script reference (GitHub)

If you need the full parameter surface for install/update/permission flows:

- [`setup/Install-Gapsio.ps1`](https://github.com/dominikhoefling/gapsio/blob/main/setup/Install-Gapsio.ps1)
- [`setup/Update-Gapsio.ps1`](https://github.com/dominikhoefling/gapsio/blob/main/setup/Update-Gapsio.ps1)
- [`setup/Grant-GapsioPermissions.ps1`](https://github.com/dominikhoefling/gapsio/blob/main/setup/Grant-GapsioPermissions.ps1)

Use `Get-Help` locally for the exact release package version you run.
