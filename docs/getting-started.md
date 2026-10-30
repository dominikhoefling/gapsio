# Quick start

This installs Wardline with the default features (Endpoint with Advanced Hunting and allow indicators, AI agents) into a
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
Invoke-WebRequest https://github.com/dominikhoefling/wardline/releases/latest/download/wardline.zip -OutFile wardline.zip
Expand-Archive wardline.zip -DestinationPath . -Force
cd wardline

# 2. Optional: see exactly which permissions will be granted
./setup/Install-Wardline.ps1 -ShowPermissions

# 3. Install
az login            # not needed in Cloud Shell
./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -Location westeurope
```

At the end the script prints the portal URL. Sign in with an account that has the **Wardline Administrator** app role
(the installing account gets it automatically; add more with `-AdminGroupId`).

!!! note "First run"
    New Graph permissions can take up to an hour to take effect. Missing data in the first run shows up as notices in
    the portal – click **Collect now** later. Device state from Defender (tamper protection, running mode) is refreshed
    by Defender every few hours, so the full picture is available by the next day.

## Next steps

- Choose features: [features and permissions](permissions.md)
- All installation options, device inventory, Deploy to Azure: [installation](installation.md)
- Keep Wardline current: [updates](updates.md)
