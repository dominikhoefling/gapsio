# Wardline

Wardline shows where protection in Microsoft Defender and for AI agents **actually** has gaps – not just what is
configured. It runs entirely in your own Azure subscription (self-hosted): no data leaves your tenant, no secrets, no
storage keys, read-only permissions only – granted per feature.

**Documentation:** see [`docs/`](docs/index.md) (published with MkDocs).

## What it shows

- **Endpoint** – exclusions from every source for Windows, macOS and Linux (Intune, local on devices, allow indicators),
  exclusions that also blind EDR, ASR rules per device and device group, MDAV baseline with drift, combined findings
- **AI agents** – cloud agents (Entra Agent ID, Agent 365, Defender AgentsInfo) with blueprint, agent and agent user IDs
  and their Conditional Access coverage; local AI agents on endpoints with auto-approve and MCP servers
- **Access** (optional) – admin roles: active, eligible via PIM, requestable via access packages
- **History** – dated snapshots and drift between runs, CSV export; portal in English and German

## Quick start (Azure Cloud Shell, PowerShell)

```powershell
Invoke-WebRequest https://github.com/dominikhoefling/wardline/releases/latest/download/wardline.zip -OutFile wardline.zip
Expand-Archive wardline.zip -DestinationPath . -Force; cd wardline
./setup/Install-Wardline.ps1 -ShowPermissions                       # what will be granted
./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -Location westeurope
```

Large organisations: the identity team can create the app registrations up front
(`setup/New-WardlineAppRegistrations.ps1`), the Azure team only attaches them – see
[separation of duties](docs/separation-of-duties.md).

## Updates

The portal shows when a new release is available. Wardline never updates itself:

```powershell
./setup/Update-Wardline.ps1 -ResourceGroup rg-wardline
```

Checksums are verified, new permissions and template changes are reported before anything changes – see [updates](docs/updates.md).

## Development

```powershell
pwsh ./tests/Test-Wardline.ps1          # tests, no Azure needed
pwsh ./build/New-WardlineDemo.ps1       # portal offline with sample data: dist/demo/index.html
pwsh ./build/New-WardlineRelease.ps1    # release assets: dist/release
```

Releases are published by tagging (`git tag v0.4.0 && git push origin v0.4.0`) – see [development](docs/development.md).
Security issues: please report privately, see [SECURITY.md](SECURITY.md). Changes: [CHANGELOG.md](CHANGELOG.md).
