# Wardline

[![CI](https://github.com/dominikhoefling/wardline/actions/workflows/ci.yml/badge.svg)](https://github.com/dominikhoefling/wardline/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dominikhoefling/wardline?display_name=tag&sort=semver)](https://github.com/dominikhoefling/wardline/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-teal.svg)](LICENSE)
[![Website](https://img.shields.io/badge/wardline.cloud-docs%20%26%20demo-0b6e82)](https://wardline.cloud)

**Configured isn't protected.** Wardline shows where protection in Microsoft Defender and for AI agents **actually** has
gaps – not just what is configured. Tools like Maester test what you set in the tenant; Wardline measures what is in
effect on the device: exclusions from every source, ASR rules in their effective mode, the Defender Antivirus baseline
with drift, Conditional Access coverage for AI agents and the real permission paths into Defender XDR.

It runs entirely in your own Azure subscription (self-hosted): no data leaves your tenant, no secrets, no
storage keys, read-only permissions only – granted per feature. Open source (MIT); the
[Enterprise key](https://wardline.cloud/#pricing) lifts the 10-row display limit and adds governance – every check
stays free, see the [open-core promise](docs/manifesto.md).

**Documentation:** see [`docs/`](docs/index.md) (published with MkDocs). **Website and demo:** [wardline.cloud](https://wardline.cloud).

## What it shows

- **Endpoint** – exclusions from every source for Windows, macOS and Linux (Intune, local on devices, allow indicators),
  exclusions that also blind EDR, ASR rules per device and device group, MDAV baseline with drift, combined findings,
  a page per device, Defender coverage gaps and exclusions without any activity in 30 days
- **AI agents** – cloud agents (Entra Agent ID, Agent 365, Defender AgentsInfo) with blueprint, agent and agent user IDs
  and their Conditional Access coverage; local AI agents on endpoints with auto-approve and MCP servers
- **Access** (optional) – Defender XDR unified RBAC: who holds which Defender role, how (direct, group, PIM eligible, access package), for which data sources – and whether it was ever used
- **Licensing** (optional) – Defender for Endpoint licence indication: plans owned vs. users entitled vs. client devices actually onboarded and who uses them; servers listed separately
- **Office preview** (optional, private preview) – Defender for Office 365 telemetry view: policy map (top recipients/domains), MDO trend probes and anti-phish drift (who changed settings, before/after outcome shifts)
- **Third-party AV/EDR** – devices running CrowdStrike, SentinelOne & co. alongside an active Defender Antivirus
- **History** – dated snapshots and drift between runs, accepted risks with audit log, notifications to Teams, CSV export; portal in English and German

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
Security review (threat model, data flows, SBOM): [docs/trust.md](docs/trust.md). Licence: [docs/licensing.md](docs/licensing.md). Support: [SUPPORT.md](SUPPORT.md).

## Contributing and licence

Contributions are welcome – see [CONTRIBUTING.md](CONTRIBUTING.md) (DCO, no CLA) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Working with an AI coding agent? Point it at [AGENTS.md](AGENTS.md).

Wardline is released under the [MIT License](LICENSE). "Wardline" and the logo are trademarks of Dominik Hoefling;
Microsoft, Microsoft Defender, Entra and Intune are trademarks of the Microsoft group of companies. Wardline is an
independent project and not affiliated with Microsoft.
