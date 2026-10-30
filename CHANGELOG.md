# Changelog

All notable changes to Wardline are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and Wardline uses [Semantic Versioning](https://semver.org/): a new **minor** version can add features and permissions,
a **patch** version only fixes bugs. Update with `./setup/Update-Wardline.ps1 -ResourceGroup <resource group>`.

## [0.4.0] – unreleased

First version published on GitHub.

### Added
- **AI agents module**: cloud agents (Entra Agent ID, Agent 365 registry, Defender AgentsInfo) with blueprint ID, agent ID and agent user ID, and Conditional Access coverage rated separately for agent identity and agent user.
- **Local AI agents** on endpoints (Defender AgentsInfo): auto-approve, trusted processes, unpinned MCP servers, combined with the device's protection state.
- **ASR rules** on three levels (target · configured · effective), per Defender device group and per device, including policy conflicts and per-rule exclusions.
- **EDR exclusions** view (Linux global exclusions, allow indicators) and **Linux** exclusions, baseline checks and local `mdatp config` weakening.
- **Least privilege per feature** (`-Features Core,Hunting,Indicators,Agents,Access,Inventory`); permissions that are no longer needed are removed.
- **Separation of duties**: app registrations can be created up front by the identity team (`New-WardlineAppRegistrations.ps1`) and attached with `-PortalAppId` / `-DataAppId`; the data-access app is used via workload identity federation (no secret).
- **English/German portal** with a language switch; all scripts and installation output in English.
- **Updates**: daily check for new releases (shown in the portal, no tenant data sent, `WL_UPDATE_CHECK=false` to disable) and `Update-Wardline.ps1` with checksum verification, permission and template change detection.

### Changed
- The access module (PIM, roles, access packages) is optional and off by default (`-Features …,Access`).
- **Graph API stability hardening**: agent and Intune data collection now use **v1.0 first** and fall back to **beta** only when the endpoint is not yet available in v1.0.
- **Beta scope reduced**: Agent Registry (`/agentRegistry/agentInstances`) remains beta-based for now (plus announced transition to Agent 365 APIs).
