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

- **Device page**: protection state incl. network protection, controlled folder access and EDR in block mode, ASR per rule, local exclusions, findings, local AI agents, changes and links to Defender and Intune.
- **Defender coverage gaps**: Intune devices not onboarded (feature `Coverage`), inactive or impaired sensors, discovered devices.
- **Unused exclusions**: exclusions without process or file activity in 30 days (Advanced Hunting).
- **Accepted risks**: accept findings and exclusions with justification, owner, ticket and expiry date; audit log.
- **Notifications** about new findings to Teams workflows or Power Automate (`-NotifyWebhookUrl`).
- **Clearer HTTP 403 notices**: when the token was issued and whether the required permission is in it.

### Changed
- Agent 365 registry: HTTP 404 (registry not available in the tenant) is shown as a note instead of a warning.
- The access module (PIM, roles, access packages) is optional and off by default (`-Features …,Access`).
- **Graph API stability**: Agent ID, Conditional Access and role management use Microsoft Graph **v1.0 first** with a remembered fallback to **beta**; beta-only Intune endpoints (Settings Catalog, templates, Remediations) stay on beta. The Agent 365 registry remains beta-only.
