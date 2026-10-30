# Changelog

All notable changes to Wardline are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and Wardline uses [Semantic Versioning](https://semver.org/): a new **minor** version can add features and permissions,
a **patch** version only fixes bugs. Update with `./setup/Update-Wardline.ps1 -ResourceGroup <resource group>`.

## [0.4.0] – unreleased

First version published on GitHub.

### Added
- **Update findings** (category *Updates*): Defender platform outside the N-2 support window relative to the newest version in the tenant, platform version sprawl, security intelligence older than three days on devices that are online, and update-ring design – `DisableGradualRelease`, the Critical (time-delay) channel, security intelligence on Broad, no update rings or no pilot ring (Beta/Preview) in fleets of 10+ Windows devices.
- **Dependency findings** (category *Dependency*): settings that are configured but inert because a prerequisite is missing – ASR rules without alerts when the cloud block level is below High, reputation-based ASR rules / EDR in block mode / portal tamper-protection changes without cloud protection, indicators and network protection without behavior monitoring, protections that do not apply in passive mode, exclusions not tamper-protected without `DisableLocalAdminMerge`, network protection on Windows Server without `AllowNetworkProtectionOnWinServer`, and indicator pitfalls (private IPs, URL paths outside Edge, allow + block on the same value, file indicators without `EnableFileHashComputation`).
- **AI agents module**: cloud agents (Entra Agent ID, Agent 365 package catalog with the legacy registry as fallback, Defender AgentsInfo) with blueprint ID, agent ID and agent user ID, and Conditional Access coverage rated separately for agent identity and agent user.
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
- **Charts**: open findings and changes per day (overview), protection per Defender feature as donuts with the devices on hover and click-to-filter (devices), changes per day (change history).
- **Colour-coded change history**: added green, removed red, changed amber with the changed parts marked in *Before*/*After*.
- **Network protection** also from block/audit events when TVM has no assessment for a device.
- **Separate retention**: `-SnapshotRetentionDays` and `-ChangeRetentionDays` (`-RetentionDays` still sets both); re-runs keep the current values.
- **Agent 365 Package Management API** (`/v1.0/copilot/admin/catalog/packages`, `CopilotPackages.Read.All`) as the primary Agent 365 source with publisher, blocked state and availability per agent; the beta registry (`AgentInstance.Read.All`) is only a fallback until its retirement in May 2026 and the portal says which source is in use.
- **Linux baseline**: exact Settings Catalog IDs (`linux_mdatp_managed_*`, verified against a tenant) with the previous patterns as fallback; the Linux tamper protection check rates the device state only, because the Settings Catalog has no such setting.
- **Tenant test data**: ASR per-rule exclusions and single-setting policies are created correctly; Linux test exclusions use the real child settings (no `scopes`, file-name type `_1`); group items with unresolved children are skipped instead of producing an invalid policy.
- **Licence key** per tenant: signed, checked offline, entered in the portal (Settings › Licence) or with `-LicenseKey`; soft enforcement – nothing stops when it expires.
- **Security review page** (threat model, data flows, release verification) and an **SBOM** (CycloneDX) in every release; support policy (`SUPPORT.md`).
- **Public demo** is pseudonymised and leak-checked on every build (names, users, groups, policies, domains, IDs, IPs, profile paths).

### Changed
- Agent 365 registry: HTTP 404 (registry not available in the tenant) is shown as a note instead of a warning.
- The access module (PIM, roles, access packages) is optional and off by default (`-Features …,Access`).
- **Graph API stability**: Agent ID, Conditional Access and role management use Microsoft Graph **v1.0 first** with a remembered fallback to **beta**; beta-only Intune endpoints (Settings Catalog, templates, Remediations) stay on beta. The Agent 365 registry remains beta-only.
