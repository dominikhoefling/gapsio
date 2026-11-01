# Changelog

All notable changes to Wardline are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and Wardline uses [Semantic Versioning](https://semver.org/): a new **minor** version can add features and permissions,
a **patch** version only fixes bugs. Update with `./setup/Update-Wardline.ps1 -ResourceGroup <resource group>`.

## [Unreleased]

### Added
- **News agent**: `tools/Get-WardlineNews.ps1` and the weekly `news.yml` workflow collect new Defender for Endpoint /
  Agent 365 items (Microsoft Learn, Tech Community, Microsoft 365 roadmap) into a `news` issue for the maintainer to
  confirm; implementation rules for confirmed items in `AGENTS.md`.
- GitHub social preview source (`.github/social-preview.html/.png`).

### Removed
- Sponsor links (`FUNDING.yml`).

## [0.4.0] – 2026-11-02

First version published on GitHub.

### Added
- **Open-source release**: MIT `LICENSE` with trademark notice, `CONTRIBUTING.md` (DCO), `CODE_OF_CONDUCT.md`,
  `AGENTS.md` for AI coding agents, issue and pull-request templates, `CODEOWNERS` and the
  open-core promise (`docs/manifesto.md`) that documents what stays free.
- **Baseline 2026.10.31** – 21 new Windows checks: threat default actions never *Allow*, no `ThreatIdDefaultAction`
  overrides, brute-force protection and remote encryption protection in block mode, network protection protocol parsing
  (`Disable…Parsing`), inbound filtering, UDP inspection and DNS sinkhole, on-access protection, archive scanning, real-time
  scan direction, block at first sight, *Turn off Microsoft Defender Antivirus*, automatic server-role exclusions, scheduled
  scan never, signature check before scan, controlled folder access in block mode, SmartScreen for Windows and Edge (incl.
  no override). New check flag `weakeningOnly` (status *Default*): such settings are only reported when a policy actually
  weakens them.
- **Browser extensions**: one *Fleet* finding per extension that Vulnerability Management rates High/Critical
  (`DeviceTvmBrowserExtensions`, active installations), aggregated across devices with browsers and a device sample.
- **Device hygiene findings**: OS end of support (Windows, Windows Server, macOS n-2), no quick scan in 14 days / never a
  full scan (`AvScanResults`), standard vs. streamlined connectivity, WSL without the Defender plug-in, PsExec/WMI ASR rule
  blocking on ConfigMgr clients, threat default actions *Allow/NoAction* in the registry. The passive-mode finding explains
  missing third-party AV and missing EDR in block mode.
- **ASR telemetry**: audit/block events per rule (30 days) with top processes; rules without audit hits are reported as
  *ready for block mode*.
- **Intune integration** (feature `Coverage`, new permissions `DeviceManagementServiceConfig.Read.All`, `Policy.Read.All`):
  Defender connector state, platform toggles and heartbeat, device risk in compliance policies, Conditional Access requiring
  compliant devices.
- **Access module**: API apps with application permissions on the Defender for Endpoint API, the Defender XDR API and the
  Defender part of Microsoft Graph (credential type and lifetime, owners, external apps); Defender role groups without access
  review; PIM for Groups activation rules (new permissions `AccessReview.Read.All`, `RoleManagementPolicy.Read.AzureADGroup`).
- **Feature `Audit`** (optional, `AuditLogsQuery.Read.All`): Defender for Endpoint activity from the Purview unified audit log
  – offboarding package downloads, live response, portal setting changes.
- **Licensing**: SKUs are shown by product name (*Defender for Endpoint P1/P2*, *Microsoft 365 E5* …) with the part number
  as secondary text.
- **Licensing module (optional, Defender for Endpoint only)**: compares the MDE service plans a tenant owns (`subscribedSkus`),
  the users that hold such a plan (`assignedPlans`) and the client devices actually onboarded (Advanced Hunting, optional Intune
  mapping) and who uses them. New portal page *Licensing (MDE)* with SKUs, client devices (Licensed/Unlicensed/No user, confidence
  Intune/Logon), licensed users and a separate server list; findings for over-consumption, unlicensed clients, Plan-1-only devices,
  licensed users without a device and users over the five-device limit; caveats are shown on the page. Feature `Licensing`
  (permissions `Organization.Read.All`, `User.Read.All`), timer `CollectLicensing`, settings `WL_SCHEDULE_LICENSING`,
  `WL_LICENSING_DAYS`, `WL_LICENSING_DEVICES_PER_USER`, `WL_LICENSING_DETAIL` (`aggregate` pseudonymises UPNs).
- **Third-party AV/EDR**: `DeviceTvmSoftwareInventory` is queried for other AV/EDR vendors; devices show the products, a new
  device chart and filter `3pav:1`, a Medium finding per device where a third-party product runs alongside an active Defender
  Antivirus and an aggregated Low finding per tenant.
- **Compliance mapping** (`docs/compliance.md`): how Wardline evidence maps to ISO 27001:2022 Annex A, NIST CSF 2.0, SOC 2 and
  GDPR, plus an audit readiness checklist.
- **Community edition without a licence key**: collection and storage are always complete, but without a valid licence the
  API serves every list (devices, findings, exclusions, agents, policies, entitlements, changes …) with only the first
  10 entries in clear; further entries are masked on the server (names, identifiers, users, paths and free text →
  `••••••••`, while severity, category, state, platform, numbers and dates stay so counts, filters and charts remain
  correct). Masked rows are blurred in the portal, cannot be opened and are left out of CSV exports. Summaries, charts,
  warnings and run history are complete. Expired licences keep the full view for a 30-day grace period. `api/me`
  reports `tier` and `communityRows` to every user. The public demo is unaffected.
- **Collapsible sidebar navigation**: modules are groups that fold (state remembered), the active group stays open, and
  below 860 px the sidebar becomes a drawer behind a menu button. The access module is labelled *Permissions (unified RBAC)*.
- **Large fleets (up to several hundred thousand devices)**: Advanced Hunting results above the 100,000-row limit are
  collected in hash shards with truncation notices and a per-minute call budget; device and coverage lists are stored in
  pages with a search index instead of inside the snapshot; the portal searches and filters devices on the server above
  10,000 devices (`api/devices`, `api/device`); identical per-device findings on more than `WL_FINDING_ROLLUP` devices are
  rolled up into one finding; the template deploys 4 GB instances (`instanceMemoryMB`).
- **Assignments and unlimited exceptions**: every finding and exclusion can be assigned to an Entra user, a security group, a distribution list or a manually typed e-mail address (people picker in the detail row, backed by `User.ReadBasic.All` and `GroupMember.Read.All`; falls back to manual e-mail when the directory is not readable). Assigned items stay open, show the assignee in the findings list (with a filter) and in notifications (`wardline.findings[].assignee`) so a flow can e-mail them. Exceptions (formerly "accept risk") can now be unlimited (no expiry) or dated up to ten years; the one-year cap is gone. *History › Exceptions & assignments* adds an *Assignments* tab; assign/unassign actions go to the same audit log.
- **macOS/Linux findings** (category *macOS / Linux*): Full Disk Access missing and system extensions not approved on Macs (from the secure configuration assessment), Defender agent builds 6+ months behind the fleet (`101.YYMM.x`, with an auditd note for Linux < 101.2408), and macOS/Linux fleets without any Intune Defender policy (Jamf-managed Macs are called out). Agent version is now collected from `DeviceTvmSoftwareInventory`.
- **Response readiness** (feature `Response`, default on, category *Response*): automated investigations waiting for approval for 1+ day, Medium/High alerts untriaged for 7+ days, devices isolated for 7+ days without release, failed or stuck response actions, response capabilities never exercised in 90 days on fleets of 25+ Windows devices, and live response sessions that ran or uploaded scripts. Uses the Defender for Endpoint API (`Machine.Read.All`, `Alert.Read.All`). Automation level per device group and live-response tenant settings have no API and are documented as portal checks.
- **Access module rebuilt around Defender XDR unified RBAC**: roles and assignments from `roleManagement/defender` only – who holds which Defender role directly, via group, eligible via PIM for groups or via access package; for which data sources (`/` = all, `Mde`, `Mdi` …); permission groups and a *response/config* tag for roles with response, live response, file collection or settings permissions. **Usage**: last interactive sign-in to the Defender portal per person (Entra sign-in logs, carried forward across runs) and last PIM-for-groups activation. Entra roles that bypass unified RBAC (Global/Security Administrator, Security Operator, Security Reader, Global Reader) are listed separately. New findings (category *Least privilege*): standing permission never used, eligible role never activated, Entra bypass roles, 3+ people with permanent response permissions on all data sources, assignments to individual users. Entra directory roles and Intune RBAC are no longer collected; permissions changed to `RoleManagement.Read.Defender`, `PrivilegedAssignmentSchedule.Read.AzureADGroup`, `AuditLog.Read.All` (added) and `RoleAssignmentSchedule.Read.Directory`, `RoleEligibilitySchedule.Read.Directory`, `DeviceManagementRBAC.Read.All` (removed). Device-group scoping of MDE roles is not exposed by any Microsoft API and is documented as a limitation.
- **Fleet findings** (category *Fleet*): internet-facing devices with high exposure, troubleshooting mode active right now or used 3+ times in 30 days, tampering attempts per device (30 days), devices excluded from Vulnerability Management, untagged devices in tag-driven fleets, and devices inactive for 90+ days that are still in the inventory (machines API, feature `Response`). Device tags, internet exposure, asset value and the new counters are shown on the device page and indexed for large fleets.
- **AgentsInfo aligned with the documented schema**: the Advanced Hunting query now uses `AgentName`, `EntraAgentId`, `EntraBlueprintId` (the previous names would have failed – KQL column names are case-sensitive) and reads `Owners`, `Model`, `Guardrails`, `Endpoints`, `McpServers`, `Permissions`, `SharedWith`, `DeclaredTools`, `DeclaredDataSources`, `ConnectedAgents`, `Channels`. New findings: agent without guardrails (explicitly empty) and agent endpoint flagged as externally connected.
- **Inventory findings** (category *Inventory*): onboarded devices outside every device group (while the tenant uses groups), duplicate device records (same Entra device ID or host name under several Defender IDs), onboarded Windows devices without a management channel (`ManagedBy` unknown – no Defender policy reaches them), and ASR rules kept in audit mode by a policy untouched for 90+ days. `ManagedBy` is now collected from `DeviceInfo`.
- **Update findings** (category *Updates*): Defender platform outside the N-2 support window relative to the newest version in the tenant, platform version sprawl, security intelligence older than three days on devices that are online, and update-ring design – `DisableGradualRelease`, the Critical (time-delay) channel, security intelligence on Broad, no update rings or no pilot ring (Beta/Preview) in fleets of 10+ Windows devices.
- **Dependency findings** (category *Dependency*): settings that are configured but inert because a prerequisite is missing – ASR rules without alerts when the cloud block level is below High, reputation-based ASR rules / EDR in block mode / portal tamper-protection changes without cloud protection, indicators and network protection without behavior monitoring, protections that do not apply in passive mode, exclusions not tamper-protected without `DisableLocalAdminMerge`, network protection on Windows Server without `AllowNetworkProtectionOnWinServer`, and indicator pitfalls (private IPs, URL paths outside Edge, allow + block on the same value, file indicators without `EnableFileHashComputation`).
- **AI agents module (beta)**: cloud agents (Entra Agent ID, Agent 365 package catalog with the legacy registry as fallback, Defender AgentsInfo) with blueprint ID, agent ID and agent user ID, and Conditional Access coverage rated separately for agent identity and agent user.
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
