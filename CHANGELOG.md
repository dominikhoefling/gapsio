# Changelog

All notable changes to Gapsio are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and Gapsio uses [Semantic Versioning](https://semver.org/): a new **minor** version can add features and permissions,
a **patch** version only fixes bugs. Update with `./setup/Update-Gapsio.ps1 -ResourceGroup <resource group>`.

## [Unreleased]

## [0.8.5] – 2026-11-12

Found in a code review of the whole product (API, storage handling, timers, assistant, update script, documentation).
No new permissions.

### Fixed
- **Devices view in fleets above 10,000 devices stayed empty.** The portal's server-side list sends `page` together
  with the search, and the API answered with the stored page instead of the search result.
- **Exceptions, assignments and their audit log could be overwritten by a failed read.** When reading the stored list
  failed for a moment, saving the next exception wrote a list with only that entry. A failed read now stops the write;
  the same applies to the local exclusion history and the Office policy histories (400 days).
- **The daily update check and the assistant's knowledge index only ran after *Collect now*.** The scheduled endpoint
  run skipped both; it now runs like a manual run (and is skipped when the endpoint module is not enabled).
- **Assistant: asking about a device whose name is also the start of other names** (WIN-01 next to WIN-010) answered
  "not found".
- Connection resets and timeouts towards Azure Storage, Microsoft Graph and the Defender API are retried like HTTP 5xx.
- `Update-Gapsio.ps1` refuses a `SHA256SUMS` file that has no checksum for the package (instead of reporting
  "verified").

### Changed
- Documentation: all app settings are listed (assistant, licensing classification, other clouds, Purview preview),
  together with the six-hourly schedule of the preview modules and the files Gapsio keeps in storage.

## [0.8.4] – 2026-11-11

Found by opening every portal view with real tenant data in a browser and by running the collectors against an empty
tenant. No new permissions.

### Fixed
- **The text "null" appeared in the portal** – on every device page (below the protection checks), under the role
  chips of *Who can do what?*, in an assignment without a note and in the empty state for non-admins.
- **Agents: a finding without a name in tenants that have no agents** (*Cloud agent without Entra Agent ID:* followed
  by nothing).
- **Passive mode on macOS and Linux** was explained with Windows causes and ended in empty brackets. The finding now
  explains the enforcement level and how to change it.
- Changes: the Purview preview had a tab without a name and without content; it keeps no change history and has no
  tab any more.

### Changed
- A test scans the portal for values that the browser would show as "null" or "false".

## [0.8.3] – 2026-11-11

The portal assistant was reviewed end to end against a real tenant and a real model. No new permissions.

### Fixed
- **Doc search never returned anything by meaning.** The vector of the question was reduced to its first number, so
  every similarity was zero.
- **The MDAV baseline was missing from the knowledge index** (the checks were read under a wrong key). Every baseline
  check and the ASR rule list are now sections with rationale and fix.
- **Device records for the model were mostly empty** – the assistant asked for fields the snapshot does not have. It
  now gets the protection state, the failed checks and whether the device still reports.
- **The device a question names was cut off** at the end of an over-long context. Devices now come first and the
  findings fill the rest, whole lines only.
- **Dates read as the wrong day** (`11/02/2026`). Everything the model sees is `yyyy-MM-dd HH:mm UTC`.
- **A failed live query looked like "nothing found".** Each part of a live result is now the data or an error; an
  empty live result says that no device reported instead of implying healthy sensors.
- **Answers after a tool call were sometimes prose without links.** Every round asks for JSON; a cut-off or empty
  answer is handled.
- **Links to devices could be dead** (device name instead of ID, wrong route). They are checked against the snapshot.
- **`#/devices?q=NAME` did not search.** The device list now applies the search term of the link.
- Two doc copies the assistant searches were out of date; a test now keeps them identical to `docs/`.

### Changed
- The knowledge index covers the Office, Licensing and Purview modules, compliance, installation and updates, is
  built with the regular run instead of during the first question, is kept in memory, and falls back to keyword
  search when embedding fails.
- A failed attempt is no longer sent back to the model as part of the conversation.

## [0.8.2] – 2026-11-11

No new permissions.

### Fixed
- **Assistant: every direct answer failed** with *Cannot bind argument to parameter 'Name'*. A final answer of the
  model carries no tool calls, which the assistant took for one empty call.
- **Assistant: rate limit.** New installations create the chat deployment with 50,000 tokens per minute instead of
  10,000 – one question with tool calls needs 6,000 to 12,000. A rate limit is retried once when the service asks for
  a short wait; otherwise the message says what to do. Existing installations: raise the capacity with the command in
  *Operations › Notices after a run* (capacity is a rate limit, billing stays per token).
- Assistant: the Purview preview snapshot was never found (other blob name).

### Changed
- The assistant knows the newer portal views (policy conflicts, device control, attack disruption, detection rules,
  the Office pages, audit evidence) and can link to them; `search_findings` covers the Office module.

## [0.8.1] – 2026-11-11

No new permissions.

### Fixed
- **Agents: the Defender agent inventory (`AgentsInfo`) never loaded.** The table has other column names than the
  schema reference (`Name`, `Description`, `EntraAgentID`, `EntraBlueprintID`), so the query failed on every run with
  an HTTP 400 notice. Gapsio now reads the column list of the tenant's table and builds the query from the columns
  that exist; a column that exists under no known name gives an empty value and one notice.

### Changed
- Agents: a server error of the retired legacy Agent 365 registry is shown as *not available* instead of a notice on
  every run.

## [0.8.0] – 2026-11-10

### Added
- **Office preview: policy changes for all protection policies.** Every audited change to anti-spam, anti-malware,
  Safe Links, Safe Attachments, Tenant Allow/Block List, transport rules, quarantine policies, DKIM, Teams protection
  and advanced delivery – with who made it and the values set. Changes that set a weak value (ZAP off, an allow entry,
  click-through allowed, a rule disabled …) raise the finding *Policy changes weakened Defender for Office 365
  protection* (High). Gapsio keeps the changes for 400 days.
- **Office preview: quarantine.** Releases, release requests, denials and deletions, who released, and the finding
  *Messages with a phishing or malware verdict were released from quarantine* (Medium, High with malware).
- **Office preview: Teams protection.** Teams messages rated phishing or malware – blocked, delivered, removed by
  ZAP – with senders and URL domains, and the finding *Teams messages rated phishing or malware were delivered and
  not removed* (High).
- Checks whose hunting table does not exist in the tenant are shown as *not available* instead of failed.

No new permissions. The three additions use `ThreatHunting.Read.All`; quarantine and policy changes need the
Microsoft 365 connector of Defender for Cloud Apps, Teams needs Defender for Office 365 Plan 2.

## [0.7.1] – 2026-11-10

No new permissions.

### Changed
- **Devices that no longer report are labelled.** Defender keeps the last configuration assessment of a device that
  stopped reporting, so Gapsio listed it like a current device. Such devices now appear under *Coverage gaps* as
  *sensor inactive*, are labelled **not reporting** in the device list and on the device page, and their findings
  carry the label **last known state**. Severity is unchanged. Summary field `devicesNotReporting`.
- Attack disruption readiness says why the Sense agent version cannot be measured (Hunting off, no Windows devices,
  or none of them reported in the lookback).
- A hunting table that the tenant does not have (product or add-on not licensed) is reported as a short notice
  instead of the raw HTTP 400.

### Fixed
- **High-risk browser extensions were never found.** The query read a `DeviceName` column that
  `DeviceTvmBrowserExtensions` does not have, so it failed in every tenant that has the table. Device names now come
  from the device list.

## [0.7.0] – 2026-11-10

New optional feature `Detections` with one read-only permission (`CustomDetection.Read.All`); everything else in
this release works with the permissions you already granted. The Office preview module was rebuilt – its findings
change, see *Changed* and *Removed*. `Update-Gapsio.ps1` reports the permission only when
you add the feature.

### Added
- **Policy conflicts (Endpoint).** Settings that reach the same devices from two or more Intune policies with
  different values – fleet-wide, with the policies, the values and the number of devices. Finding *Policy conflict*
  (Medium). No extra permission.
- **Device control (Endpoint).** USB storage in use (30 days) versus the device control policies that reach those
  devices, with policy events. Finding *USB storage used without a device control policy* (Medium). No extra permission.
- **Attack disruption readiness (Endpoint).** What can be verified of the prerequisites of automatic attack
  disruption (Sense agent version for Contain User, coverage, Defender for Identity signals, disruption events) –
  and what Microsoft only shows in the portal, listed as *not measurable* with the place to check. No extra permission.
- **Custom detection rules (new optional feature `Detections`, Graph `CustomDetection.Read.All`).** Rules that
  Defender switched off automatically (High), failed, disabled and automatically acting rules; rule changes appear in
  the change history. Enable with `-Features …,Detections`.
- **Audit evidence (History).** Open findings and accepted risks by ISO/IEC 27001:2022 Annex A and NIS2 Art. 21(2)
  control; printable, CSV export. The mapping (`config/control-mapping.json`) can be replaced in the `config` container.
- **Access: held but not used.** New table per person and unified RBAC permission – *used*, *not used* or *not
  measurable* with the reason – and the finding *Defender permissions held but not used* (Medium/Low). *Not used* is
  only claimed when every source that can reveal the use was read; otherwise the permission is *not measurable*
  (e.g. feature `Audit` off, audit query still running). The page shows which usage sources were read.

### Changed
- **Office preview rebuilt on documented hunting columns.** The module now answers "what got through, and why":
  phishing and malware that is still in an inbox, threats an allow delivered (organisation-level and mailbox-level
  allows kept apart), Safe Links click-through and inbound mail that spoofs your own domains. The policy map shows
  which protection acted and what organisation-level and mailbox policies did.
- Office findings are regular findings now: they appear in the Findings list, can be assigned and accepted, count in
  the audit evidence, and every run is compared with the previous one (change history, notifications, run index).
  The snapshot is `state/officepreview-latest.json`; the earlier file is still read until the module has run once.
- Office: all texts are available in English and German.
- Portal sign-in fallback for missing `roles` claim now reads direct app-role assignments on the user object.
  Least-privilege mapping moved to the required `Core` feature with Graph `RoleManagement.Read.Directory`.
- Access: *last used* also counts recorded actions (response actions, alert triage, audit log), so people who act
  through the API are no longer reported as *never used*.
- Access: an empty *permissions actually used* table now says whether no source could be read or nothing was found.

### Removed
- Office checks that rested on misread or undocumented columns: *policy overlap*, *duplicate policy effects* and
  *precedence conflicts* (they treated `UserLevelPolicy` – the recipient's own mailbox policy – as an admin policy),
  *TABL/IOC inventory* (read a Microsoft Sentinel table that is not part of the Defender hunting schema), *ZAP blind
  spots* (counted every message without a post-delivery event), *encrypted attachments* (undocumented field), and the
  licensing finding in the Office module.

### Fixed
- **The nightly runs of the Office and Purview preview modules failed**: their timer functions called collectors the
  module did not export. Only *Collect now* worked. A test now checks every Function entry point.
- **A second click on *Collect now* queued a second run**: the two-minute debounce called a function the module did
  not export and silently did nothing.
- Office: a hunting query that failed was counted as "ok, no data". Failed checks are now shown as failed, raise no
  finding and leave their number empty.
- German texts of several findings and one installer message were cut off: typographic quotation marks inside a
  double-quoted PowerShell string end the string. All 18 places are fixed and a test guards against new ones.
- Access: antivirus scans and investigation packages count as *Alerts (manage)* (previously *Response* / *File
  collection*), as in Microsoft's permission reference.
- Access: an alert that is only assigned (status New) no longer counts as use by the assignee.
- Access: a failed read of the audit log records no longer looks like "no activity".
- Access: paging links of the Defender for Endpoint API are only followed to `https://*.microsoft.com`.
- Docs: the findings table on the Access page was split by an empty line.
- Security: paging links are checked for every Microsoft API call (Graph and Defender for Endpoint), not only in Access –
  a link to a host outside `https://*.microsoft.com` stops the read instead of receiving the bearer token.
- API: the device search page size is capped at 1,000; the Office and Purview preview routes answer 404 when the module
  is not enabled (as the other modules do).
- Portal: Office and Purview preview findings showed raw dictionary keys (`x.severity`, `x.detail` …) as column headers
  and the exclusions page title instead of "Finding"; the Office page labelled the collection time "Loading"; the header
  showed no data timestamp on the preview pages; cmdlet names in the anti-phish drift wrapped mid-word.
- Setup: `Update-Gapsio.ps1` and `Uninstall-Gapsio.ps1` also find installations without the `gapsio-component` tag
  (older installations: tag `wl-component`, or the only Function App tagged `product=Gapsio`); an update sets the tag.
- Demo: Office and Purview preview data (fictitious) and the Access module are part of the demo; display names now
  match the pseudonymised UPNs, and dictionary keys are pseudonymised as well.

## [0.6.0] – 2026-11-04

### Changed (breaking)
- **Product renamed to Gapsio.** App settings are now `GAPSIO_*` (previously `WL_*`), the on-demand queue is `gapsio-run`,
  Azure resource tags are `gapsio-component`, release assets are `gapsio.zip` / `gapsio-functionapp.zip`.
- **New licence signing key.** Licence keys now start with `GP1.` and licence IDs with `GP-`; keys issued for earlier
  versions are no longer accepted. Customers receive a new key by e-mail (or via *Resend licence* on gapsio.cloud).
- The portal admin app role is `Gapsio.Admin`.

### Added
- **Purview DLP preview module (optional, private preview)**: `-Features ...,PurviewPreview`
  enables `purviewpreview`. DLP licence coverage, Purview role holders, sensitivity labels
  and 12 Advanced Hunting probes. Portal group *Purview*. See docs/modules/purview-preview.md.
- **Office preview module (optional, private preview)**: `-Features Endpoint,Agents,OfficePreview` enables the `officepreview`
  module (`ThreatHunting.Read.All`). It collects anti-phish policy drift from Defender for Office 365 audit events (who changed
  which setting, direction *weakened*/*hardened*) and sets each change against phishing outcomes before and after
  (delivered vs. blocked, per policy, 400-day history). Portal: *Office preview*, *Phish drift* and *Policy map*.
  Findings `office.antiphish_weakened` (High) and `office.antiphish_delivery_up` (Medium).
- Installer writes `GAPSIO_MODULES` from the selected features; *Installation* lists which modules exist and how to add one.

### Changed
- Documentation is published at https://gapsio.cloud/docs/ (canonical); GitHub Pages remains as the build source.

## [0.5.0] – 2026-11-02

### Added
- **Gapsio Assistant (Enterprise, optional)**: install with `-Assistant` and Gapsio creates an Azure OpenAI resource
  (`gpt-4.1-mini` + `text-embedding-3-small`) **in your subscription**, keyless via managed identity. The portal gets a
  chat helper for admins that answers from your data with read-only tools: stored findings and devices of the last run,
  one device record, **live Microsoft Defender Advanced Hunting** (last seen, sensor health, alerts of the last 7 days,
  failed secure-configuration checks – when the *hunting* feature is enabled) and a semantic search over the Gapsio
  documentation and the MDAV baseline rationale. Every answer lists the tools used and the doc sections cited.
  Requires an Enterprise licence; Community installations see the entry point with an upgrade hint.
  New installer parameters: `-Assistant`, `-AssistantEndpoint`, `-AssistantDeployment`, `-AssistantEmbeddingDeployment`,
  `-AssistantLocation`. See *Installation › Optional: portal assistant*.
- **News agent**: `tools/Get-GapsioNews.ps1` collects new Defender for Endpoint / Agent 365 items (Microsoft Learn,
  Tech Community, Microsoft 365 roadmap) into a Markdown digest; implementation rules for confirmed items in `AGENTS.md`.
- GitHub social preview source (`.github/social-preview.html/.png`).
- **Inventory findings for Linux audit-mode previews**: Gapsio now flags assigned Linux policies that keep
  antivirus or tamper protection in *audit* mode (preview) as rollout hygiene findings.

### Changed
- ARM/Bicep template: new optional Azure OpenAI resources and role assignment (`Cognitive Services OpenAI User` for the
  runner identity) – only deployed with `enableAssistant=true`. No new Graph or Defender permissions.

### Fixed
- **Intune policy exclusions per device were always 0**: the policy platform (`Windows`) was compared with the
  Advanced Hunting OS product (`Windows11`, `WindowsServer2025`); both are now normalised to the platform family.
- **Coverage: onboarded hosts no longer appear as "discovered, can be onboarded"** – device discovery keeps its
  own record for up to 30 days after onboarding; those rows are now suppressed when an onboarded device with the
  same Entra device ID or host name exists.
- **"Collect now"** no longer queues a second run when clicked twice within two minutes (e.g. after a slow
  response on a cold Function host); the error toast shows the HTTP status.

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
  (permissions `Organization.Read.All`, `User.Read.All`), timer `CollectLicensing`, settings `GAPSIO_SCHEDULE_LICENSING`,
  `GAPSIO_LICENSING_DAYS`, `GAPSIO_LICENSING_DEVICES_PER_USER`, `GAPSIO_LICENSING_DETAIL` (`aggregate` pseudonymises UPNs).
- **Third-party AV/EDR**: `DeviceTvmSoftwareInventory` is queried for other AV/EDR vendors; devices show the products, a new
  device chart and filter `3pav:1`, a Medium finding per device where a third-party product runs alongside an active Defender
  Antivirus and an aggregated Low finding per tenant.
- **Compliance mapping** (`docs/compliance.md`): how Gapsio evidence maps to ISO 27001:2022 Annex A, NIST CSF 2.0, SOC 2 and
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
  10,000 devices (`api/devices`, `api/device`); identical per-device findings on more than `GAPSIO_FINDING_ROLLUP` devices are
  rolled up into one finding; the template deploys 4 GB instances (`instanceMemoryMB`).
- **Assignments and unlimited exceptions**: every finding and exclusion can be assigned to an Entra user, a security group, a distribution list or a manually typed e-mail address (people picker in the detail row, backed by `User.ReadBasic.All` and `GroupMember.Read.All`; falls back to manual e-mail when the directory is not readable). Assigned items stay open, show the assignee in the findings list (with a filter) and in notifications (`gapsio.findings[].assignee`) so a flow can e-mail them. Exceptions (formerly "accept risk") can now be unlimited (no expiry) or dated up to ten years; the one-year cap is gone. *History › Exceptions & assignments* adds an *Assignments* tab; assign/unassign actions go to the same audit log.
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
- **Separation of duties**: app registrations can be created up front by the identity team (`New-GapsioAppRegistrations.ps1`) and attached with `-PortalAppId` / `-DataAppId`; the data-access app is used via workload identity federation (no secret).
- **English/German portal** with a language switch; all scripts and installation output in English.
- **Updates**: daily check for new releases (shown in the portal, no tenant data sent, `GAPSIO_UPDATE_CHECK=false` to disable) and `Update-Gapsio.ps1` with checksum verification, permission and template change detection.

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
