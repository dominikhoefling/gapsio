# Known limitations

- **Beta APIs**: Intune policies (`configurationPolicies`, `intents`, `deviceConfigurations`), Defender unified RBAC (`roleManagement/defender`) and the agent
  APIs only exist in Microsoft Graph *beta*. Microsoft may change them.
- **Settings Catalog IDs**: the baseline uses the known Defender CSP IDs and patterns for macOS. After the first run the
  baseline page lists every Defender setting found in the tenant – use it to verify and adjust IDs.
- **Linux Settings Catalog IDs** are not documented by Microsoft. The baseline ships the exact IDs verified against a
  tenant (`linux_mdatp_managed_antivirusengine_*`, `linux_mdatp_managed_cloudservice_*`,
  `linux_mdatp_managed_networkprotection_enforcementlevel`) and keeps a pattern (`definitionIdPattern`) as a fallback;
  option values are evaluated by display name (e.g. `real_time`, `admin_only`). The Settings Catalog has **no
  tamperProtection setting for Linux** – that check rates the device state only.
- **Linux exclusions in the Settings Catalog** have no `scopes` child; the scope (AV vs. global) is therefore only known
  for policies that encode it as an option or for the "Global exclusions" template.
- **EDR exclusions**: Linux global exclusions and allow indicators are collected. Automation folder exclusions and alert
  tuning rules are not exposed by Microsoft via API.
- **ASR per device group** refers to Defender device groups (MachineGroup). Intune assignments are shown per rule.
- **Agents**: Entra Agent ID and Agent 365 require licences. The Agent 365 inventory comes from the Package Management
  API (`copilot/admin/catalog/packages`, `CopilotPackages.Read.All`, Agent 365 licence); the legacy registry
  (`agentRegistry/agentInstances`, retired from May 2026) is only a fallback. Without either, agents from Entra Agent ID
  and Defender are still shown. Policies with attribute filters (custom security attributes) are rated "unclear"
  because Wardline does not read the attributes.
- **Effective settings in the Defender portal** (per device): no public API; Wardline uses Advanced Hunting instead.
- **macOS with third-party MDM** (e.g. Jamf): profiles deployed there are not visible via Graph; local `mdatp` changes are.
- **Origin of local exclusions** (Windows): entries under `…\Policies\…` count as GPO, all others under
  `…\Windows Defender\Exclusions` as local. Exclusions set from script files only show the script call.
- **Exclusions without activity** are checked tenant-wide (any device) over the 30 days Advanced Hunting keeps. Values
  with wildcards or environment variables are not checked, and very large tenants can hit Advanced Hunting limits – the
  exclusions then stay "not checked" and the run shows a notice.
- **Device page**: Wardline does not resolve which groups a device is a member of, so it shows policy assignments
  instead of the exact set of policies that apply to the device.
- **Assignments**: policies without assignments count as "not effective" and do not count for the baseline. The
  baseline is evaluated tenant-wide, not per device group.
- **Device state** from `DeviceTvm…` (tamper protection, running mode) is refreshed by Defender only every few hours.
- **New Graph permissions** of a managed identity take effect only with its next token. Azure caches managed identity
  tokens for up to 24 hours, so a feature added later can show HTTP 403 notices until then.
