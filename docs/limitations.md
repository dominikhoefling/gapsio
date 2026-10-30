# Known limitations

- **Beta APIs**: Intune policies (`configurationPolicies`, `intents`, `deviceConfigurations`, Intune RBAC) and the agent
  APIs only exist in Microsoft Graph *beta*. Microsoft may change them.
- **Settings Catalog IDs**: the baseline uses the known Defender CSP IDs and patterns for macOS. After the first run the
  baseline page lists every Defender setting found in the tenant – use it to verify and adjust IDs.
- **Linux Settings Catalog IDs** are not documented by Microsoft; the baseline finds them by pattern
  (`definitionIdPattern`) and evaluates the option's display name (e.g. `real_time`, `admin_only`).
- **EDR exclusions**: Linux global exclusions and allow indicators are collected. Automation folder exclusions and alert
  tuning rules are not exposed by Microsoft via API.
- **ASR per device group** refers to Defender device groups (MachineGroup). Intune assignments are shown per rule.
- **Agents**: Entra Agent ID and Agent 365 require licences. Policies with attribute filters (custom security
  attributes) are rated "unclear" because Wardline does not read the attributes.
- **Effective settings in the Defender portal** (per device): no public API; Wardline uses Advanced Hunting instead.
- **macOS with third-party MDM** (e.g. Jamf): profiles deployed there are not visible via Graph; local `mdatp` changes are.
- **Origin of local exclusions** (Windows): entries under `…\Policies\…` count as GPO, all others under
  `…\Windows Defender\Exclusions` as local. Exclusions set from script files only show the script call.
- **Assignments**: policies without assignments count as "not effective" and do not count for the baseline. The
  baseline is evaluated tenant-wide, not per device group.
- **Device state** from `DeviceTvm…` (tamper protection, running mode) is refreshed by Defender only every few hours.
- **New Graph permissions** of a managed identity can take up to an hour to take effect.
