# Endpoint

Always on (feature `Core`); `Hunting`, `Indicators` and `Inventory` add data sources.

## Exclusions

- From every source, for **Windows, macOS and Linux**: Intune / Security Settings Management (Settings Catalog, endpoint
  security templates, legacy device configuration) and allow indicators from Defender for Endpoint.
- **Local exclusions on devices** (feature `Hunting`): Windows via registry events, macOS/Linux via `mdatp exclusion …` and
  `mdatp threat allowed …` commands. Wardline keeps the history beyond the 30 days of Advanced Hunting and attributes the
  calling process and command line (e.g. `powershell.exe … Add-MpPreference`).
- **Exclusions that also blind EDR** (own view): Linux global exclusions (policy or `mdatp … --scope global`) and allow
  indicators. Windows and macOS exclusions only affect antivirus.
- **Risk rating** for every exclusion: whole folders or drives, wildcards, file type exclusions, interpreters as process
  exclusions, user-writable paths. Contextual exclusions and SHA256 indicators count as good practice.

## Unused exclusions

Wardline checks in Advanced Hunting whether excluded processes, paths and file types showed **any process or file
activity on any device in the last 30 days**. Exclusions without activity are flagged as "No activity (30 days)" – likely
leftovers that nobody dares to delete. Values with wildcards or environment variables are not checked. (Exclusions only
affect antivirus scanning; Defender's EDR sensor still records the activity, which is what makes this check possible.)

## ASR rules

Three levels – target · configured · effective – overall, **per Defender device group** and **per device**:

- Conflicts between policies (e.g. Warn in one policy, Block in another)
- Global ASR exclusions and per-rule exclusions
- Effective mode from `DeviceTvmInfoGathering` (AsrConfigurationStates), with TVM as fallback
- Rules permanently in audit, rules below the minimum, rules not configured at all

## Devices

Every device has its own page (click the device name): protection state (running mode, real-time, behaviour, cloud and
PUA protection, tamper protection, **network protection**, controlled folder access, EDR in block mode, signatures, sensor
health), ASR rules on the device against the target, local exclusions with who/when/command line, findings, local AI
agents, policies with exclusions and their assignments, the change history and direct links to the device in the
Defender portal and in Intune.

### Network protection

Wardline reads network protection per device from Defender's secure configuration assessment (TVM). Devices without an
assessment fall back to network protection events of the last 30 days: block events mean it is on, audit events only
mean audit mode (shown as off). Devices with neither stay "unknown" – the device page says which source was used.

## Defender coverage gaps

The **Coverage gaps** tab lists devices Defender does not (fully) protect:

- Intune-managed Windows, macOS and Linux devices (synced in the last 30 days) that never showed up in Defender – feature `Coverage`
- onboarded devices whose sensor is inactive, misconfigured or has impaired communications
- devices found by Defender device discovery that can be onboarded

## MDAV baseline

Windows, macOS and Linux checks on three levels: target · configured in Intune · effective on the device (tamper
protection, running mode, real-time, cloud, behaviour and PUA protection, sensor communication). Linux: local weakening
via `mdatp config …` and changes to `mdatp_managed.json` outside of Defender. See [customising the baseline](../baseline.md).

### ASR telemetry

`DeviceEvents` action types `Asr…Audited` / `Asr…Blocked` (30 days) are counted per rule with the top five
triggering processes. A rule that is still in audit mode and produced **no audit event** is reported as
*ASR rule ready for block mode*; otherwise the finding lists the processes to review before switching.

## Combined findings

Findings that only appear when several signals meet, for example:

- tamper protection off **and** local exclusions present
- passive mode **and** local exclusions
- local exclusions effective because `DisableLocalAdminMerge` / `exclusionsMergePolicy` is missing
- a local AI agent with auto-approve on a weakened device (see [AI agents](agents.md))

## Dependency findings

Many Defender features silently depend on another one. The *Dependency* category flags settings that are
configured but cannot work:

| Configured | Needs | Otherwise |
|---|---|---|
| ASR rules in block/warn | `CloudBlockLevel` ≥ High (High Plus for EDR alerts) | blocks happen, but no alerts |
| Reputation-based ASR rules (prevalence, ransomware), EDR in block mode, portal tamper-protection toggle, BAFS | cloud-delivered protection | inert on devices with cloud protection off |
| Custom indicators, network protection, web content filtering | behavior monitoring | silently stop working |
| ASR, network protection, cloud protection, indicators | Defender Antivirus in active mode | not enforced in passive mode |
| Tamper protection for exclusions | `DisableLocalAdminMerge` = 1 via Intune / security settings management | local admins can still add exclusions |
| Network protection on Windows Server | `AllowNetworkProtectionOnWinServer` (+ `AllowDatagramProcessingOnWinServer`) | stays off on servers |
| File hash indicators | `EnableFileHashComputation` | new files are matched late |

Indicator pitfalls are reported too: private (RFC 1918) IP indicators are ignored, URL indicators with a path
only match in Microsoft Edge, and an allow and a block indicator for the same value resolve by creation order.

## Update findings

The *Updates* category looks at how Defender itself is kept current:

- **Platform age (N-2)** – the platform version (`4.18.YYMM*.x`) of every active Windows device is compared with the
  newest version in the tenant. More than two monthly releases behind is Medium, six or more is High. Microsoft only
  supports the current and the two previous platform releases.
- **Version sprawl** – four or more different monthly platform releases across 10+ devices usually means a broken
  update path for a subset of the fleet.
- **Signature age** – a device that was seen in the last 14 days but whose security intelligence was published
  three or more days ago (High from seven days). This catches devices where the "up to date" flag is misleading.
- **Update rings** – `DisableGradualRelease`, the Critical (time-delay) platform/engine channel and security
  intelligence on the Broad channel are flagged. In fleets of 10+ Windows devices Wardline also reports when no
  platform/engine channel is configured at all or when no policy puts a pilot group on Beta/Preview.

## Inventory findings

The *Inventory* category covers grouping and record hygiene – things that quietly undermine RBAC, automation
and policy reach:

- **Ungrouped devices** – the tenant uses device groups, but some onboarded devices fall into *Ungrouped devices
  (default)*. They inherit the default group's automation level and visibility.
- **Duplicate device records** – the same Entra device ID or host name appears under several Defender device IDs
  (golden image onboarded before sysprep, reimaging without offboarding). Counts, grouping and per-device
  indicators are distorted and the stale record keeps showing an old protection state.
- **No management channel** – onboarded Windows devices whose `ManagedBy` is unknown: neither Intune, ConfigMgr
  nor security settings management reach them, so none of the Defender policies Wardline evaluates apply.
- **Eternal audit** – an ASR rule is assigned in audit mode by a policy that has not been modified for 90+ days.
  Audit is an evaluation step, not a protection state.

## Fleet findings

The *Fleet* category covers exposure and operational hygiene across the device estate. Sources are the
documented `DeviceInfo` columns (`IsInternetFacing`, `ExposureLevel`, `AssetValue`, `IsExcluded`,
`ExclusionReason`, `DeviceManualTags`, `DeviceDynamicTags`, `RegistryDeviceTag`, `IsTransient`), the
`DeviceEvents` action types `AntivirusTroubleshootModeEvent` and `TamperingAttempt` (30 days) and – with the
`Response` feature – the Defender for Endpoint machines API.

- **Internet-facing device with high exposure** (Medium; High when tamper protection is off or Defender runs in
  passive mode) – reachable from the internet and rated *High* exposure at the same time.
- **Troubleshooting mode active** (High, per device) – a troubleshooting-mode session started within the last
  four hours. While it is active, local administrators can change policy-managed settings and switch off tamper
  protection; policy changes are not applied.
- **Troubleshooting mode used repeatedly** (Medium, per device) – three or more sessions in 30 days; fix the root
  cause in policy instead of weakening the device over and over.
- **Tampering attempts** (Medium; High for 10+ attempts or when tamper protection is off on that device) – the
  number of `TamperingAttempt` events per device in 30 days. Typical for persistence and defence evasion, but also
  for scripts that write Defender settings directly.
- **Excluded from Vulnerability Management** (Low) – devices with `IsExcluded`; they vanish from exposure score,
  recommendations and vulnerability reports.
- **Devices without a device tag** (Low) – only when at least half of the fleet (10+ devices) carries a tag, so
  tag-scoped device groups, indicators or automation rules have gaps.
- **Inactive 90+ days, still in the inventory** (Low) – devices whose sensor has been *Inactive* for at least
  90 days, from the machines API. Offboarding candidates; they keep counting against groups, reports and licences.

- **Operating system out of support** (Medium; High for Windows 7/8 and Server 2008; Low while the end date is still
  ahead) – one finding per OS: Windows 10 (except LTSC 2019/2021 builds), Windows 11 21H2/22H2/23H2, Windows Server
  2008 R2/2012/2012 R2/2016, and macOS older than the three releases Defender supports (n-2, counted by release so
  15 → 26 is one step). ESU is mentioned where Microsoft offers it.
- **No quick scan in 14 days / never a full scan** (Low) – from `AvScanResults` in `DeviceTvmInfoGathering`, Windows
  devices in active or EDR-block mode only.
- **Standard connectivity** (Low) – devices whose `DeviceInfo.ConnectivityType` is still *Standard* while others use
  streamlined connectivity.
- **WSL without the Defender plug-in** (Medium) – Windows Subsystem for Linux in the software inventory without the
  Defender for Endpoint plug-in for WSL.
- **PsExec/WMI ASR rule blocks on ConfigMgr clients** (Medium, ASR) – Microsoft documents the rule as incompatible with
  Configuration Manager.
- **Detected threats are allowed to run** (High, per device) – `ThreatIdDefaultAction` / `ThreatSeverityDefaultAction`
  registry values set to *Allow* (6) or *NoAction* (9) in the last 30 days (`DeviceRegistryEvents`).
- **High-risk browser extension** (Medium; High for *Critical*) – one finding per extension that Vulnerability
  Management rates *High* or *Critical* (`DeviceTvmBrowserExtensions`, active installations only), with the browsers,
  device count and a device sample. Extensions run with the user's sessions and cookies outside the reach of ASR,
  SmartScreen and AV scanning; block them with `ExtensionInstallBlocklist` or move to an allowlist.
- The **passive-mode** finding now says whether a third-party AV is visible at all (no product → likely a leftover
  `ForceDefenderPassiveMode` or a fake security-center registration) and whether EDR in block mode backs it up.

### Intune integration (feature `Coverage`)

- **Intune connection to Defender for Endpoint not enabled** (High) – the Defender connector is missing or not
  *enabled*; device risk never reaches compliance.
- **Defender connector off for platforms in use** (Medium) – Windows/macOS/iOS/Android toggle off while onboarded
  devices of that platform exist; **no heartbeat for 2+ days** (Medium).
- **Device risk not part of compliance** (Medium) – no assigned compliance policy with *Require the device to be at or
  under the machine risk score* for a platform in use; **policies tolerating medium/high risk** (Low).
- **No Conditional Access policy requires a compliant device** (Medium).

Per-device Fleet findings are rolled up in large fleets like every other per-device finding (see
[Operations › Large fleets](../operations.md#large-fleets)). The device page shows tags, internet exposure,
asset value, tampering and troubleshooting counters.

## macOS and Linux

The *macOS / Linux* category covers what is different on non-Windows endpoints – the places where Defender is
installed but not actually working:

- **Full Disk Access missing** (High, per Mac) – without the TCC grant the sensor cannot read protected folders.
  Deploy the PPPC profile through MDM; users cannot grant it reliably.
- **System extensions not approved** (High, per Mac) – endpoint security or network extension not loaded: no
  real-time protection, no EDR data, no network protection.
- **Agent build 6+ months behind** (Medium, per platform) – Defender for macOS/Linux versions encode their month
  (`101.YYMM.x`); devices six or more months behind the newest build in the fleet are listed. Linux builds before
  101.2408 still rely on auditd, which is no longer supported as event provider.
- **Platform without an Intune Defender policy** (Medium; Low when all Macs are managed by another MDM such as
  Jamf) – Wardline can only observe the device state then, not the intended configuration.

## Response readiness

Feature `Response` (default on; Defender for Endpoint API `Machine.Read.All`, `Alert.Read.All`). Protection
settings are one half of Defender; whether anyone can and does respond is the other. Wardline reads the response
actions of the last 90 days and the alerts of the last 30 days with their automated-investigation state:

- **Investigations waiting for approval** (High) – automated investigation found remediation actions, the device
  group is on semi-automation and nobody approved for more than a day. The threat stays until someone clicks.
- **Untriaged alerts** (Medium) – Medium/High alerts still *New* after seven days.
- **Forgotten isolations** (Medium) – a device isolated for more than seven days without release.
- **Failed or stuck actions** (Low) – three or more actions failed, timed out or pending for 2+ days.
- **Response never exercised** (Low) – 25+ Windows devices and no isolation, live response, investigation
  package or code restriction in 90 days: nobody has verified that response works (permissions, live response
  enabled, servers included).
- **Live response with scripts** (Low) – who ran or uploaded scripts through live response; a prompt to check
  the library and the *unsigned script execution* setting.

Not available through any API and therefore not shown: the automation level per device group and the
live-response tenant settings (enabled, for servers, unsigned scripts). Both have to be checked in the portal
under *Settings → Endpoints*.
