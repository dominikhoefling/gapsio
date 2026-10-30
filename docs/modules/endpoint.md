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

## Combined findings

Findings that only appear when several signals meet, for example:

- tamper protection off **and** local exclusions present
- passive mode **and** local exclusions
- local exclusions effective because `DisableLocalAdminMerge` / `exclusionsMergePolicy` is missing
- a local AI agent with auto-approve on a weakened device (see [AI agents](agents.md))
