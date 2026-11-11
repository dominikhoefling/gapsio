# Compliance mapping

Gapsio is **not** a compliance tool and does not certify anything. It produces evidence – dated snapshots, findings and a change history – that auditors regularly ask for when they assess how an organisation protects its endpoints, its AI agents and its privileged access. This page maps that evidence to the controls it typically supports, so that you can point an auditor to the right export instead of building the evidence by hand.

!!! warning "Evidence, not certification"
    Every control below still needs a policy, an owner and a process around it. Gapsio shows *what the tenant looks like*; it cannot show that someone reviewed it. Treat the portal, the exports and the change history as inputs to your own review, not as the review itself.

## What Gapsio provides as evidence

| Evidence | Where | Typical use |
|---|---|---|
| Daily snapshot per module (`endpoint`, `agents`, `access`, `licensing`) | `state/*-latest.json`, dated copies in `snapshots/` | Point-in-time proof of coverage and configuration |
| Findings with severity, category and affected devices/identities | Portal → Findings, API `/api/findings`, CSV export | Open risk register, remediation tracking |
| Change history (new/resolved findings, new devices, setting changes) | Portal → Changes, `state/changes.json` | Proof that drift is detected and acted on |
| Baseline comparison against the Defender Antivirus baseline | Portal → Baseline, [Customising the baseline](baseline.md) | Configuration standard and deviations |
| Device inventory with onboarding, sensor health, AV mode, third-party AV/EDR | Portal → Devices | Asset inventory of protected endpoints |
| MDE licence indication (plans owned vs. users vs. devices) | Portal → Licensing (MDE), [Licensing module](modules/licensing.md) | Licence compliance, cost control |
| Privileged role and PIM observations | Portal → Access, [Access module](modules/access.md) | Access reviews |
| Portal access log (who viewed what, admin actions) | Function App logs / Application Insights | Accountability for the evidence itself |

All exports are UTC-stamped and contain the Gapsio version that produced them.

## ISO/IEC 27001:2022 – Annex A

| Control | Title | How Gapsio helps | Module |
|---|---|---|---|
| A.5.9 | Inventory of information and other associated assets | Device list with onboarding state, OS, last seen; devices seen by Intune/Entra but not onboarded to Defender | Endpoint |
| A.5.15 / A.5.18 | Access control / Access rights | Privileged role assignments, permanent vs. eligible (PIM), stale or orphaned assignments | Access |
| A.5.32 | Intellectual property rights | Indication whether MDE plans owned cover the users and devices actually protected; over-consumption finding | Licensing |
| A.8.1 | User endpoint devices | Defender AV mode (active/passive/disabled), real-time protection, tamper protection, EDR sensor health per device | Endpoint |
| A.8.7 | Protection against malware | Baseline comparison of Defender Antivirus settings, signature age, cloud protection, ASR rules; third-party AV/EDR running alongside Defender | Endpoint |
| A.8.8 | Management of technical vulnerabilities | Onboarding gaps (devices without EDR sensor are blind to vulnerability management) | Endpoint |
| A.8.9 | Configuration management | Baseline and drift history; setting changes appear in the change history with date | Endpoint |
| A.8.15 / A.8.16 | Logging / Monitoring activities | Sensor health, devices not reporting, inactive devices; Gapsio's own portal access log | Endpoint, Core |
| A.8.2 | Privileged access rights | PIM usage, break-glass accounts, role assignments outside PIM | Access |
| A.5.23 | Information security for use of cloud services | Visibility of AI agents (Copilot Studio, Azure AI) and whether they are covered by Defender | Agents |
| A.7.10 / A.8.12 | Storage media / Data leakage prevention | USB storage in use versus device control policies | Endpoint |
| A.8.16 | Monitoring activities | Custom detection rules that were switched off, fail or are disabled | Endpoint (`Detections`) |
| A.5.24 / A.5.26 | Incident management planning / Response to incidents | Response readiness and the prerequisites of automatic attack disruption | Endpoint |

## NIS2 – Article 21(2)

| Measure | Title | How Gapsio helps |
|---|---|---|
| (b) | Incident handling | Response readiness, attack disruption prerequisites, custom detection rules that stopped |
| (e) | Security in acquisition, development and maintenance, including vulnerability handling | Update findings (Defender platform, engine and signature age, update rings) |
| (f) | Assessing the effectiveness of risk-management measures | Baseline versus effective state, policy conflicts, dependency and combined findings, coverage gaps |
| (g) | Basic cyber hygiene practices | Exclusions, allow indicators, ASR rules, device state, device control |
| (i) | Access control policies and asset management | Defender roles and their use, API apps, device and agent inventory |
| (j) | Multi-factor or continuous authentication | Conditional Access coverage of AI agents |

## Audit evidence in the portal

*History › Audit evidence* sorts the open findings and the accepted risks by these controls (ISO/IEC 27001:2022
Annex A and NIS2 Article 21(2)): per control the status (*findings open*, *risks accepted*, *no findings*, *not
assessed*), the open findings by severity and the areas Gapsio checks. The page can be printed or saved as PDF; the
second table (one row per control and finding) exports as CSV for the audit file.

The mapping ships in `config/control-mapping.json` (finding category → control). To adjust it, put your own
`control-mapping.json` into the `config` container of the storage account – same mechanism as the
[baseline](baseline.md).

It is a mapping aid: it shows which findings are relevant evidence for a control, not that a control is fulfilled.

## NIST Cybersecurity Framework 2.0

| Function / Category | How Gapsio helps |
|---|---|
| **GV.OC / GV.RM** Organisational context, risk management | Findings with severity provide a prioritised, repeatable input to the risk register |
| **ID.AM-01/02** Hardware and software inventory | Onboarded devices, missing devices, third-party security software inventory |
| **ID.RA** Risk assessment | Finding categories (Coverage, Configuration, Health, Licensing, Access) with trend over time |
| **PR.AA-05** Access permissions and authorisations | Privileged roles, PIM eligibility, permanent assignments |
| **PR.PS-01** Configuration management practices | Baseline comparison and drift history |
| **PR.PS-05** Prevent installation/execution of unauthorised software | ASR rules and AV mode as part of the baseline |
| **DE.CM-01/09** Monitoring of networks and computing hardware | Sensor health, devices not reporting, passive-mode AV |
| **DE.AE** Adverse event analysis | Not covered – Gapsio does not process alerts or incidents |
| **RS / RC** Respond / Recover | Not covered |

## SOC 2 – Trust Services Criteria (Security)

| Criteria | How Gapsio helps |
|---|---|
| CC6.1 Logical access security | Privileged role inventory, PIM coverage (Access) |
| CC6.6 Protection against threats from outside system boundaries | Endpoint protection coverage, AV mode, EDR onboarding |
| CC6.8 Prevention/detection of unauthorised or malicious software | Baseline comparison, ASR rules, third-party AV/EDR detection |
| CC7.1 Detection of configuration changes and vulnerabilities | Change history, baseline drift |
| CC7.2 Monitoring of system components for anomalies | Sensor health and inactive devices |
| CC8.1 Change management | Setting changes recorded with date; Gapsio itself updates only via explicit `Update-Gapsio` |

## GDPR / data protection

Gapsio processes personal data (user principal names, device names, role assignments). The design decisions that support the data-protection principles are:

| Principle (Art. 5) / Obligation | How Gapsio addresses it |
|---|---|
| Purpose limitation | Read-only collection, fixed set of Graph/Defender queries per module; no alert or content data |
| Data minimisation | Only the attributes needed for a finding are stored. `GAPSIO_LICENSING_DETAIL=aggregate` pseudonymises UPNs in the licensing snapshot; the Community edition masks names in exports |
| Storage limitation | `GAPSIO_SNAPSHOT_RETENTION_DAYS` and `GAPSIO_CHANGE_RETENTION_DAYS` (default 365) enforced by a storage lifecycle rule |
| Integrity and confidentiality | Data stays in your own Azure subscription; Entra ID sign-in with role-based portal access; no outbound transfer except the optional update check (no tenant data) |
| Accountability (Art. 5(2), Art. 30) | Portal access log; this page and [Architecture and data protection](security.md) as input to the record of processing activities |
| Data protection by design (Art. 25) | Optional modules are off by default; permissions are granted per feature ([Features and permissions](permissions.md)) |
| Security of processing (Art. 32) | See [Security review](trust.md) |

A short description of the processing for your record of processing activities is in [Architecture and data protection](security.md).

## Readiness checklist

Use this before an audit to make sure the evidence is complete:

- [ ] All modules that are in scope are enabled and have collected within the last 24 hours (Portal → Overview shows the collection timestamp).
- [ ] Snapshot and change retention cover the audit period (`GAPSIO_SNAPSHOT_RETENTION_DAYS`, `GAPSIO_CHANGE_RETENTION_DAYS`).
- [ ] The Defender Antivirus baseline has been reviewed and deviations are either fixed or documented ([Customising the baseline](baseline.md)).
- [ ] High findings have an owner and a due date outside Gapsio (ticketing system).
- [ ] Device exclusions for devices that must not be onboarded (e.g. lab systems) are documented.
- [ ] If the Licensing module is used, the observation window and the devices-per-user value match the licence terms you have agreed with Microsoft.
- [ ] Portal roles follow [Separation of duties](separation-of-duties.md); the admin role is limited.
- [ ] Export of findings and the device list has been produced and archived with a date.
- [ ] Known gaps are stated explicitly ([Known limitations](limitations.md)) – auditors prefer a documented gap to an undocumented assumption.

## Not in scope

Gapsio does not provide: alert or incident handling, vulnerability scoring, data loss prevention, identity protection signals, backup or recovery evidence, or legal advice on licensing. For those, use the respective Microsoft Defender XDR, Purview and Entra workloads.
