# Office preview (private preview) – Defender for Office 365

> Optional module (`officepreview`) in private preview.

The Office module answers one question for Defender for Office 365: **what got through, and why?** It reads the mail
telemetry in Advanced Hunting – it is not a copy of the Defender portal and it does not read the policy settings.

## What it checks

Every check uses documented columns of the hunting schema
([EmailEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-emailevents-table),
[EmailPostDeliveryEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-emailpostdeliveryevents-table),
[UrlClickEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-urlclickevents-table)), last 30 days,
inbound mail.

| Check | How it is measured | Finding |
|---|---|---|
| **Phish and malware still in inboxes** | `ThreatTypes` is phishing or malware (the current verdict) and `LatestDeliveryLocation` is the inbox | High |
| **Threats delivered by an allow** | Threat verdict and `OrgLevelAction` or `UserLevelAction` is an allow – with the policy that allowed it | High when delivered, otherwise Medium |
| **Safe Links click-through** | `IsClickedThrough`: the user saw the warning and continued | Medium |
| **Own sender domains failing DMARC** | Inbound mail whose From domain is one of the domains in your outbound mail, DMARC failed, still delivered | High |
| Post-delivery actions | Phish ZAP, malware ZAP, manual remediation (`EmailPostDeliveryEvents.ActionType`) | – (context) |
| Trends | Threat types and delivery outcomes per day, threats by type and classification | – (context) |

A check that cannot be read is shown as **failed** – its number is missing, not zero, and it raises no finding.

!!! note "Organisation-level and mailbox policies"
    `OrgLevelPolicy` is a policy defined by the organisation (Tenant Allow/Block List, transport rules, connectors).
    `UserLevelPolicy` is the **recipient's own mailbox policy**, such as the safe senders list – not an admin policy.
    Gapsio keeps the two apart: an allow on mailbox level means a user's safe sender entry delivered mail the
    organisation would have stopped.

## Policy map

Three tables for inbound mail:

- **Which protection acted** – the policy type that determined the final action (`EmailActionPolicy`: anti-spam,
  anti-phishing spoof, Safe Attachments, transport rules …) and the action taken
- **Organisation-level policies** – what each policy did, how many of its messages carried a threat verdict
- **Mailbox policies of the recipients** – the same for safe and blocked sender lists

## Anti-phish drift

Who changed which anti-phish policy setting (phishing threshold, impersonation and spoof actions, exclusions), rated
as *weaker* or *stronger*, and how the share of delivered phishing moved in the seven days before and after. The
changes come from the Exchange admin audit trail in `CloudAppEvents`; this needs the Microsoft 365 connector of
Defender for Cloud Apps. Findings: *Anti-phish protection was weakened* (High), *More phish delivered after a policy
change* (Medium).

## Findings, history and notifications

Office findings appear in the **Findings** list with the other modules: they can be assigned, accepted with a reason
and an expiry, and they count in the audit evidence view. Every run is compared with the previous one – new and
resolved findings are in the change history and can go to Teams or Power Automate like any other finding.

## Limits

- **Policy settings are not read.** Microsoft Graph has no API for Defender for Office 365 policies; they are only
  available through Exchange Online PowerShell. Gapsio therefore shows the effect of the policies (telemetry) and
  their changes (audit trail), not their configuration.
- **Values Microsoft does not enumerate** (`OrgLevelAction`, `AuthenticationDetails`) are matched tolerantly
  ("contains allow", `dmarc … fail`).
- **Own domains** are the sender domains seen in your outbound and intra-org mail of the last 30 days. A domain you
  never send from is not recognised as your own.
- **Not covered yet:** Teams messages, quarantine releases, changes to other policy types (anti-spam, Safe Links,
  Safe Attachments, quarantine policies).
- Advanced Hunting keeps 30 days; the anti-phish history is kept by Gapsio and grows from the first run.

## Enable and run

```powershell
./setup/Install-Gapsio.ps1 -ResourceGroup rg-gapsio -Features Hunting,Indicators,Coverage,Response,Agents,OfficePreview
```

This sets `GAPSIO_MODULES=…,officepreview`. The module runs on its own timer (`CollectOfficePreview`) and with
*Collect now*. Snapshot: `state/officepreview-latest.json`, change history `state/officepreview-changes.json`.

## Permissions

`ThreatHunting.Read.All` (feature `Hunting`) – nothing else. The licence figures in the overview come from the
Licensing module when it is enabled.
