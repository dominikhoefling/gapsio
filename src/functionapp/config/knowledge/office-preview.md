# Office preview (private preview) – Defender for Office 365

> Optional module (`officepreview`) in private preview.

The Office module answers one question for Defender for Office 365: **what got through, and why?** It reads the mail
and Teams telemetry and the audit trail in Advanced Hunting – it is not a copy of the Defender portal and it does not
read the policy settings.

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
The Teams, quarantine and policy change checks need tables that not every tenant has; when a table does not exist,
the check is **not available** (grey) instead of failed.

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

## Policy changes

Every change to a protection policy of Defender for Office 365 and Exchange Online Protection, with who made it,
when, and the values that were set: anti-spam (inbound, outbound, connection filter), anti-malware, Safe Links, Safe
Attachments, the tenant-wide Defender for Office 365 settings, preset security policies, the Tenant Allow/Block List,
transport rules, quarantine policies, DKIM, the Teams protection policy and advanced delivery.

A change is rated **weakens protection** when the value it sets lowers protection in itself, for example:

| Policy type | Values rated as weakening |
|---|---|
| Anti-spam | High confidence phishing not quarantined, phishing moved to the mailbox, spam left in the inbox, ZAP off, allowed senders or domains |
| Anti-malware | Common attachments filter off, ZAP off |
| Safe Links | A protection switched off (mail, Teams, Office, URL scanning, internal senders), click-through allowed, URLs excluded from rewriting |
| Safe Attachments | Switched off, or action *Allow* / *Monitor* |
| Tenant Allow/Block List | An allow entry – called out separately when it never expires |
| Transport rule | `SetSCL -1`, or a header that skips Safe Links or Safe Attachments processing |
| Other | A rule disabled, a preset security policy switched off, DKIM signing off, ZAP for Teams off, an IP allow list in the connection filter, an advanced delivery override |

Finding: *Policy changes weakened Defender for Office 365 protection* (High). Failed cmdlet calls are listed but not
rated. Anti-phish policies are listed here and rated in the anti-phish drift view, which compares with the value
before. Source: the Exchange admin audit trail in `CloudAppEvents`. Advanced Hunting keeps 30 days; Gapsio keeps the
changes for 400 days (`state/office-policy-history.json`).

## Quarantine

Releases, release requests and their denials, deletions and previews of quarantined mail (audit operations starting
with `Quarantine`), and who released. Each release is matched with the mail in `EmailEvents` through the network
message ID. Finding: *Messages with a phishing or malware verdict were released from quarantine* (Medium; High when
malware is among them). The page says how many releases could be matched – verdicts are only known for those. A
release can be the correct handling of a false positive; the finding asks for a review, it does not claim a mistake.

## Teams protection

Teams messages that Defender for Office 365 rates as phishing or malware
([MessageEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-messageevents-table),
[MessagePostDeliveryEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-messagepostdeliveryevents-table),
[MessageUrlInfo](https://learn.microsoft.com/defender-xdr/advanced-hunting-messageurlinfo-table)): blocked, delivered,
removed afterwards by ZAP or manual remediation, the senders and the domains of the URLs in these messages. Finding:
*Teams messages rated phishing or malware were delivered and not removed* (High) – delivered messages for which no
post-delivery action is recorded.

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
- **A policy change is rated by the value it sets**, not by comparison with the value before (the configuration is
  not readable). Removing a policy or rule is listed but not rated.
- **Teams tables** hold every message of conversations with external participants and internal messages that contain
  URLs – not all Teams traffic. They need Defender for Office 365 Plan 2. `MessageUrlInfo.ThreatTypes` is documented
  but does not resolve in practice; Gapsio takes the verdict from the message.
- **Quarantine and policy changes** come from `CloudAppEvents` and need the Microsoft 365 connector of Defender for
  Cloud Apps. The operation names and the `NetworkMessageId` field follow the audit schema; no quarantine activity
  was available to verify them against a tenant.
- Advanced Hunting keeps 30 days; the anti-phish and policy change histories are kept by Gapsio and grow from the
  first run.

## Enable and run

```powershell
./setup/Install-Gapsio.ps1 -ResourceGroup rg-gapsio -Features Hunting,Indicators,Coverage,Response,Agents,OfficePreview
```

This sets `GAPSIO_MODULES=…,officepreview`. The module runs on its own timer (`CollectOfficePreview`) and with
*Collect now*. Snapshot: `state/officepreview-latest.json`, change history `state/officepreview-changes.json`.

## Permissions

`ThreatHunting.Read.All` (feature `Hunting`) – nothing else. The licence figures in the overview come from the
Licensing module when it is enabled.
