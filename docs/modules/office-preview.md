# Office preview (private preview) – Defender for Office 365

> Optional module (`officepreview`) in private preview.

The Office preview gives a **telemetry-based risk view** for Defender for Office 365. It is intentionally not a copy of the Defender portal. It highlights where policy targeting and observed outcomes can conflict or become redundant.

## What it checks

Current probes include:

- override exposure (allow/deliver outcomes)
- Safe Links click-through signals
- likely ZAP blind spots
- authentication failure posture (DMARC/SPF/DKIM)
- risky first-contact traffic
- encrypted attachment volume
- user/domain policy overlap
- duplicate-like policy effects
- precedence conflict signals
- TABL/IOC inventory and action/type breakdown
- licensing context from `licensing-latest.json` (if available)
- effective policy map (top recipients / top domains)
- MDO dashboard trends (daily threat categories, daily action outcomes, top campaigns/themes)

## Effective policy map

The page now shows two tables:

- **Top recipients**: recipient, events, number of policies, effective actions, policy set
- **Top domains**: domain, events, affected users, number of policies, effective actions, policy set

This is a fast way to spot:

- recipients/domains hit by many policies,
- multiple policies that lead to the same action,
- potential order/precedence conflicts.

## How to read “Result” (plain language)

The `Result` column is not meant as a KPI by itself. It is a **triage signal**:

- “66 messages, 4 overrides …” = there were 66 matching events and 4 were delivered via override-like outcomes.
- “36 attachments, 12 encrypted …” = 12 attachments reduced content-inspection visibility.
- “No telemetry data …” = no matching events in the selected window (not automatically good or bad).

Use it like this:

1. Check whether the signal is non-zero.
2. Open the probe details.
3. Use the direct **Open in Defender Advanced Hunting** link.
4. Investigate concrete senders/recipients/policies there.

So the module answers: **“Where should I look first?”**
It does not replace the full Defender policy/configuration analysis.

## TABL / IOC view

The preview now includes an IOC/TABL section:

- inventory snapshot (total, active, expiring soon)
- top action/type buckets (e.g. URL+Block, Domain+Warn)

This helps validate that email/domain/url/IP indicators are actually present and active.

## MDO dashboard view

The preview now includes chart-based reports similar to endpoint views:

- threat categories by day (30d)
- action outcomes by day (allow/block/quarantine/junk)
- top campaigns/themes by event volume and recipients

Use these charts for prioritisation and drill down via the Defender AH links in probe details.

## Data source and caveats

- Source: Defender Advanced Hunting (`EmailEvents`, `UrlClickEvents`, `EmailPostDeliveryEvents`, `EmailAttachmentInfo`).
- The checks are **heuristics** from observed events, not an authoritative policy assignment report.
- True policy priority/assignment truth still comes from Exchange/MDO policy configuration APIs and admin configuration.

## Output

Snapshot file:

- `state/office-preview-latest.json`

Key fields:

- `version`
- `generatedAt`
- `windowDays`
- `ok` / `errors`
- `results[]`
- `findings[]`

## Enable and runtime

Enable it via the install script feature `OfficePreview`:

```powershell
./setup/Install-Gapsio.ps1 -ResourceGroup rg-gapsio -Features Hunting,Indicators,Coverage,Response,Agents,OfficePreview
```

This sets `WL_MODULES=...,officepreview`.

Runtime:

- Timer function: `CollectOfficePreview`
- Manual run: `RunOnDemand` with `{"module":"officepreview"}`

## Permissions

- `ThreatHunting.Read.All` (feature `Hunting`) is required.
- For licensing context, the optional Licensing module snapshot must exist.
