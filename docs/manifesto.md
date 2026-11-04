# Gapsio – the open-core promise

Gapsio is open source (MIT) and has a paid Enterprise edition. This page says exactly what that means, so that
nobody has to guess what might be taken away later.

## What is free, forever

- **Every check, collector and data source.** Exclusions from every source, ASR rules, the MDAV baseline, device
  hygiene, AI agents, access paths, licensing – all of it runs in the Community edition and all of it is in this
  repository. There is no hidden "pro" collector and no check that only runs with a key.
- **Complete data in your storage account.** Collection and history are always complete. The Community limit is a
  *display* limit: lists show their first 10 rows in clear, the rest is masked server-side. Counts, charts,
  severities, drift and notices are never masked.
- **Self-hosting, offline licence check, no telemetry.** Gapsio never calls home – not for licences, not for usage.
  That will not change.
- **Updates and security fixes** for the Community edition, on the same schedule as Enterprise.
- **Documentation**, the baseline definition, the permission model and the threat model.

## What Enterprise pays for

The Enterprise licence (per tenant, [€19 per month or €199 per year](https://gapsio.cloud/#pricing)) removes the
10-row display limit and unlocks governance: assigning findings, accepting risks with expiry and justification,
the change history and notifications. In short: everything that an organisation needs to *run* Gapsio as an
auditable control rather than look at it.

The money funds the work that an open-source security tool otherwise does not get: keeping up with Microsoft's
beta APIs, re-testing the baseline against every Defender platform release, writing the rationale and fix text for
each check in two languages, and answering support requests from people whose job depends on the numbers being right.

## Why not just MIT and donations?

Because security tooling that depends on Microsoft APIs rots in months, not years, and because a product that
companies put in front of auditors needs somebody who is accountable for it. A small, predictable price per tenant
is the most honest way to make that sustainable – more honest than a free tool with a "contact sales" enterprise
version, and more honest than tracking usage to sell something later.

## Why is the limit on display and not on features?

Because a check that only exists behind a paywall is a check the community cannot read, review or improve. Keeping
the full data in your own storage account also means that if you ever stop paying, nothing is lost: enter a key
again and the full view is back; or read the tables with your own tooling – they are yours.

## Could someone fork it and remove the limit?

Yes – that is what MIT allows, and we chose MIT with that in mind. The display limit is a few lines in the API
layer, not DRM. What a fork cannot do is call itself Gapsio, issue Gapsio licence keys, or receive our updates,
baseline maintenance and support. We think organisations will pay for a maintained product; if we are wrong, the
licence was still the right choice for the people who use it.

## Governance

- One maintainer today ([Dominik Hoefling](https://github.com/dominikhoefling)); contributions under the Developer
  Certificate of Origin, no CLA. If the project grows, the maintainers will be listed in `CODEOWNERS`.
- Releases are tagged, checksummed and carry build provenance; the updater verifies both. See
  [development](development.md) and [security review](trust.md).
- Roadmap decisions are made in the open in GitHub Discussions and on the [public roadmap](https://gapsio.cloud/roadmap).
- If Gapsio is ever discontinued, the last release stays MIT and the licence check will be published with a
  perpetual key for existing customers. Nobody should lose a security control because a vendor went away.
