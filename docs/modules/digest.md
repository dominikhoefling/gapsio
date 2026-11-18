# Change digest

Feature `Digest` (off by default). What Microsoft announces for the security products Gapsio audits – and what it asks
you to do, by when.

Microsoft announces changes to Defender, Intune, Entra and Purview in the **message center** of every tenant: new
defaults, retirements, features that need a decision, deadlines. The posts arrive mixed with everything else Microsoft
365 announces, and a post with a deadline looks like any other. The change digest keeps the posts that concern security
products, puts the ones that need action first and turns deadlines into findings.

## Source

The Microsoft 365 message center of the tenant, read through Microsoft Graph
(`admin/serviceAnnouncement/messages`, v1.0). Permission: `ServiceMessage.Read.All` (application, read-only) – it
allows reading message center posts and nothing else.

Posts are kept when one of their services matches Defender, Intune, Entra, Purview, Sentinel, Security Copilot,
Agent 365 or Exchange Online Protection. Add more with the app setting `GAPSIO_DIGEST_SERVICES` (a regular expression
on the service names, for example `Microsoft Teams|SharePoint`). Posts Microsoft has taken off the message center are
dropped.

The collection runs daily at 04:05 UTC and on demand (**Collect now**).

## How posts are rated

No model is involved. Gapsio uses the fields Microsoft sets and the sections Microsoft writes into the post.

| To do | When | Priority |
|---|---|---|
| Act by a date | The post has a deadline (`actionRequiredByDateTime`) that is still ahead | High within 14 days, Medium within 60 days, otherwise Low |
| Deadline passed | The deadline is in the past | Medium |
| Plan for the change | Major change, retirement, or category *plan for change* | Medium for major changes and retirements, otherwise Low |
| Check | Category *prevent or fix issue* | Low |
| For information | Everything else | Info |

For every post the view shows Microsoft's own sections, when the post has them: **What you need to do to prepare**,
**When this will happen**, **How this will affect your organization** and the summary. Microsoft writes these in
English; Gapsio does not translate or rephrase them. A link opens the post in the message center.

## Findings

Posts become findings, so they can be assigned to an owner, documented as handled (accept the finding with a note)
and sent to Teams with the other notifications:

- **Microsoft asks for action by a date** – severity by the days left (High, Medium, Low)
- **Deadline passed** in the last 30 days – Medium
- **Major change or retirement announced** in the last 30 days, without a deadline – Low

There is one finding per post. When Microsoft moves the deadline or rewords the title, the finding changes – it is
not reported as a new one.

## When the message center cannot be read

If the read fails – usually because `ServiceMessage.Read.All` has not been granted yet – the run keeps the posts and
findings of the last successful run, marks the snapshot as *unavailable* and shows since when the list is unchanged.
Posts are not reported as removed and do not come back as new findings with the next successful run.

## Limits

- The message center shows what Microsoft announces for the tenant. Documentation changes on Microsoft Learn and
  product release notes are not part of this version.
- Whether a post matters for this tenant is not checked against the tenant's configuration yet (for example whether
  an affected feature is in use).
- Deadlines are the dates Microsoft sets in the post; some posts name a date only in their text – those have no
  deadline here and are rated *plan for the change*.
