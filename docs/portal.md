# Portal

The portal is served by the Function App itself under `https://<function app>.azurewebsites.net/` and protected by
App Service Authentication (Entra ID).

## Roles

| Who | Sees |
|---|---|
| **Wardline Administrator** (app role `Wardline.Admin`) | Everything; can start runs ("Collect now"); sees update notices |
| Other users of the tenant | Only "My access" (when the Access feature is on). Use `-RestrictToAssignedUsers` to block everyone without an assignment. |

## Views

| Area | Views |
|---|---|
| Endpoint | Overview, Findings, Exclusions (policy, local, indicators, EDR), ASR rules (rules, device groups, devices, exclusions), Devices, Baseline |
| AI agents | Agents (cloud / local), Conditional Access |
| Access | Roles, Who can do what?, My access |
| History | Changes between runs, accepted risks |

Every table can be filtered and exported as CSV. Device names link to the device page.

## Charts

- **Overview › Trend (30 days)**: open findings per severity (accepted ones excluded) and changes per day (added, changed,
  removed). Click a day to open the changes of that day.
- **Devices › Protection at a glance**: one donut per Defender feature – tamper, real-time, cloud, behaviour and PUA
  protection, network protection, controlled folder access, EDR in block mode, signatures, EDR sensor, antivirus mode and
  platforms. The centre shows the share of devices with the feature on (unknown counts against it, not applicable does
  not count). Hover a segment to see the devices, click it to filter the device table.
- **History › Changes**: changes per day with details per area on hover; a click filters the table to that day.

Charts are plain SVG rendered by the portal – no external library, nothing leaves the browser. The trend fills up with
every run from this version on; changes per day also use the existing change history.

## Change history

Every change is colour-coded: **green** = added, **red** = removed, **amber** = changed. For changed items the parts of
*Before* that are gone are marked red and struck through, the new parts in *After* green – so a device going from
`NetworkProtection=GOOD` to `NetworkProtection=BAD` is visible at a glance.

## Accepted risks

Administrators can **accept** a finding or an exclusion (in its detail row): justification, owner, optional ticket and an
expiry date of at most one year. Accepted items stay visible with an "Accepted" tag, but no longer count as open, are
hidden by default and do not trigger notifications. After the expiry date they are open again. **History › Accepted
risks** lists all acceptances and an audit log of every accept and revoke – the record auditors ask for.

## Language

English and German, switchable in the header. The default follows the browser language; the choice is remembered per
browser. Findings, baseline texts and status values are translated as well.

## Version and updates

The sidebar shows the installed version. When a newer release exists, administrators see **Update available** with a
link to the release notes – see [updates](updates.md).
