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
