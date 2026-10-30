# Access (optional)

Off by default. Enable with the feature `Access`:

```powershell
./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -Features Hunting,Indicators,Coverage,Agents,Access
```

The module looks at **one thing only: Microsoft Defender XDR unified RBAC** – the roles and assignments under *Permissions → Roles* in the Defender portal (Graph: `roleManagement/defender`).

## What it shows

- **Who holds which Defender role** – and how: *direct*, *via group* (transitive members), *eligible via PIM for groups*, or *via access package* (requestable, or already assigned when the package grants a role-holding group)
- **For which data sources** – the assignment's `appScopeIds`: *All data sources* (`/`) or specific ones such as Defender for Endpoint, Defender for Identity, Defender for Office 365
- **Permission groups** of the role (`secops`, `securityposture`, `configuration`) and whether the role carries **response or configuration permissions** (response actions, live response, file collection, security/system settings, authorization). Those are tagged *response/config* and drive the findings.
- **Last used** – the person's last interactive sign-in to the Defender portal (Entra sign-in logs, app `security.microsoft.com`). Sign-in logs reach back 30 days; Wardline carries the last-seen date forward across runs, so the observation window grows with every day the module is active. For PIM-eligible people the **last activation** of the group membership is shown as well.
- **Full access outside unified RBAC** – a separate table of people with Entra roles that bypass unified RBAC entirely: Global Administrator, Security Administrator, Security Operator (full access), Security Reader, Global Reader (read everything). They do not appear in the role list in the portal and are easy to forget.
- **Who can do what?** – search by role or permission (e.g. `liveresponse`, `microsoft.xdr/configuration/security/manage`)
- **My access** for every employee – their own Defender roles with links to PIM and My Access

## Findings (category *Least privilege*)

| Severity | Finding |
|---|---|
| Medium | Standing permission never used – a person holds a role with response/config permissions permanently but has not signed in to the Defender portal for `WL_ACCESS_UNUSED_DAYS` days (default 30) |
| Low | Eligible role never activated – PIM-eligible, no activation and no portal sign-in in the window |
| High | People with full Defender access through Entra roles (Global/Security Administrator, Security Operator) |
| Low | People reading all Defender data through Entra reader roles |
| Medium | Three or more people with permanent response/config permissions on all data sources (no PIM, no data-source scope) |
| Low | Role assignments made to individual users instead of groups |

A person who has not used a permission in the observation window is reported as *never used*; while the window is still shorter than `WL_ACCESS_UNUSED_DAYS` (first runs), the verdict is *no data yet* and no finding is raised.

## Limitations

- **Device-group scoping** for Defender for Endpoint (which device groups a role assignment applies to) is configured on the *Device groups* page and is not part of the role assignment object. Microsoft does not expose it through a public API, so Wardline cannot show it. The data-source scope (`Mde`, `/` …) is shown instead.
- Usage is based on interactive portal sign-ins. API-only use (e.g. a SOC automation signing in with a user account through a script) is not counted.
- Large groups are capped at 10,000 members when resolving (`WL_MAX_GROUP_MEMBERS`).

## Permissions

`RoleManagement.Read.Defender`, `RoleManagement.Read.Directory`, `PrivilegedEligibilitySchedule.Read.AzureADGroup`, `PrivilegedAssignmentSchedule.Read.AzureADGroup`, `EntitlementManagement.Read.All`, `AuditLog.Read.All`, `Directory.Read.All` – all read-only; see [Permissions](../permissions.md).
