# Access (optional)

Off by default. Enable with the feature `Access`:

```powershell
./setup/Install-Gapsio.ps1 -ResourceGroup rg-gapsio -Features Hunting,Indicators,Coverage,Response,Agents,Access
```

The module looks at **one thing only: Microsoft Defender XDR unified RBAC** – the roles and assignments under *Permissions → Roles* in the Defender portal (Graph: `roleManagement/defender`).

## What it shows

- **Who holds which Defender role** – and how: *direct*, *via group* (transitive members), *eligible via PIM for groups*, or *via access package* (requestable, or already assigned when the package grants a role-holding group)
- **For which data sources** – the assignment's `appScopeIds`: *All data sources* (`/`) or specific ones such as Defender for Endpoint, Defender for Identity, Defender for Office 365
- **Permission groups** of the role (`secops`, `securityposture`, `configuration`) and whether the role carries **response or configuration permissions** (response actions, live response, file collection, security/system settings, authorization). Those are tagged *response/config* and drive the findings.
- **Last used** – the person's last interactive sign-in to the Defender portal (Entra sign-in logs, app `security.microsoft.com`). Sign-in logs reach back 30 days; Gapsio carries the last-seen date forward across runs, so the observation window grows with every day the module is active. For PIM-eligible people the **last activation** of the group membership is shown as well.
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

| High / Medium | API app with Defender write permissions – application permissions such as `Machine.Offboard`, `Machine.LiveResponse`, `Machine.Isolate`, `Ti.ReadWrite.All` or Graph `Security…ReadWrite` on the Defender for Endpoint API, the Defender XDR API or Microsoft Graph. High when the app uses a client secret, has a credential valid for more than two years, has no owner or is registered in another tenant (category *Platform*) |
| Low | Read-only Defender integrations that authenticate with a client secret (category *Platform*) |
| Medium / Low | Defender role groups without an active access review (Medium when a group grants response, live response or settings permissions) |
| Medium / Low | Weak PIM activation for a privileged Defender group – no MFA/authentication context, no justification, activation longer than 8 hours |
| Medium | Offboarding package downloaded (feature `Audit`, unified audit log, 30 days) |
| Low | Live response actions and portal setting changes in 30 days (feature `Audit`) |

A person who has not used a permission in the observation window is reported as *never used*; while the window is still shorter than `WL_ACCESS_UNUSED_DAYS` (first runs), the verdict is *no data yet* and no finding is raised.

## Limitations

- **Device-group scoping** for Defender for Endpoint (which device groups a role assignment applies to) is configured on the *Device groups* page and is not part of the role assignment object. Microsoft does not expose it through a public API, so Gapsio cannot show it. The data-source scope (`Mde`, `/` …) is shown instead.
- Usage is based on interactive portal sign-ins. API-only use (e.g. a SOC automation signing in with a user account through a script) is not counted.
- Large groups are capped at 10,000 members when resolving (`WL_MAX_GROUP_MEMBERS`).

- **Audit log** (feature `Audit`): the Graph audit log query API runs asynchronously. Each run reads the query the
  previous run started, so results appear from the second run on. Operation names are classified by keyword
  (offboard, live response, settings); Microsoft does not publish a fixed list for record type `mdatpAudit`.

## Permissions

`RoleManagement.Read.Defender`, `RoleManagement.Read.Directory`, `PrivilegedEligibilitySchedule.Read.AzureADGroup`, `PrivilegedAssignmentSchedule.Read.AzureADGroup`, `EntitlementManagement.Read.All`, `AuditLog.Read.All`, `Directory.Read.All`, `AccessReview.Read.All`, `RoleManagementPolicy.Read.AzureADGroup`; feature `Audit`: `AuditLogsQuery.Read.All` – all read-only; see [Permissions](../permissions.md).
