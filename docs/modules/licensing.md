# Licensing (optional) – Defender for Endpoint

Off by default. Enable with the feature `Licensing` (it needs `Hunting` for the device mapping):

```powershell
./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -Features Hunting,Indicators,Coverage,Response,Agents,Licensing
```

The module answers one question for **Microsoft Defender for Endpoint only**: do the licences you bought and assigned match the devices that are actually onboarded? It is an **indication, not an audit** – Microsoft's licence terms are enforced contractually, not technically, and the only authoritative numbers are the ones in the Microsoft 365 admin center and your agreement.

## How Defender for Endpoint is licensed (what the module relies on)

| Statement | Certainty | Source |
|---|---|---|
| MDE Plan 1, Plan 2 and Defender for Business are **per-user** licences; the service plan appears in `assignedPlans` of the user (`WINDEFATP` = P2, `MDE_LITE` = P1, `MDE_SMB` = Defender for Business). | High | Microsoft Graph `subscribedSkus` / `users?$select=assignedPlans`, [licensing service plan reference](https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference) |
| A licensed user may use Defender for Endpoint on **up to five concurrent devices**. | Medium–high – stated in the Product Terms and in Microsoft's MDE licensing FAQ, but the exact wording differs by agreement; check yours. | Microsoft Product Terms (Microsoft 365 / Defender for Endpoint) |
| **Servers** are not covered by user licences. They need Defender for Servers (Defender for Cloud, per Azure subscription) or a *Defender for Endpoint Server* SKU. Defender for Servers is not visible in Microsoft Graph. | High | Microsoft Defender for Servers documentation |
| Devices with **no user** (kiosks, shared devices, VDI pools) are licensed through the users who use them; Microsoft has no per-device licence for clients. | High | Product Terms |

The module never decides whether you are compliant. It shows the gap between *users with a plan* and *devices that are onboarded* so a licensing or security owner can look at the right places.

## What it collects

1. **Purchased plans** – `subscribedSkus` (needs `Organization.Read.All`): every SKU that contains an MDE service plan, with purchased (`prepaidUnits.enabled`) and assigned (`consumedUnits`) units. SKUs for servers (`MDATP_Server`, `…_SERVER`) are flagged separately.
2. **Licensed users** – `users?$select=id,userPrincipalName,displayName,accountEnabled,userType,assignedPlans` (needs `User.Read.All`): users whose `assignedPlans` contain an MDE plan with `capabilityStatus = Enabled`. Deleted/suspended plans do not count. The best plan wins (P2 > P1 > Defender for Business).
3. **Onboarded devices** – Advanced Hunting `DeviceInfo` (onboarded, last 30 days) with `LoggedOnUsers`, plus `DeviceLogonEvents` (interactive, remote-interactive and unlock logons of the last 30 days, aggregated per device and account). Servers (`DeviceType = Server` or a server OS) are kept apart from clients.
4. **Intune primary user** – when the Coverage feature is on, the managed device's `userPrincipalName` (exact match via Entra device ID) is the most reliable mapping.

Device → user mapping, in order of confidence:

| Confidence | Meaning |
|---|---|
| `Intune` | Entra device ID matched an Intune managed device with a primary user (exact UPN) |
| `Logon` | Defender's `LoggedOnUsers` field or a `DeviceLogonEvents` account name matched a UPN or SAM account name |
| `None` | No user seen in the window (*No user*) |

## What the portal shows

**Licences (Defender for Endpoint)** in the sidebar:

- Summary: users with an MDE plan, onboarded clients, licensed / unlicensed / no-user clients, licensed users without a device, users above the device allowance, onboarded servers.
- **Purchased plans** – SKU, plan, purchased, assigned, free; over-assigned SKUs are flagged.
- **Client devices** – every onboarded client with the users seen in the window, the best plan among them, the covering user and the mapping confidence. Filters for licence state and platform.
- **Licensed users** – each user with a plan, how many onboarded clients they were seen on and which. States: *In use*, *No device*, *Above n devices*, *Account disabled*.
- **Servers** – listed separately with the hint that their licence lives in Azure.
- **Read before acting** – the caveats, always visible.

The overview page gets a short *Licences* block when the module is enabled; the findings page includes the module's findings (category *Licensing*).

## Findings (category *Licensing*)

| Severity | Finding | What it means |
|---|---|---|
| High | More licences assigned than purchased: *SKU* | `consumedUnits > prepaidUnits.enabled`. Microsoft tolerates this temporarily; it is billed or blocked at the next true-up. |
| Medium | *n* onboarded client(s) used only by users without a Defender for Endpoint licence | Every user seen on the device in 30 days has no MDE plan. Assign a plan (group-based licensing) or stop onboarding the device. |
| Medium | *n* client(s) covered only by Plan 1 in a tenant using Plan 2 features | The device's users hold P1 only while the tenant has P2 SKUs; P1 has no EDR, vulnerability management or automated investigation – but the device gets them. |
| Low | *n* licensed user(s) without an onboarded device in 30 days | Possibly unused licences – or a device that is not onboarded, has no interactive logons (VDI, Mac without Intune), or was inactive. Cross-check with Coverage. |
| Low | *n* user(s) seen on more than `WL_LICENSING_DEVICES_PER_USER` (5) devices | Above the per-user allowance – or an administrator / technician account that logs on everywhere. |
| Low | *n* onboarded server(s) – no server licence visible in Microsoft 365 | Normal when servers are licensed through Defender for Servers in Azure. Confirm it there. |

Aggregated findings carry `deviceCount` and `deviceSample` like fleet findings and keep a stable key, so an accepted exception survives count changes.

## Caveats (shown in the portal)

- Indication, not an audit. The mapping comes from Intune and interactive logons; shared devices, kiosks, VDI and service accounts produce *no user* or inflate per-user counts.
- A device used by one licensed and one unlicensed person counts as **licensed** (the licensed user covers it).
- Guests and disabled accounts: disabled accounts with a plan are listed as *Account disabled*; guests are included if they hold a plan.
- Server licences (Defender for Servers) are not visible in Graph; servers are only counted.
- `DeviceLogonEvents` is not available for macOS/Linux in the same depth as Windows; Macs without Intune often end up as *no user*.
- The 5-device allowance is a Product Terms rule, not something Microsoft enforces technically; treat the *above n devices* hint as a prompt to look, not a violation.

## Data protection

The snapshot contains UPNs and display names of licensed users and the accounts seen on each device. If that is more than you want to store, set the app setting `WL_LICENSING_DETAIL = aggregate`: user identities are replaced by stable pseudonyms (`user-xxxxxxxx`), display names are dropped, and only counts remain meaningful. The Community edition masks user rows beyond the first ten in any case.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `WL_SCHEDULE_LICENSING` | `0 17 3 * * *` | NCRONTAB schedule of the collector (UTC) |
| `WL_LICENSING_DAYS` | `30` | Observation window for logons and device activity (7–90) |
| `WL_LICENSING_DEVICES_PER_USER` | `5` | Device allowance used for the *above n devices* hint |
| `WL_LICENSING_DETAIL` | `users` | `aggregate` pseudonymises users in the snapshot |

## Permissions

| Permission | Why |
|---|---|
| `Organization.Read.All` (Graph) | `subscribedSkus` – purchased and assigned units |
| `User.Read.All` (Graph) | `assignedPlans` per user |
| `ThreatHunting.Read.All` (Graph, feature `Hunting`) | `DeviceInfo`, `DeviceLogonEvents` |
| `DeviceManagementManagedDevices.Read.All` (Graph, feature `Coverage`, optional) | Intune primary user for the exact mapping |

All read-only. Without `Hunting` the module reports SKUs and users but cannot map devices.

## Not in scope (yet)

Agent 365, Defender for Identity, Defender for Office 365 and Defender for Cloud Apps licences. The module is deliberately limited to Defender for Endpoint, where the per-user/per-device question is concrete.
