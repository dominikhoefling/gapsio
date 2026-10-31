# Licence

Wardline is licensed **per Entra tenant**. A licence key is bound to the tenant ID and checked **offline** with a
public key that is built into Wardline – nothing is sent to the vendor to check it.

## Without a licence key: Community edition

Wardline collects, checks and stores **everything** – but the portal and the API serve lists in the **Community
edition**: every list (devices, findings, exclusions, agents, policies, entitlements, changes …) shows its **first 10
entries in clear**; all further entries are **masked on the server** before they leave the Function App. Masked entries
keep their classification (severity, category, state, platform, numbers, dates) so counts, filters and charts stay
correct, but names, identifiers, users, paths and free text are replaced by `••••••••`. Masked rows are blurred in the
portal, cannot be opened and are left out of CSV exports. Summaries, statistics, charts, warnings and the history of
runs are complete.

Administrators see "No licence (Community edition)" in the sidebar and under **Settings › Licence**. Entering a valid key
switches to the full view immediately – nothing has to be collected again, because the stored data is always complete.

!!! note "Public demo"
    The hosted demo is built from pseudonymised data and shows everything; the Community limit applies to installations
    without a valid key.

## Entering the key

=== "Portal"

    **Settings › Licence › Enter licence key** (Wardline administrators only). The key is validated before it is saved:
    it must be signed by the vendor and belong to this tenant.

=== "Installation"

    ```powershell
    ./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -LicenseKey 'WL1.…'
    ```

    The key is stored as the app setting `WL_LICENSE_KEY`; re-runs keep it. A key entered in the portal takes precedence.

## When the licence expires

Wardline **does not stop**. Thirty days before the expiry date administrators see a notice; after it the notice says the
licence has expired. Collection, history and notifications keep working; the full view stays available for a **grace
period of 30 days** after the expiry date, then Wardline falls back to the Community edition until a renewed key is
entered – it simply replaces the old one.

| Status | Meaning | View |
|---|---|---|
| Valid | Signed for this tenant and not expired | Full |
| Expires soon | Expires within 30 days | Full |
| Expired | Past the expiry date | Full for 30 days, then Community |
| Invalid | Not a Wardline key or the signature does not match | Community |
| Wrong tenant | Signed for a different tenant ID | Community |
| None | No key entered | Community |

## What the key contains

A key looks like `WL1.<data>.<signature>`. The data is readable (base64url JSON): licence ID, customer name, tenant ID,
plan, issue and expiry date. It contains no secret and grants no access to anything – it only confirms the licence.
