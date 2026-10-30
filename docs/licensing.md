# Licence

Wardline is licensed **per Entra tenant**. A licence key is bound to the tenant ID and checked **offline** with a
public key that is built into Wardline – nothing is sent to the vendor to check it.

## Without a licence key

Everything works. Administrators see "No licence (evaluation)" in the sidebar and under **Settings › Licence**. Use this
to evaluate Wardline in your tenant.

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
licence has expired. Collection, portal, history and notifications keep working. Enter the renewed key the same way –
it simply replaces the old one.

| Status | Meaning |
|---|---|
| Valid | Signed for this tenant and not expired |
| Expires soon | Expires within 30 days |
| Expired | Past the expiry date – everything keeps working |
| Invalid | Not a Wardline key or the signature does not match |
| Wrong tenant | Signed for a different tenant ID |

## What the key contains

A key looks like `WL1.<data>.<signature>`. The data is readable (base64url JSON): licence ID, customer name, tenant ID,
plan, issue and expiry date. It contains no secret and grants no access to anything – it only confirms the licence.
