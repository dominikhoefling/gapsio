# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting instead:
**Security › Report a vulnerability** in this repository. You will get an answer within a few working days.

Helpful details: affected version (shown in the portal sidebar), the component (Function App, portal, setup scripts),
steps to reproduce and the impact you see.

## Supported versions

Only the latest minor release receives security fixes. Update with `./setup/Update-Wardline.ps1 -ResourceGroup <resource group>`.

## Design principles

- Read-only application permissions only, granted per feature (least privilege) – see `setup/permissions.json`.
- No secrets: managed identity, workload identity federation, App Service Authentication without a client secret.
- Storage with Entra authentication only (shared keys disabled); all data stays in the customer's subscription.
- The portal serves only its own files under a strict Content Security Policy; tenant data is rendered as text, never as HTML.
- Wardline never updates itself. Release packages are checksummed and (for public releases) carry a build provenance attestation.
