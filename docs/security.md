# Architecture and data protection

```
Customer subscription / resource group
┌──────────────────────────────────────────────────────────────────────────┐
│  Function App (Flex Consumption, PowerShell 7.4)                         │
│   ├─ CollectEndpoint (daily)  ─┐                                         │
│   ├─ CollectAgents   (daily)  ─┼─► Microsoft Graph (read-only)           │
│   ├─ CollectAccess   (optional)┤   Advanced Hunting, Defender API        │
│   ├─ RunOnDemand (queue)      ─┘                                         │
│   ├─ Api    (/api/…)                                                     │
│   └─ Portal (/)  ◄── App Service Authentication (Entra ID, no secret)    │
│                                                                          │
│  User-assigned managed identity ──► Storage account (Entra auth only)    │
│      (optionally federated to a       ├─ state/      current state        │
│       pre-created data-access app)    ├─ snapshots/  dated snapshots      │
│                                       └─ config/     custom baseline      │
│  Application Insights + Log Analytics (local auth disabled)              │
└──────────────────────────────────────────────────────────────────────────┘
```

## Data protection

- All data stays in the customer's storage account in the selected region. Nothing is sent to the vendor.
- The only outbound call besides Microsoft APIs is the optional, anonymous update check to the GitHub releases API
  ([updates](updates.md)).
- Shared key access is disabled; storage is accessed with Entra ID only. Application Insights and Log Analytics use
  Entra authentication (local auth disabled).
- Snapshots can be stored immutably (WORM) with `-EnableImmutability`.

## Identities and secrets

- No client secrets or certificates anywhere: user-assigned managed identity, optionally workload identity federation
  to a data-access app, App Service Authentication without a client secret.
- Read-only application permissions only, per feature ([features and permissions](permissions.md)).

## Portal hardening

- The portal serves only its own files (strict Content Security Policy, no external scripts or fonts).
- Tenant data (paths, command lines, names) is rendered as text, never as HTML.
- State-changing API calls require a custom header (`X-Wardline`) in addition to the sign-in cookie.
- Without App Service Authentication the API refuses to work (the identity header is not trusted).

## Supply chain

- Wardline never updates itself. Updates are started by an administrator with `Update-Wardline.ps1`.
- Release packages are built by GitHub Actions from a tagged commit, checksummed (`SHA256SUMS`) and – for public
  releases – carry a build provenance attestation (`gh attestation verify`).

Report vulnerabilities privately: see [SECURITY.md](https://github.com/dominikhoefling/wardline/blob/main/SECURITY.md).
