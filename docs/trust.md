# Trust and security review

This page is written for the security team that has to approve Gapsio before it is installed. It collects what such
reviews usually ask for: what Gapsio can access, where data goes, how it is protected, how releases can be verified
and what remains your responsibility.

## Summary

| Question | Answer |
|---|---|
| Where does Gapsio run? | Entirely in **your** Azure subscription and region (Function App, storage account, monitoring). |
| Does data leave the tenant? | **No.** No telemetry, no vendor backend, no licence server. Optional outbound calls are listed under [data flows](#data-flows). |
| Can the vendor access the installation? | **No.** The vendor has no account, key, identity or network path into your tenant or subscription. |
| What can Gapsio change in the tenant? | At runtime: **nothing** – read-only application permissions only. The setup scripts create the Azure resources and app registrations, and grant the permissions you select. The optional device inventory deploys one detection-only Intune remediation script. |
| Secrets? | **None.** Managed identity, workload identity federation, App Service Authentication without a client secret, storage with Entra ID only (shared keys disabled). |
| Third-party code? | **None shipped.** No JavaScript framework, no PowerShell Gallery modules – see the [SBOM](#software-bill-of-materials). |
| Updates? | Never automatic. An administrator runs `Update-Gapsio.ps1`, which verifies checksums and reports new permissions before anything changes. |

## Permissions

Every feature adds only the read-only application permissions it needs; the reason for each permission is part of the
permission model in [`setup/permissions.json`](https://github.com/dominikhoefling/gapsio/blob/main/setup/permissions.json)
and listed on [features and permissions](permissions.md). Show exactly what an installation would grant, without
changing anything:

```powershell
./setup/Install-Gapsio.ps1 -ShowPermissions -Features Hunting,Indicators,Coverage,Response,Agents
```

Who holds the permissions is your choice: the managed identity of the Function App (default) or a data-access app
registration your identity team creates and owns ([separation of duties](separation-of-duties.md)). Switching a
feature off and running the install again removes the permissions it no longer needs.

!!! warning "Treat the installation as sensitive"
    Read-only does not mean harmless: `ThreatHunting.Read.All`, `Directory.Read.All` (Access feature) or
    `DeviceManagementConfiguration.Read.All` reveal a lot about your environment. Anyone who can run code in the
    Function App can use these permissions. Restrict who has **Owner/Contributor** on the Gapsio resource group (PIM),
    and treat the storage account like any other security data store.

## Data flows

| From | To | What | Protection |
|---|---|---|---|
| Function App | Microsoft Graph, Advanced Hunting, Defender for Endpoint API | Read-only queries | Managed identity token, TLS |
| Function App | Your storage account | Snapshots, change history, accepted risks, run log | Entra ID only (no shared key), TLS 1.2+, encryption at rest, optional WORM |
| Browser | Function App (portal, API) | Portal pages and the data shown | Entra ID sign-in (App Service Authentication), app role `Gapsio.Admin`, TLS |
| Function App | Application Insights / Log Analytics in your resource group | Run logs, errors | Entra authentication (local auth disabled) |
| Function App | `api.github.com` (optional, `GAPSIO_UPDATE_CHECK`) | Anonymous request for the latest release number – no tenant data | TLS; disable with `GAPSIO_UPDATE_CHECK=false` |
| Function App | Your webhook (optional, `GAPSIO_NOTIFY_WEBHOOK`) | New findings: severity, category, title, device name – no exclusion values or command lines | HTTPS only |

The licence key is verified **offline** with a public key built into Gapsio. Nothing is sent anywhere to check it.

## Threat model

| Threat | Mitigation | Residual risk / your part |
|---|---|---|
| Attacker abuses Gapsio's identity | Read-only permissions per feature; no secrets to steal; identity scoped to the Function App | Protect the resource group (PIM, Defender for Cloud, activity log alerts) |
| Unauthorised portal access | Entra ID sign-in, admin views require the app role `Gapsio.Admin`; optional `-RestrictToAssignedUsers` | Apply your Conditional Access policies to the portal app (e.g. MFA, compliant device) |
| Malicious tenant data in the portal (XSS via file paths, command lines, names) | All tenant data is rendered as text, never as HTML; strict Content Security Policy (`script-src 'self'`, no inline scripts, no external resources) | – |
| Cross-site request forgery | State-changing API calls require POST and a custom `X-Gapsio` header; cookies are same-site | – |
| Spoofed identity header | The API refuses to work unless App Service Authentication is enabled | Do not disable App Service Authentication |
| Tampered release package | `SHA256SUMS` verified by `Update-Gapsio.ps1`; build provenance attestation for public releases; packages built only by GitHub Actions from a tagged commit | Verify manually for first installs (see below) |
| Vendor compromise | No vendor access, no auto-update, no telemetry, offline licence check | Review release notes and permission changes before updating |
| Tampering with history | Snapshots can be stored immutably (`-EnableImmutability`); accepted risks have an append-only audit log | Lock the immutability policy if your audit requires it |
| Data exfiltration via notifications | Only finding titles, severity and device names; HTTPS only; off by default | Point the webhook to your own Teams workflow / Power Automate |
| Microsoft API changes | Errors become notices in the portal, a run never aborts; v1.0 first with beta fallback | Missing data is visible as notices – keep Gapsio current |

## Verifying a release

```bash
# Checksums (all assets are listed in SHA256SUMS)
sha256sum -c SHA256SUMS --ignore-missing

# Build provenance (public releases): proves the file was built by the release workflow of this repository
gh attestation verify gapsio.zip --repo dominikhoefling/gapsio
```

`Update-Gapsio.ps1` verifies the checksums automatically and stops if a file does not match.

## Software bill of materials

Every release contains `sbom.cdx.json` (CycloneDX 1.5): every file of the function package with its SHA-256 hash, and
the platform components Gapsio runs on or calls (Azure Functions PowerShell worker, extension bundle, Microsoft
Graph, Defender API, Azure CLI for setup). Gapsio ships **no third-party libraries**.

## Security testing

- Automated tests run on every commit: logic and end-to-end tests with fictitious tenant data, parsing of all scripts,
  Bicep compilation and the release build.
- An independent penetration test has **not** been performed yet. Findings from your own review are welcome – see
  [reporting a vulnerability](https://github.com/dominikhoefling/gapsio/blob/main/SECURITY.md).

## Your responsibilities

- Decide which features (and therefore permissions) to enable.
- Restrict access to the Gapsio resource group and the portal app (PIM, Conditional Access).
- Keep Gapsio updated and review permission changes before you update.
- Decide on retention and immutability of snapshots according to your policies.

See also: [architecture and data protection](security.md), [known limitations](limitations.md).
