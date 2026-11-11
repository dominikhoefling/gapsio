# Purview DLP preview (optional, private preview)

The `purviewpreview` module shows how ready a tenant is for Microsoft Purview Data Loss Prevention. It reads data only and changes nothing.

## Enable

```powershell
./setup/Install-Gapsio.ps1 -ResourceGroup rg-gapsio -Features Hunting,Indicators,Coverage,Response,Agents,PurviewPreview
```

On an existing installation, run `./setup/Update-Gapsio.ps1` with the same `-Features` value.

## What it collects

| Area | Source | Output |
|---|---|---|
| Licences | `subscribedSkus` and user licence details | 15 DLP capabilities with the number of users per plan |
| Purview roles | Entra role assignments and PIM eligibility | Holders of 8 Purview-related roles, active and eligible |
| Sensitivity labels | Graph `dataSecurityAndGovernance`, falling back to `informationProtection` | Label inventory |
| Devices and activity | 12 Advanced Hunting probes (`DeviceInfo`, `CloudAppEvents`, `AlertInfo`, `DeviceFileEvents`) | Endpoint DLP readiness, DLP matches, alerts and file activity |

- The timer `CollectPurviewPreview` runs every 6 hours.
- Results go to `state/purview-preview-latest.json`.
- Portal views: *Purview*, *Devices*, *Licensing*, *Access* and *Hunting*.

## Permissions (application, read-only)

`ThreatHunting.Read.All`, `Organization.Read.All`, `User.Read.All`, `RoleManagement.Read.Directory`, `InformationProtectionPolicy.Read.All`.

## Limitations

- This is a private preview, so the probes and findings may change.
- Label reads return 403 until the token refreshes after the permissions are granted, which takes up to about 1 hour.
- DLP policies themselves are not available through Graph. Gapsio infers coverage from licences and telemetry.
