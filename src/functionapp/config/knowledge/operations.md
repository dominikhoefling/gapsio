# Operations and settings

## Runs

- Scheduled daily (times below, UTC) and on demand via **Collect now** in the portal.
- Logs: Application Insights in the Wardline resource group.
- Cost: Flex Consumption with daily runs, a small storage account and Log Analytics with little data – usually a few
  euros per month; larger tenants accordingly more.

## App settings

Set by the install script; change them in the Function App configuration or via the install script parameters.

| Setting | Default | Meaning |
|---|---|---|
| `WL_MODULES` | `endpoint,agents` | Enabled modules (`endpoint`, `agents`, `access`, `licensing`, `officepreview`) – derived from `-Features` |
| `WL_FEATURES` | `hunting,indicators` | Endpoint data sources (`hunting`, `indicators`, `inventory`) – derived from `-Features` |
| `WL_SCHEDULE_ENDPOINT` | `0 17 2 * * *` | Schedule of the endpoint collection (NCRONTAB, UTC) |
| `WL_SCHEDULE_AGENTS` | `0 32 2 * * *` | Schedule of the agents collection |
| `WL_SCHEDULE_ACCESS` | `0 47 2 * * *` | Schedule of the access collection |
| `WL_SCHEDULE_LICENSING` | `0 17 3 * * *` | Schedule of the licensing collection |
| `WL_LICENSING_DAYS` | `30` | Observation window for device logons (7–90, [Licensing module](modules/licensing.md)) |
| `WL_LICENSING_DEVICES_PER_USER` | `5` | Devices covered per user licence |
| `WL_LICENSING_DETAIL` | `users` | `users` keeps UPNs in the licensing snapshot, `aggregate` pseudonymises them |
| `WL_CHANGE_RETENTION_DAYS` | `365` | Retention of the change history (`-ChangeRetentionDays`) |
| `WL_SNAPSHOT_RETENTION_DAYS` | `365` | Retention of the snapshots (`-SnapshotRetentionDays`); informational – the storage lifecycle rule enforces it |
| `WL_DEVICE_INVENTORY` | `false` | Device inventory via Intune Remediations (`-DeviceInventory`) |
| `WL_DEVICE_LOOKBACK_DAYS` | `7` | How far back device state is read from Advanced Hunting |
| `WL_DATA_APP_ID` | – | Pre-created data-access app (workload identity federation) |
| `WL_UPDATE_CHECK` | `true` | Daily check for new releases (no tenant data sent) |
| `WL_NOTIFY_WEBHOOK` | – | Webhook for notifications about new findings (`-NotifyWebhookUrl`) |
| `WL_NOTIFY_MIN_SEVERITY` | `High` | Minimum severity of new findings that are sent (`-NotifyMinSeverity`) |
| `WL_UPDATE_REPOSITORY` | – | Different GitHub repository for the update check (e.g. an internal mirror) |
| `WL_MAX_GROUP_MEMBERS` | `10000` | Cap when resolving group members (Access module) |
| `WL_PAGE_SIZE` | `2000` | Devices per stored page (`state/endpoint-devices/NNNN.json`) |
| `WL_FINDING_ROLLUP` | `200` | Above this many devices, identical per-device findings are rolled up into one finding with the device count |
| `WL_TENANT_ID`, `WL_CLIENT_ID`, `WL_STORAGE_ACCOUNT`, `WL_STORAGE_SUFFIX` | set by the template | Do not change |

## Notifications

After each run Wardline can post **new findings** (not in the previous run, at least `WL_NOTIFY_MIN_SEVERITY`, not
accepted) to a webhook:

- **Teams**: create a workflow in the channel with the template *"Post to a channel when a webhook request is received"* and pass its URL.
  Wardline sends an Adaptive Card with the findings and a link to the portal.
- **E-mail or anything else**: a Power Automate flow with the trigger *"When an HTTP request is received"* – the payload
  also contains the plain field `wardline.findings` (severity, category, title, device, and `assignee` with `type`,
  `displayName` and `mail` when the finding is [assigned](portal.md#exceptions-and-assignments) to someone). A flow can
  use `assignee.mail` to notify the person, group or distribution list directly.

```powershell
./setup/Install-Wardline.ps1 -ResourceGroup rg-wardline -NotifyWebhookUrl "https://…" -NotifyMinSeverity High
```

Re-runs keep the webhook unless you pass a new one. Wardline only sends findings – no exclusion values or command lines.

## Notices after a run

Missing data does not abort a run; it shows up as a notice in the portal.

| Notice | Meaning | What to do |
|---|---|---|
| `HTTP 403 … Not in the token: X` | Permission `X` is not granted, or was granted after the managed identity's current token was issued | Re-run the install or `Grant-WardlinePermissions.ps1` (lists what is granted). Azure caches managed identity tokens for up to 24 hours – the notice disappears with the next token. |
| `HTTP 403 … The token contains X` | The permission is there, but the API refuses anyway | Usually a missing licence (Agent ID, Agent 365) or a preview API that is not enabled in the tenant |
| `HTTP 400/404` on agent APIs | The API is not available in the tenant (yet) | Nothing – the agents module shows what it can |

## Storage layout

| Container | Content |
|---|---|
| `state` | Current state per module, change history, run log, update info, exceptions, assignments and their audit log |
| `state/endpoint-devices/`, `state/endpoint-coverage/` | Device and coverage lists in pages of `WL_PAGE_SIZE` entries, with a tab-separated search index (`endpoint-devices.tsv`) and a fingerprint list for drift detection |
| `snapshots` | Dated snapshots of every run (optionally immutable) |
| `config` | Your custom baseline (`mdav-baseline.json`) |

## Large fleets

Wardline is built for tenants with a few hundred up to several hundred thousand devices:

- **Advanced Hunting** returns at most 100,000 rows per query. When a query hits that limit Wardline counts the
  result and re-runs it in hash shards over `DeviceId`, so every device is collected exactly once. The run also
  keeps within the 45-calls-per-minute budget of the API. If a shard is still truncated the run shows a notice.
- **Device lists** are not stored inside the snapshot but in pages; the snapshot keeps the aggregates
  (`deviceStats`) the charts need. The portal loads the full list up to 10,000 devices; above that the Devices
  view searches and filters on the server (`api/devices`) and opens single devices via `api/device`.
- **Findings** that affect more than `WL_FINDING_ROLLUP` devices (e.g. Tamper Protection off on 12,000 devices)
  are rolled up into one finding with the device count and a sample of names; the exact set is one filter click
  away in the Devices view.
- **Function memory**: the template deploys 4 GB instances (`instanceMemoryMB`). A run with 300,000 devices takes
  roughly 15–30 minutes, most of it waiting for Advanced Hunting; 2 GB is enough below ~50,000 devices.
- `tests/Invoke-WardlineScaleTest.ps1 -Devices 300000` runs the paging, search and drift code against a synthetic
  fleet locally and prints timings.
