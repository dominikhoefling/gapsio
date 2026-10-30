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
| `WL_MODULES` | `endpoint,agents` | Enabled modules (`endpoint`, `agents`, `access`) – derived from `-Features` |
| `WL_FEATURES` | `hunting,indicators` | Endpoint data sources (`hunting`, `indicators`, `inventory`) – derived from `-Features` |
| `WL_SCHEDULE_ENDPOINT` | `0 17 2 * * *` | Schedule of the endpoint collection (NCRONTAB, UTC) |
| `WL_SCHEDULE_AGENTS` | `0 32 2 * * *` | Schedule of the agents collection |
| `WL_SCHEDULE_ACCESS` | `0 47 2 * * *` | Schedule of the access collection |
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
| `WL_TENANT_ID`, `WL_CLIENT_ID`, `WL_STORAGE_ACCOUNT`, `WL_STORAGE_SUFFIX` | set by the template | Do not change |

## Notifications

After each run Wardline can post **new findings** (not in the previous run, at least `WL_NOTIFY_MIN_SEVERITY`, not
accepted) to a webhook:

- **Teams**: create a workflow in the channel with the template *"Post to a channel when a webhook request is received"* and pass its URL.
  Wardline sends an Adaptive Card with the findings and a link to the portal.
- **E-mail or anything else**: a Power Automate flow with the trigger *"When an HTTP request is received"* – the payload
  also contains the plain field `wardline.findings` (severity, category, title, device).

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
| `state` | Current state per module, change history, run log, update info, accepted risks and their audit log |
| `snapshots` | Dated snapshots of every run (optionally immutable) |
| `config` | Your custom baseline (`mdav-baseline.json`) |
