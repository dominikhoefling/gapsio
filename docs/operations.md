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
| `WL_CHANGE_RETENTION_DAYS` | `365` | Retention of the change history (`-RetentionDays`) |
| `WL_DEVICE_INVENTORY` | `false` | Device inventory via Intune Remediations (`-DeviceInventory`) |
| `WL_DEVICE_LOOKBACK_DAYS` | `7` | How far back device state is read from Advanced Hunting |
| `WL_DATA_APP_ID` | – | Pre-created data-access app (workload identity federation) |
| `WL_UPDATE_CHECK` | `true` | Daily check for new releases (no tenant data sent) |
| `WL_UPDATE_REPOSITORY` | – | Different GitHub repository for the update check (e.g. an internal mirror) |
| `WL_MAX_GROUP_MEMBERS` | `10000` | Cap when resolving group members (Access module) |
| `WL_TENANT_ID`, `WL_CLIENT_ID`, `WL_STORAGE_ACCOUNT`, `WL_STORAGE_SUFFIX` | set by the template | Do not change |

## Storage layout

| Container | Content |
|---|---|
| `state` | Current state per module, change history, run log, update info |
| `snapshots` | Dated snapshots of every run (optionally immutable) |
| `config` | Your custom baseline (`mdav-baseline.json`) |
