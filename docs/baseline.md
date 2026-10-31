# Customising the baseline

The shipped baseline is `src/functionapp/config/mdav-baseline.json` (titles and texts in English and German).

To use your own: edit a copy and upload it as `config/mdav-baseline.json` to the **config** container of the Wardline
storage account. It then takes precedence over the shipped one – also after updates.

## Check format

| Field | Meaning |
|---|---|
| `id` | Unique name of the check |
| `platform` | `Windows`, `macOS` or `Linux` |
| `definitionId` | Exact Settings Catalog setting ID |
| `definitionIdPattern` | Regex as an alternative or fallback to the exact ID (Linux checks carry both) |
| `expect` | `{ "op": "eq" \| "ne" \| "in" \| "gte" \| "lte" \| "range" \| "match" \| "notmatch" \| "display", … }` |
| `weakeningOnly` | `true` for settings whose product default is already safe: *not configured* counts as status `Default` (no finding); only a configured weakening value is reported |
| `effective` | Effective check on the device: a TVM `scid-…`, a check name such as `TamperProtection`, or `avmode` |
| `severity` | `Critical`, `High`, `Medium`, `Low` |
| `title`, `expectText`, `rationale`, `remediation`, `category` | Plain string or `{ "en": "…", "de": "…" }` |

`display` compares the display name of the selected option (e.g. `real_time`, `admin_only`) – useful where the option
IDs differ between tenants.

## ASR rules

The `asrRules` section sets per rule the `minimum` (e.g. Audit) and `recommended` mode (e.g. Block), the severity of a
deviation and an optional note.

!!! tip
    After the first run the Baseline view lists every Defender setting found in your tenant – use it to verify IDs.
    `tests/tenant/New-WardlineTestData.ps1` writes a full ID check report as well.
