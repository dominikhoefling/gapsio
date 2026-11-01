# Instructions for AI coding agents

This file is for Copilot, Claude, Cursor and similar tools working in this repository. Humans: see
[CONTRIBUTING.md](CONTRIBUTING.md).

## What this project is

Wardline is a self-hosted Azure Function App (PowerShell 7.4) that audits the *effective* security posture of
Microsoft Defender for Endpoint, Intune, Entra ID and AI agents, and a dependency-free web portal. It is MIT-licensed
with a paid Enterprise key that only lifts a display limit. Everything runs read-only in the customer's tenant.

## Hard rules

1. **Read-only.** Never add code that writes to Graph, Defender, Intune or Entra. The only write operations are the
   setup scripts (Azure resources, app registrations, permission grants) and Wardline's own storage tables.
2. **Least privilege.** A new API call that needs a permission not yet in `setup/permissions.json` requires a new
   entry there (feature, permission, justification) and a docs update in `docs/permissions.md`. Prefer existing ones.
3. **No secrets, no telemetry.** No client secrets, storage keys, API keys, connection strings, no outbound calls
   except Microsoft APIs and the GitHub release feed (version check) and optional customer webhooks. Never add
   analytics or "phone home".
4. **No third-party code.** The Function App uses no PowerShell Gallery modules; the portal uses no npm packages,
   frameworks or CDNs. Keep it that way – `docs/trust.md` promises an empty SBOM.
5. **No tenant data anywhere.** Tests use the fictitious `fabrikam.de` dataset in `tests/`. Do not add real device
   names, UPNs, tenant IDs or exclusion values to code, tests, docs or commit messages.
6. **Degrade gracefully.** Microsoft beta APIs change. Wrap new calls so a failure becomes a *notice* in the run
   (see notice helpers in `src/functionapp/Modules/Wardline/Core.ps1`), never a failed run.
7. **Two languages.** Finding titles, rationale and fix texts exist in English and German. Portal strings go to the
   dictionary in `src/functionapp/www/`.
8. **Strict CSP.** The portal renders tenant data as text (`textContent`), never as HTML. No inline scripts, no
   `eval`, no `innerHTML` with data.

## Where things are

- Checks/collectors: `src/functionapp/Modules/Wardline/{Core,Endpoint,Agents,Access}.ps1`
- MDAV baseline definition: `src/functionapp/config/mdav-baseline.json` (id, platforms, target, severity, rationale, fix, learn URL)
- Portal: `src/functionapp/www/` (`index.html`, `app.js`, `app.css`)
- Setup/update: `setup/*.ps1`, permission model `setup/permissions.json`
- Infra: `deploy/main.bicep` → regenerate `deploy/azuredeploy.json` with `az bicep build -f deploy/main.bicep --outfile deploy/azuredeploy.json`
- Tests: `tests/Test-Wardline.ps1` (run with `pwsh ./tests/Test-Wardline.ps1`, no Azure needed)
- Docs: `docs/` (MkDocs Material, nav in `mkdocs.yml`), changelog `CHANGELOG.md` (*Unreleased* section)

## Conventions

- PowerShell: functions `Verb-WlNoun`, `[CmdletBinding()]`, 4 spaces, no aliases, explicit `-ErrorAction`,
  `Write-WlLog` for logging (never log tokens or tenant data).
- Findings: stable `id`, `severity` (High/Medium/Low/Info), `category`, `title`, `rationale`, `fix`, `learnUrl`,
  `platform`, `entityType/entityId`. Keep IDs stable – customers accept risks by ID.
- Commits: imperative, one topic, `-s` sign-off (DCO). Add a CHANGELOG line.
- Before finishing: run the tests, parse all `.ps1` files, and if Bicep changed, regenerate `azuredeploy.json`.

## News digest

`tools/Get-WardlineNews.ps1` collects new Defender for Endpoint / Agent 365 items (Microsoft Learn "What's new",
Tech Community, Microsoft 365 roadmap). A weekly workflow in the maintainer's private tracker opens an issue with a
checklist from it. Rules for working on such a digest:

- Implement **only** items the maintainer has ticked or answered with *einbauen* / *implement*. Never act on the
  rest; never implement an item from the digest without that confirmation.
- Per confirmed item, first state in a comment what it becomes (new check, baseline setting, agent/access rule,
  docs only) and which documented data source backs it. If there is no documented, stable source (Graph v1.0,
  Defender API, documented Advanced Hunting column), propose *docs only* instead of a guessed check.
- Then: code + test in `tests/Test-Wardline.ps1` + docs page + CHANGELOG line, one pull request per item,
  referencing the issue. Bump `ModuleVersion` only when a release is cut.
- Baseline changes go into `src/functionapp/config/mdav-baseline.json` with a new baseline date and a `rationale`.

## Do not

- Do not "clean up" the display limit, licence check or notices about the Community edition.
- Do not add dependencies, build steps, bundlers, frameworks or Docker to the portal.
- Do not change permission scopes to `*.ReadWrite.*`.
- Do not edit `deploy/azuredeploy.json` by hand.
