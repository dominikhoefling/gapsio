# Contributing to Wardline

Thank you for helping make Defender posture visible. Wardline is MIT-licensed; the checks, collectors, portal and
documentation are open to contributions. This page explains how to get a change merged quickly.

## Before you start

- **Bugs**: open an issue with the Wardline version (portal sidebar), the component and steps to reproduce.
  Never paste tenant data (device names, users, exclusion values, tokens). Sample data from `tests/` is fine.
- **New checks or features**: open an issue or discussion first and describe the gap, the data source
  (Graph endpoint, Advanced Hunting table, Defender API) and the permission it needs. Checks must stay
  **read-only** and work with **application permissions** – that is a hard rule.
- **Security problems**: private vulnerability reporting only, see [SECURITY.md](SECURITY.md).

## Development setup

```powershell
git clone https://github.com/dominikhoefling/wardline.git
cd wardline
pwsh ./tests/Test-Wardline.ps1          # all logic and end-to-end tests, no Azure or tenant needed
pwsh ./build/New-WardlineDemo.ps1       # portal offline with sample data: dist/demo/index.html
```

PowerShell 7.4+, Azure CLI with Bicep and Node 20 (only for the demo build) are enough. Testing against a real
tenant: [docs/testing.md](docs/testing.md).

## Project layout

| Path | What lives there |
|---|---|
| `src/functionapp/Modules/Wardline/*.ps1` | Collectors and checks: `Core.ps1` (shared, storage, findings), `Endpoint.ps1`, `Agents.ps1`, `Access.ps1` |
| `src/functionapp/config/mdav-baseline.json` | The MDAV baseline – every check with rationale, platforms and fix text (EN/DE) |
| `src/functionapp/www/` | Portal (vanilla HTML/CSS/JS, no framework, strict CSP) |
| `setup/` | Install, update, uninstall, app registrations; `permissions.json` is the single source of truth for permissions |
| `deploy/main.bicep` | Infrastructure; `azuredeploy.json` is generated from it (CI checks drift) |
| `tests/Test-Wardline.ps1` | Tests; add one for every behaviour you change |
| `docs/` | MkDocs documentation (Material) |

## Rules for checks

1. **Read-only and least privilege.** A new permission needs an entry in `setup/permissions.json` with the feature it
   belongs to and a one-sentence justification. Prefer an existing permission.
2. **Explain the finding.** Every finding has a severity, a short title, a rationale ("why does this matter") and a
   fix text in English and German. Link the Microsoft Learn page.
3. **No tenant data in code or docs.** Tests use the fictitious `fabrikam.de` data in `tests/`.
4. **Degrade, don't fail.** Microsoft changes beta APIs. Wrap calls so a failing source becomes a notice in the run,
   not a failed run (see `Invoke-WlGraph` and the notice helpers in `Core.ps1`).
5. **Both languages.** Portal strings go into the dictionary in `www/`; documentation is English, the portal is EN/DE.

## Pull requests

- Branch from `main`, keep PRs focused, describe *what* and *why*. Link the issue.
- Run `pwsh ./tests/Test-Wardline.ps1` – CI runs the same plus a parser pass over all `.ps1` files and a Bicep drift
  check. If you changed `deploy/main.bicep`: `az bicep build -f deploy/main.bicep --outfile deploy/azuredeploy.json`.
- Add a line to `CHANGELOG.md` under *Unreleased*.
- Sign off your commits (`git commit -s`). By contributing you certify the
  [Developer Certificate of Origin](https://developercertificate.org/) and agree that your contribution is licensed
  under the MIT License of this repository. No CLA.

## Style

PowerShell: `Verb-WlNoun` for functions, 4-space indent, no aliases in scripts, `[CmdletBinding()]`, explicit
`-ErrorAction`. JavaScript/CSS: no frameworks, no build step, no third-party code – the portal ships without
dependencies on purpose (see [docs/trust.md](docs/trust.md)). `.editorconfig` has the rest.

## What stays free

Everything in this repository is and stays MIT. The Enterprise licence key removes the 10-row display limit and
unlocks governance features; it does not gate any check, collector or data. See
[docs/manifesto.md](docs/manifesto.md) for the reasoning and the promise behind it.
