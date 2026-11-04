## What and why

<!-- One or two sentences. Link the issue: Fixes #123 -->

## Checklist

- [ ] `pwsh ./tests/Test-Gapsio.ps1` passes locally
- [ ] Read-only: no new write operations against Graph / Defender / Intune / Entra
- [ ] New permission? → entry in `setup/permissions.json` with justification + `docs/permissions.md`
- [ ] New or changed finding? → stable `id`, rationale and fix text in EN and DE, Learn URL
- [ ] No tenant data in code, tests, docs or screenshots
- [ ] `deploy/main.bicep` changed? → `deploy/azuredeploy.json` regenerated
- [ ] `CHANGELOG.md` updated under *Unreleased*
- [ ] Commits signed off (`git commit -s`, DCO)
