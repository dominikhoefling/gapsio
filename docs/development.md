# Development and releases

## Repository layout

```
deploy/              main.bicep (source), azuredeploy.json (compiled – keep in sync, CI checks it)
setup/               Install-, Update-, Uninstall-Wardline, Grant-WardlinePermissions, New-WardlineAppRegistrations,
                     permissions.json (permission model), WardlineSetup.ps1 (shared helpers)
src/functionapp/
  Modules/Wardline/  Core.ps1, Endpoint.ps1, Agents.ps1, Access.ps1, Wardline.psd1 (version)
  CollectEndpoint, CollectAgents, CollectAccess, RunOnDemand, Api, Portal   (functions)
  www/               portal (HTML/CSS/JS, no dependencies, English/German)
  config/            mdav-baseline.json
build/               New-WardlinePackage.ps1, New-WardlineRelease.ps1, New-WardlineDemo.ps1
tests/               Test-Wardline.ps1 (logic and end-to-end tests with sample data, no Azure needed)
                     tenant/ test data in a test tenant · vm/ test VM and local exclusions
docs/                this documentation (MkDocs Material)
.github/workflows/   ci.yml, release.yml, docs.yml
```

## Local commands

```powershell
pwsh ./tests/Test-Wardline.ps1              # tests
pwsh ./build/New-WardlineDemo.ps1           # portal offline with sample data: open dist/demo/index.html
pwsh ./build/New-WardlineRelease.ps1        # release assets in dist/release
az bicep build -f deploy/main.bicep --outfile deploy/azuredeploy.json
```

Documentation preview:

```bash
pip install -r docs/requirements.txt
mkdocs serve        # http://127.0.0.1:8000
```

## Continuous integration

Every push and pull request runs the tests, parses every PowerShell file, checks that `azuredeploy.json` matches
`main.bicep`, builds the release assets and builds the documentation with `--strict`.

## Publishing a release

1. Set `ModuleVersion` in `src/functionapp/Modules/Wardline/Wardline.psd1` (the single source of the version).
2. Add a section `## [x.y.z] – YYYY-MM-DD` to `CHANGELOG.md`.
3. Commit, then tag and push:

    ```bash
    git tag v0.4.0
    git push origin v0.4.0
    ```

The release workflow checks that the tag matches the module version, runs the tests, builds the assets, attests them
(public repositories) and publishes the GitHub release with the changelog section as release notes. Tags with a suffix
(`v0.5.0-rc.1`) become pre-releases, which "latest" and the update check ignore.
