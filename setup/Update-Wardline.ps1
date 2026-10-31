#Requires -Version 7.2
<#
.SYNOPSIS
    Updates the Wardline code of an existing installation to the latest (or a specific) release.

.DESCRIPTION
    Wardline never updates itself. The portal shows when a new release is available; an administrator then runs:

        ./setup/Update-Wardline.ps1 -ResourceGroup rg-wardline

    What the script does:
      1. Finds the Wardline Function App in the resource group and reads the installed version and features
      2. Downloads the release assets from GitHub (or uses -PackagePath for offline/air-gapped updates)
      3. Verifies the SHA256 checksums (and the GitHub build attestation if the GitHub CLI is installed)
      4. Checks whether the new release needs additional permissions for the installed features
         (reported; granted only with -GrantPermissions, which needs Privileged Role Administrator)
      5. Checks whether the release changes the Azure resources (template). If so, it tells you to run
         Install-Wardline.ps1 from the release bundle with your usual parameters.
      6. Deploys the new function package. Settings, data, history and permissions stay as they are.

    Requires: Azure CLI signed in ("az login") with Contributor (or Website Contributor) on the resource group.

.EXAMPLE
    ./setup/Update-Wardline.ps1 -ResourceGroup rg-wardline -CheckOnly

.EXAMPLE
    ./setup/Update-Wardline.ps1 -ResourceGroup rg-wardline -Version 0.5.0

.EXAMPLE
    # Offline: release assets downloaded beforehand into one folder
    ./setup/Update-Wardline.ps1 -ResourceGroup rg-wardline -PackagePath ./release/wardline-functionapp.zip
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$Version = 'latest',
    [string]$Repository,
    [string]$PackagePath,
    [string]$SubscriptionId,
    [switch]$CheckOnly,
    [switch]$GrantPermissions,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'WardlineSetup.ps1')
if (-not $Repository) { $Repository = $script:WardlineRepository }

# ---------------------------------------------------------------- Installation
Write-Step 'Reading the installation'
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI (az) not found.' }
if ($SubscriptionId) { Invoke-Az -Arguments @('account', 'set', '--subscription', $SubscriptionId) | Out-Null }
$fa = (Invoke-Az -Arguments @('functionapp', 'list', '-g', $ResourceGroup, '--query', "[?tags.""wardline-component""=='functionapp'] | [0].{name:name, id:id, tags:tags}", '-o', 'json')) | ConvertFrom-Json
if (-not $fa) { throw "No Wardline Function App found in resource group '$ResourceGroup'." }
$installed = if ($fa.tags.PSObject.Properties['wardline-version']) { $fa.tags.'wardline-version' } else { $null }
$installedTemplate = if ($fa.tags.PSObject.Properties['wardline-template']) { $fa.tags.'wardline-template' } else { $null }
$settings = @{}
foreach ($s in ((Invoke-Az -Arguments @('functionapp', 'config', 'appsettings', 'list', '-g', $ResourceGroup, '-n', $fa.name, '-o', 'json')) | ConvertFrom-Json)) { $settings[$s.name] = $s.value }
$modules = @(([string]$settings['WL_MODULES']) -split '[,; ]+' | Where-Object { $_ })
if (-not $modules) { $modules = @('endpoint', 'agents') }
$epFeatures = @(([string]$settings['WL_FEATURES']) -split '[,; ]+' | Where-Object { $_ })
if (-not $settings.ContainsKey('WL_FEATURES')) { $epFeatures = @('hunting', 'indicators') }
$features = @('Core') + @($epFeatures | ForEach-Object { (Get-Culture).TextInfo.ToTitleCase($_.ToLowerInvariant()) }) +
    $(if ($settings['WL_DEVICE_INVENTORY'] -eq 'true') { 'Inventory' }) + $(if ($modules -contains 'agents') { 'Agents' }) + $(if ($modules -contains 'access') { 'Access' }) + $(if ($modules -contains 'licensing') { 'Licensing' })
$features = @($features | Where-Object { $_ } | Select-Object -Unique)
Write-Ok "Function App:  $($fa.name)"
Write-Ok "Installed:     $(if ($installed) { $installed } else { 'unknown (installed before version tags existed)' })"
Write-Ok "Features:      $($features -join ', ')"

# ---------------------------------------------------------------- Release assets
$work = Join-Path ([IO.Path]::GetTempPath()) "wardline-update-$([guid]::NewGuid().ToString('n'))"
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    if ($PackagePath) {
        Write-Step 'Using the local release assets'
        $src = Split-Path (Resolve-Path $PackagePath).Path -Parent
        Copy-Item (Resolve-Path $PackagePath).Path (Join-Path $work 'wardline-functionapp.zip')
        foreach ($n in 'SHA256SUMS', 'permissions.json', 'release.json') { if (Test-Path (Join-Path $src $n)) { Copy-Item (Join-Path $src $n) $work } }
        $releaseUrl = $null
    }
    else {
        Write-Step "Downloading release '$Version' from github.com/$Repository"
        if ($Repository -like 'OWNER/*') { throw 'The release repository is not configured yet. Pass -Repository <owner>/<repo>.' }
        $headers = @{ 'User-Agent' = 'Wardline-Update'; Accept = 'application/vnd.github+json' }
        if ($env:GITHUB_TOKEN) { $headers.Authorization = "Bearer $env:GITHUB_TOKEN" }
        $relPath = if ($Version -eq 'latest') { 'latest' } else { "tags/v$($Version -replace '^v', '')" }
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/$relPath" -Headers $headers
        $releaseUrl = $rel.html_url
        foreach ($n in 'wardline-functionapp.zip', 'SHA256SUMS', 'permissions.json', 'release.json') {
            $asset = @($rel.assets) | Where-Object { $_.name -eq $n } | Select-Object -First 1
            if (-not $asset) { if ($n -in 'wardline-functionapp.zip', 'SHA256SUMS') { throw "Release $($rel.tag_name) has no asset '$n'." } else { continue } }
            if ($env:GITHUB_TOKEN) { Invoke-WebRequest -Uri $asset.url -Headers @{ 'User-Agent' = 'Wardline-Update'; Authorization = "Bearer $env:GITHUB_TOKEN"; Accept = 'application/octet-stream' } -OutFile (Join-Path $work $n) }
            else { Invoke-WebRequest -Uri $asset.browser_download_url -Headers @{ 'User-Agent' = 'Wardline-Update' } -OutFile (Join-Path $work $n) }
        }
        Write-Ok "Release $($rel.tag_name) ($($rel.published_at))"
    }

    # Integrity
    $pkg = Join-Path $work 'wardline-functionapp.zip'
    $sumFile = Join-Path $work 'SHA256SUMS'
    if (Test-Path $sumFile) {
        foreach ($line in Get-Content $sumFile) {
            if ($line -notmatch '^([0-9a-f]{64})\s+\*?(.+)$') { continue }
            $f = Join-Path $work $Matches[2].Trim()
            if (-not (Test-Path $f)) { continue }
            $actual = (Get-FileHash -Algorithm SHA256 $f).Hash.ToLowerInvariant()
            if ($actual -ne $Matches[1]) { throw "Checksum mismatch for $($Matches[2]) – the download is corrupt or was tampered with. Nothing was changed." }
        }
        Write-Ok 'SHA256 checksums verified'
    }
    elseif (-not $Force) { throw 'SHA256SUMS missing next to the package. Use -Force to deploy an unverified package.' }
    if (-not $PackagePath -and (Get-Command gh -ErrorAction SilentlyContinue)) {
        & gh attestation verify $pkg --repo $Repository *> $null
        if ($LASTEXITCODE -eq 0) { Write-Ok 'Build attestation verified (built by the GitHub release workflow)' } else { Write-Note 'Build attestation could not be verified (gh attestation verify).' }
    }

    $target = Get-WardlinePackageVersion -Path $pkg
    if (-not $target) { throw 'The package does not contain the Wardline module.' }
    Write-Ok "Target version: $target"
    $newer = if ($installed) { $a = [version]($target -replace '[-+].*$', ''); $b = [version]($installed -replace '[-+].*$', ''); $a.CompareTo($b) } else { 1 }
    if ($newer -le 0 -and -not $Force) {
        Write-Ok "Wardline is up to date ($installed)."
        return
    }

    # ---------------------------------------------------------------- Permissions of the new release
    Write-Step 'Checking permissions for the installed features'
    if (Test-Path (Join-Path $work 'permissions.json')) { $script:WardlinePermissionsPath = Join-Path $work 'permissions.json' }
    $principalId = $null
    if ($settings['WL_DATA_APP_ID']) {
        $sp = Get-ServicePrincipalByAppId -AppId $settings['WL_DATA_APP_ID'] -Select 'id,appId,displayName'
        $principalId = $sp.id
        $who = "data-access app $($settings['WL_DATA_APP_ID'])"
    }
    else {
        $principalId = ((Invoke-Az -Arguments @('identity', 'list', '-g', $ResourceGroup, '--query', "[?ends_with(name, '-runner')] | [0].principalId", '-o', 'tsv')) ?? '').Trim()
        $who = 'managed identity'
    }
    $missing = @()
    if ($principalId) {
        try { $missing = Get-WardlineMissingPermissions -PrincipalId $principalId -Features $features }
        catch { Write-Note "Permissions could not be read ($($_.Exception.Message)). Check them with Grant-WardlinePermissions.ps1 -ShowOnly." }
    }
    if ($missing.Count) {
        Write-Note "The new release needs additional permissions for the $who`: $($missing -join ', ')"
        if ($GrantPermissions -and -not $CheckOnly) {
            $r = Grant-WardlinePermissions -PrincipalId $principalId -Features $features
            Write-Ok "$($r.granted) permission(s) granted"
        }
        else { Write-Host "     Grant them (Privileged Role Administrator): ./setup/Update-Wardline.ps1 -ResourceGroup $ResourceGroup -GrantPermissions" }
    }
    else { Write-Ok 'No additional permissions needed' }

    # ---------------------------------------------------------------- Infrastructure changes
    $relMeta = if (Test-Path (Join-Path $work 'release.json')) { Get-Content -Raw (Join-Path $work 'release.json') | ConvertFrom-Json } else { $null }
    $infraChanged = $relMeta -and $relMeta.templateSha256 -and $installedTemplate -and ($relMeta.templateSha256 -ne $installedTemplate)
    if ($infraChanged) {
        Write-Note 'This release also changes the Azure resources (template). After the code update, download wardline.zip of this release'
        Write-Host '     and run setup/Install-Wardline.ps1 with your usual parameters (idempotent, keeps data and settings).'
    }

    if ($CheckOnly) {
        Write-Host ''
        Write-Ok "Update available: $(if ($installed) { $installed } else { '?' }) → $target$(if ($releaseUrl) { "   $releaseUrl" })"
        return
    }

    # ---------------------------------------------------------------- Deploy
    Write-Step "Deploying Wardline $target"
    if (-not $PSCmdlet.ShouldProcess($fa.name, "Deploy Wardline $target")) { return }
    $deployed = $false
    for ($i = 1; $i -le 4 -and -not $deployed; $i++) {
        $r = Invoke-Az -Arguments @('functionapp', 'deployment', 'source', 'config-zip', '-g', $ResourceGroup, '-n', $fa.name, '--src', $pkg, '-o', 'none') -AllowFailure
        if ($null -ne $r) { $deployed = $true } else { Write-Note "Attempt $i failed, waiting 20 s …"; Start-Sleep -Seconds 20 }
    }
    if (-not $deployed) { throw 'The package could not be deployed. The previous version keeps running.' }
    Set-WardlineVersionTags -ResourceGroup $ResourceGroup -FunctionAppName $fa.name -Version $target
    Write-Ok "Wardline $target deployed. Data, history, settings and permissions are unchanged."
    if ($releaseUrl) { Write-Host "     Release notes: $releaseUrl" }
}
finally { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
