# Shared helpers for the Wardline setup scripts (dot-sourced). Uses the Azure CLI (az) for all calls,
# so it runs in Azure Cloud Shell, on Windows, macOS and Linux without additional PowerShell modules.

# GitHub repository that publishes the Wardline releases (Update-Wardline.ps1). Override with -Repository.
$script:WardlineRepository = 'OWNER/wardline'
# Permission model; Update-Wardline.ps1 points this to the permissions.json of the release it installs.
$script:WardlinePermissionsPath = Join-Path $PSScriptRoot 'permissions.json'

function Write-Step { param([string]$Text) Write-Host "`n▶ $Text" -ForegroundColor Cyan }
function Write-Ok { param([string]$Text) Write-Host "  ✓ $Text" -ForegroundColor Green }
function Write-Note { param([string]$Text) Write-Host "  ! $Text" -ForegroundColor Yellow }

function Invoke-Az {
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$AllowFailure)
    $out = & az @Arguments --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) {
        if ($AllowFailure) { return $null }
        throw "az $($Arguments[0..([Math]::Min(3, $Arguments.Count - 1))] -join ' ') … failed:`n$($out | Out-String)"
    }
    ($out | Out-String)
}

function Invoke-Graph {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body, [switch]$AllowFailure)
    $a = @('rest', '--method', $Method, '--uri', $Uri, '--headers', 'Content-Type=application/json')
    $tmp = $null
    if ($null -ne $Body) {
        $tmp = New-TemporaryFile
        ConvertTo-Json -InputObject $Body -Depth 20 | Set-Content -Path $tmp -Encoding utf8
        $a += @('--body', "@$($tmp.FullName)")
    }
    try { $r = Invoke-Az -Arguments $a -AllowFailure:$AllowFailure }
    finally { if ($tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } }
    # With -AllowFailure: $false = call failed, $null = success without a body
    if ($null -eq $r) { return $(if ($AllowFailure) { $false } else { $null }) }
    if ($r.Trim()) { $r | ConvertFrom-Json -Depth 30 } else { $null }
}

function Get-GraphAll {
    param([Parameter(Mandatory)][string]$Uri)
    $items = @()
    while ($Uri) {
        $r = Invoke-Graph -Uri $Uri
        $items += @($r.value)
        $Uri = if ($r.PSObject.Properties['@odata.nextLink']) { $r.'@odata.nextLink' } else { $null }
    }
    $items
}

function Get-WardlinePermissionModel {
    Get-Content -Raw -Path $script:WardlinePermissionsPath | ConvertFrom-Json
}

function Resolve-WardlineFeatures {
    <#
    .SYNOPSIS
    Normalises the feature list: Core is always included; unknown names cause an error.
    #>
    param([string[]]$Features)
    $model = Get-WardlinePermissionModel
    $known = @($model.features | ForEach-Object { $_.id })
    $out = @('Core')
    foreach ($f in @($Features)) {
        if (-not $f) { continue }
        $m = $known | Where-Object { $_ -ieq $f } | Select-Object -First 1
        if (-not $m) { throw "Unknown feature '$f'. Valid: $($known -join ', ')" }
        if ($out -notcontains $m) { $out += $m }
    }
    $out
}

function Get-WardlinePermissionSet {
    <#
    .SYNOPSIS
    Returns the permissions required for the given features: resource key, permission value, feature and reason.
    #>
    param([string[]]$Features)
    $model = Get-WardlinePermissionModel
    $set = foreach ($f in $model.features | Where-Object { $Features -contains $_.id }) {
        foreach ($p in $f.permissions) { [pscustomobject]@{ Resource = $p.resource; Value = $p.value; Feature = $f.id; Why = $p.why } }
    }
    @($set)
}

function Show-WardlinePermissions {
    param([string[]]$Features)
    $set = Get-WardlinePermissionSet -Features $Features
    $model = Get-WardlinePermissionModel
    foreach ($g in ($set | Group-Object Resource)) {
        Write-Host "  $($model.resources.($g.Name).name)" -ForegroundColor White
        foreach ($p in ($g.Group | Sort-Object Value -Unique)) { Write-Host ("    {0,-48} {1,-11} {2}" -f $p.Value, $p.Feature, $p.Why) }
    }
}

function Get-ServicePrincipalByAppId {
    param([Parameter(Mandatory)][string]$AppId, [string]$Select = 'id,appId,displayName,appRoles')
    @(Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'&`$select=$Select").value | Select-Object -First 1
}

function Grant-WardlinePermissions {
    <#
    .SYNOPSIS
    Grants exactly the application permissions of the selected features to a service principal (managed identity or
    data-access app registration). With -Prune, Wardline permissions that are no longer needed are removed again, so the
    identity stays least-privilege when features are switched off. Requires Privileged Role Administrator or Global Administrator.
    #>
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string[]]$Features, [switch]$Prune)
    $model = Get-WardlinePermissionModel
    $wanted = Get-WardlinePermissionSet -Features $Features
    $allWardline = Get-WardlinePermissionSet -Features @($model.features | ForEach-Object { $_.id })
    $existing = @(Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments")
    $result = [ordered]@{ granted = 0; present = 0; removed = 0; missing = @() }

    foreach ($resKey in @($model.resources.PSObject.Properties.Name)) {
        $res = $model.resources.$resKey
        $sp = Get-ServicePrincipalByAppId -AppId $res.appId
        $need = @($wanted | Where-Object Resource -eq $resKey | ForEach-Object Value | Sort-Object -Unique)
        if (-not $sp) {
            if ($need.Count) { Write-Note "$($res.name) is not available in this tenant – skipped: $($need -join ', ')"; $result.missing += $need }
            continue
        }
        foreach ($v in $need) {
            $role = @($sp.appRoles) | Where-Object { $_.value -eq $v -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
            if (-not $role) { Write-Note "$v does not exist on $($res.name) (yet) – skipped"; $result.missing += $v; continue }
            if ($existing | Where-Object { $_.resourceId -eq $sp.id -and $_.appRoleId -eq $role.id }) { Write-Ok "$v (already granted)"; $result.present++; continue }
            Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" -Body @{ principalId = $PrincipalId; resourceId = $sp.id; appRoleId = $role.id } | Out-Null
            Write-Ok $v; $result.granted++
        }
        if ($Prune) {
            $known = @($allWardline | Where-Object Resource -eq $resKey | ForEach-Object Value | Sort-Object -Unique)
            foreach ($a in @($existing | Where-Object { $_.resourceId -eq $sp.id })) {
                $val = (@($sp.appRoles) | Where-Object { $_.id -eq $a.appRoleId } | Select-Object -First 1).value
                if ($val -and $known -contains $val -and $need -notcontains $val) {
                    Invoke-Graph -Method DELETE -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments/$($a.id)" | Out-Null
                    Write-Ok "$val removed (feature not selected)"; $result.removed++
                }
            }
        }
    }
    [pscustomobject]$result
}

function Set-WardlineFederatedCredential {
    <#
    .SYNOPSIS
    Lets the Wardline managed identity sign in as a pre-created data-access app registration (workload identity
    federation, no secret). Requires owner of the app registration or Application Administrator.
    #>
    param([Parameter(Mandatory)][string]$AppObjectId, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ManagedIdentityPrincipalId, [string]$Name = 'wardline-managed-identity')
    $fics = @(Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId/federatedIdentityCredentials")
    if ($fics | Where-Object { $_.subject -eq $ManagedIdentityPrincipalId }) { return 'present' }
    Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId/federatedIdentityCredentials" -Body @{
        name = $Name; issuer = "https://login.microsoftonline.com/$TenantId/v2.0"; subject = $ManagedIdentityPrincipalId; audiences = @('api://AzureADTokenExchange')
        description = 'Wardline: managed identity of the Wardline Function App signs in as this app (no secret).'
    } | Out-Null
    'created'
}

function Get-WardlineMissingPermissions {
    <#
    .SYNOPSIS
    Returns the permissions the selected features need that the service principal does not hold yet.
    #>
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string[]]$Features)
    $model = Get-WardlinePermissionModel
    $assigned = @(Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments")
    $missing = foreach ($p in Get-WardlinePermissionSet -Features $Features) {
        $resSp = Get-ServicePrincipalByAppId -AppId $model.resources.($p.Resource).appId
        if (-not $resSp) { continue }
        $role = @($resSp.appRoles) | Where-Object { $_.value -eq $p.Value } | Select-Object -First 1
        if ($role -and -not ($assigned | Where-Object { $_.resourceId -eq $resSp.id -and $_.appRoleId -eq $role.id })) { $p.Value }
    }
    @($missing | Sort-Object -Unique)
}

function Get-WardlinePackageVersion {
    <#
    .SYNOPSIS
    Reads the Wardline version (ModuleVersion) from a function package zip.
    #>
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $Path).Path)
    try {
        $entry = $zip.Entries | Where-Object { ($_.FullName -replace '\\', '/') -match '(^|/)Modules/Wardline/Wardline\.psd1$' } | Select-Object -First 1
        if (-not $entry) { return $null }
        $reader = [IO.StreamReader]::new($entry.Open())
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        if ($text -match "ModuleVersion\s*=\s*'([^']+)'") { $Matches[1] } else { $null }
    }
    finally { $zip.Dispose() }
}

function Set-WardlineVersionTags {
    <#
    .SYNOPSIS
    Records the deployed version and the template hash as tags on the Function App (read by Update-Wardline.ps1).
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$FunctionAppName, [string]$Version, [string]$TemplateSha256)
    $id = (Invoke-Az -Arguments @('functionapp', 'show', '-g', $ResourceGroup, '-n', $FunctionAppName, '--query', 'id', '-o', 'tsv')).Trim()
    $tags = @()
    if ($Version) { $tags += "wardline-version=$Version" }
    if ($TemplateSha256) { $tags += "wardline-template=$TemplateSha256" }
    if ($tags) { Invoke-Az -Arguments (@('tag', 'update', '--resource-id', $id, '--operation', 'Merge', '--tags') + $tags + @('-o', 'none')) -AllowFailure | Out-Null }
}
