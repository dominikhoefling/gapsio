# Shared helpers for the Gapsio setup scripts (dot-sourced). Uses the Azure CLI (az) for all calls,
# so it runs in Azure Cloud Shell, on Windows, macOS and Linux without additional PowerShell modules.

# GitHub repository that publishes the Gapsio releases (Update-Gapsio.ps1). Override with -Repository.
$script:GapsioRepository = 'dominikhoefling/gapsio'
# Permission model; Update-Gapsio.ps1 points this to the permissions.json of the release it installs.
$script:GapsioPermissionsPath = Join-Path $PSScriptRoot 'permissions.json'

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

function Get-GapsioPermissionModel {
    Get-Content -Raw -Path $script:GapsioPermissionsPath | ConvertFrom-Json
}

function Resolve-GapsioFeatures {
    <#
    .SYNOPSIS
    Normalises the feature list: Core is always included; unknown names cause an error.
    #>
    param([string[]]$Features)
    $model = Get-GapsioPermissionModel
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

function Get-GapsioPermissionSet {
    <#
    .SYNOPSIS
    Returns the permissions required for the given features: resource key, permission value, feature and reason.
    #>
    param([string[]]$Features)
    $model = Get-GapsioPermissionModel
    $set = foreach ($f in $model.features | Where-Object { $Features -contains $_.id }) {
        foreach ($p in $f.permissions) { [pscustomobject]@{ Resource = $p.resource; Value = $p.value; Feature = $f.id; Why = $p.why } }
    }
    @($set)
}

function Show-GapsioPermissions {
    param([string[]]$Features)
    $set = Get-GapsioPermissionSet -Features $Features
    $model = Get-GapsioPermissionModel
    foreach ($g in ($set | Group-Object Resource)) {
        Write-Host "  $($model.resources.($g.Name).name)" -ForegroundColor White
        foreach ($p in ($g.Group | Sort-Object Value -Unique)) { Write-Host ("    {0,-48} {1,-11} {2}" -f $p.Value, $p.Feature, $p.Why) }
    }
}

function Get-ServicePrincipalByAppId {
    param([Parameter(Mandatory)][string]$AppId, [string]$Select = 'id,appId,displayName,appRoles')
    @(Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'&`$select=$Select").value | Select-Object -First 1
}

function Grant-GapsioPermissions {
    <#
    .SYNOPSIS
    Grants exactly the application permissions of the selected features to a service principal (managed identity or
    data-access app registration). With -Prune, Gapsio permissions that are no longer needed are removed again, so the
    identity stays least-privilege when features are switched off. Requires Privileged Role Administrator or Global Administrator.
    #>
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string[]]$Features, [switch]$Prune)
    $model = Get-GapsioPermissionModel
    $wanted = Get-GapsioPermissionSet -Features $Features
    $allGapsio = Get-GapsioPermissionSet -Features @($model.features | ForEach-Object { $_.id })
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
            $known = @($allGapsio | Where-Object Resource -eq $resKey | ForEach-Object Value | Sort-Object -Unique)
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

function Set-GapsioFederatedCredential {
    <#
    .SYNOPSIS
    Lets the Gapsio managed identity sign in as a pre-created data-access app registration (workload identity
    federation, no secret). Requires owner of the app registration or Application Administrator.
    #>
    param([Parameter(Mandatory)][string]$AppObjectId, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ManagedIdentityPrincipalId, [string]$Name = 'gapsio-managed-identity')
    $fics = @(Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId/federatedIdentityCredentials")
    if ($fics | Where-Object { $_.subject -eq $ManagedIdentityPrincipalId }) { return 'present' }
    Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId/federatedIdentityCredentials" -Body @{
        name = $Name; issuer = "https://login.microsoftonline.com/$TenantId/v2.0"; subject = $ManagedIdentityPrincipalId; audiences = @('api://AzureADTokenExchange')
        description = 'Gapsio: managed identity of the Gapsio Function App signs in as this app (no secret).'
    } | Out-Null
    'created'
}

function Get-GapsioMissingPermissions {
    <#
    .SYNOPSIS
    Returns the permissions the selected features need that the service principal does not hold yet.
    #>
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string[]]$Features)
    $model = Get-GapsioPermissionModel
    $assigned = @(Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments")
    $missing = foreach ($p in Get-GapsioPermissionSet -Features $Features) {
        $resSp = Get-ServicePrincipalByAppId -AppId $model.resources.($p.Resource).appId
        if (-not $resSp) { continue }
        $role = @($resSp.appRoles) | Where-Object { $_.value -eq $p.Value } | Select-Object -First 1
        if ($role -and -not ($assigned | Where-Object { $_.resourceId -eq $resSp.id -and $_.appRoleId -eq $role.id })) { $p.Value }
    }
    @($missing | Sort-Object -Unique)
}

function Get-GapsioPackageVersion {
    <#
    .SYNOPSIS
    Reads the Gapsio version (ModuleVersion) from a function package zip.
    #>
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $Path).Path)
    try {
        $entry = $zip.Entries | Where-Object { ($_.FullName -replace '\\', '/') -match '(^|/)Modules/Gapsio/Gapsio\.psd1$' } | Select-Object -First 1
        if (-not $entry) { return $null }
        $reader = [IO.StreamReader]::new($entry.Open())
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        if ($text -match "ModuleVersion\s*=\s*'([^']+)'") { $Matches[1] } else { $null }
    }
    finally { $zip.Dispose() }
}

function Resolve-GapsioDns {
    # DNS lookup via DNS-over-HTTPS – works the same on Windows, macOS, Linux and Cloud Shell
    param([string]$Name, [ValidateSet('TXT', 'CNAME')][string]$Type)
    try {
        $r = Invoke-RestMethod -Uri "https://dns.google/resolve?name=$([uri]::EscapeDataString($Name))&type=$Type" -TimeoutSec 10
        @($r.Answer | Where-Object { $_.type -eq $(if ($Type -eq 'TXT') { 16 } else { 5 }) } | ForEach-Object { ([string]$_.data).Trim('"').TrimEnd('.') })
    }
    catch { @() }
}

function Add-GapsioCustomDomain {
    <#
    .SYNOPSIS
    Binds a custom domain to the portal: checks the DNS records (CNAME + TXT asuid), adds the hostname, creates a free
    managed certificate and binds it (SNI). Idempotent.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$FunctionAppName,
        [Parameter(Mandatory)][string]$DefaultHostName, [Parameter(Mandatory)][string]$Domain, [int]$WaitMinutes = 30)
    $site = Invoke-Az -Arguments @('functionapp', 'show', '-g', $ResourceGroup, '-n', $FunctionAppName, '--query', '{v:customDomainVerificationId, h:hostNames, s:hostNameSslStates}', '-o', 'json') | ConvertFrom-Json
    $verifyId = [string]$site.v
    $bound = @($site.h) -contains $Domain
    $sslOk = @($site.s | Where-Object { $_.name -eq $Domain -and $_.sslState -eq 'SniEnabled' }).Count -gt 0
    if ($bound -and $sslOk) { Write-Ok "Custom domain bound with certificate: https://$Domain"; return }

    $test = {
        $cn = Resolve-GapsioDns -Name $Domain -Type CNAME
        $tx = Resolve-GapsioDns -Name "asuid.$Domain" -Type TXT
        [pscustomobject]@{ cname = ($cn -contains $DefaultHostName); txt = ($tx -contains $verifyId) }
    }
    $dns = & $test
    if (-not ($dns.cname -and $dns.txt)) {
        Write-Note 'Please create these DNS records at your DNS provider:'
        Write-Host ''
        Write-Host "     Type   Name                              Value" -ForegroundColor DarkGray
        Write-Host ("     CNAME  {0,-33} {1}" -f $Domain, $DefaultHostName)
        Write-Host ("     TXT    {0,-33} {1}" -f "asuid.$Domain", $verifyId)
        Write-Host ''
        Write-Note "Waiting up to $WaitMinutes minutes for the records (Ctrl+C to stop – the installer can be re-run any time) ..."
        $until = (Get-Date).AddMinutes($WaitMinutes)
        while (-not ($dns.cname -and $dns.txt) -and (Get-Date) -lt $until) { Start-Sleep -Seconds 20; $dns = & $test }
        if (-not ($dns.cname -and $dns.txt)) {
            Write-Note "DNS records not found yet (CNAME: $($dns.cname), TXT: $($dns.txt)). The portal stays reachable at https://$DefaultHostName – re-run the installer with -CustomDomain $Domain once DNS is in place."
            return
        }
    }
    Write-Ok 'DNS records found (CNAME + TXT asuid)'
    if (-not $bound) {
        Invoke-Az -Arguments @('functionapp', 'config', 'hostname', 'add', '-g', $ResourceGroup, '--webapp-name', $FunctionAppName, '--hostname', $Domain, '-o', 'none') | Out-Null
        Write-Ok "Hostname added: $Domain"
    }
    $thumb = $null
    for ($i = 0; $i -lt 3 -and -not $thumb; $i++) {
        $cert = Invoke-Az -Arguments @('functionapp', 'config', 'ssl', 'create', '-g', $ResourceGroup, '-n', $FunctionAppName, '--hostname', $Domain, '-o', 'json') -AllowFailure
        if ($cert) { $thumb = ($cert | ConvertFrom-Json).thumbprint } else { Start-Sleep -Seconds 30 }
    }
    if (-not $thumb) { Write-Note "The managed certificate could not be created yet. Re-run the installer in a few minutes (domain: $Domain)."; return }
    Invoke-Az -Arguments @('functionapp', 'config', 'ssl', 'bind', '-g', $ResourceGroup, '-n', $FunctionAppName, '--certificate-thumbprint', $thumb, '--ssl-type', 'SNI', '-o', 'none') | Out-Null
    Write-Ok "Managed certificate bound (renews automatically): https://$Domain"
}

function Set-GapsioVersionTags {
    <#
    .SYNOPSIS
    Records the deployed version and the template hash as tags on the Function App (read by Update-Gapsio.ps1).
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$FunctionAppName, [string]$Version, [string]$TemplateSha256)
    $id = (Invoke-Az -Arguments @('functionapp', 'show', '-g', $ResourceGroup, '-n', $FunctionAppName, '--query', 'id', '-o', 'tsv')).Trim()
    $tags = @()
    if ($Version) { $tags += "gapsio-version=$Version" }
    if ($TemplateSha256) { $tags += "gapsio-template=$TemplateSha256" }
    if ($tags) { Invoke-Az -Arguments (@('tag', 'update', '--resource-id', $id, '--operation', 'Merge', '--tags') + $tags + @('-o', 'none')) -AllowFailure | Out-Null }
}
