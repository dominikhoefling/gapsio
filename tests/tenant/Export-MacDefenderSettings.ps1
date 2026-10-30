#Requires -Version 7.2
<#
.SYNOPSIS
    Reads (read-only) the macOS Defender definitions from the Intune Settings Catalog and writes them to
    mac-defender-settings.json – to check the Wardline baseline (option _0/_1/_2 -> meaning).
#>
param([Parameter(Mandatory)][string]$TenantId, [string]$OutFile = (Join-Path (Get-Location) 'mac-defender-settings.json'))
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication
$ctx = Get-MgContext
if (-not $ctx -or $ctx.Scopes -notcontains 'DeviceManagementConfiguration.ReadWrite.All' -and $ctx.Scopes -notcontains 'DeviceManagementConfiguration.Read.All') {
    Connect-MgGraph -TenantId $TenantId -Scopes 'DeviceManagementConfiguration.Read.All' -NoWelcome
}
$base = 'https://graph.microsoft.com/beta/deviceManagement/configurationSettings'
$all = @()
$uri = "$base`?`$filter=startswith(id,'com.apple.managedclient.preferences_')"
while ($uri) { $r = Invoke-MgGraphRequest -Uri $uri -OutputType PSObject; $all += @($r.value); $uri = $r.'@odata.nextLink' }

$out = foreach ($d in $all) {
    [ordered]@{
        id          = $d.id
        displayName = $d.displayName
        name        = $d.name
        offsetUri   = $d.offsetUri
        baseUri     = $d.baseUri
        rootId      = $d.rootDefinitionId
        categoryId  = $d.categoryId
        type        = $d.'@odata.type'
        childIds    = @($d.childIds)
        options     = @($d.options | ForEach-Object { [ordered]@{ itemId = $_.itemId; displayName = $_.displayName; value = $_.optionValue.value } })
    }
}
$out | ConvertTo-Json -Depth 8 | Set-Content -Path $OutFile -Encoding utf8
Write-Host "Written: $OutFile ($(@($out).Count) definitions)" -ForegroundColor Green
