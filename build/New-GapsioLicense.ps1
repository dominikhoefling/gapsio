#Requires -Version 7.2
<#
.SYNOPSIS
    Vendor tool: issues a Gapsio licence key for one customer tenant.

.DESCRIPTION
    Signs the licence with the vendor's private key (ECDSA P-256). The private key never belongs in this repository;
    keep it offline (e.g. password manager) with a backup – without it no new keys can be issued for existing
    installations.

    Every issued key is appended to licenses.csv next to the private key (your ledger).

.EXAMPLE
    ./build/New-GapsioLicense.ps1 -PrivateKeyPath ~/gapsio-licensing/gapsio-license-private.pem `
        -TenantId 8ec97a46-1300-4625-ba25-fc1339bc01e2 -Customer 'Contoso GmbH' -Plan Annual -Months 12

.EXAMPLE
    # Pilot licence until a fixed date
    ./build/New-GapsioLicense.ps1 -PrivateKeyPath <pem> -TenantId <id> -Customer 'Fabrikam AG' -Plan Pilot -Expires 2027-03-31

.EXAMPLE
    # Show what a key contains (no private key needed)
    ./build/New-GapsioLicense.ps1 -Inspect 'GP1.….…'
#>
[CmdletBinding(DefaultParameterSetName = 'Issue')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Issue')][string]$PrivateKeyPath,
    [Parameter(Mandatory, ParameterSetName = 'Issue')][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
    [Parameter(Mandatory, ParameterSetName = 'Issue')][ValidateLength(2, 120)][string]$Customer,
    [Parameter(ParameterSetName = 'Issue')][ValidateSet('Monthly', 'Annual', 'Assessment', 'Pilot', 'Partner')][string]$Plan = 'Annual',
    [Parameter(ParameterSetName = 'Issue')][ValidateRange(1, 60)][int]$Months = 12,
    [Parameter(ParameterSetName = 'Issue')][string]$Expires,
    [Parameter(ParameterSetName = 'Issue')][switch]$NoLedger,
    [Parameter(Mandatory, ParameterSetName = 'Inspect')][string]$Inspect
)
$ErrorActionPreference = 'Stop'

function ConvertTo-Base64Url([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
function ConvertFrom-Base64Url([string]$Text) {
    $s = $Text.Replace('-', '+').Replace('_', '/'); switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    [Convert]::FromBase64String($s)
}

if ($PSCmdlet.ParameterSetName -eq 'Inspect') {
    $parts = $Inspect.Trim() -split '\.'
    if ($parts.Count -ne 3 -or $parts[0] -ne 'GP1') { throw 'Not a Gapsio licence key.' }
    [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[1])) | ConvertFrom-Json
    return
}

$exp = if ($Expires) { [datetime]::ParseExact($Expires, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } else { [DateTime]::UtcNow.Date.AddMonths($Months) }
if ($exp -le [DateTime]::UtcNow.Date) { throw 'The expiry date must be in the future.' }

$payload = [ordered]@{
    v    = 1
    lid  = "GP-$([DateTime]::UtcNow.ToString('yyyyMMdd'))-$(-join ((1..6) | ForEach-Object { '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'[(Get-Random -Maximum 32)] }))"
    cust = $Customer
    tid  = $TenantId.ToLowerInvariant()
    plan = $Plan
    iss  = [DateTime]::UtcNow.ToString('yyyy-MM-dd')
    exp  = $exp.ToString('yyyy-MM-dd')
}
$body = "GP1.$(ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))))"

$ec = [System.Security.Cryptography.ECDsa]::Create()
try {
    $ec.ImportFromPem((Get-Content -Raw -Path $PrivateKeyPath))
    $sig = $ec.SignData([Text.Encoding]::ASCII.GetBytes($body), [System.Security.Cryptography.HashAlgorithmName]::SHA256)
}
finally { $ec.Dispose() }
$key = "$body.$(ConvertTo-Base64Url $sig)"

if (-not $NoLedger) {
    $ledger = Join-Path (Split-Path -Parent (Resolve-Path $PrivateKeyPath)) 'licenses.csv'
    [pscustomobject]@{ licenseId = $payload.lid; issued = $payload.iss; expires = $payload.exp; plan = $Plan; customer = $Customer; tenantId = $payload.tid; key = $key } |
        Export-Csv -Path $ledger -Append -NoTypeInformation -Encoding utf8
}
Write-Host "Licence $($payload.lid) for $Customer ($Plan) – tenant $($payload.tid), valid until $($payload.exp)" -ForegroundColor Green
$key
