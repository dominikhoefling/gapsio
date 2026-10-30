# Licence keys: bound to one Entra tenant, signed by the vendor (ECDSA P-256 / SHA-256) and checked offline – Wardline
# never calls home. Enforcement is soft: nothing is blocked, the portal shows the licence status to administrators.
#
# Key format:  WL1.<payload>.<signature>   (both base64url)
# Payload:     { "v":1, "lid":"…", "cust":"…", "tid":"<tenant id>", "plan":"Annual", "iss":"yyyy-MM-dd", "exp":"yyyy-MM-dd" }

$script:WlLicensePublicKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMDPCx3t3BmrtK6vCHp3Omi0mC759TdRjV1qns93rd4vW6BiVKh/eT9hENyr2tp5SYfxqJNxkxKQ+x9geNZrjVQ=='
$script:WlLicenseWarnDays = 30

function ConvertFrom-WlBase64Url {
    param([Parameter(Mandatory)][string]$Text)
    $s = $Text.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } 1 { throw [System.FormatException]::new('Invalid base64url.') } }
    [Convert]::FromBase64String($s)
}

function Test-WlLicenseKey {
    <#
    .SYNOPSIS
    Verifies a licence key: signature, tenant and expiry. Returns the licence status, never throws.
    Status: None, Invalid, WrongTenant, Valid, ExpiringSoon (within 30 days), Expired.
    #>
    param(
        [string]$Key,
        [string]$TenantId = (Get-WlSetting -Name 'WL_TENANT_ID'),
        [datetime]$Now = [DateTime]::UtcNow,
        [string]$PublicKey = $script:WlLicensePublicKey
    )
    $r = [ordered]@{ status = 'None'; licenseId = $null; customer = $null; plan = $null; tenantId = $null; issued = $null; expires = $null; daysLeft = $null }
    $Key = ([string]$Key).Trim()
    if (-not $Key) { return $r }
    $r.status = 'Invalid'
    $parts = $Key -split '\.'
    if ($parts.Count -ne 3 -or $parts[0] -ne 'WL1' -or $Key.Length -gt 4000) { return $r }
    try {
        $data = [Text.Encoding]::ASCII.GetBytes("$($parts[0]).$($parts[1])")
        $sig = ConvertFrom-WlBase64Url $parts[2]
        $ec = [System.Security.Cryptography.ECDsa]::Create()
        try {
            $read = 0
            $ec.ImportSubjectPublicKeyInfo([Convert]::FromBase64String($PublicKey), [ref]$read)
            if (-not $ec.VerifyData($data, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256)) { return $r }
        }
        finally { $ec.Dispose() }
        $p = [Text.Encoding]::UTF8.GetString((ConvertFrom-WlBase64Url $parts[1])) | ConvertFrom-Json
    }
    catch { return $r }

    $r.licenseId = [string]$p.lid; $r.customer = [string]$p.cust; $r.plan = [string]$p.plan
    $r.tenantId = [string]$p.tid; $r.issued = [string]$p.iss; $r.expires = [string]$p.exp
    if ([int]$p.v -ne 1) { return $r }
    if (-not $TenantId -or ([string]$p.tid).ToLowerInvariant() -ne $TenantId.ToLowerInvariant()) { $r.status = 'WrongTenant'; return $r }
    $exp = [datetime]::MinValue
    if (-not [datetime]::TryParseExact([string]$p.exp, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$exp)) { return $r }
    # Valid through the end of the expiry day (UTC)
    $end = $exp.Date.AddDays(1)
    $r.daysLeft = [int][Math]::Ceiling(($end - $Now).TotalDays)
    $r.status = if ($Now -ge $end) { 'Expired' } elseif ($r.daysLeft -le $script:WlLicenseWarnDays) { 'ExpiringSoon' } else { 'Valid' }
    $r
}

function Get-WlLicense {
    <#
    .SYNOPSIS
    The licence of this installation: the key entered in the portal (state/license.json) or, as fallback, the app
    setting WL_LICENSE_KEY (install parameter -LicenseKey).
    #>
    $stored = $null
    try { $stored = Get-WlBlob -Container 'state' -Name 'license.json' } catch { $stored = $null }
    $key = if ($stored -and (Get-WlProp $stored 'key')) { [string]$stored.key } else { Get-WlSetting -Name 'WL_LICENSE_KEY' }
    $r = Test-WlLicenseKey -Key $key
    $r.source = if ($stored -and (Get-WlProp $stored 'key')) { 'Portal' } elseif ($key) { 'AppSetting' } else { $null }
    if ($r.source -eq 'Portal') { $r.setBy = [string]$stored.setBy; $r.setAt = [string]$stored.setAt }
    $r
}

function Set-WlLicense {
    <#
    .SYNOPSIS
    Stores a licence key entered in the portal. Only keys with a valid signature for this tenant are accepted
    (expired keys too – a renewal simply replaces them).
    #>
    param([Parameter(Mandatory)]$Data, [Parameter(Mandatory)][string]$By)
    $key = ([string](Get-WlProp $Data 'key')).Trim()
    if (-not $key) { throw [System.ArgumentException]::new('Licence key missing.') }
    $r = Test-WlLicenseKey -Key $key
    switch ($r.status) {
        'Invalid' { throw [System.ArgumentException]::new('This is not a valid Wardline licence key.') }
        'WrongTenant' { throw [System.ArgumentException]::new("This licence key belongs to another tenant ($($r.tenantId)).") }
    }
    Set-WlBlob -Container 'state' -Name 'license.json' -Object ([ordered]@{ key = $key; setBy = $By; setAt = [DateTime]::UtcNow.ToString('o') })
    Get-WlLicense
}
