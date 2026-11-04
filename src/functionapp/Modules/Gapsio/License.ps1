# Licence keys: bound to one Entra tenant, signed by the vendor (ECDSA P-256 / SHA-256) and checked offline – Gapsio
# never calls home. Enforcement is soft: nothing is blocked, the portal shows the licence status to administrators.
#
# Key format:  WL1.<payload>.<signature>   (both base64url)
# Payload:     { "v":1, "lid":"…", "cust":"…", "tid":"<tenant id>", "plan":"Annual", "iss":"yyyy-MM-dd", "exp":"yyyy-MM-dd" }

$script:WlLicensePublicKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMDPCx3t3BmrtK6vCHp3Omi0mC759TdRjV1qns93rd4vW6BiVKh/eT9hENyr2tp5SYfxqJNxkxKQ+x9geNZrjVQ=='
$script:WlLicenseWarnDays = 30
# Monthly keys are renewed automatically every billing period: shorter warning and grace windows,
# otherwise a cancelled subscription would keep the full view for another month.
$script:WlLicenseWindows = @{ Monthly = @{ warn = 7; grace = 7 } }

function Get-WlLicenseWindow {
    param([string]$Plan, [ValidateSet('warn', 'grace')][string]$Kind)
    $w = $script:WlLicenseWindows[[string]$Plan]
    if ($w) { return [int]$w[$Kind] }
    if ($Kind -eq 'warn') { $script:WlLicenseWarnDays } else { $script:WlLicenseGraceDays }
}

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
    Status: None, Invalid, WrongTenant, Valid, ExpiringSoon (within 30 days, Monthly: 7), Expired.
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
    $r.status = if ($Now -ge $end) { 'Expired' } elseif ($r.daysLeft -le (Get-WlLicenseWindow -Plan $r.plan -Kind warn)) { 'ExpiringSoon' } else { 'Valid' }
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
        'Invalid' { throw [System.ArgumentException]::new('This is not a valid Gapsio licence key.') }
        'WrongTenant' { throw [System.ArgumentException]::new("This licence key belongs to another tenant ($($r.tenantId)).") }
    }
    Set-WlBlob -Container 'state' -Name 'license.json' -Object ([ordered]@{ key = $key; setBy = $By; setAt = [DateTime]::UtcNow.ToString('o') })
    Get-WlLicense
}

#region Community edition (no valid licence): first rows of every list are real, the rest is masked server-side
$script:WlCommunityRows = 10
$script:WlLicenseGraceDays = 30
$script:WlLicenseTierOverride = $null   # tests only (set from inside the module)
$script:WlMaskText = '••••••••'
# Property names whose string values are enumerations/codes the portal needs for filters, charts and colours – never identifiers.
$script:WlMaskKeepNames = @('severity', 'category', 'status', 'os', 'osPlatform', 'type', 'scope', 'platform', 'mode', 'agentType', 'source', 'kind', 'level', 'via', 'state', 'present',
    'active', 'module', 'audience', 'principalType', 'dataSource', 'operator', 'assignmentType', 'operation', 'result', 'action', 'avMode', 'avModeText', 'sensorHealth', 'exposure',
    'assetValue', 'joinType', 'deviceType', 'managedBy', 'usage', 'publishedStatus', 'lifecycle', 'networkProtectionSource', 'plan', 'tier', 'confidence', 'isServer', 'detail', '_masked')
# Property names whose whole subtree consists of codes (feature → GOOD/BAD, rule → mode, counts …).
$script:WlMaskKeepParents = @('checks', 'asr', 'effective', 'targets', 'controls', 'riskLevels', 'sources', 'summary', 'charts', 'groups', 'modes', 'counts', 'dataSources', 'permissionGroups', 'sevCount')

function Get-WlCommunityRows { $script:WlCommunityRows }

function Get-WlLicenseTier {
    <#
    .SYNOPSIS
    'Full' with a valid licence (including the warning window and a grace period after expiry: 30 days, Monthly 7), otherwise
    'Community': every list shows the first rows, the rest is masked before it leaves the server. Demo builds are Full.
    #>
    param($License)
    if ($script:WlLicenseTierOverride) { return $script:WlLicenseTierOverride }
    if (-not $License) { try { $License = Get-WlLicense } catch { return 'Community' } }
    $st = [string](Get-WlProp $License 'status')
    if ($st -in 'Valid', 'ExpiringSoon') { return 'Full' }
    if ($st -eq 'Expired') { $dl = Get-WlProp $License 'daysLeft'; if ($null -ne $dl -and [int]$dl -ge -(Get-WlLicenseWindow -Plan ([string](Get-WlProp $License 'plan')) -Kind grace)) { return 'Full' } }
    'Community'
}

function Hide-WlValue {
    param($Value, [string]$Name = '', [bool]$Keep = $false)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        if ($Keep -or $Value -eq '' -or $script:WlMaskKeepNames -contains $Name -or $Value -match '^\d{4}-\d{2}-\d{2}') { return $Value }
        return $script:WlMaskText
    }
    if ($Value -is [bool] -or $Value -is [datetime] -or $Value -is [decimal] -or $Value.GetType().IsPrimitive) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in @($Value.Keys)) { $o[$k] = Hide-WlValue -Value $Value[$k] -Name ([string]$k) -Keep ($Keep -or $script:WlMaskKeepParents -contains [string]$k) }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable]) { return @(foreach ($e in $Value) { , (Hide-WlValue -Value $e -Name $Name -Keep $Keep) }) }
    if ($Value -is [pscustomobject]) {
        $o = [ordered]@{}
        foreach ($p in $Value.PSObject.Properties) { $o[$p.Name] = Hide-WlValue -Value $p.Value -Name $p.Name -Keep ($Keep -or $script:WlMaskKeepParents -contains $p.Name) }
        return [pscustomobject]$o
    }
    $Value
}

function Hide-WlItem {
    # One list entry with every free text and identifier replaced; codes and numbers stay so filters and charts still work.
    param($Item)
    $o = Hide-WlValue -Value $Item
    if ($o -is [System.Collections.IDictionary]) { $o['_masked'] = $true; return [pscustomobject]$o }
    if ($o -is [pscustomobject]) { $o | Add-Member -NotePropertyName _masked -NotePropertyValue $true -Force; return $o }
    $o
}

function Protect-WlCommunityList {
    param([AllowEmptyCollection()][object[]]$Items, [int]$Limit = $script:WlCommunityRows, [int]$Offset = 0)
    $out = [System.Collections.Generic.List[object]]::new()
    $i = $Offset
    foreach ($it in @($Items)) { if ($null -eq $it) { continue }; if ($i -lt $Limit) { $out.Add($it) } else { $out.Add((Hide-WlItem $it)) }; $i++ }
    $out.ToArray()
}

function Protect-WlCommunity {
    <#
    .SYNOPSIS
    Community view of a snapshot: every top-level list keeps its first rows, the rest is masked; summaries, statistics,
    warnings and static catalogues stay complete. Marks the snapshot with tier = 'Community'.
    #>
    param([Parameter(Mandatory)]$Snapshot, [int]$Limit = $script:WlCommunityRows, [string[]]$Keep = @('warnings', 'seenDefenderSettings', 'asrCatalog', 'runs'))
    $o = [ordered]@{}
    $pairs = if ($Snapshot -is [System.Collections.IDictionary]) { @($Snapshot.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Key; Value = $_.Value } }) } else { @($Snapshot.PSObject.Properties) }
    foreach ($p in $pairs) {
        $v = $p.Value
        if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string] -and $v -isnot [System.Collections.IDictionary] -and $Keep -notcontains $p.Name) { $o[$p.Name] = Protect-WlCommunityList -Items @($v) -Limit $Limit }
        else { $o[$p.Name] = $v }
    }
    $o['tier'] = 'Community'; $o['communityRows'] = $Limit
    [pscustomobject]$o
}
#endregion
