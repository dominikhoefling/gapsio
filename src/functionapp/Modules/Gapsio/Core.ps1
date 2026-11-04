# Gapsio core: configuration, tokens, REST/Graph/Hunting, storage, snapshots, auth.

$script:GapsioTokens = @{}
$script:GapsioWarnings = [System.Collections.Generic.List[string]]::new()
$script:GapsioStorageVersion = '2023-11-03'
# Single source of the version: ModuleVersion in Gapsio.psd1 (the release workflow checks it against the git tag).
$script:GapsioVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'Gapsio.psd1')).ModuleVersion.ToString()
# GitHub repository that publishes Gapsio releases (update check). Override with the app setting GAPSIO_UPDATE_REPOSITORY.
$script:GapsioDefaultRepository = 'dominikhoefling/gapsio'

#region Configuration & warnings
function Get-GapsioSetting {
    param([Parameter(Mandatory)][string]$Name, [string]$Default)
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    $v
}

function Get-GapsioModules {
    <#
    .SYNOPSIS
    Enabled modules from the app setting GAPSIO_MODULES (comma-separated). Default: endpoint,agents.
    The 'access' (PIM/roles), 'licensing' (Defender licence indication) and
    'officepreview' (Defender for Office 365 private preview) modules are optional.
    #>
    $raw = Get-GapsioSetting -Name 'GAPSIO_MODULES' -Default 'endpoint,agents'
    @($raw -split '[,; ]+' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -in 'endpoint', 'agents', 'access', 'licensing', 'officepreview' } | Select-Object -Unique)
}

function Test-GapsioFeature {
    <#
    .SYNOPSIS
    Endpoint sub-features from the app setting GAPSIO_FEATURES (comma-separated): hunting, indicators, inventory, coverage, response.
    A feature that is not selected was not granted a permission, so its data source is skipped quietly.
    Default (setting missing, e.g. older installations): hunting and indicators.
    #>
    param([Parameter(Mandatory)][string]$Name)
    $raw = Get-GapsioSetting -Name 'GAPSIO_FEATURES' -Default 'hunting,indicators'
    $set = @($raw -split '[,; ]+' | ForEach-Object { $_.Trim().ToLowerInvariant() })
    if ($Name -ieq 'inventory') { return ($set -contains 'inventory') -or ((Get-GapsioSetting -Name 'GAPSIO_DEVICE_INVENTORY' -Default 'false') -eq 'true') }
    $set -contains $Name.ToLowerInvariant()
}

function Get-GapsioVersion { $script:GapsioVersion }

function Compare-GapsioVersion {
    <#
    .SYNOPSIS
    Compares two versions such as 'v0.4.1' and '0.4.0'. Returns 1 if A is newer, -1 if B is newer, 0 if equal.
    Pre-release suffixes (-rc.1) are ignored for the comparison.
    #>
    param([string]$A, [string]$B)
    $pa = $null; $pb = $null
    if (-not [version]::TryParse(($A -replace '^v', '' -replace '[-+].*$', ''), [ref]$pa)) { return 0 }
    if (-not [version]::TryParse(($B -replace '^v', '' -replace '[-+].*$', ''), [ref]$pb)) { return 0 }
    $pa.CompareTo($pb)
}

function Update-GapsioReleaseInfo {
    <#
    .SYNOPSIS
    Checks once a day whether a newer Gapsio release exists and stores the result in state/release.json (shown in the portal).
    The check is an anonymous GET to the GitHub releases API – no tenant data is sent. Disable with GAPSIO_UPDATE_CHECK=false.
    Gapsio never updates itself; customers update with setup/Update-Gapsio.ps1.
    #>
    param([switch]$Force)
    if ((Get-GapsioSetting -Name 'GAPSIO_UPDATE_CHECK' -Default 'true') -eq 'false') { return $null }
    $repo = Get-GapsioSetting -Name 'GAPSIO_UPDATE_REPOSITORY' -Default $script:GapsioDefaultRepository
    if ($repo -notmatch '^[\w.-]+/[\w.-]+$' -or $repo -like 'OWNER/*') { return $null }
    $cur = $null
    try { $cur = Get-GapsioBlob -Container 'state' -Name 'release.json' } catch { }
    if (-not $Force -and $cur -and $cur.checkedAt -and $cur.current -eq $script:GapsioVersion -and ([DateTime]$cur.checkedAt).ToUniversalTime() -gt [DateTime]::UtcNow.AddHours(-20)) { return $cur }
    try {
        $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -TimeoutSec 15 -Headers @{ 'User-Agent' = "Gapsio/$script:GapsioVersion"; Accept = 'application/vnd.github+json' }
        $latest = ([string]$r.tag_name) -replace '^v', ''
        $info = [ordered]@{
            current = $script:GapsioVersion; latest = $latest; available = ((Compare-GapsioVersion $latest $script:GapsioVersion) -gt 0)
            url = [string]$r.html_url; publishedAt = [string]$r.published_at; checkedAt = [DateTime]::UtcNow.ToString('o'); repository = $repo
        }
        Set-GapsioBlob -Container 'state' -Name 'release.json' -Object $info
        [pscustomobject]$info
    }
    catch { Write-Warning "Update check failed: $($_.Exception.Message)"; $cur }
}

function Test-GapsioModuleEnabled {
    param([Parameter(Mandatory)][string]$Name)
    (Get-GapsioModules) -contains $Name.ToLowerInvariant()
}

function Reset-GapsioWarnings { $script:GapsioWarnings.Clear() }

function Add-GapsioWarning {
    param([Parameter(Mandatory)][string]$Message)
    $script:GapsioWarnings.Add($Message)
    Write-Warning $Message
}

function Get-GapsioWarnings { $script:GapsioWarnings.ToArray() }
#endregion

#region Tokens & REST
function Get-GapsioToken {
    <#
    .SYNOPSIS
    Gets a token of the (user-assigned) managed identity for a resource. No secret, no certificate.
    #>
    param([Parameter(Mandatory)][string]$Resource)
    $cached = $script:GapsioTokens[$Resource]
    if ($cached -and $cached.ExpiresOn -gt [DateTime]::UtcNow.AddMinutes(5)) { return $cached.Token }

    # Optional: a pre-created data-access app registration (GAPSIO_DATA_APP_ID). The managed identity signs in to it via
    # workload identity federation (no secret). Storage and Azure OpenAI (Azure RBAC) always use the managed identity directly.
    $dataApp = Get-GapsioSetting -Name 'GAPSIO_DATA_APP_ID'
    if ($dataApp -and $Resource -notmatch 'storage\.azure\.com|AzureADTokenExchange|cognitiveservices\.azure\.com') {
        $assertion = Get-GapsioToken -Resource 'api://AzureADTokenExchange'
        $loginHost = Get-GapsioSetting -Name 'GAPSIO_LOGIN_HOST' -Default 'login.microsoftonline.com'
        $tenant = Get-GapsioSetting -Name 'GAPSIO_TENANT_ID'
        $r = Invoke-RestMethod -Method Post -Uri "https://$loginHost/$tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
            client_id             = $dataApp
            scope                 = "$($Resource.TrimEnd('/'))/.default"
            grant_type            = 'client_credentials'
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $assertion
        }
        $script:GapsioTokens[$Resource] = @{ Token = $r.access_token; ExpiresOn = [DateTime]::UtcNow.AddSeconds([Math]::Min([int]$r.expires_in, 3600)) }
        return $r.access_token
    }

    $endpoint = $env:IDENTITY_ENDPOINT
    if (-not $endpoint) { throw 'Managed identity not available (IDENTITY_ENDPOINT missing). Is the code running in the Function App?' }
    $uri = "$endpoint`?resource=$([uri]::EscapeDataString($Resource))&api-version=2019-08-01"
    $clientId = Get-GapsioSetting -Name 'GAPSIO_CLIENT_ID'
    if ($clientId) { $uri += "&client_id=$clientId" }

    $r = Invoke-RestMethod -Uri $uri -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER } -Method Get
    # Cache for at most an hour, so newly granted permissions are picked up as soon as the platform issues a new token.
    $expires = [DateTimeOffset]::FromUnixTimeSeconds([long]$r.expires_on).UtcDateTime
    $cap = [DateTime]::UtcNow.AddHours(1)
    if ($expires -gt $cap) { $expires = $cap }
    $script:GapsioTokens[$Resource] = @{ Token = $r.access_token; ExpiresOn = $expires }
    $r.access_token
}

function New-GapsioHttpException {
    param([int]$Status, [string]$Message)
    $e = [System.Exception]::new($Message)
    $e.Data['Status'] = $Status
    $e
}

function Invoke-GapsioRest {
    <#
    .SYNOPSIS
    REST call with a managed identity token; retries on 429/5xx (honours Retry-After).
    -Raw returns the response body as text instead of a parsed object.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        $Body,
        [Parameter(Mandatory)][string]$Resource,
        [hashtable]$Headers = @{},
        [string]$ContentType = 'application/json; charset=utf-8',
        [switch]$Raw,
        [int]$MaxRetries = 5
    )
    $attempt = 0
    while ($true) {
        $attempt++
        $h = @{ Authorization = "Bearer $(Get-GapsioToken -Resource $Resource)" }
        foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }

        $params = @{
            Uri                = $Uri
            Method             = $Method
            Headers            = $h
            SkipHttpErrorCheck = $true
        }
        if ($null -ne $Body) {
            $params.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 -Compress }
            $params.ContentType = $ContentType
        }

        $status = 0; $respHeaders = $null
        if ($Raw) {
            # Invoke-WebRequest has no -StatusCodeVariable/-ResponseHeadersVariable – read them from the response object.
            $resp = Invoke-WebRequest @params
            $status = [int]$resp.StatusCode
            $respHeaders = $resp.Headers
            $content = $resp.Content
            if ($content -is [byte[]]) { $content = [Text.Encoding]::UTF8.GetString($content) }
        }
        else {
            $resp = Invoke-RestMethod @params -StatusCodeVariable 'status' -ResponseHeadersVariable 'respHeaders'
            $content = $resp
        }

        if ($status -ge 200 -and $status -lt 300) { return $content }

        if (($status -eq 429 -or $status -ge 500) -and $attempt -le $MaxRetries) {
            $wait = [Math]::Pow(2, $attempt)
            if ($respHeaders -and $respHeaders['Retry-After']) {
                $ra = 0
                if ([int]::TryParse([string]($respHeaders['Retry-After'] | Select-Object -First 1), [ref]$ra)) { $wait = $ra }
            }
            Start-Sleep -Seconds ([Math]::Min([Math]::Max($wait, 1), 60))
            continue
        }

        $detail = if ($content -is [string]) { $content } else { ($content | ConvertTo-Json -Depth 5 -Compress) }
        if ($detail.Length -gt 600) { $detail = $detail.Substring(0, 600) + '…' }
        throw (New-GapsioHttpException -Status $status -Message "HTTP $status for $Method $Uri :: $detail")
    }
}

function Invoke-GapsioGraph {
    <#
    .SYNOPSIS
    Microsoft Graph (v1.0 or -Beta). -All follows @odata.nextLink and returns an array.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Beta,
        [switch]$All,
        [string]$Method = 'GET',
        $Body,
        [hashtable]$Headers = @{}
    )
    $base = if ($Beta) { 'https://graph.microsoft.com/beta' } else { 'https://graph.microsoft.com/v1.0' }
    $uri = if ($Path -match '^https://') { $Path } else { "$base/$($Path.TrimStart('/'))" }
    if (-not $All) {
        return Invoke-GapsioRest -Uri $uri -Method $Method -Body $Body -Resource 'https://graph.microsoft.com' -Headers $Headers
    }
    $items = [System.Collections.Generic.List[object]]::new()
    while ($uri) {
        $r = Invoke-GapsioRest -Uri $uri -Resource 'https://graph.microsoft.com' -Headers $Headers
        if ($r.PSObject.Properties['value']) { foreach ($i in @($r.value)) { if ($null -ne $i) { $items.Add($i) } } }
        $uri = if ($r.PSObject.Properties['@odata.nextLink']) { $r.'@odata.nextLink' } else { $null }
    }
    $items.ToArray()
}

function Get-GapsioTokenClaims {
    <#
    .SYNOPSIS
    Decodes the payload of a cached access token (no validation – only used to explain errors).
    #>
    param([string]$Resource = 'https://graph.microsoft.com')
    $cached = $script:GapsioTokens[$Resource]
    if (-not $cached) { $cached = $script:GapsioTokens[$Resource.TrimEnd('/')] }
    if (-not $cached -or -not $cached.Token) { return $null }
    try {
        $part = ($cached.Token -split '\.')[1].Replace('-', '+').Replace('_', '/')
        switch ($part.Length % 4) { 2 { $part += '==' } 3 { $part += '=' } }
        [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json
    }
    catch { $null }
}

function Get-GapsioErrorText {
    <#
    .SYNOPSIS
    Error text for a run notice. For HTTP 403 it adds why this usually happens and what to check: the permission is
    missing, or it was granted after the managed identity's current token was issued (tokens are cached up to 24 hours).
    #>
    param([Parameter(Mandatory)]$Exception, [string]$Context, [string]$Resource = 'https://graph.microsoft.com')
    $msg = $Exception.Message
    $status = $Exception.Data['Status']
    if ($status -ne 403 -and $msg -notmatch '^HTTP 403\b') { return $msg }
    $short = ($msg -split ' :: ')[0]
    $code = if ($msg -match '"code"\s*:\s*"([^"]+)"') { $Matches[1] } else { '' }
    $hint = "HTTP 403$(if ($code) { " ($code)" }) – permission missing or not yet in the managed identity's token."
    $claims = Get-GapsioTokenClaims -Resource $Resource
    if ($claims) {
        $roles = @($claims.roles)
        if ($claims.iat) { $hint += " Token issued $([DateTimeOffset]::FromUnixTimeSeconds([long]$claims.iat).UtcDateTime.ToString('yyyy-MM-dd HH:mm')) UTC with $($roles.Count) permission(s)." }
        $needed = @([regex]::Matches([string]$Context, '\b([A-Z][A-Za-z]+(?:\.[A-Z][A-Za-z]+)+)\b') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -match '\.Read' })
        $absent = @($needed | Where-Object { $_ -notin $roles })
        if ($needed -and -not $absent) { $hint += " The token contains $($needed -join ', ') – the API may need an additional role or licence." }
        elseif ($absent) { $hint += " Not in the token: $($absent -join ', ')." }
    }
    $hint += ' Permissions granted after that take effect with the next token (up to 24 hours). Re-running ./setup/Grant-GapsioPermissions.ps1 -PrincipalId <managed identity> -Features … shows what is granted.'
    "$hint [$short]"
}

function Invoke-GapsioGraphSafe {
    <#
    .SYNOPSIS
    Like Invoke-GapsioGraph, but logs errors as a warning and returns $null, so a missing permission or
    licence does not abort the whole run.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Beta,
        [switch]$All,
        [Parameter(Mandatory)][string]$Context,
        [hashtable]$Headers = @{}
    )
    try { Invoke-GapsioGraph -Path $Path -Beta:$Beta -All:$All -Headers $Headers }
    catch { Add-GapsioWarning "${Context}: $(Get-GapsioErrorText -Exception $_.Exception -Context $Context)"; $null }
}

$script:GapsioV1Unavailable = @{}
function Invoke-GapsioGraphV1First {
    <#
    .SYNOPSIS
    Calls Microsoft Graph v1.0 first and falls back to beta when the endpoint is not available in v1.0 (yet).
    The fallback is remembered per endpoint for the rest of the run, so beta-only endpoints cost one extra call at most.
    Errors are logged as a warning (unless -Silent) and $null is returned, like Invoke-GapsioGraphSafe.
    Use it for endpoints that exist in v1.0 with the same shape (Agent ID, Conditional Access, role management).
    Endpoints that only exist in beta (Intune Settings Catalog, intents, remediations) call beta directly.
    #>
    param([Parameter(Mandatory)][string]$Path, [switch]$All, [Parameter(Mandatory)][string]$Context, [switch]$Silent)
    $root = (($Path -split '\?')[0] -split '/' | Where-Object { $_ } | Select-Object -First 2) -join '/' -replace '\(.*$', ''
    if (-not $script:GapsioV1Unavailable.ContainsKey($root)) {
        try { return Invoke-GapsioGraph -Path $Path -All:$All }
        catch { $v1Error = $_.Exception.Message }
    }
    try {
        $r = Invoke-GapsioGraph -Beta -Path $Path -All:$All
        if ($v1Error) { $script:GapsioV1Unavailable[$root] = $true }
        return $r
    }
    catch {
        if (-not $Silent) { Add-GapsioWarning "${Context}: $(Get-GapsioErrorText -Exception $_.Exception -Context $Context)" }
        return $null
    }
}

function Invoke-GapsioHunting {
    <#
    .SYNOPSIS
    Advanced Hunting via Microsoft Graph (security/runHuntingQuery, v1.0). Keeps within the tenant budget of
    45 calls per minute by pausing when needed.
    #>
    param([Parameter(Mandatory)][string]$Query, [string]$Timespan = 'P30D')
    Wait-GapsioHuntingBudget
    $body = @{ Query = $Query }
    if ($Timespan) { $body.Timespan = $Timespan }
    $r = Invoke-GapsioRest -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Method POST -Body $body -Resource 'https://graph.microsoft.com'
    @($r.results)
}

# Advanced Hunting API limits: 100,000 rows per query, 45 calls per minute, 10 minutes running time per hour.
$script:GapsioHuntingRowLimit = 100000
$script:GapsioHuntingCallsPerMinute = 40
$script:GapsioHuntingCalls = [System.Collections.Generic.List[datetime]]::new()
function Wait-GapsioHuntingBudget {
    $now = [DateTime]::UtcNow
    $script:GapsioHuntingCalls.RemoveAll({ param($t) $t -lt $now.AddSeconds(-60) }) | Out-Null
    if ($script:GapsioHuntingCalls.Count -ge $script:GapsioHuntingCallsPerMinute) {
        $wait = [int][Math]::Ceiling((($script:GapsioHuntingCalls[0].AddSeconds(61)) - $now).TotalSeconds)
        if ($wait -gt 0) { Start-Sleep -Seconds $wait }
        $script:GapsioHuntingCalls.Clear()
    }
    $script:GapsioHuntingCalls.Add([DateTime]::UtcNow)
}

function Invoke-GapsioHuntingSharded {
    <#
    .SYNOPSIS
    Advanced Hunting for result sets that may exceed the 100,000-row limit of the API (large fleets). Runs the query
    once; when the row limit is hit, counts the full result and re-runs it in N shards selected with
    hash(<ShardColumn>, N) == i, so every row is returned exactly once. The shard column must be in the query's
    output (all device queries project DeviceId). Returns the rows; sets $script:GapsioHuntingTruncated when a shard
    is still truncated so the caller can warn.
    #>
    param([Parameter(Mandatory)][string]$Query, [string]$Timespan = 'P30D', [string]$ShardColumn = 'DeviceId', [string]$Context = 'Advanced Hunting')
    $limit = $script:GapsioHuntingRowLimit
    $rows = Invoke-GapsioHunting -Query $Query -Timespan $Timespan
    if ($rows.Count -lt $limit) { return $rows }
    # Truncated: find out how many rows there really are and split
    $total = $limit
    try { $c = Invoke-GapsioHunting -Query "$Query`n| summarize Rows = count()" -Timespan $Timespan; if ($c.Count) { $total = [long]$c[0].Rows } } catch { }
    $n = [int][Math]::Ceiling($total / ($limit * 0.8))
    if ($n -lt 2) { $n = 2 }
    if ($n -gt 400) { Add-GapsioWarning "${Context}: $total rows – more than $($limit * 0.8 * 400) rows cannot be collected in one run."; $n = 400 }
    Write-Information "Gapsio: $Context has $total rows – collecting in $n shards." -InformationAction Continue
    $out = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $n; $i++) {
        $part = Invoke-GapsioHunting -Query "$Query`n| where hash($ShardColumn, $n) == $i" -Timespan $Timespan
        if ($part.Count -ge $limit) { Add-GapsioWarning "${Context}: shard $i of $n still hit the $limit-row limit – results are incomplete." }
        foreach ($r in $part) { if ($null -ne $r) { $out.Add($r) } }
    }
    $out.ToArray()
}

function Invoke-GapsioHuntingSafe {
    # Skipped quietly when the Hunting feature (ThreatHunting.Read.All) is not selected. Large results are sharded.
    param([Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][string]$Context, [string]$Timespan = 'P30D', [string]$ShardColumn = 'DeviceId', [switch]$NoShard)
    if (-not (Test-GapsioFeature -Name 'hunting')) { return $null }
    try {
        if ($NoShard) { return (Invoke-GapsioHunting -Query $Query -Timespan $Timespan) }
        Invoke-GapsioHuntingSharded -Query $Query -Timespan $Timespan -ShardColumn $ShardColumn -Context $Context
    }
    catch { Add-GapsioWarning "${Context}: $(Get-GapsioErrorText -Exception $_.Exception -Context "$Context ThreatHunting.Read.All")"; $null }
}
#endregion

#region Storage (Entra auth only, no shared key)
function Get-GapsioStorageAccount {
    $acct = Get-GapsioSetting -Name 'GAPSIO_STORAGE_ACCOUNT'
    if (-not $acct) { throw 'App setting GAPSIO_STORAGE_ACCOUNT is missing.' }
    $acct
}

function Get-GapsioBlobUri {
    param([string]$Container, [string]$Name)
    $suffix = Get-GapsioSetting -Name 'GAPSIO_STORAGE_SUFFIX' -Default 'core.windows.net'
    "https://$(Get-GapsioStorageAccount).blob.$suffix/$Container/$Name"
}

function Get-GapsioBlobText {
    param([Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Name)
    try {
        Invoke-GapsioRest -Uri (Get-GapsioBlobUri $Container $Name) -Resource 'https://storage.azure.com/' -Headers @{ 'x-ms-version' = $script:GapsioStorageVersion } -Raw
    }
    catch {
        if ($_.Exception.Data['Status'] -eq 404) { return $null }
        throw
    }
}

function Get-GapsioBlob {
    param([Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Name)
    $text = Get-GapsioBlobText -Container $Container -Name $Name
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text | ConvertFrom-Json -Depth 64
}

function Set-GapsioBlob {
    param(
        [Parameter(Mandatory)][string]$Container,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Object,
        [int]$Depth = 32,
        [string]$ContentType = 'application/json; charset=utf-8'
    )
    $json = if ($Object -is [string]) { $Object } else { ConvertTo-Json -InputObject $Object -Depth $Depth -Compress }
    $headers = @{ 'x-ms-version' = $script:GapsioStorageVersion; 'x-ms-blob-type' = 'BlockBlob'; 'x-ms-blob-content-type' = $ContentType }
    Invoke-GapsioRest -Uri (Get-GapsioBlobUri $Container $Name) -Method PUT -Body $json -Resource 'https://storage.azure.com/' -Headers $headers | Out-Null
}

function Remove-GapsioBlob {
    param([Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Name)
    try { Invoke-GapsioRest -Uri (Get-GapsioBlobUri $Container $Name) -Method DELETE -Resource 'https://storage.azure.com/' -Headers @{ 'x-ms-version' = $script:GapsioStorageVersion } | Out-Null }
    catch { if ($_.Exception.Data['Status'] -ne 404) { throw } }
}

#region Paged collections (large fleets)
# Per-device collections are not stored inside the snapshot (300,000 devices would be a JSON of several hundred MB)
# but in pages of GAPSIO_PAGE_SIZE items (state/<module>-<name>/0000.json ...) with a small meta blob, a tab-separated
# search index (state/<module>-<name>.tsv) for the API and a compact key/fingerprint list for drift detection.
function Get-GapsioPageSize { [Math]::Max(100, [int](Get-GapsioSetting -Name 'GAPSIO_PAGE_SIZE' -Default '2000')) }

function Get-GapsioPagedMeta {
    param([Parameter(Mandatory)][string]$Module, [Parameter(Mandatory)][string]$Name)
    try { Get-GapsioBlob -Container 'state' -Name "$Module-$Name.json" } catch { $null }
}

function Get-GapsioPage {
    param([Parameter(Mandatory)][string]$Module, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][int]$Page, [switch]$Raw)
    $blob = "$Module-$Name/$('{0:D4}' -f $Page).json"
    if ($Raw) { Get-GapsioBlobText -Container 'state' -Name $blob } else { @(Get-GapsioBlob -Container 'state' -Name $blob | Where-Object { $_ }) }
}

function Get-GapsioPagedCollection {
    # All items of a paged collection (tests, small tenants, notifications). Falls back to the inline collection of
    # snapshots written by older versions.
    param([Parameter(Mandatory)][string]$Module, [Parameter(Mandatory)][string]$Name, $Snapshot)
    $meta = Get-GapsioPagedMeta -Module $Module -Name $Name
    if (-not $meta) { return @(Get-GapsioProp $Snapshot $Name) }
    $out = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt [int]$meta.pages; $i++) { foreach ($x in (Get-GapsioPage -Module $Module -Name $Name -Page $i)) { $out.Add($x) } }
    $out.ToArray()
}

function ConvertTo-GapsioTsvValue {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.Collections.IDictionary]) { return (@($Value.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';') }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    if ($Value -is [pscustomobject]) { return (@($Value.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ';') }
    ([string]$Value) -replace '[\t\r\n]', ' '
}

function Write-GapsioPagedCollection {
    <#
    .SYNOPSIS
    Writes a collection in pages, the tab-separated index (IndexColumns + page) and the fingerprint list; removes
    pages of the previous run that are no longer needed. Returns the meta object stored in the snapshot.
    Written without per-cell function calls on purpose: 300,000 devices x 25 columns must finish in seconds.
    #>
    param([Parameter(Mandatory)][string]$Module, [Parameter(Mandatory)][string]$Name, [AllowEmptyCollection()][object[]]$Items, [string[]]$IndexColumns = @(), [string]$At)
    $items = @($Items | Where-Object { $_ })
    $size = Get-GapsioPageSize
    $pages = [int][Math]::Ceiling($items.Count / $size)
    $prev = Get-GapsioPagedMeta -Module $Module -Name $Name
    $tsv = [System.Text.StringBuilder]::new()
    $cols = @($IndexColumns)
    if ($cols.Count) { [void]$tsv.Append(($cols + 'page') -join "`t").Append("`n") }
    $fps = [System.Collections.Generic.List[object]]::new($items.Count)
    $tabRx = [regex]'[\t\r\n]'
    for ($p = 0; $p -lt $pages; $p++) {
        $slice = @($items[($p * $size)..([Math]::Min($items.Count, ($p + 1) * $size) - 1)])
        Set-GapsioBlob -Container 'state' -Name "$Module-$Name/$('{0:D4}' -f $p).json" -Object $slice -Depth 32
        foreach ($it in $slice) {
            $isDict = $it -is [System.Collections.IDictionary]
            $props = $null; if (-not $isDict) { $props = $it.PSObject.Properties }   # direct assignment: an if-expression would enumerate the collection
            if ($cols.Count) {
                foreach ($c in $cols) {
                    $v = $null
                    if ($isDict) { $v = $it[$c] } else { $pp = $props[$c]; if ($pp) { $v = $pp.Value } }
                    if ($null -eq $v) { }
                    elseif ($v -is [string]) { [void]$tsv.Append($tabRx.Replace($v, ' ')) }
                    elseif ($v -is [System.Collections.IDictionary]) { $first = $true; foreach ($e in $v.GetEnumerator()) { if (-not $first) { [void]$tsv.Append(';') }; $first = $false; [void]$tsv.Append([string]$e.Key).Append('=').Append([string]$e.Value) } }
                    elseif ($v -is [datetime]) { [void]$tsv.Append($v.ToUniversalTime().ToString('o')) }
                    elseif ($v -is [System.Array]) { $first = $true; foreach ($e in $v) { if (-not $first) { [void]$tsv.Append(';') }; $first = $false; [void]$tsv.Append($tabRx.Replace([string]$e, ' ')) } }
                    elseif ($v -is [pscustomobject]) { $first = $true; foreach ($e in $v.PSObject.Properties) { if (-not $first) { [void]$tsv.Append(';') }; $first = $false; [void]$tsv.Append($e.Name).Append('=').Append([string]$e.Value) } }
                    else { [void]$tsv.Append($tabRx.Replace([string]$v, ' ')) }
                    [void]$tsv.Append("`t")
                }
                [void]$tsv.Append($p).Append("`n")
            }
            $g = { param($n) if ($isDict) { return $it[$n] }; $pp = $props[$n]; if ($pp) { return $pp.Value }; $null }
            $fp = [ordered]@{ key = & $g 'key'; fp = & $g 'fp'; label = & $g 'label'; state = & $g 'state' }
            $pr = & $g 'present'; if ($null -ne $pr) { $fp.present = [bool]$pr }
            $fps.Add([pscustomobject]$fp)
        }
    }
    if ($prev) { for ($p = $pages; $p -lt [int]$prev.pages; $p++) { Remove-GapsioBlob -Container 'state' -Name "$Module-$Name/$('{0:D4}' -f $p).json" } }
    if ($cols.Count) { Set-GapsioBlob -Container 'state' -Name "$Module-$Name.tsv" -Object $tsv.ToString() -ContentType 'text/tab-separated-values; charset=utf-8' }
    Set-GapsioBlob -Container 'state' -Name "$Module-$Name-fp.json" -Object @($fps.ToArray())
    $meta = [ordered]@{ count = $items.Count; pageSize = $size; pages = $pages; index = [bool]$cols.Count; at = $At }
    Set-GapsioBlob -Container 'state' -Name "$Module-$Name.json" -Object $meta
    $meta
}

$script:GapsioIndexCache = @{}
function Get-GapsioPagedIndexRaw {
    <#
    .SYNOPSIS
    The tab-separated index of a paged collection in columnar form: @{ cols = @{ name = position }; rows = List[string[]] }.
    Cached in the worker process per snapshot time so searches do not re-download or re-parse the index on
    every request. Row values are strings; the last column is the page number.
    #>
    param([Parameter(Mandatory)][string]$Module, [Parameter(Mandatory)][string]$Name)
    $meta = Get-GapsioPagedMeta -Module $Module -Name $Name
    $empty = @{ cols = @{}; names = @(); rows = [System.Collections.Generic.List[string[]]]::new() }
    if (-not $meta -or -not $meta.index) { return $empty }
    $ck = "$Module-$Name"
    $c = $script:GapsioIndexCache[$ck]
    if ($c -and $c.at -eq [string]$meta.at) { return $c }
    $text = Get-GapsioBlobText -Container 'state' -Name "$Module-$Name.tsv"
    if (-not $text) { return $empty }
    $lines = $text.Split("`n")
    $names = @($lines[0].TrimEnd("`r").Split("`t"))
    $cols = @{}; for ($i = 0; $i -lt $names.Count; $i++) { $cols[$names[$i]] = $i }
    $rows = [System.Collections.Generic.List[string[]]]::new($lines.Count)
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l.Length -eq 0) { continue }
        $rows.Add($l.TrimEnd("`r").Split("`t"))
    }
    $c = @{ at = [string]$meta.at; cols = $cols; names = $names; rows = $rows }
    $script:GapsioIndexCache[$ck] = $c
    $c
}

function ConvertFrom-GapsioIndexRow {
    # One raw index row as an object with the column names (string values).
    param([Parameter(Mandatory)]$Index, [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Row)
    $o = [ordered]@{}
    $names = $Index.names
    for ($i = 0; $i -lt $names.Count; $i++) { $o[$names[$i]] = $(if ($i -lt $Row.Count) { $Row[$i] } else { '' }) }
    [pscustomobject]$o
}

function Get-GapsioPagedIndex {
    # The index as objects (one per item). Convenient for small collections; large searches use Get-GapsioPagedIndexRaw.
    param([Parameter(Mandatory)][string]$Module, [Parameter(Mandatory)][string]$Name)
    $ix = Get-GapsioPagedIndexRaw -Module $Module -Name $Name
    @(foreach ($r in $ix.rows) { ConvertFrom-GapsioIndexRow -Index $ix -Row $r })
}

function Get-GapsioPagedItem {
    # One item of a paged collection by a property value (uses the index to find the page).
    param([Parameter(Mandatory)][string]$Module, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Property, [Parameter(Mandatory)][string]$Value)
    $ix = Get-GapsioPagedIndexRaw -Module $Module -Name $Name
    if (-not $ix.cols.ContainsKey($Property)) { return $null }
    $ci = $ix.cols[$Property]; $pi = $ix.cols['page']
    $page = -1
    foreach ($r in $ix.rows) { if ($r[$ci] -eq $Value) { $page = [int]$r[$pi]; break } }
    if ($page -lt 0) { return $null }
    foreach ($x in (Get-GapsioPage -Module $Module -Name $Name -Page $page)) { if ([string](Get-GapsioProp $x $Property) -eq $Value) { return $x } }
    $null
}
#endregion

function Add-GapsioQueueMessage {
    param([string]$Queue = 'gapsio-run', [Parameter(Mandatory)][string]$Text)
    $suffix = Get-GapsioSetting -Name 'GAPSIO_STORAGE_SUFFIX' -Default 'core.windows.net'
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text))
    $xml = "<QueueMessage><MessageText>$b64</MessageText></QueueMessage>"
    Invoke-GapsioRest -Uri "https://$(Get-GapsioStorageAccount).queue.$suffix/$Queue/messages" -Method POST -Body $xml -Resource 'https://storage.azure.com/' -Headers @{ 'x-ms-version' = $script:GapsioStorageVersion } -ContentType 'application/xml' | Out-Null
}
#endregion

#region Helpers
function Get-GapsioHash {
    param([AllowEmptyString()][string]$Text)
    $bytes = [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(([string]$Text).ToLowerInvariant()))
    ([Convert]::ToHexString($bytes)).Substring(0, 24).ToLowerInvariant()
}

function ConvertTo-GapsioUtc {
    # Timestamps without a time zone are UTC (that is how Advanced Hunting returns them).
    param($Value)
    if ($Value -is [datetime]) { return $(if ($Value.Kind -eq 'Unspecified') { [datetime]::SpecifyKind($Value, 'Utc') } else { $Value.ToUniversalTime() }) }
    [DateTimeOffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
}

function Get-GapsioProp {
    # Reads a property null-safely (also when the property does not exist).
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

function Expand-GapsioSettingInstance {
    param($Instance, [System.Collections.Generic.List[object]]$Out, [string]$GroupKey)
    if ($null -eq $Instance) { return }
    $def = [string](Get-GapsioProp $Instance 'settingDefinitionId')
    $type = [string](Get-GapsioProp $Instance '@odata.type')
    switch -Wildcard ($type) {
        '*simpleSettingInstance' {
            $v = Get-GapsioProp (Get-GapsioProp $Instance 'simpleSettingValue') 'value'
            $Out.Add([pscustomobject]@{ definitionId = $def; value = [string]$v; kind = 'simple'; group = $GroupKey })
        }
        '*simpleSettingCollectionInstance' {
            foreach ($v in @(Get-GapsioProp $Instance 'simpleSettingCollectionValue')) {
                if ($null -eq $v) { continue }
                $Out.Add([pscustomobject]@{ definitionId = $def; value = [string](Get-GapsioProp $v 'value'); kind = 'simple'; group = $GroupKey })
            }
        }
        '*choiceSettingInstance' {
            $c = Get-GapsioProp $Instance 'choiceSettingValue'
            $Out.Add([pscustomobject]@{ definitionId = $def; value = [string](Get-GapsioProp $c 'value'); kind = 'choice'; group = $GroupKey })
            foreach ($ch in @(Get-GapsioProp $c 'children')) { Expand-GapsioSettingInstance -Instance $ch -Out $Out -GroupKey $GroupKey }
        }
        '*choiceSettingCollectionInstance' {
            foreach ($c in @(Get-GapsioProp $Instance 'choiceSettingCollectionValue')) {
                if ($null -eq $c) { continue }
                $Out.Add([pscustomobject]@{ definitionId = $def; value = [string](Get-GapsioProp $c 'value'); kind = 'choice'; group = $GroupKey })
                foreach ($ch in @(Get-GapsioProp $c 'children')) { Expand-GapsioSettingInstance -Instance $ch -Out $Out -GroupKey $GroupKey }
            }
        }
        '*groupSettingCollectionInstance' {
            $i = 0
            foreach ($g in @(Get-GapsioProp $Instance 'groupSettingCollectionValue')) {
                if ($null -eq $g) { continue }
                $i++
                $gk = "$def#$i"
                foreach ($ch in @(Get-GapsioProp $g 'children')) { Expand-GapsioSettingInstance -Instance $ch -Out $Out -GroupKey $gk }
            }
        }
        '*groupSettingInstance' {
            foreach ($ch in @(Get-GapsioProp (Get-GapsioProp $Instance 'groupSettingValue') 'children')) { Expand-GapsioSettingInstance -Instance $ch -Out $Out -GroupKey "$def#1" }
        }
    }
}

function Get-GapsioSettingValues {
    <#
    .SYNOPSIS
    Flattens a Settings Catalog settingInstance into values (definitionId, value, kind, group).
    #>
    param($Instance)
    $out = [System.Collections.Generic.List[object]]::new()
    Expand-GapsioSettingInstance -Instance $Instance -Out $out -GroupKey ''
    $out.ToArray()
}

function New-GapsioText {
    <#
    .SYNOPSIS
    Bilingual text for the portal (English/German). The portal shows the language the user selected.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$En, [AllowEmptyString()][string]$De)
    [ordered]@{ en = $En; de = $(if ($De) { $De } else { $En }) }
}

function ConvertTo-GapsioText {
    # Accepts a plain string (custom baselines) or an object with en/de and always returns {en, de}.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return (New-GapsioText -En $Value -De $Value) }
    $en = [string](Get-GapsioProp $Value 'en'); $de = [string](Get-GapsioProp $Value 'de')
    New-GapsioText -En $(if ($en) { $en } else { $de }) -De $de
}

function Get-GapsioRiskLevel {
    param([int]$Score)
    if ($Score -ge 80) { return 'Critical' }
    if ($Score -ge 50) { return 'High' }
    if ($Score -ge 25) { return 'Medium' }
    'Low'
}

function Get-GapsioExclusionRisk {
    <#
    .SYNOPSIS
    Rates an exclusion using the criteria from "Microsoft Defender for Endpoint in Depth" (2nd ed., ch. 2 and 13):
    whole folders/drives, wildcards, file-type exclusions, interpreters as process exclusions and user-writable
    paths. Contextual exclusions (\:{...}) count as good practice.
    Types: Path, TempPath, Process, Extension, IP, ASR, CFA, TamperException, AllowedThreat
    Origins: Policy, Local, GPO      Scope: AV, Global, ASR, CFA
    #>
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [string]$Origin = 'Policy',
        [string]$Scope = 'AV'
    )
    $score = 10
    $reasons = [System.Collections.Generic.List[object]]::new()
    $add = { param($en, $de) $reasons.Add((New-GapsioText -En $en -De $de)) }
    $v = $Value.Trim()
    $lv = $v.ToLowerInvariant()
    $contextual = $v -match '\\:\{'
    $pathPart = if ($contextual) { ($lv -split '\\:\{')[0] } else { $lv }

    if ($contextual) { $score -= 5; & $add 'Contextual exclusion (narrowed) – good practice' 'Kontextuelle Exclusion (eingeschränkt) – gute Praxis' }

    if ($Type -eq 'Extension') {
        $score += 30; & $add 'File-type exclusion applies everywhere on the device' 'Dateityp-Exclusion gilt überall auf dem Gerät'
        $ext = $lv.TrimStart('*').TrimStart('.')
        if ($ext -match '^(exe|dll|sys|ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|hta|scr|msi|msp|lnk|wsf|com|jar|py|sh|iso|img|zip)$') {
            $score += 45; & $add "Executable, script or container file type (.$ext)" "Ausführbarer bzw. Skript-/Container-Dateityp (.$ext)"
        }
        if ($lv -match '\*') { $score += 10; & $add 'Wildcard in file-type exclusion' 'Wildcard in Dateityp-Exclusion' }
    }

    if ($Type -in 'Path', 'ASR', 'CFA', 'TempPath') {
        if ($pathPart -match '^[a-z]:\\?\*?$' -or $pathPart -in '\', '/', '*', '/*') {
            $score += 85; & $add 'Entire drive or root excluded' 'Ganzes Laufwerk bzw. Root ausgenommen'
        }
        if ($pathPart -match '[\*\?]') { $score += 15; & $add 'Wildcard in path' 'Wildcard im Pfad' }
        $isFile = $pathPart -match '\.[a-z0-9]{1,6}$' -and $pathPart -notmatch '\\$'
        if (-not $isFile -and -not ($contextual -and $lv -match 'pathtype:file')) {
            $score += 15; & $add 'Whole folder instead of a single file' 'Ganzer Ordner statt einzelner Datei'
        }
        if ($pathPart -match '%userprofile%|%appdata%|%localappdata%|%temp%|%tmp%|\\users\\|\\appdata\\|\\temp\\|\\downloads\\|\\desktop\\|\\public\\|^/tmp|^/var/tmp|^/home/|^/users/') {
            $score += 35; & $add 'User-writable path' 'Durch Benutzer beschreibbarer Pfad'
        }
        elseif ($pathPart -match '%programdata%|\\programdata\\') {
            $score += 15; & $add 'ProgramData (often writable by users)' 'ProgramData (häufig für Benutzer beschreibbar)'
        }
        if ($pathPart -match '^\\\\') { $score += 10; & $add 'Network path' 'Netzwerkpfad' }
    }

    if ($Type -eq 'Process') {
        $leaf = ($pathPart -split '[\\/]')[-1]
        $lolbins = @('powershell.exe', 'pwsh.exe', 'powershell_ise.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe',
            'regsvr32.exe', 'python.exe', 'pythonw.exe', 'node.exe', 'java.exe', 'javaw.exe', 'msbuild.exe', 'installutil.exe', 'wmic.exe',
            'certutil.exe', 'bitsadmin.exe', 'msiexec.exe', 'explorer.exe', 'bash', 'sh', 'zsh', 'python', 'python3', 'perl', 'node', 'java')
        if ($leaf -in $lolbins) { $score += 70; & $add "Script interpreter or LOLBin as process exclusion ($leaf)" "Skript-Interpreter bzw. LOLBin als Prozess-Exclusion ($leaf)" }
        if ($pathPart -notmatch '[\\/]') { $score += 15; & $add 'File name only, no path – applies to every process with that name' 'Nur Dateiname ohne Pfad – gilt für jeden gleichnamigen Prozess' }
        if ($pathPart -match '\*') { $score += 15; & $add 'Wildcard in process exclusion' 'Wildcard in Prozess-Exclusion' }
    }

    if ($Type -eq 'IP') { $score += 10; & $add 'Network traffic to this address is not inspected' 'Netzwerkverkehr dieser Adresse wird nicht geprüft' }
    if ($Type -eq 'TamperException') { $score += 55; & $add 'May modify Defender despite Tamper Protection (macOS tamperProtection/exclusions)' 'Darf Defender trotz Tamper Protection verändern (macOS tamperProtection/exclusions)' }
    if ($Type -eq 'AllowedThreat') { $score += 50; & $add 'A detected threat is explicitly allowed (mdatp threat allowed)' 'Eine erkannte Bedrohung wird ausdrücklich erlaubt (mdatp threat allowed)' }
    if ($Scope -eq 'Global') { $score += 20; & $add 'Global (AV+EDR): no EDR alerts and no visibility either' 'Global (AV+EDR): auch keine EDR-Alerts und keine Sichtbarkeit' }
    if ($Origin -eq 'Local') { $score += 20; & $add 'Set locally – not centrally managed' 'Lokal gesetzt – nicht zentral verwaltet' }
    if ($Origin -eq 'GPO') { $score += 5; & $add 'Set by Group Policy – outside Intune/MDE' 'Per Gruppenrichtlinie gesetzt – außerhalb von Intune/MDE' }

    $score = [Math]::Max(0, [Math]::Min(100, $score))
    [pscustomobject]@{ score = $score; level = (Get-GapsioRiskLevel $score); reasons = $reasons.ToArray() }
}

function Get-GapsioIndicatorRisk {
    param([Parameter(Mandatory)][string]$IndicatorType)
    switch ($IndicatorType) {
        'FileSha256' { $s = 15; $r = New-GapsioText 'SHA256 allow indicator (recommended, narrowly scoped)' 'SHA256-Allow-Indikator (empfohlene, eng begrenzte Variante)' }
        'FileSha1' { $s = 30; $r = New-GapsioText 'SHA1 allow indicator – prefer SHA256' 'SHA1-Allow-Indikator – SHA256 bevorzugen' }
        'FileMd5' { $s = 35; $r = New-GapsioText 'MD5 allow indicator – prefer SHA256' 'MD5-Allow-Indikator – SHA256 bevorzugen' }
        'CertificateThumbprint' { $s = 60; $r = New-GapsioText 'Certificate allowed – applies to every file signed with it' 'Zertifikat erlaubt – gilt für alle damit signierten Dateien' }
        'DomainName' { $s = 35; $r = New-GapsioText 'Domain allowed – overrides web protection and blocks' 'Domain erlaubt – überschreibt Web-Schutz und Blockierungen' }
        'Url' { $s = 30; $r = New-GapsioText 'URL allowed – overrides web protection and blocks' 'URL erlaubt – überschreibt Web-Schutz und Blockierungen' }
        'IpAddress' { $s = 35; $r = New-GapsioText 'IP address allowed – overrides network protection' 'IP-Adresse erlaubt – überschreibt Network Protection' }
        default { $s = 30; $r = New-GapsioText "Allow indicator ($IndicatorType)" "Allow-Indikator ($IndicatorType)" }
    }
    [pscustomobject]@{ score = $s; level = (Get-GapsioRiskLevel $s); reasons = @($r) }
}
#endregion

#region Snapshots & Drift
function Compare-GapsioCollection {
    <#
    .SYNOPSIS
    Compares two collections by 'key' and 'fp' (fingerprint) and returns the changes.
    Items with a presence lifecycle (boolean 'present', e.g. local exclusions that stay in the list for 90 days
    after removal) are reported in plain words: appearing or coming back = Added, disappearing from the device =
    Removed. Bookkeeping changes on an already removed entry and its final clean-up are not changes.
    #>
    param([string]$Module, [string]$Name, [object[]]$Old, [object[]]$New, [string]$At)
    $changes = [System.Collections.Generic.List[object]]::new()
    # Inline property access (no function or scriptblock calls per item): this runs over hundreds of thousands
    # of devices in large fleets. Items are PSCustomObjects (snapshots, JSON) or hashtables.
    $oldMap = [System.Collections.Generic.Dictionary[string, object]]::new()
    foreach ($o in $Old) {
        if ($null -eq $o) { continue }
        $k = if ($o -is [System.Collections.IDictionary]) { $o['key'] } else { $o.PSObject.Properties['key'].Value }
        if ($k) { $oldMap[[string]$k] = $o }
    }
    $newMap = [System.Collections.Generic.Dictionary[string, object]]::new()
    foreach ($n in $New) {
        if ($null -eq $n) { continue }
        $k = if ($n -is [System.Collections.IDictionary]) { $n['key'] } else { $n.PSObject.Properties['key'].Value }
        if ($k) { $newMap[[string]$k] = $n }
    }
    $mk = { param($k, $change, $src, $before, $after) [pscustomobject]@{ at = $At; module = $Module; collection = $Name; key = $k; change = $change; label = (Get-GapsioProp $src 'label'); before = $before; after = $after } }

    foreach ($k in $newMap.Keys) {
        $n = $newMap[$k]
        if ($n -is [System.Collections.IDictionary]) { $nfp = $n['fp']; $npRaw = $n['present'] }
        else { $ps = $n.PSObject.Properties; $nfp = $ps['fp'].Value; $npRaw = $ps['present'].Value }
        $np = $null; if ($null -ne $npRaw) { $np = [bool]$npRaw }
        if (-not $oldMap.ContainsKey($k)) {
            if ($np -eq $false) { continue }   # first seen already removed: history, not a change
            $changes.Add((& $mk $k 'Added' $n $null (Get-GapsioProp $n 'state')))
            continue
        }
        $o = $oldMap[$k]
        if ($o -is [System.Collections.IDictionary]) { $ofp = $o['fp']; $opRaw = $o['present'] }
        else { $ps = $o.PSObject.Properties; $ofp = $ps['fp'].Value; $opRaw = $ps['present'].Value }
        $op = $null; if ($null -ne $opRaw) { $op = [bool]$opRaw }
        if ($null -ne $np -and $null -ne $op) {
            if ($op -and -not $np) { $changes.Add((& $mk $k 'Removed' $n (Get-GapsioProp $o 'state') $null)) }
            elseif (-not $op -and $np) { $changes.Add((& $mk $k 'Added' $n $null (Get-GapsioProp $n 'state'))) }
            continue
        }
        if ([string]$ofp -ne [string]$nfp) {
            $changes.Add((& $mk $k 'Changed' $n (Get-GapsioProp $o 'state') (Get-GapsioProp $n 'state')))
        }
    }
    foreach ($k in $oldMap.Keys) {
        if (-not $newMap.ContainsKey($k)) {
            $o = $oldMap[$k]
            $opRaw = Get-GapsioProp $o 'present'
            if ($null -ne $opRaw -and -not [bool]$opRaw) { continue }   # clean-up of an entry that was already reported as removed
            $changes.Add((& $mk $k 'Removed' $o (Get-GapsioProp $o 'state') $null))
        }
    }
    $changes.ToArray()
}

function Get-GapsioDriftCounts {
    # Added / changed / removed per run.
    param([object[]]$Changes)
    $c = [ordered]@{ Added = 0; Changed = 0; Removed = 0 }
    foreach ($x in @($Changes)) { if ($x -and $c.Contains([string]$x.change)) { $c[[string]$x.change]++ } }
    $c
}

function Get-GapsioOpenFindingCounts {
    # Findings per severity that are not accepted at the time of the run.
    param([object[]]$Findings)
    $c = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    if (-not @($Findings | Where-Object { $_ }).Count) { return $c }
    $accepted = @{}
    foreach ($a in @(Get-GapsioAcceptances)) { if (Test-GapsioAcceptanceActive -Acceptance $a) { $accepted[[string]$a.key] = $true } }
    foreach ($f in @($Findings)) {
        if (-not $f) { continue }
        $sev = [string](Get-GapsioProp $f 'severity')
        if ($c.Contains($sev) -and -not $accepted[[string](Get-GapsioProp $f 'key')]) { $c[$sev]++ }
    }
    $c
}

function Get-GapsioProtectionCounts {
    # Devices per protection feature: on (GOOD) / off (BAD). Unknown is the rest of the device count.
    param([object[]]$Devices)
    $list = @($Devices | Where-Object { $_ })
    if (-not $list.Count) { return $null }
    $c = [ordered]@{ devices = $list.Count }
    foreach ($d in $list) {
        $checks = Get-GapsioProp $d 'checks'
        if (-not $checks) { continue }
        $pairs = if ($checks -is [System.Collections.IDictionary]) { $checks.GetEnumerator() } else { $checks.PSObject.Properties }
        foreach ($p in $pairs) {
            $k = [string]$p.Name; if (-not $k) { $k = [string]$p.Key }
            if (-not $c.Contains($k)) { $c[$k] = [ordered]@{ on = 0; off = 0 } }
            if ($p.Value -eq 'GOOD') { $c[$k].on++ } elseif ($p.Value -eq 'BAD') { $c[$k].off++ }
        }
    }
    $c
}

function Save-GapsioSnapshot {
    <#
    .SYNOPSIS
    Stores a snapshot (dated, optionally immutable), updates "latest", calculates drift against the
    previous run and maintains the run history.
    #>
    param(
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Snapshot,
        [Parameter(Mandatory)][string[]]$Collections,
        [datetime]$Started,
        [string[]]$Paged = @(),
        [hashtable]$Index = @{}
    )
    $now = [DateTime]::UtcNow
    $at = $now.ToString('o')
    $prev = Get-GapsioBlob -Container 'state' -Name "$Module-latest.json"

    $changes = [System.Collections.Generic.List[object]]::new()
    if ($prev) {
        foreach ($c in $Collections) {
            $old = if ($c -in $Paged) { $fpOld = Get-GapsioBlob -Container 'state' -Name "$Module-$c-fp.json"; if ($null -ne $fpOld) { @($fpOld) } else { @(Get-GapsioProp $prev $c) } } else { @(Get-GapsioProp $prev $c) }
            foreach ($x in (Compare-GapsioCollection -Module $Module -Name $c -Old $old -New @($Snapshot[$c]) -At $at)) { $changes.Add($x) }
        }
    }
    $Snapshot['changesSincePrevious'] = $changes.Count
    $Snapshot['isFirstRun'] = ($null -eq $prev)
    if ($prev) {
        $sent = Send-GapsioNotification -Module $Module -Changes $changes.ToArray() -Snapshot $Snapshot
        if ($sent) { $Snapshot['notified'] = $sent }
        $Snapshot['warnings'] = @(Get-GapsioWarnings)
    }
    $protection = Get-GapsioProtectionCounts -Devices @($Snapshot['devices'])

    # Large per-device collections go to pages; the snapshot keeps only their meta data
    foreach ($c in $Paged) {
        if (-not $Snapshot.Contains($c)) { continue }
        $Snapshot["${c}Pages"] = Write-GapsioPagedCollection -Module $Module -Name $c -Items @($Snapshot[$c]) -IndexColumns @($Index[$c]) -At $at
        $Snapshot.Remove($c)
    }

    $snapName = "$Module/$($now.ToString('yyyy/MM/dd/HHmmssfff')).json"
    Set-GapsioBlob -Container 'snapshots' -Name $snapName -Object $Snapshot
    Set-GapsioBlob -Container 'state' -Name "$Module-latest.json" -Object $Snapshot

    # Change history (rolling)
    $retDays = [int](Get-GapsioSetting -Name 'GAPSIO_CHANGE_RETENTION_DAYS' -Default '365')
    $cutoff = $now.AddDays(-$retDays)
    $hist = @(Get-GapsioBlob -Container 'state' -Name "$Module-changes.json")
    $merged = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $changes) { $merged.Add($c) }
    foreach ($h in $hist) {
        if ($null -eq $h) { continue }
        $hAt = $null
        try { $hAt = ConvertTo-GapsioUtc (Get-GapsioProp $h 'at') } catch { }
        if ($hAt -and $hAt -ge $cutoff) { $merged.Add($h) }
    }
    $maxEntries = 25000
    $out = if ($merged.Count -gt $maxEntries) { $merged.GetRange(0, $maxEntries).ToArray() } else { $merged.ToArray() }
    Set-GapsioBlob -Container 'state' -Name "$Module-changes.json" -Object @($out)

    # Run index – with the numbers the portal charts over time (open findings, drift, protection per feature)
    $runs = [System.Collections.Generic.List[object]]::new()
    $runs.Add([pscustomobject]@{
            module      = $Module
            at          = $at
            durationSec = if ($Started) { [int]($now - $Started).TotalSeconds } else { $null }
            changes     = $changes.Count
            drift       = Get-GapsioDriftCounts -Changes $changes.ToArray()
            findings    = Get-GapsioOpenFindingCounts -Findings @($Snapshot['findings'])
            protection  = $protection
            warnings    = @($Snapshot['warnings']).Count
            snapshot    = $snapName
        })
    foreach ($r in @(Get-GapsioBlob -Container 'state' -Name 'runs.json')) { if ($null -ne $r -and $runs.Count -lt 500) { $runs.Add($r) } }
    Set-GapsioBlob -Container 'state' -Name 'runs.json' -Object @($runs.ToArray())

    [pscustomobject]@{ module = $Module; at = $at; changes = $changes.Count; snapshot = $snapName; warnings = @($Snapshot['warnings']).Count }
}
#endregion

#region Accepted risks
function Get-GapsioAcceptances {
    <#
    .SYNOPSIS
    Accepted risks (state/acceptances.json): findings or exclusions an administrator consciously accepted with a
    justification, owner and expiry date. Expired acceptances count as not accepted again.
    #>
    $a = @()
    try { $a = @(Get-GapsioBlob -Container 'state' -Name 'acceptances.json' | Where-Object { $_ }) } catch { }
    $a
}

function Test-GapsioAcceptanceActive {
    param($Acceptance, [datetime]$Now = [DateTime]::UtcNow)
    if (-not $Acceptance -or (Get-GapsioProp $Acceptance 'revokedAt')) { return $false }
    $raw = Get-GapsioProp $Acceptance 'expires'
    if ($null -eq $raw -or [string]$raw -eq '') { return $true }   # no expiry date = unlimited exception
    try { $exp = ConvertTo-GapsioUtc $raw } catch { return $false }
    $exp.Date.AddDays(1) -gt $Now
}

function ConvertTo-GapsioAssignee {
    <#
    .SYNOPSIS
    Validates and normalises an assignee from the portal: an Entra user, a (security) group, a distribution list
    or a manually entered e-mail address. Returns $null when nothing was assigned.
    #>
    param($Data)
    if ($null -eq $Data) { return $null }
    if ($Data -is [string]) { $Data = [pscustomobject]@{ type = 'email'; mail = $Data } }
    $type = ([string](Get-GapsioProp $Data 'type')).Trim().ToLowerInvariant()
    $mail = ([string](Get-GapsioProp $Data 'mail')).Trim()
    $id = ([string](Get-GapsioProp $Data 'id')).Trim()
    $name = ([string](Get-GapsioProp $Data 'displayName')).Trim()
    if (-not $type -and -not $mail -and -not $id) { return $null }
    $types = @{ 'user' = 'user'; 'group' = 'group'; 'distributionlist' = 'distributionList'; 'email' = 'email' }
    if (-not $types.ContainsKey($type)) { throw [System.ArgumentException]::new('Assignee type must be user, group, distributionList or email.') }
    $type = $types[$type]
    if ($mail -and ($mail.Length -gt 320 -or $mail -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$')) { throw [System.ArgumentException]::new('The assignee e-mail address is not valid.') }
    if ($type -eq 'email') { if (-not $mail) { throw [System.ArgumentException]::new('An e-mail address is required.') }; $id = ''; if (-not $name) { $name = $mail } }
    else {
        if ($id -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw [System.ArgumentException]::new('A directory object id is required for a user or group assignee.') }
        if (-not $name) { throw [System.ArgumentException]::new('A display name is required for a user or group assignee.') }
    }
    if ($name.Length -gt 200) { $name = $name.Substring(0, 200) }
    [pscustomobject][ordered]@{ type = $type; id = $(if ($id) { $id } else { $null }); displayName = $name; mail = $(if ($mail) { $mail } else { $null }) }
}

function Set-GapsioAcceptance {
    <#
    .SYNOPSIS
    Accepts (or with -Revoke revokes) the risk of a finding or exclusion. Validates the input, keeps one entry per key
    and appends every action to the audit log (state/acceptances-log.json).
    #>
    param([Parameter(Mandatory)]$Data, [Parameter(Mandatory)][string]$By, [switch]$Revoke)
    $key = [string](Get-GapsioProp $Data 'key')
    if ($key -notmatch '^[a-f0-9]{8,64}$') { throw [System.ArgumentException]::new('Invalid key.') }
    $now = [DateTime]::UtcNow
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($x in Get-GapsioAcceptances) { if ($x.key -ne $key) { $list.Add($x) } else { $existing = $x } }
    if ($Revoke) {
        if (-not $existing) { throw [System.ArgumentException]::new('No acceptance for this key.') }
        $existing | Add-Member -NotePropertyName revokedAt -NotePropertyValue $now.ToString('o') -Force
        $existing | Add-Member -NotePropertyName revokedBy -NotePropertyValue $By -Force
        $list.Add($existing); $entry = $existing; $action = 'revoke'
    }
    else {
        $just = ([string](Get-GapsioProp $Data 'justification')).Trim()
        $owner = ([string](Get-GapsioProp $Data 'owner')).Trim()
        if ($just.Length -lt 10 -or $just.Length -gt 1000) { throw [System.ArgumentException]::new('A justification of 10–1000 characters is required.') }
        if (-not $owner -or $owner.Length -gt 200) { throw [System.ArgumentException]::new('An owner is required.') }
        $rawExp = Get-GapsioProp $Data 'expires'
        $expires = $null
        if ($null -ne $rawExp -and ([string]$rawExp).Trim() -ne '' -and ([string]$rawExp).Trim() -notin @('never', 'unlimited')) {
            try { $exp = (ConvertTo-GapsioUtc $rawExp).Date } catch { throw [System.ArgumentException]::new('A valid expiry date is required (or none for an unlimited exception).') }
            if ($exp -le $now.Date -or $exp -gt $now.Date.AddYears(10)) { throw [System.ArgumentException]::new('The expiry date must be in the future and at most ten years ahead.') }
            $expires = $exp.ToString('yyyy-MM-dd')
        }
        $assignee = ConvertTo-GapsioAssignee (Get-GapsioProp $Data 'assignee')
        $clip = { param($v, $n) $s = ([string]$v).Trim(); if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s } }
        $entry = [pscustomobject][ordered]@{
            key = $key; kind = (& $clip (Get-GapsioProp $Data 'kind') 30); module = (& $clip (Get-GapsioProp $Data 'module') 20)
            title = (& $clip (Get-GapsioProp $Data 'title') 300); justification = $just; owner = $owner; ticket = (& $clip (Get-GapsioProp $Data 'ticket') 100)
            expires = $expires; assignee = $assignee; acceptedBy = $By; acceptedAt = $now.ToString('o')
        }
        $list.Add($entry); $action = 'accept'
    }
    Set-GapsioBlob -Container 'state' -Name 'acceptances.json' -Object @($list.ToArray())
    Add-GapsioAcceptanceLog -Entry ([pscustomobject]@{ at = $now.ToString('o'); action = $action; by = $By; key = $key; title = $entry.title; justification = $entry.justification; owner = $entry.owner; ticket = $entry.ticket; expires = $entry.expires; assignee = (Get-GapsioProp $entry 'assignee') })
    $entry
}

function Add-GapsioAcceptanceLog {
    <# .SYNOPSIS Prepends one entry to the audit log (state/acceptances-log.json), capped at 5000 entries. #>
    param([Parameter(Mandatory)]$Entry)
    $log = [System.Collections.Generic.List[object]]::new()
    $log.Add($Entry)
    try { foreach ($l in @(Get-GapsioBlob -Container 'state' -Name 'acceptances-log.json')) { if ($l -and $log.Count -lt 5000) { $log.Add($l) } } } catch { }
    Set-GapsioBlob -Container 'state' -Name 'acceptances-log.json' -Object @($log.ToArray())
}

function Get-GapsioAssignments {
    <#
    .SYNOPSIS
    Assignments (state/assignments.json): who is working on a finding or exclusion – an Entra user, a group, a
    distribution list or a plain e-mail address. Independent of an exception: an item can be assigned and stay open.
    #>
    $a = @()
    try { $a = @(Get-GapsioBlob -Container 'state' -Name 'assignments.json' | Where-Object { $_ }) } catch { }
    $a
}

function Set-GapsioAssignment {
    <#
    .SYNOPSIS
    Assigns (or with -Clear unassigns) a finding or exclusion. One assignment per key; every action is written to
    the same audit log as the exceptions.
    #>
    param([Parameter(Mandatory)]$Data, [Parameter(Mandatory)][string]$By, [switch]$Clear)
    $key = [string](Get-GapsioProp $Data 'key')
    if ($key -notmatch '^[a-f0-9]{8,64}$') { throw [System.ArgumentException]::new('Invalid key.') }
    $now = [DateTime]::UtcNow
    $list = [System.Collections.Generic.List[object]]::new()
    $existing = $null
    foreach ($x in Get-GapsioAssignments) { if ($x.key -ne $key) { $list.Add($x) } else { $existing = $x } }
    $clip = { param($v, $n) $s = ([string]$v).Trim(); if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s } }
    if ($Clear) {
        if (-not $existing) { throw [System.ArgumentException]::new('No assignment for this key.') }
        $entry = $existing; $action = 'unassign'
    }
    else {
        $assignee = ConvertTo-GapsioAssignee (Get-GapsioProp $Data 'assignee')
        if (-not $assignee) { throw [System.ArgumentException]::new('An assignee is required.') }
        $entry = [pscustomobject][ordered]@{
            key = $key; kind = (& $clip (Get-GapsioProp $Data 'kind') 30); module = (& $clip (Get-GapsioProp $Data 'module') 20)
            title = (& $clip (Get-GapsioProp $Data 'title') 300); assignee = $assignee; note = (& $clip (Get-GapsioProp $Data 'note') 1000)
            assignedBy = $By; assignedAt = $now.ToString('o')
        }
        $list.Add($entry); $action = 'assign'
    }
    Set-GapsioBlob -Container 'state' -Name 'assignments.json' -Object @($list.ToArray())
    Add-GapsioAcceptanceLog -Entry ([pscustomobject]@{ at = $now.ToString('o'); action = $action; by = $By; key = $key; title = $entry.title; justification = $entry.note; assignee = $entry.assignee })
    $entry
}

function Search-GapsioDirectory {
    <#
    .SYNOPSIS
    People picker for assignments: users (User.ReadBasic.All), groups and distribution lists (GroupMember.Read.All)
    whose name, UPN or e-mail starts with the query. Returns up to 10 of each; a missing permission yields an empty
    list for that kind and a notice so the portal can fall back to a manual e-mail address.
    #>
    param([Parameter(Mandatory)][string]$Query)
    $q = $Query.Trim()
    if ($q.Length -lt 2 -or $q.Length -gt 100) { return [ordered]@{ results = @(); notices = @() } }
    $esc = $q.Replace("'", "''")
    $results = [System.Collections.Generic.List[object]]::new(); $notices = [System.Collections.Generic.List[string]]::new()
    try {
        $users = Invoke-GapsioGraph -Path "users?`$filter=startswith(displayName,'$esc') or startswith(userPrincipalName,'$esc') or startswith(mail,'$esc')&`$select=id,displayName,mail,userPrincipalName,accountEnabled&`$top=10"
        foreach ($u in @($users.value)) {
            if ($u.PSObject.Properties['accountEnabled'] -and $u.accountEnabled -eq $false) { continue }
            $results.Add([pscustomobject][ordered]@{ type = 'user'; id = [string]$u.id; displayName = [string]$u.displayName; mail = [string]($(if ($u.mail) { $u.mail } else { $u.userPrincipalName })) })
        }
    }
    catch { $notices.Add("Users: $(Get-GapsioErrorText -Exception $_.Exception -Context 'User.ReadBasic.All')") }
    try {
        $groups = Invoke-GapsioGraph -Path "groups?`$filter=startswith(displayName,'$esc') or startswith(mail,'$esc')&`$select=id,displayName,mail,mailEnabled,securityEnabled,groupTypes&`$top=10"
        foreach ($g in @($groups.value)) {
            $isDl = $g.mailEnabled -eq $true -and $g.securityEnabled -ne $true -and @($g.groupTypes) -notcontains 'Unified'
            $results.Add([pscustomobject][ordered]@{ type = $(if ($isDl) { 'distributionList' } else { 'group' }); id = [string]$g.id; displayName = [string]$g.displayName; mail = $(if ($g.mail) { [string]$g.mail } else { $null }) })
        }
    }
    catch { $notices.Add("Groups: $(Get-GapsioErrorText -Exception $_.Exception -Context 'GroupMember.Read.All')") }
    [ordered]@{ results = @($results | Sort-Object { $_.type -ne 'user' }, displayName); notices = @($notices) }
}
#endregion

#region Notifications
function Send-GapsioNotification {
    <#
    .SYNOPSIS
    Sends new findings of a run to a webhook (app setting GAPSIO_NOTIFY_WEBHOOK): a Teams workflow ("When a Teams webhook
    request is received"), a Power Automate flow (e.g. to send e-mail) or any endpoint that accepts JSON.
    Only findings that are new since the previous run, at least GAPSIO_NOTIFY_MIN_SEVERITY (default High) and not accepted.
    #>
    param([string]$Module, [object[]]$Changes, [System.Collections.IDictionary]$Snapshot)
    $url = Get-GapsioSetting -Name 'GAPSIO_NOTIFY_WEBHOOK'
    if (-not $url) { return $null }
    if ($url -notmatch '^https://') { Add-GapsioWarning 'GAPSIO_NOTIFY_WEBHOOK must be an https URL.'; return $null }
    $order = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
    $min = Get-GapsioSetting -Name 'GAPSIO_NOTIFY_MIN_SEVERITY' -Default 'High'
    $minRank = if ($order.ContainsKey($min)) { $order[$min] } else { 1 }
    $accepted = @{}; foreach ($a in Get-GapsioAcceptances) { if (Test-GapsioAcceptanceActive $a) { $accepted[[string]$a.key] = $true } }
    $byKey = @{}; foreach ($f in @($Snapshot['findings'])) { if ($f) { $byKey[[string]$f.key] = $f } }
    $new = @(foreach ($c in @($Changes)) {
            if ($c.collection -ne 'findings' -or $c.change -ne 'Added' -or $accepted.ContainsKey([string]$c.key)) { continue }
            $f = $byKey[[string]$c.key]
            if (-not $f -or -not $order.ContainsKey([string]$f.severity) -or $order[[string]$f.severity] -gt $minRank) { continue }
            $f
        }) | Sort-Object { $order[[string]$_.severity] }
    if (-not $new.Count) { return $null }
    $assigned = @{}; foreach ($a in Get-GapsioAssignments) { if ($a.assignee) { $assigned[[string]$a.key] = $a.assignee } }
    $who = { param($f) $a = $assigned[[string]$f.key]; if ($a) { if ($a.mail) { "$($a.displayName) <$($a.mail)>" } else { [string]$a.displayName } } else { $null } }
    $portal = if ($env:WEBSITE_HOSTNAME) { "https://$($env:WEBSITE_HOSTNAME)/#/findings" } else { $null }
    $lines = @($new | Select-Object -First 15 | ForEach-Object { "**$($_.severity)** · $(Get-GapsioProp $_.title 'en')$(if ($_.deviceName) { " · $($_.deviceName)" })$(if ($w = & $who $_) { " · → $w" })" })
    if ($new.Count -gt 15) { $lines += "… and $($new.Count - 15) more" }
    $title = "Gapsio: $($new.Count) new finding(s) ($Module)"
    $body = @(@{ type = 'TextBlock'; text = $title; weight = 'Bolder'; size = 'Medium'; wrap = $true }) + @($lines | ForEach-Object { @{ type = 'TextBlock'; text = $_; wrap = $true; spacing = 'Small' } })
    $card = @{ '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'; type = 'AdaptiveCard'; version = '1.4'; body = $body }
    if ($portal) { $card.actions = @(@{ type = 'Action.OpenUrl'; title = 'Open Gapsio'; url = $portal }) }
    $payload = [ordered]@{
        type = 'message'; attachments = @(@{ contentType = 'application/vnd.microsoft.card.adaptive'; content = $card })
        # Plain fields for Power Automate or other receivers
        gapsio = [ordered]@{ module = $Module; title = $title; portal = $portal; findings = @($new | ForEach-Object { [ordered]@{ severity = $_.severity; category = $_.category; title = (Get-GapsioProp $_.title 'en'); device = $_.deviceName; key = $_.key; assignee = $assigned[[string]$_.key] } }) }
    }
    try {
        Invoke-RestMethod -Method Post -Uri $url -ContentType 'application/json; charset=utf-8' -Body (ConvertTo-Json -InputObject $payload -Depth 12 -Compress) -TimeoutSec 20 | Out-Null
        $new.Count
    }
    catch { Add-GapsioWarning "Notification webhook failed: $($_.Exception.Message)"; $null }
}
#endregion

#region Auth (App Service Authentication / Easy Auth)
$script:GapsioRoleCache = @{}
function Get-GapsioAssignedAppRoles {
    <#
    .SYNOPSIS
    App role values a user holds on the portal app, read from Entra (direct assignment or via a group).
    Fallback for sign-ins whose header carries no roles claim. Cached for 5 minutes per user. Needs Directory.Read.All.
    #>
    param([Parameter(Mandatory)][string]$UserId, [string]$PortalAppId)
    if (-not $PortalAppId) { $PortalAppId = $env:WEBSITE_AUTH_CLIENT_ID }
    if ($UserId -notmatch '^[0-9a-fA-F-]{36}$' -or $PortalAppId -notmatch '^[0-9a-fA-F-]{36}$') { return @() }

    $hit = $script:GapsioRoleCache[$UserId]
    if ($hit -and $hit.At -gt [DateTime]::UtcNow.AddMinutes(-5)) { return $hit.Roles }

    $roles = @()
    try {
        $sp = @(Invoke-GapsioGraph -Path "servicePrincipals?`$filter=appId eq '$PortalAppId'&`$select=id,appRoles").value | Select-Object -First 1
        if ($sp) {
            # Groups (transitive) plus the user itself: an assignment to any of them grants the role.
            $principals = @($UserId) + @(Invoke-GapsioGraph -Path "users/$UserId/transitiveMemberOf/microsoft.graph.group?`$select=id" -All | ForEach-Object { $_.id })
            $assigned = @(Invoke-GapsioGraph -Path "servicePrincipals/$($sp.id)/appRoleAssignedTo?`$select=principalId,appRoleId" -All |
                    Where-Object { $_.principalId -in $principals } | ForEach-Object { $_.appRoleId })
            $roles = @($sp.appRoles | Where-Object { $_.isEnabled -and [string]$_.id -in @($assigned | ForEach-Object { [string]$_ }) } | ForEach-Object { [string]$_.value })
            Write-Information "Gapsio sign-in: Entra lookup found $($assigned.Count) assignment(s) for $UserId on the portal app."
        }
        else { Write-Warning "Gapsio sign-in: portal service principal $PortalAppId not found." }
    }
    catch { Write-Warning "Gapsio sign-in: could not read app role assignments from Entra: $($_.Exception.Message)" }

    $script:GapsioRoleCache[$UserId] = @{ At = [DateTime]::UtcNow; Roles = $roles }
    $roles
}

function Get-GapsioPrincipal {
    <#
    .SYNOPSIS
    Reads the signed-in user from X-MS-CLIENT-PRINCIPAL. The header is only trusted when App Service
    Authentication is really enabled (otherwise it could be forged).
    #>
    param($Request)
    if ($env:WEBSITE_AUTH_ENABLED -ne 'True') {
        return [pscustomobject]@{ ok = $false; status = 503; message = 'Sign-in is not configured yet. Run setup/Install-Gapsio.ps1.' }
    }
    $headers = $Request.Headers
    $raw = $null
    foreach ($k in @($headers.Keys)) { if ($k -ieq 'x-ms-client-principal') { $raw = $headers[$k] } }
    if (-not $raw) { return [pscustomobject]@{ ok = $false; status = 401; message = 'Not signed in.' } }

    try { $p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$raw)) | ConvertFrom-Json }
    catch { return [pscustomobject]@{ ok = $false; status = 401; message = 'Invalid principal header.' } }

    $claims = @($p.claims)
    $first = {
        param([string[]]$Types)
        foreach ($t in $Types) { $c = $claims | Where-Object { $_.typ -eq $t } | Select-Object -First 1; if ($c) { return [string]$c.val } }
        $null
    }
    $roleTypes = @('roles', 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role')
    if ($p.PSObject.Properties['role_typ'] -and $p.role_typ) { $roleTypes += [string]$p.role_typ }
    # A roles claim can arrive as one claim per role, as a JSON array string or as an array value.
    $roles = @($claims | Where-Object { $_.typ -in $roleTypes } | ForEach-Object {
            foreach ($v in @($_.val)) {
                $s = ([string]$v).Trim()
                if ($s.StartsWith('[')) { try { @($s | ConvertFrom-Json) | ForEach-Object { ([string]$_).Trim() } } catch { $s } } else { $s }
            }
        } | Where-Object { $_ })
    $oid = & $first @('http://schemas.microsoft.com/identity/claims/objectidentifier', 'oid')

    # Fallback: if the sign-in header carries no admin role, ask Entra directly (direct and group assignments).
    if ($roles -notcontains 'Gapsio.Admin' -and $oid) {
        $aud = & $first @('aud')
        $fromEntra = @(Get-GapsioAssignedAppRoles -UserId $oid -PortalAppId $aud)
        Write-Information "Gapsio sign-in: header roles [$($roles -join ', ')], Entra roles [$($fromEntra -join ', ')] for $oid (app $aud)."
        $roles = @(@($roles) + $fromEntra | Select-Object -Unique)
    }

    [pscustomobject]@{
        ok          = $true
        status      = 200
        oid         = $oid
        tid         = & $first @('http://schemas.microsoft.com/identity/claims/tenantid', 'tid')
        upn         = & $first @('preferred_username', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn', 'upn', 'email')
        displayName = & $first @('name', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name')
        roles       = $roles
        isAdmin     = ($roles -contains 'Gapsio.Admin')
    }
}
#endregion

#region Baseline
function Get-GapsioBaseline {
    <#
    .SYNOPSIS
    Loads the MDAV baseline: the customer's own version from storage (config/mdav-baseline.json), otherwise the shipped one.
    #>
    $custom = $null
    try { $custom = Get-GapsioBlob -Container 'config' -Name 'mdav-baseline.json' } catch { Add-GapsioWarning "Custom baseline could not be read: $($_.Exception.Message)" }
    if ($custom) { $custom | Add-Member -NotePropertyName source -NotePropertyValue 'custom' -Force; return $custom }
    $appRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $path = Join-Path $appRoot 'config/mdav-baseline.json'
    $b = Get-Content -Raw -Path $path | ConvertFrom-Json -Depth 32
    $b | Add-Member -NotePropertyName source -NotePropertyValue 'default' -Force
    $b
}

function ConvertTo-GapsioComparable {
    # Settings Catalog values: "..._cloudblocklevel_2" -> 2, "..._audit" -> 'audit', "50" -> 50
    param([AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { return $null }
    $n = 0L
    if ([long]::TryParse($Value, [ref]$n)) { return $n }
    if ($Value -match '_(\d+)$') { return [long]$Matches[1] }
    if ($Value -match '_([a-z]+)$') { return $Matches[1].ToLowerInvariant() }
    $Value.ToLowerInvariant()
}

function Test-GapsioBaselineValue {
    # -Display: display name of the selected option (Settings Catalog), e.g. "real_time" or "admin_only".
    param([AllowEmptyString()][string]$Value, $Expect, [string]$Display)
    $c = ConvertTo-GapsioComparable $Value
    $op = [string](Get-GapsioProp $Expect 'op')
    switch ($op) {
        'display' { return ("$Display $Value").ToLowerInvariant() -match [string](Get-GapsioProp $Expect 'pattern') }
        'eq' { return ([string]$c -eq [string](Get-GapsioProp $Expect 'value')) }
        'ne' { return ([string]$c -ne [string](Get-GapsioProp $Expect 'value')) }
        'in' { return (@(Get-GapsioProp $Expect 'values') | ForEach-Object { [string]$_ }) -contains [string]$c }
        'gte' { return ($c -is [long]) -and $c -ge [long](Get-GapsioProp $Expect 'value') }
        'lte' { return ($c -is [long]) -and $c -le [long](Get-GapsioProp $Expect 'value') }
        'range' { return ($c -is [long]) -and $c -ge [long](Get-GapsioProp $Expect 'min') -and $c -le [long](Get-GapsioProp $Expect 'max') }
        'match' { return ([string]$Value).ToLowerInvariant() -match [string](Get-GapsioProp $Expect 'pattern') }
        'notmatch' { return ("$Display $Value").ToLowerInvariant() -notmatch [string](Get-GapsioProp $Expect 'pattern') }
        default { return $false }
    }
}
#endregion
