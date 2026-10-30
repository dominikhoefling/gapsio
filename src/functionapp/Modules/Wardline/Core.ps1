# Wardline core: configuration, tokens, REST/Graph/Hunting, storage, snapshots, auth.

$script:WlTokens = @{}
$script:WlWarnings = [System.Collections.Generic.List[string]]::new()
$script:WlStorageVersion = '2023-11-03'
# Single source of the version: ModuleVersion in Wardline.psd1 (the release workflow checks it against the git tag).
$script:WlVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'Wardline.psd1')).ModuleVersion.ToString()
# GitHub repository that publishes Wardline releases (update check). Override with the app setting WL_UPDATE_REPOSITORY.
$script:WlDefaultRepository = 'OWNER/wardline'

#region Configuration & warnings
function Get-WlSetting {
    param([Parameter(Mandatory)][string]$Name, [string]$Default)
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    $v
}

function Get-WlModules {
    <#
    .SYNOPSIS
    Enabled modules from the app setting WL_MODULES (comma-separated). Default: endpoint,agents.
    The 'access' module (PIM/roles) is included but disabled by default.
    #>
    $raw = Get-WlSetting -Name 'WL_MODULES' -Default 'endpoint,agents'
    @($raw -split '[,; ]+' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -in 'endpoint', 'agents', 'access' } | Select-Object -Unique)
}

function Test-WlFeature {
    <#
    .SYNOPSIS
    Endpoint sub-features from the app setting WL_FEATURES (comma-separated): hunting, indicators, inventory.
    A feature that is not selected was not granted a permission, so its data source is skipped quietly.
    Default (setting missing, e.g. older installations): hunting and indicators.
    #>
    param([Parameter(Mandatory)][string]$Name)
    $raw = Get-WlSetting -Name 'WL_FEATURES' -Default 'hunting,indicators'
    $set = @($raw -split '[,; ]+' | ForEach-Object { $_.Trim().ToLowerInvariant() })
    if ($Name -ieq 'inventory') { return ($set -contains 'inventory') -or ((Get-WlSetting -Name 'WL_DEVICE_INVENTORY' -Default 'false') -eq 'true') }
    $set -contains $Name.ToLowerInvariant()
}

function Get-WlVersion { $script:WlVersion }

function Compare-WlVersion {
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

function Update-WlReleaseInfo {
    <#
    .SYNOPSIS
    Checks once a day whether a newer Wardline release exists and stores the result in state/release.json (shown in the portal).
    The check is an anonymous GET to the GitHub releases API – no tenant data is sent. Disable with WL_UPDATE_CHECK=false.
    Wardline never updates itself; customers update with setup/Update-Wardline.ps1.
    #>
    param([switch]$Force)
    if ((Get-WlSetting -Name 'WL_UPDATE_CHECK' -Default 'true') -eq 'false') { return $null }
    $repo = Get-WlSetting -Name 'WL_UPDATE_REPOSITORY' -Default $script:WlDefaultRepository
    if ($repo -notmatch '^[\w.-]+/[\w.-]+$' -or $repo -like 'OWNER/*') { return $null }
    $cur = $null
    try { $cur = Get-WlBlob -Container 'state' -Name 'release.json' } catch { }
    if (-not $Force -and $cur -and $cur.checkedAt -and $cur.current -eq $script:WlVersion -and ([DateTime]$cur.checkedAt).ToUniversalTime() -gt [DateTime]::UtcNow.AddHours(-20)) { return $cur }
    try {
        $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -TimeoutSec 15 -Headers @{ 'User-Agent' = "Wardline/$script:WlVersion"; Accept = 'application/vnd.github+json' }
        $latest = ([string]$r.tag_name) -replace '^v', ''
        $info = [ordered]@{
            current = $script:WlVersion; latest = $latest; available = ((Compare-WlVersion $latest $script:WlVersion) -gt 0)
            url = [string]$r.html_url; publishedAt = [string]$r.published_at; checkedAt = [DateTime]::UtcNow.ToString('o'); repository = $repo
        }
        Set-WlBlob -Container 'state' -Name 'release.json' -Object $info
        [pscustomobject]$info
    }
    catch { Write-Warning "Update check failed: $($_.Exception.Message)"; $cur }
}

function Test-WlModuleEnabled {
    param([Parameter(Mandatory)][string]$Name)
    (Get-WlModules) -contains $Name.ToLowerInvariant()
}

function Reset-WlWarnings { $script:WlWarnings.Clear() }

function Add-WlWarning {
    param([Parameter(Mandatory)][string]$Message)
    $script:WlWarnings.Add($Message)
    Write-Warning $Message
}

function Get-WlWarnings { $script:WlWarnings.ToArray() }
#endregion

#region Tokens & REST
function Get-WlToken {
    <#
    .SYNOPSIS
    Gets a token of the (user-assigned) managed identity for a resource. No secret, no certificate.
    #>
    param([Parameter(Mandatory)][string]$Resource)
    $cached = $script:WlTokens[$Resource]
    if ($cached -and $cached.ExpiresOn -gt [DateTime]::UtcNow.AddMinutes(5)) { return $cached.Token }

    # Optional: a pre-created data-access app registration (WL_DATA_APP_ID). The managed identity signs in to it via
    # workload identity federation (no secret). Storage always uses the managed identity directly.
    $dataApp = Get-WlSetting -Name 'WL_DATA_APP_ID'
    if ($dataApp -and $Resource -notmatch 'storage\.azure\.com|AzureADTokenExchange') {
        $assertion = Get-WlToken -Resource 'api://AzureADTokenExchange'
        $loginHost = Get-WlSetting -Name 'WL_LOGIN_HOST' -Default 'login.microsoftonline.com'
        $tenant = Get-WlSetting -Name 'WL_TENANT_ID'
        $r = Invoke-RestMethod -Method Post -Uri "https://$loginHost/$tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
            client_id             = $dataApp
            scope                 = "$($Resource.TrimEnd('/'))/.default"
            grant_type            = 'client_credentials'
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $assertion
        }
        $script:WlTokens[$Resource] = @{ Token = $r.access_token; ExpiresOn = [DateTime]::UtcNow.AddSeconds([int]$r.expires_in) }
        return $r.access_token
    }

    $endpoint = $env:IDENTITY_ENDPOINT
    if (-not $endpoint) { throw 'Managed identity not available (IDENTITY_ENDPOINT missing). Is the code running in the Function App?' }
    $uri = "$endpoint`?resource=$([uri]::EscapeDataString($Resource))&api-version=2019-08-01"
    $clientId = Get-WlSetting -Name 'WL_CLIENT_ID'
    if ($clientId) { $uri += "&client_id=$clientId" }

    $r = Invoke-RestMethod -Uri $uri -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER } -Method Get
    $expires = [DateTimeOffset]::FromUnixTimeSeconds([long]$r.expires_on).UtcDateTime
    $script:WlTokens[$Resource] = @{ Token = $r.access_token; ExpiresOn = $expires }
    $r.access_token
}

function New-WlHttpException {
    param([int]$Status, [string]$Message)
    $e = [System.Exception]::new($Message)
    $e.Data['Status'] = $Status
    $e
}

function Invoke-WlRest {
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
        $h = @{ Authorization = "Bearer $(Get-WlToken -Resource $Resource)" }
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
        throw (New-WlHttpException -Status $status -Message "HTTP $status for $Method $Uri :: $detail")
    }
}

function Invoke-WlGraph {
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
        return Invoke-WlRest -Uri $uri -Method $Method -Body $Body -Resource 'https://graph.microsoft.com' -Headers $Headers
    }
    $items = [System.Collections.Generic.List[object]]::new()
    while ($uri) {
        $r = Invoke-WlRest -Uri $uri -Resource 'https://graph.microsoft.com' -Headers $Headers
        if ($r.PSObject.Properties['value']) { foreach ($i in @($r.value)) { if ($null -ne $i) { $items.Add($i) } } }
        $uri = if ($r.PSObject.Properties['@odata.nextLink']) { $r.'@odata.nextLink' } else { $null }
    }
    $items.ToArray()
}

function Invoke-WlGraphSafe {
    <#
    .SYNOPSIS
    Like Invoke-WlGraph, but logs errors as a warning and returns $null, so a missing permission or
    licence does not abort the whole run.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Beta,
        [switch]$All,
        [Parameter(Mandatory)][string]$Context,
        [hashtable]$Headers = @{}
    )
    try { Invoke-WlGraph -Path $Path -Beta:$Beta -All:$All -Headers $Headers }
    catch { Add-WlWarning "${Context}: $($_.Exception.Message)"; $null }
}

function Invoke-WlHunting {
    <#
    .SYNOPSIS
    Advanced Hunting via Microsoft Graph (security/runHuntingQuery, v1.0).
    #>
    param([Parameter(Mandatory)][string]$Query, [string]$Timespan = 'P30D')
    $body = @{ Query = $Query }
    if ($Timespan) { $body.Timespan = $Timespan }
    $r = Invoke-WlRest -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Method POST -Body $body -Resource 'https://graph.microsoft.com'
    @($r.results)
}

function Invoke-WlHuntingSafe {
    # Skipped quietly when the Hunting feature (ThreatHunting.Read.All) is not selected.
    param([Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][string]$Context, [string]$Timespan = 'P30D')
    if (-not (Test-WlFeature -Name 'hunting')) { return $null }
    try { Invoke-WlHunting -Query $Query -Timespan $Timespan }
    catch { Add-WlWarning "${Context}: $($_.Exception.Message)"; $null }
}
#endregion

#region Storage (Entra auth only, no shared key)
function Get-WlStorageAccount {
    $acct = Get-WlSetting -Name 'WL_STORAGE_ACCOUNT'
    if (-not $acct) { throw 'App setting WL_STORAGE_ACCOUNT is missing.' }
    $acct
}

function Get-WlBlobUri {
    param([string]$Container, [string]$Name)
    $suffix = Get-WlSetting -Name 'WL_STORAGE_SUFFIX' -Default 'core.windows.net'
    "https://$(Get-WlStorageAccount).blob.$suffix/$Container/$Name"
}

function Get-WlBlobText {
    param([Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Name)
    try {
        Invoke-WlRest -Uri (Get-WlBlobUri $Container $Name) -Resource 'https://storage.azure.com/' -Headers @{ 'x-ms-version' = $script:WlStorageVersion } -Raw
    }
    catch {
        if ($_.Exception.Data['Status'] -eq 404) { return $null }
        throw
    }
}

function Get-WlBlob {
    param([Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Name)
    $text = Get-WlBlobText -Container $Container -Name $Name
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text | ConvertFrom-Json -Depth 64
}

function Set-WlBlob {
    param(
        [Parameter(Mandatory)][string]$Container,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Object,
        [int]$Depth = 32
    )
    $json = if ($Object -is [string]) { $Object } else { ConvertTo-Json -InputObject $Object -Depth $Depth -Compress }
    $headers = @{ 'x-ms-version' = $script:WlStorageVersion; 'x-ms-blob-type' = 'BlockBlob'; 'x-ms-blob-content-type' = 'application/json; charset=utf-8' }
    Invoke-WlRest -Uri (Get-WlBlobUri $Container $Name) -Method PUT -Body $json -Resource 'https://storage.azure.com/' -Headers $headers | Out-Null
}

function Add-WlQueueMessage {
    param([string]$Queue = 'wl-run', [Parameter(Mandatory)][string]$Text)
    $suffix = Get-WlSetting -Name 'WL_STORAGE_SUFFIX' -Default 'core.windows.net'
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text))
    $xml = "<QueueMessage><MessageText>$b64</MessageText></QueueMessage>"
    Invoke-WlRest -Uri "https://$(Get-WlStorageAccount).queue.$suffix/$Queue/messages" -Method POST -Body $xml -Resource 'https://storage.azure.com/' -Headers @{ 'x-ms-version' = $script:WlStorageVersion } -ContentType 'application/xml' | Out-Null
}
#endregion

#region Helpers
function Get-WlHash {
    param([AllowEmptyString()][string]$Text)
    $bytes = [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(([string]$Text).ToLowerInvariant()))
    ([Convert]::ToHexString($bytes)).Substring(0, 24).ToLowerInvariant()
}

function ConvertTo-WlUtc {
    # Timestamps without a time zone are UTC (that is how Advanced Hunting returns them).
    param($Value)
    if ($Value -is [datetime]) { return $(if ($Value.Kind -eq 'Unspecified') { [datetime]::SpecifyKind($Value, 'Utc') } else { $Value.ToUniversalTime() }) }
    [DateTimeOffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
}

function Get-WlProp {
    # Reads a property null-safely (also when the property does not exist).
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

function Expand-WlSettingInstance {
    param($Instance, [System.Collections.Generic.List[object]]$Out, [string]$GroupKey)
    if ($null -eq $Instance) { return }
    $def = [string](Get-WlProp $Instance 'settingDefinitionId')
    $type = [string](Get-WlProp $Instance '@odata.type')
    switch -Wildcard ($type) {
        '*simpleSettingInstance' {
            $v = Get-WlProp (Get-WlProp $Instance 'simpleSettingValue') 'value'
            $Out.Add([pscustomobject]@{ definitionId = $def; value = [string]$v; kind = 'simple'; group = $GroupKey })
        }
        '*simpleSettingCollectionInstance' {
            foreach ($v in @(Get-WlProp $Instance 'simpleSettingCollectionValue')) {
                if ($null -eq $v) { continue }
                $Out.Add([pscustomobject]@{ definitionId = $def; value = [string](Get-WlProp $v 'value'); kind = 'simple'; group = $GroupKey })
            }
        }
        '*choiceSettingInstance' {
            $c = Get-WlProp $Instance 'choiceSettingValue'
            $Out.Add([pscustomobject]@{ definitionId = $def; value = [string](Get-WlProp $c 'value'); kind = 'choice'; group = $GroupKey })
            foreach ($ch in @(Get-WlProp $c 'children')) { Expand-WlSettingInstance -Instance $ch -Out $Out -GroupKey $GroupKey }
        }
        '*choiceSettingCollectionInstance' {
            foreach ($c in @(Get-WlProp $Instance 'choiceSettingCollectionValue')) {
                if ($null -eq $c) { continue }
                $Out.Add([pscustomobject]@{ definitionId = $def; value = [string](Get-WlProp $c 'value'); kind = 'choice'; group = $GroupKey })
                foreach ($ch in @(Get-WlProp $c 'children')) { Expand-WlSettingInstance -Instance $ch -Out $Out -GroupKey $GroupKey }
            }
        }
        '*groupSettingCollectionInstance' {
            $i = 0
            foreach ($g in @(Get-WlProp $Instance 'groupSettingCollectionValue')) {
                if ($null -eq $g) { continue }
                $i++
                $gk = "$def#$i"
                foreach ($ch in @(Get-WlProp $g 'children')) { Expand-WlSettingInstance -Instance $ch -Out $Out -GroupKey $gk }
            }
        }
        '*groupSettingInstance' {
            foreach ($ch in @(Get-WlProp (Get-WlProp $Instance 'groupSettingValue') 'children')) { Expand-WlSettingInstance -Instance $ch -Out $Out -GroupKey "$def#1" }
        }
    }
}

function Get-WlSettingValues {
    <#
    .SYNOPSIS
    Flattens a Settings Catalog settingInstance into values (definitionId, value, kind, group).
    #>
    param($Instance)
    $out = [System.Collections.Generic.List[object]]::new()
    Expand-WlSettingInstance -Instance $Instance -Out $out -GroupKey ''
    $out.ToArray()
}

function New-WlText {
    <#
    .SYNOPSIS
    Bilingual text for the portal (English/German). The portal shows the language the user selected.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$En, [AllowEmptyString()][string]$De)
    [ordered]@{ en = $En; de = $(if ($De) { $De } else { $En }) }
}

function ConvertTo-WlText {
    # Accepts a plain string (custom baselines) or an object with en/de and always returns {en, de}.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return (New-WlText -En $Value -De $Value) }
    $en = [string](Get-WlProp $Value 'en'); $de = [string](Get-WlProp $Value 'de')
    New-WlText -En $(if ($en) { $en } else { $de }) -De $de
}

function Get-WlRiskLevel {
    param([int]$Score)
    if ($Score -ge 80) { return 'Critical' }
    if ($Score -ge 50) { return 'High' }
    if ($Score -ge 25) { return 'Medium' }
    'Low'
}

function Get-WlExclusionRisk {
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
    $add = { param($en, $de) $reasons.Add((New-WlText -En $en -De $de)) }
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
    [pscustomobject]@{ score = $score; level = (Get-WlRiskLevel $score); reasons = $reasons.ToArray() }
}

function Get-WlIndicatorRisk {
    param([Parameter(Mandatory)][string]$IndicatorType)
    switch ($IndicatorType) {
        'FileSha256' { $s = 15; $r = New-WlText 'SHA256 allow indicator (recommended, narrowly scoped)' 'SHA256-Allow-Indikator (empfohlene, eng begrenzte Variante)' }
        'FileSha1' { $s = 30; $r = New-WlText 'SHA1 allow indicator – prefer SHA256' 'SHA1-Allow-Indikator – SHA256 bevorzugen' }
        'FileMd5' { $s = 35; $r = New-WlText 'MD5 allow indicator – prefer SHA256' 'MD5-Allow-Indikator – SHA256 bevorzugen' }
        'CertificateThumbprint' { $s = 60; $r = New-WlText 'Certificate allowed – applies to every file signed with it' 'Zertifikat erlaubt – gilt für alle damit signierten Dateien' }
        'DomainName' { $s = 35; $r = New-WlText 'Domain allowed – overrides web protection and blocks' 'Domain erlaubt – überschreibt Web-Schutz und Blockierungen' }
        'Url' { $s = 30; $r = New-WlText 'URL allowed – overrides web protection and blocks' 'URL erlaubt – überschreibt Web-Schutz und Blockierungen' }
        'IpAddress' { $s = 35; $r = New-WlText 'IP address allowed – overrides network protection' 'IP-Adresse erlaubt – überschreibt Network Protection' }
        default { $s = 30; $r = New-WlText "Allow indicator ($IndicatorType)" "Allow-Indikator ($IndicatorType)" }
    }
    [pscustomobject]@{ score = $s; level = (Get-WlRiskLevel $s); reasons = @($r) }
}
#endregion

#region Snapshots & Drift
function Compare-WlCollection {
    <#
    .SYNOPSIS
    Compares two collections by 'key' and 'fp' (fingerprint) and returns the changes.
    #>
    param([string]$Module, [string]$Name, [object[]]$Old, [object[]]$New, [string]$At)
    $changes = [System.Collections.Generic.List[object]]::new()
    $oldMap = @{}; foreach ($o in @($Old)) { if ($o -and (Get-WlProp $o 'key')) { $oldMap[[string]$o.key] = $o } }
    $newMap = @{}; foreach ($n in @($New)) { if ($n -and (Get-WlProp $n 'key')) { $newMap[[string]$n.key] = $n } }

    foreach ($k in $newMap.Keys) {
        $n = $newMap[$k]
        if (-not $oldMap.ContainsKey($k)) {
            $changes.Add([pscustomobject]@{ at = $At; module = $Module; collection = $Name; key = $k; change = 'Added'; label = (Get-WlProp $n 'label'); before = $null; after = (Get-WlProp $n 'state') })
        }
        elseif ([string](Get-WlProp $oldMap[$k] 'fp') -ne [string](Get-WlProp $n 'fp')) {
            $changes.Add([pscustomobject]@{ at = $At; module = $Module; collection = $Name; key = $k; change = 'Changed'; label = (Get-WlProp $n 'label'); before = (Get-WlProp $oldMap[$k] 'state'); after = (Get-WlProp $n 'state') })
        }
    }
    foreach ($k in $oldMap.Keys) {
        if (-not $newMap.ContainsKey($k)) {
            $o = $oldMap[$k]
            $changes.Add([pscustomobject]@{ at = $At; module = $Module; collection = $Name; key = $k; change = 'Removed'; label = (Get-WlProp $o 'label'); before = (Get-WlProp $o 'state'); after = $null })
        }
    }
    $changes.ToArray()
}

function Save-WlSnapshot {
    <#
    .SYNOPSIS
    Stores a snapshot (dated, optionally immutable), updates "latest", calculates drift against the
    previous run and maintains the run history.
    #>
    param(
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Snapshot,
        [Parameter(Mandatory)][string[]]$Collections,
        [datetime]$Started
    )
    $now = [DateTime]::UtcNow
    $at = $now.ToString('o')
    $prev = Get-WlBlob -Container 'state' -Name "$Module-latest.json"

    $changes = [System.Collections.Generic.List[object]]::new()
    if ($prev) {
        foreach ($c in $Collections) {
            foreach ($x in (Compare-WlCollection -Module $Module -Name $c -Old @(Get-WlProp $prev $c) -New @($Snapshot[$c]) -At $at)) { $changes.Add($x) }
        }
    }
    $Snapshot['changesSincePrevious'] = $changes.Count
    $Snapshot['isFirstRun'] = ($null -eq $prev)

    $snapName = "$Module/$($now.ToString('yyyy/MM/dd/HHmmssfff')).json"
    Set-WlBlob -Container 'snapshots' -Name $snapName -Object $Snapshot
    Set-WlBlob -Container 'state' -Name "$Module-latest.json" -Object $Snapshot

    # Change history (rolling)
    $retDays = [int](Get-WlSetting -Name 'WL_CHANGE_RETENTION_DAYS' -Default '365')
    $cutoff = $now.AddDays(-$retDays)
    $hist = @(Get-WlBlob -Container 'state' -Name "$Module-changes.json")
    $merged = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $changes) { $merged.Add($c) }
    foreach ($h in $hist) {
        if ($null -eq $h) { continue }
        $hAt = [datetime]::MinValue
        if ([datetime]::TryParse([string](Get-WlProp $h 'at'), [ref]$hAt) -and $hAt.ToUniversalTime() -ge $cutoff) { $merged.Add($h) }
    }
    $maxEntries = 25000
    $out = if ($merged.Count -gt $maxEntries) { $merged.GetRange(0, $maxEntries).ToArray() } else { $merged.ToArray() }
    Set-WlBlob -Container 'state' -Name "$Module-changes.json" -Object @($out)

    # Run index
    $runs = [System.Collections.Generic.List[object]]::new()
    $runs.Add([pscustomobject]@{
            module      = $Module
            at          = $at
            durationSec = if ($Started) { [int]($now - $Started).TotalSeconds } else { $null }
            changes     = $changes.Count
            warnings    = @($Snapshot['warnings']).Count
            snapshot    = $snapName
        })
    foreach ($r in @(Get-WlBlob -Container 'state' -Name 'runs.json')) { if ($null -ne $r -and $runs.Count -lt 500) { $runs.Add($r) } }
    Set-WlBlob -Container 'state' -Name 'runs.json' -Object @($runs.ToArray())

    [pscustomobject]@{ module = $Module; at = $at; changes = $changes.Count; snapshot = $snapName; warnings = @($Snapshot['warnings']).Count }
}
#endregion

#region Auth (App Service Authentication / Easy Auth)
function Get-WlPrincipal {
    <#
    .SYNOPSIS
    Reads the signed-in user from X-MS-CLIENT-PRINCIPAL. The header is only trusted when App Service
    Authentication is really enabled (otherwise it could be forged).
    #>
    param($Request)
    if ($env:WEBSITE_AUTH_ENABLED -ne 'True') {
        return [pscustomobject]@{ ok = $false; status = 503; message = 'Sign-in is not configured yet. Run setup/Install-Wardline.ps1.' }
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
    $roles = @($claims | Where-Object { $_.typ -in $roleTypes } | ForEach-Object { [string]$_.val })

    [pscustomobject]@{
        ok          = $true
        status      = 200
        oid         = & $first @('http://schemas.microsoft.com/identity/claims/objectidentifier', 'oid')
        tid         = & $first @('http://schemas.microsoft.com/identity/claims/tenantid', 'tid')
        upn         = & $first @('preferred_username', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn', 'upn', 'email')
        displayName = & $first @('name', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name')
        roles       = $roles
        isAdmin     = ($roles -contains 'Wardline.Admin')
    }
}
#endregion

#region Baseline
function Get-WlBaseline {
    <#
    .SYNOPSIS
    Loads the MDAV baseline: the customer's own version from storage (config/mdav-baseline.json), otherwise the shipped one.
    #>
    $custom = $null
    try { $custom = Get-WlBlob -Container 'config' -Name 'mdav-baseline.json' } catch { Add-WlWarning "Custom baseline could not be read: $($_.Exception.Message)" }
    if ($custom) { $custom | Add-Member -NotePropertyName source -NotePropertyValue 'custom' -Force; return $custom }
    $appRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $path = Join-Path $appRoot 'config/mdav-baseline.json'
    $b = Get-Content -Raw -Path $path | ConvertFrom-Json -Depth 32
    $b | Add-Member -NotePropertyName source -NotePropertyValue 'default' -Force
    $b
}

function ConvertTo-WlComparable {
    # Settings Catalog values: "..._cloudblocklevel_2" -> 2, "..._audit" -> 'audit', "50" -> 50
    param([AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { return $null }
    $n = 0L
    if ([long]::TryParse($Value, [ref]$n)) { return $n }
    if ($Value -match '_(\d+)$') { return [long]$Matches[1] }
    if ($Value -match '_([a-z]+)$') { return $Matches[1].ToLowerInvariant() }
    $Value.ToLowerInvariant()
}

function Test-WlBaselineValue {
    # -Display: display name of the selected option (Settings Catalog), e.g. "real_time" or "admin_only".
    param([AllowEmptyString()][string]$Value, $Expect, [string]$Display)
    $c = ConvertTo-WlComparable $Value
    $op = [string](Get-WlProp $Expect 'op')
    switch ($op) {
        'display' { return ("$Display $Value").ToLowerInvariant() -match [string](Get-WlProp $Expect 'pattern') }
        'eq' { return ([string]$c -eq [string](Get-WlProp $Expect 'value')) }
        'ne' { return ([string]$c -ne [string](Get-WlProp $Expect 'value')) }
        'in' { return (@(Get-WlProp $Expect 'values') | ForEach-Object { [string]$_ }) -contains [string]$c }
        'gte' { return ($c -is [long]) -and $c -ge [long](Get-WlProp $Expect 'value') }
        'lte' { return ($c -is [long]) -and $c -le [long](Get-WlProp $Expect 'value') }
        'range' { return ($c -is [long]) -and $c -ge [long](Get-WlProp $Expect 'min') -and $c -le [long](Get-WlProp $Expect 'max') }
        'match' { return ([string]$Value).ToLowerInvariant() -match [string](Get-WlProp $Expect 'pattern') }
        default { return $false }
    }
}
#endregion
