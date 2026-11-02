using namespace System.Net
# Wardline API (portal only). Authentication via App Service Authentication (Entra ID).
# Administrators = app role "Wardline.Admin" in the portal app registration.
param($Request, $TriggerMetadata)
Import-Module Wardline

function Send-Response {
    param([int]$Status, $Body, [switch]$RawJson, [switch]$AsArray)
    $text = if ($RawJson) { [string]$Body } elseif ($AsArray) { ConvertTo-Json -InputObject @($(if ($null -eq $Body) { @() } else { @($Body) })) -Depth 32 -Compress } elseif ($Body -is [string]) { ConvertTo-Json -InputObject @{ message = $Body } -Compress } else { ConvertTo-Json -InputObject $Body -Depth 32 -Compress }
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]$Status
            Body        = $text
            ContentType = 'application/json; charset=utf-8'
            Headers     = @{
                'Cache-Control'          = 'no-store'
                'X-Content-Type-Options' = 'nosniff'
                'Strict-Transport-Security' = 'max-age=31536000'
                'Permissions-Policy'     = 'geolocation=(), camera=(), microphone=()'
                'Cross-Origin-Resource-Policy' = 'same-origin'
            }
        })
}

function Test-WlCsrf {
    # State-changing calls: POST only, and a custom header that cross-site forms cannot set.
    if ($method -ne 'POST') { Send-Response -Status 405 -Body 'POST only.'; return $false }
    $csrf = $null; foreach ($k in @($Request.Headers.Keys)) { if ($k -ieq 'x-wardline') { $csrf = $Request.Headers[$k] } }
    if ($csrf -ne '1') { Send-Response -Status 400 -Body 'Header X-Wardline is missing.'; return $false }
    $true
}
function Get-WlRequestJson {
    $b = $Request.Body
    if ($b -is [string]) { if ($b.Length -gt 20000) { throw [System.ArgumentException]::new('Request too large.') }; try { return ($b | ConvertFrom-Json) } catch { throw [System.ArgumentException]::new('Invalid JSON.') } }
    if ($null -eq $b) { throw [System.ArgumentException]::new('Request body missing.') }
    $b
}

$principal = Get-WlPrincipal -Request $Request
if (-not $principal.ok) { Send-Response -Status $principal.status -Body $principal.message; return }

$route = ([string]$Request.Params.segments).Trim('/').ToLowerInvariant()
$method = ([string]$Request.Method).ToUpperInvariant()
$adminRoutes = @('endpoint', 'devices', 'device', 'coverage', 'agents', 'access', 'licensing', 'assistant', 'changes', 'runs', 'baseline', 'run', 'acceptances', 'acceptances/revoke', 'acceptances/log', 'assignments', 'assignments/clear', 'directory/search', 'license')
if ($route -in $adminRoutes -and -not $principal.isAdmin) {
    Send-Response -Status 403 -Body 'This view requires the Wardline.Admin role.'
    return
}
$modules = Get-WlModules
$routeModule = switch -Regex ($route) { '^endpoint$|^baseline$|^devices?$|^coverage$' { 'endpoint' } '^agents$' { 'agents' } '^access(/me)?$' { 'access' } '^licensing$' { 'licensing' } default { $null } }
if ($routeModule -and $modules -notcontains $routeModule) {
    Send-Response -Status 404 -Body "The module '$routeModule' is not enabled in this installation."
    return
}

# Community edition (no valid licence): lists are cut to the first rows on the server, everything else is masked.
$tier = Get-WlLicenseTier
$community = $tier -eq 'Community'
function Send-Snapshot {
    param([string]$Name)
    if ($community) {
        $s = Get-WlBlob -Container 'state' -Name $Name
        if ($s) { Send-Response -Status 200 -Body (Protect-WlCommunity -Snapshot $s) } else { Send-Response -Status 404 -Body 'No data yet. Start a run.' }
        return
    }
    $t = Get-WlBlobText -Container 'state' -Name $Name
    if ($t) { Send-Response -Status 200 -Body $t -RawJson } else { Send-Response -Status 404 -Body 'No data yet. Start a run.' }
}

try {
    switch ($route) {
        'me' {
            Send-Response -Status 200 -Body ([ordered]@{
                    oid = $principal.oid; upn = $principal.upn; displayName = $principal.displayName
                    isAdmin = $principal.isAdmin; roles = $principal.roles; modules = @($modules)
                    tier = $tier; communityRows = $(if ($community) { Get-WlCommunityRows } else { $null })
                    features = @(@('hunting', 'indicators', 'coverage', 'inventory', 'response') | Where-Object { Test-WlFeature -Name $_ })
                    tenantId = Get-WlSetting -Name 'WL_TENANT_ID'; version = (Get-WlVersion)
                    assistant = $(if ($principal.isAdmin) { [bool](Test-WlAssistant) -and $tier -eq 'Full' } else { $false })
                    assistantConfigured = $(if ($principal.isAdmin) { [bool](Test-WlAssistant) } else { $false })
                    update = $(if ($principal.isAdmin) { try { Get-WlBlob -Container 'state' -Name 'release.json' } catch { $null } })
                    license = $(if ($principal.isAdmin) { try { $l = Get-WlLicense; [ordered]@{ status = $l.status; plan = $l.plan; customer = $l.customer; expires = $l.expires; daysLeft = $l.daysLeft } } catch { $null } })
                })
        }
        'endpoint' { Send-Snapshot -Name 'endpoint-latest.json' }
        { $_ -in 'devices', 'coverage' } {
            # Paged collections: ?page=N returns one stored page as-is; devices additionally support server-side search.
            $pageQ = [string]$Request.Query.page
            $isSearch = $route -eq 'devices' -and @('q', 'os', 'group', 'issues', 'chart', 'asrBelow', 'size') | Where-Object { $null -ne $Request.Query.$_ }
            if ($pageQ -match '^\d+$' -and -not $isSearch) {
                if ($community) {
                    $items = @(Get-WlPage -Module 'endpoint' -Name $route -Page ([int]$pageQ))
                    Send-Response -Status 200 -Body (Protect-WlCommunityList -Items $items -Offset ([int]$pageQ * (Get-WlPageSize))) -AsArray; return
                }
                $t = Get-WlPage -Module 'endpoint' -Name $route -Page ([int]$pageQ) -Raw
                Send-Response -Status 200 -Body ($(if ($t) { $t } else { '[]' })) -RawJson; return
            }
            if ($route -eq 'coverage') { Send-Response -Status 400 -Body 'Parameter page is required.'; return }
            $size = 200; if ([string]$Request.Query.size -match '^\d+$') { $size = [int]$Request.Query.size }
            $pg = 0; if ($pageQ -match '^\d+$') { $pg = [int]$pageQ }
            $res = Search-WlDevices -Query ([string]$Request.Query.q) -Os ([string]$Request.Query.os) -Group ([string]$Request.Query.group) -IssuesOnly:([string]$Request.Query.issues -eq '1') `
                -Chart ([string]$Request.Query.chart) -AsrBelow:([string]$Request.Query.asrBelow -eq '1') -Page $pg -Size $size
            if ($community) { $res.rows = Protect-WlCommunityList -Items @($res.rows) -Offset ($pg * [int]$res.size); $res.tier = 'Community'; $res.communityRows = Get-WlCommunityRows }
            Send-Response -Status 200 -Body $res
        }
        'device' {
            $id = [string]$Request.Query.id
            if (-not $id) { Send-Response -Status 400 -Body 'Parameter id is required.'; return }
            $d = Get-WlDevice -DeviceId $id
            if ($d) { Send-Response -Status 200 -Body ([ordered]@{ device = $d }) } else { Send-Response -Status 404 -Body 'Device not found.' }
        }
        'agents' { Send-Snapshot -Name 'agents-latest.json' }
        'access' { Send-Snapshot -Name 'access-latest.json' }
        'licensing' { Send-Snapshot -Name 'licensing-latest.json' }
        'assistant' {
            # Optional chat helper (WL_ASSISTANT). Admins only; POST with the CSRF header; the model sees a server-built summary only.
            if (-not (Test-WlAssistant)) { Send-Response -Status 404 -Body 'The assistant is not enabled in this installation.'; return }
            if ($tier -ne 'Full') { Send-Response -Status 402 -Body 'The assistant is an Enterprise feature. Enter a licence key under Settings > Licence.'; return }
            if (-not (Test-WlCsrf)) { return }
            try {
                $q = Get-WlRequestJson
                $res = Invoke-WlAssistant -Question ([string]$q.question) -History @($q.history) -Lang ([string]$q.lang) -User $principal.upn
                Send-Response -Status 200 -Body $res
            }
            catch [System.ArgumentException] { Send-Response -Status 400 -Body $_.Exception.Message }
            catch { Write-Error $_ -ErrorAction Continue; Send-Response -Status 502 -Body ([string]$_.Exception.Message) }
        }
        'access/me' {
            $snap = Get-WlBlob -Container 'state' -Name 'access-latest.json'
            if (-not $snap) { Send-Response -Status 404 -Body 'No data yet.'; return }
            $mine = @($snap.entitlements | Where-Object { $_.principalId -eq $principal.oid })
            $userType = 'Member'
            try { $u = Invoke-WlGraph -Path "users/$($principal.oid)?`$select=userType"; if ($u.userType) { $userType = [string]$u.userType } } catch { }
            $aud = @($snap.audiences | Where-Object {
                    switch ($_.audience) {
                        'allDirectoryUsers' { $true }
                        'allMemberUsers' { $userType -eq 'Member' }
                        'allExternalUsers' { $userType -eq 'Guest' }
                        'allConfiguredConnectedOrganizationUsers' { $userType -eq 'Guest' }
                        default { $false }
                    }
                })
            Send-Response -Status 200 -Body ([ordered]@{
                    generatedAt = $snap.generatedAt; tenantId = $snap.tenantId; userType = $userType
                    entitlements = $mine; audiences = $aud
                })
        }
        'changes' {
            $m = ([string]$Request.Query.module).ToLowerInvariant()
            if ($m -notin $modules) { Send-Response -Status 400 -Body "Parameter module must be one of the enabled modules: $($modules -join ', ')."; return }
            if ($community) { Send-Response -Status 200 -Body (Protect-WlCommunityList -Items @(Get-WlBlob -Container 'state' -Name "$m-changes.json")) -AsArray; return }
            $t = Get-WlBlobText -Container 'state' -Name "$m-changes.json"
            Send-Response -Status 200 -Body ($(if ($t) { $t } else { '[]' })) -RawJson
        }
        'runs' {
            $t = Get-WlBlobText -Container 'state' -Name 'runs.json'
            Send-Response -Status 200 -Body ($(if ($t) { $t } else { '[]' })) -RawJson
        }
        'baseline' {
            Send-Response -Status 200 -Body (Get-WlBaseline)
        }
        'acceptances' {
            if ($method -eq 'GET') {
                $list = @(Get-WlAcceptances | ForEach-Object { $_ | Add-Member -NotePropertyName active -NotePropertyValue (Test-WlAcceptanceActive $_) -Force -PassThru })
                Send-Response -Status 200 -Body ([ordered]@{ acceptances = $list })
                return
            }
            if (-not (Test-WlCsrf)) { return }
            try { $e = Set-WlAcceptance -Data (Get-WlRequestJson) -By $principal.upn; Send-Response -Status 200 -Body ([ordered]@{ acceptance = $e }) }
            catch [System.ArgumentException] { Send-Response -Status 400 -Body $_.Exception.Message }
        }
        'acceptances/revoke' {
            if (-not (Test-WlCsrf)) { return }
            try { $e = Set-WlAcceptance -Data (Get-WlRequestJson) -By $principal.upn -Revoke; Send-Response -Status 200 -Body ([ordered]@{ acceptance = $e }) }
            catch [System.ArgumentException] { Send-Response -Status 400 -Body $_.Exception.Message }
        }
        'license' {
            if ($method -eq 'GET') { Send-Response -Status 200 -Body (Get-WlLicense); return }
            if (-not (Test-WlCsrf)) { return }
            try { Send-Response -Status 200 -Body (Set-WlLicense -Data (Get-WlRequestJson) -By $principal.upn) }
            catch [System.ArgumentException] { Send-Response -Status 400 -Body $_.Exception.Message }
        }
        'acceptances/log' {
            $t = Get-WlBlobText -Container 'state' -Name 'acceptances-log.json'
            Send-Response -Status 200 -Body ($(if ($t) { $t } else { '[]' })) -RawJson
        }
        'assignments' {
            if ($method -eq 'GET') { Send-Response -Status 200 -Body ([ordered]@{ assignments = @(Get-WlAssignments) }); return }
            if (-not (Test-WlCsrf)) { return }
            try { $e = Set-WlAssignment -Data (Get-WlRequestJson) -By $principal.upn; Send-Response -Status 200 -Body ([ordered]@{ assignment = $e }) }
            catch [System.ArgumentException] { Send-Response -Status 400 -Body $_.Exception.Message }
        }
        'assignments/clear' {
            if (-not (Test-WlCsrf)) { return }
            try { $e = Set-WlAssignment -Data (Get-WlRequestJson) -By $principal.upn -Clear; Send-Response -Status 200 -Body ([ordered]@{ assignment = $e }) }
            catch [System.ArgumentException] { Send-Response -Status 400 -Body $_.Exception.Message }
        }
        'directory/search' {
            # People picker: users, groups and distribution lists for assignments (read-only, admins only).
            Send-Response -Status 200 -Body (Search-WlDirectory -Query ([string]$Request.Query.q))
        }
        'run' {
            if ($method -ne 'POST') { Send-Response -Status 405 -Body 'POST only.'; return }
            # Simple CSRF protection: browser forms from other sites cannot set this header.
            $csrf = $null; foreach ($k in @($Request.Headers.Keys)) { if ($k -ieq 'x-wardline') { $csrf = $Request.Headers[$k] } }
            if ($csrf -ne '1') { Send-Response -Status 400 -Body 'Header X-Wardline is missing.'; return }
            $m = ([string]$Request.Query.module).ToLowerInvariant()
            if ($m -notin @($modules) + 'all') { $m = 'all' }
            # Debounce: a second click within two minutes (double click, retry after a slow response) must not queue a second run.
            $marker = "run-requested-$m.json"
            $prev = $null; try { $prev = Get-WlBlob -Container 'state' -Name $marker } catch { $prev = $null }
            $prevAt = $null; if ($prev -and $prev.at) { try { $prevAt = ConvertTo-WlUtc $prev.at } catch { $prevAt = $null } }
            if ($prevAt -and $prevAt -gt [DateTime]::UtcNow.AddMinutes(-2)) {
                Send-Response -Status 202 -Body ([ordered]@{ message = "Run for '$m' is already queued. Results appear within a few minutes."; module = $m; queued = $false })
                return
            }
            $msg = ConvertTo-Json -Compress -InputObject @{ module = $m; requestedBy = $principal.upn; at = [DateTime]::UtcNow.ToString('o') }
            Add-WlQueueMessage -Text $msg
            try { Set-WlBlob -Container 'state' -Name $marker -Object @{ at = [DateTime]::UtcNow.ToString('o'); by = $principal.upn } } catch { Write-Warning "Run marker could not be written: $($_.Exception.Message)" }
            Send-Response -Status 202 -Body ([ordered]@{ message = "Run for '$m' started. Results appear within a few minutes."; module = $m; queued = $true })
        }
        default { Send-Response -Status 404 -Body 'Unknown endpoint.' }
    }
}
catch {
    Write-Error $_ -ErrorAction Continue
    Send-Response -Status 500 -Body 'Internal error. Details are in the Function App''s Application Insights log.'
}
