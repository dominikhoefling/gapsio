using namespace System.Net
# Wardline API (portal only). Authentication via App Service Authentication (Entra ID).
# Administrators = app role "Wardline.Admin" in the portal app registration.
param($Request, $TriggerMetadata)
Import-Module Wardline

function Send-Response {
    param([int]$Status, $Body, [switch]$RawJson)
    $text = if ($RawJson) { [string]$Body } elseif ($Body -is [string]) { ConvertTo-Json -InputObject @{ message = $Body } -Compress } else { ConvertTo-Json -InputObject $Body -Depth 32 -Compress }
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

$principal = Get-WlPrincipal -Request $Request
if (-not $principal.ok) { Send-Response -Status $principal.status -Body $principal.message; return }

$route = ([string]$Request.Params.segments).Trim('/').ToLowerInvariant()
$method = ([string]$Request.Method).ToUpperInvariant()
$adminRoutes = @('endpoint', 'agents', 'access', 'changes', 'runs', 'baseline', 'run')
if ($route -in $adminRoutes -and -not $principal.isAdmin) {
    Send-Response -Status 403 -Body 'This view requires the Wardline.Admin role.'
    return
}
$modules = Get-WlModules
$routeModule = switch -Regex ($route) { '^endpoint$|^baseline$' { 'endpoint' } '^agents$' { 'agents' } '^access(/me)?$' { 'access' } default { $null } }
if ($routeModule -and $modules -notcontains $routeModule) {
    Send-Response -Status 404 -Body "The module '$routeModule' is not enabled in this installation."
    return
}

try {
    switch ($route) {
        'me' {
            Send-Response -Status 200 -Body ([ordered]@{
                    oid = $principal.oid; upn = $principal.upn; displayName = $principal.displayName
                    isAdmin = $principal.isAdmin; roles = $principal.roles; modules = @($modules)
                    features = @(@('hunting', 'indicators', 'inventory') | Where-Object { Test-WlFeature -Name $_ })
                    tenantId = Get-WlSetting -Name 'WL_TENANT_ID'; version = (Get-WlVersion)
                    update = $(if ($principal.isAdmin) { try { Get-WlBlob -Container 'state' -Name 'release.json' } catch { $null } })
                })
        }
        'endpoint' {
            $t = Get-WlBlobText -Container 'state' -Name 'endpoint-latest.json'
            if ($t) { Send-Response -Status 200 -Body $t -RawJson } else { Send-Response -Status 404 -Body 'No data yet. Start a run.' }
        }
        'agents' {
            $t = Get-WlBlobText -Container 'state' -Name 'agents-latest.json'
            if ($t) { Send-Response -Status 200 -Body $t -RawJson } else { Send-Response -Status 404 -Body 'No data yet. Start a run.' }
        }
        'access' {
            $t = Get-WlBlobText -Container 'state' -Name 'access-latest.json'
            if ($t) { Send-Response -Status 200 -Body $t -RawJson } else { Send-Response -Status 404 -Body 'No data yet. Start a run.' }
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
        'run' {
            if ($method -ne 'POST') { Send-Response -Status 405 -Body 'POST only.'; return }
            # Simple CSRF protection: browser forms from other sites cannot set this header.
            $csrf = $null; foreach ($k in @($Request.Headers.Keys)) { if ($k -ieq 'x-wardline') { $csrf = $Request.Headers[$k] } }
            if ($csrf -ne '1') { Send-Response -Status 400 -Body 'Header X-Wardline is missing.'; return }
            $m = ([string]$Request.Query.module).ToLowerInvariant()
            if ($m -notin @($modules) + 'all') { $m = 'all' }
            $msg = ConvertTo-Json -Compress -InputObject @{ module = $m; requestedBy = $principal.upn; at = [DateTime]::UtcNow.ToString('o') }
            Add-WlQueueMessage -Text $msg
            Send-Response -Status 202 -Body ([ordered]@{ message = "Run for '$m' started. Results appear within a few minutes."; module = $m })
        }
        default { Send-Response -Status 404 -Body 'Unknown endpoint.' }
    }
}
catch {
    Write-Error $_ -ErrorAction Continue
    Send-Response -Status 500 -Body 'Internal error. Details are in the Function App''s Application Insights log.'
}
