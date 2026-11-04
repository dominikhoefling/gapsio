using namespace System.Net
# Serves the portal (static files from www/) – signed-in users only.
param($Request, $TriggerMetadata)
Import-Module Gapsio

$securityHeaders = @{
    'X-Content-Type-Options'  = 'nosniff'
    'X-Frame-Options'         = 'DENY'
    'Referrer-Policy'         = 'same-origin'   # Easy Auth requires a Referer on POST with a session cookie (CSRF protection)
    'Content-Security-Policy' = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    'Strict-Transport-Security' = 'max-age=31536000'
    'Permissions-Policy'      = 'geolocation=(), camera=(), microphone=()'
    'Cross-Origin-Resource-Policy' = 'same-origin'
}

function Send-File {
    param([int]$Status, $Body, [string]$ContentType, [string]$Cache = 'no-cache')
    # Set Content-Type via the property, not as a header: otherwise the PowerShell runtime may
    # add text/plain, and the browser drops CSS/JS because of "nosniff".
    $h = @{ 'Cache-Control' = $Cache }
    foreach ($k in $securityHeaders.Keys) { $h[$k] = $securityHeaders[$k] }
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]$Status; Body = $Body; ContentType = $ContentType; Headers = $h })
}

$principal = Get-GapsioPrincipal -Request $Request
if (-not $principal.ok) {
    $msg = [System.Net.WebUtility]::HtmlEncode($principal.message)
    Send-File -Status $principal.status -ContentType 'text/html; charset=utf-8' -Body "<!doctype html><html lang=`"de`"><meta charset=`"utf-8`"><title>Gapsio</title><body><h1>Gapsio</h1><p>$msg</p></body></html>"
    return
}

$path = ([string]$Request.Params.path).Trim('/')
if ($path -match '^api(/|$)') { Send-File -Status 404 -ContentType 'text/plain' -Body 'Not found'; return }
if (-not $path) { $path = 'index.html' }

$www = Join-Path (Split-Path $PSScriptRoot -Parent) 'www'
$full = [System.IO.Path]::GetFullPath((Join-Path $www $path))
$root = [System.IO.Path]::GetFullPath($www) + [System.IO.Path]::DirectorySeparatorChar
if (-not $full.StartsWith($root) -or -not (Test-Path -LiteralPath $full -PathType Leaf)) {
    # SPA: unknown paths go to index.html
    $full = Join-Path $www 'index.html'
}

$types = @{
    '.html' = 'text/html; charset=utf-8'; '.js' = 'text/javascript; charset=utf-8'; '.css' = 'text/css; charset=utf-8'
    '.svg' = 'image/svg+xml'; '.png' = 'image/png'; '.ico' = 'image/x-icon'; '.json' = 'application/json; charset=utf-8'
}
$ext = [System.IO.Path]::GetExtension($full).ToLowerInvariant()
$ct = if ($types.ContainsKey($ext)) { $types[$ext] } else { 'application/octet-stream' }
$body = if ($ct -match '^(text|application/json|image/svg)') { Get-Content -LiteralPath $full -Raw -Encoding utf8 } else { [System.IO.File]::ReadAllBytes($full) }
Send-File -Status 200 -Body $body -ContentType $ct -Cache ($(if ($ext -eq '.html') { 'no-cache' } else { 'public, max-age=300' }))
