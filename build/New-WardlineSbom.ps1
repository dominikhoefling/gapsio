#Requires -Version 7.2
<#
.SYNOPSIS
    Writes a software bill of materials (CycloneDX 1.5, JSON) for a Wardline release.

.DESCRIPTION
    Wardline ships no third-party libraries: the portal uses no JavaScript framework and the function code uses no
    PowerShell Gallery modules. The SBOM therefore lists
      - every file of the function package with its SHA-256 hash,
      - the platform components Wardline runs on or calls (provided and patched by Microsoft, not shipped).

.EXAMPLE
    ./build/New-WardlineSbom.ps1 -PackagePath dist/release/wardline-functionapp.zip -OutFile dist/release/sbom.cdx.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackagePath,
    [Parameter(Mandatory)][string]$OutFile
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$version = (Import-PowerShellDataFile (Join-Path $root 'src/functionapp/Modules/Wardline/Wardline.psd1')).ModuleVersion
$host_ = Get-Content -Raw (Join-Path $root 'src/functionapp/host.json') | ConvertFrom-Json

$tmp = Join-Path ([IO.Path]::GetTempPath()) "wardline-sbom-$([guid]::NewGuid().ToString('n'))"
Expand-Archive -Path $PackagePath -DestinationPath $tmp
try {
    $files = Get-ChildItem -Path $tmp -Recurse -File | Sort-Object FullName | ForEach-Object {
        $rel = [IO.Path]::GetRelativePath($tmp, $_.FullName).Replace('\', '/')
        [ordered]@{
            type     = 'file'
            'bom-ref' = "file:$rel"
            name     = $rel
            hashes   = @([ordered]@{ alg = 'SHA-256'; content = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant() })
        }
    }
}
finally { Remove-Item $tmp -Recurse -Force }

$platform = @(
    [ordered]@{ type = 'platform'; 'bom-ref' = 'platform:azure-functions-powershell'; name = 'Azure Functions PowerShell worker'; version = '7.4'; supplier = @{ name = 'Microsoft' }; description = 'Runtime of the Function App (Flex Consumption). Provided and patched by Microsoft, not shipped with Wardline.' },
    [ordered]@{ type = 'library'; 'bom-ref' = 'platform:extension-bundle'; name = [string]$host_.extensionBundle.id; version = [string]$host_.extensionBundle.version; supplier = @{ name = 'Microsoft' }; description = 'Azure Functions extension bundle (queue and timer triggers). Loaded by the platform, not shipped with Wardline.' },
    [ordered]@{ type = 'platform'; 'bom-ref' = 'service:microsoft-graph'; name = 'Microsoft Graph API'; supplier = @{ name = 'Microsoft' }; description = 'Read-only calls with the permissions of the selected features.' },
    [ordered]@{ type = 'platform'; 'bom-ref' = 'service:defender-api'; name = 'Microsoft Defender for Endpoint API'; supplier = @{ name = 'Microsoft' }; description = 'Read-only: allow indicators (feature Indicators).' },
    [ordered]@{ type = 'application'; 'bom-ref' = 'setup:azure-cli'; name = 'Azure CLI'; supplier = @{ name = 'Microsoft' }; description = 'Used by the setup scripts on the administrator''s machine or in Cloud Shell. Not shipped.' }
)

$bom = [ordered]@{
    bomFormat    = 'CycloneDX'
    specVersion  = '1.5'
    serialNumber = "urn:uuid:$([guid]::NewGuid())"
    version      = 1
    metadata     = [ordered]@{
        timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        component = [ordered]@{ type = 'application'; 'bom-ref' = 'wardline'; name = 'Wardline'; version = $version; description = 'Self-hosted visibility into Microsoft Defender and AI agent protection gaps.' }
        properties = @([ordered]@{ name = 'wardline:thirdPartyLibraries'; value = '0' })
    }
    components   = @($files) + $platform
    dependencies = @([ordered]@{ ref = 'wardline'; dependsOn = @($platform | ForEach-Object { $_.'bom-ref' }) })
}
$bom | ConvertTo-Json -Depth 10 | Set-Content -Path $OutFile -Encoding utf8
Write-Host "SBOM: $OutFile ($(@($files).Count) files, $($platform.Count) platform components)"
