#Requires -Version 7.2
<#
.SYNOPSIS
    Creates a Windows 11 Enterprise test VM in Azure and optionally onboards it to Defender for Endpoint right away.

.DESCRIPTION
    - No inbound connections (NSG without allow rule); RDP only with -AllowRdpFrom for a single IP
    - Public IP for outbound traffic only (Defender cloud), daily auto-shutdown
    - Onboarding without RDP via "az vm run-command": download the package in the Defender portal
      (Settings › Endpoints › Onboarding › Windows 10 and 11 › deployment method "Group Policy"
       or "Local Script") and pass the path to the ZIP file with -OnboardingPackage

    Licence: Windows 11 client VMs in Azure are covered by Microsoft 365 E3/E5 (--license-type Windows_Client).
    Cost: Standard_B2ms ~€0.09/h, plus disk and public IP. Delete: az group delete -n <ResourceGroup>

.EXAMPLE
    ./tests/vm/New-GapsioTestVm.ps1 -ResourceGroup rg-gapsio-testvm -Location germanywestcentral -OnboardingPackage ~/Downloads/WindowsDefenderATPOnboardingPackage.zip
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup = 'rg-gapsio-testvm',
    [string]$Location = 'germanywestcentral',
    [ValidateLength(1, 15)][string]$VmName = 'wl-test-win11',
    [string]$Size = 'Standard_B2ms',
    [string]$AdminUser = 'wladmin',
    [securestring]$AdminPassword,
    [string]$AllowRdpFrom,
    [string]$ShutdownUtc = '1800',
    [string]$OnboardingPackage
)
$ErrorActionPreference = 'Stop'
function Write-Step { param([string]$Text) Write-Host "`n▶ $Text" -ForegroundColor Cyan }
function Write-Ok { param([string]$Text) Write-Host "  ✓ $Text" -ForegroundColor Green }
function Invoke-Az {
    param([string[]]$Arguments)
    $out = & az @Arguments --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) { throw "az $($Arguments[0..2] -join ' ') … failed:`n$($out | Out-String)" }
    ($out | Out-String).Trim()
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI missing (macOS: brew install azure-cli).' }
$acct = Invoke-Az @('account', 'show', '-o', 'json') | ConvertFrom-Json
Write-Host "Subscription: $($acct.name)  Tenant: $($acct.tenantId)"

if ($OnboardingPackage) {
    $resolved = Resolve-Path -LiteralPath ($OnboardingPackage -replace '^~', $HOME) -ErrorAction SilentlyContinue
    if (-not $resolved) { throw "Onboarding package not found: $OnboardingPackage (put paths with spaces in quotes)" }
    $OnboardingPackage = $resolved.Path
}

$existing = & az vm show -g $ResourceGroup -n $VmName --query id -o tsv --only-show-errors 2>$null
$vmExists = ($LASTEXITCODE -eq 0 -and $existing)
if ($vmExists) {
    Write-Host "VM $VmName already exists – creation skipped." -ForegroundColor Yellow
    & az vm start -g $ResourceGroup -n $VmName --only-show-errors -o none 2>$null
}
else {
if (-not $AdminPassword) { $AdminPassword = Read-Host -AsSecureString "Password for the local admin '$AdminUser' (min. 12 characters, complex)" }
$plain = [System.Net.NetworkCredential]::new('', $AdminPassword).Password
if ($plain.Length -lt 12) { throw 'Password too short (at least 12 characters).' }

Write-Step 'Resource group and network security group'
Invoke-Az @('group', 'create', '-n', $ResourceGroup, '-l', $Location, '--tags', 'product=Gapsio-Test', '-o', 'none') | Out-Null
$nsg = "$VmName-nsg"
Invoke-Az @('network', 'nsg', 'create', '-g', $ResourceGroup, '-n', $nsg, '-l', $Location, '-o', 'none') | Out-Null
if ($AllowRdpFrom) {
    Invoke-Az @('network', 'nsg', 'rule', 'create', '-g', $ResourceGroup, '--nsg-name', $nsg, '-n', 'rdp-single-ip', '--priority', '1000', '--direction', 'Inbound',
        '--access', 'Allow', '--protocol', 'Tcp', '--destination-port-ranges', '3389', '--source-address-prefixes', $AllowRdpFrom, '-o', 'none') | Out-Null
    Write-Ok "RDP allowed only from $AllowRdpFrom"
}
else { Write-Ok 'No inbound connections allowed (management via Run Command)' }

Write-Step 'Finding the Windows 11 Enterprise image'
$skus = (Invoke-Az @('vm', 'image', 'list-skus', '-l', $Location, '-p', 'MicrosoftWindowsDesktop', '-f', 'windows-11', '--query', '[].name', '-o', 'tsv')) -split "`n" | ForEach-Object { $_.Trim() }
$sku = $skus | Where-Object { $_ -match '^win11-(\d{2})h(\d)-ent$' } | Sort-Object { [int]($_ -replace '^win11-(\d{2})h(\d)-ent$', '$1$2') } | Select-Object -Last 1
if (-not $sku) { throw "No Windows 11 Enterprise image found in $Location." }
$image = "MicrosoftWindowsDesktop:windows-11:${sku}:latest"
Write-Ok $image

Write-Step "Creating VM $VmName ($Size) – takes a few minutes"
Invoke-Az @('vm', 'create', '-g', $ResourceGroup, '-n', $VmName, '--image', $image, '--size', $Size, '--admin-username', $AdminUser, '--admin-password', $plain,
    '--license-type', 'Windows_Client', '--public-ip-sku', 'Standard', '--nsg', $nsg, '--os-disk-delete-option', 'Delete', '--nic-delete-option', 'Delete',
    '--tags', 'product=Gapsio-Test', '-o', 'none') | Out-Null
$plain = $null
Invoke-Az @('vm', 'auto-shutdown', '-g', $ResourceGroup, '-n', $VmName, '--time', $ShutdownUtc, '-o', 'none') | Out-Null
Write-Ok "VM running; daily auto-shutdown at $($ShutdownUtc.Insert(2, ':')) UTC"
}

if ($OnboardingPackage) {
    Write-Step 'Defender for Endpoint onboarding via Run Command'
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "wl-onboard-$([guid]::NewGuid().ToString('n'))"
    Expand-Archive -Path $OnboardingPackage -DestinationPath $tmp -Force
    $cmd = Get-ChildItem -Path $tmp -Recurse -Filter '*Onboarding*.cmd' | Select-Object -First 1
    if (-not $cmd) { throw 'No *Onboarding*.cmd found in the package. Please use the Windows 10/11 package (Group Policy or Local Script).' }
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($cmd.FullName))
    $remote = @"
`$path = Join-Path `$env:TEMP '$($cmd.Name)'
[IO.File]::WriteAllBytes(`$path, [Convert]::FromBase64String('$b64'))
# The local script asks for confirmation – 'Y' is answered via standard input.
'Y' | & cmd.exe /c `$path
"Onboarding script finished with code `$LASTEXITCODE"
Start-Sleep -Seconds 30
Get-Service -Name Sense | Format-Table Name, Status -AutoSize | Out-String
Remove-Item `$path -Force -ErrorAction SilentlyContinue
"@
    $scriptFile = Join-Path $tmp 'onboard.ps1'
    Set-Content -Path $scriptFile -Value $remote -Encoding utf8
    $res = Invoke-Az @('vm', 'run-command', 'invoke', '-g', $ResourceGroup, '-n', $VmName, '--command-id', 'RunPowerShellScript', '--scripts', "@$scriptFile", '--query', 'value[].message', '-o', 'tsv')
    Remove-Item $tmp -Recurse -Force
    Write-Host $res
    Write-Ok 'Onboarding done. The device shows up in the Defender portal after 15–60 minutes.'
}

$ip = Invoke-Az @('vm', 'show', '-d', '-g', $ResourceGroup, '-n', $VmName, '--query', 'publicIps', '-o', 'tsv')
Write-Host ''
Write-Host "Test VM ready: $VmName ($ip)" -ForegroundColor Green
if (-not $OnboardingPackage) { Write-Host 'Onboarding: run the script again with -OnboardingPackage <zip>, or start the local script via RDP.' }
Write-Host "Create local exclusions:     ./tests/vm/Invoke-GapsioVmTest.ps1 -ResourceGroup $ResourceGroup -VmName $VmName -Phase Setup"
Write-Host "Delete:                      az group delete -n $ResourceGroup --yes"
