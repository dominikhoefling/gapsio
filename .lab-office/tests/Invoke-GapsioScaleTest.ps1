<#
.SYNOPSIS
    Synthetic scale test: runs the paging, index, search, statistics and drift code of the endpoint module against
    N generated devices (default 300,000) with storage mocked in memory, and prints timings and memory.
    Local only – not part of Test-Gapsio.ps1 because it takes a few minutes.

.EXAMPLE
    pwsh -File tests/Invoke-GapsioScaleTest.ps1 -Devices 300000
#>
param([int]$Devices = 300000)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$mod = Import-Module (Join-Path $root 'src/functionapp/Modules/Gapsio/Gapsio.psd1') -Force -PassThru

& $mod {
    param($n)
    $script:Blobs = @{}
    function script:Invoke-WlRest {
        param([string]$Uri, [string]$Method = 'GET', $Body, [string]$Resource, [hashtable]$Headers = @{}, [string]$ContentType, [switch]$Raw, [int]$MaxRetries)
        if ($Uri -match '\.blob\.core\.windows\.net/(.+)$') {
            $k = $Matches[1]
            if ($Method -eq 'PUT') { $script:Blobs[$k] = [string]$Body; return '' }
            if ($Method -eq 'DELETE') { $script:Blobs.Remove($k); return '' }
            if (-not $script:Blobs.ContainsKey($k)) { throw (New-WlHttpException -Status 404 -Message "404 $k") }
            if ($Raw) { return $script:Blobs[$k] } else { return ($script:Blobs[$k] | ConvertFrom-Json) }
        }
        throw "Unexpected call: $Method $Uri"
    }
    $env:WL_STORAGE_ACCOUNT = 'scaletest'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $step = { param($label) Write-Host ("{0,-42} {1,8:N1}s  {2,6:N0} MB" -f $label, $sw.Elapsed.TotalSeconds, ([GC]::GetTotalMemory($false) / 1MB)); $sw.Restart() }

    $os = @('Windows11', 'Windows10', 'WindowsServer2022', 'macOS', 'Linux')
    $items = [object[]]::new($n)
    for ($i = 0; $i -lt $n; $i++) {
        $items[$i] = [pscustomobject]@{ _filter = $null; _search = $null;
            deviceId = "d$i"; deviceName = "PC-$('{0:D6}' -f $i)"; os = $os[$i % 5]; osVersion = '10.0.22631'; deviceGroup = "Group-$($i % 40)"; deviceType = 'Workstation'; managedBy = 'Intune'
            avMode = @('0', '0', '0', '1')[$i % 4]; avModeText = 'Active'; sensorHealth = 'Active'; signatureUpToDate = 'True'; platformUpToDate = 'True'
            asrBelowMinimum = $i % 7; asrBlocked = 0; localExclusions = $i % 11; localExclusionsHighRisk = $false; exclusionAlerts = 0
            lastSeen = '2026-05-01T00:00:00Z'; lastUser = "user$i@contoso.com"; intuneDeviceId = ''; aadDeviceId = ''
            checks = [ordered]@{ TamperProtection = @('GOOD', 'BAD')[$i % 2]; RealtimeProtection = 'GOOD'; CloudProtection = 'GOOD'; BehaviorMonitoring = 'GOOD'; PUAProtection = 'GOOD'; NetworkProtection = 'N/A'; ControlledFolderAccess = 'N/A'; EdrBlockMode = 'GOOD' }
            asr = [ordered]@{ a = 'Block'; b = 'Audit' }; key = "k$i"; fp = "f$i"; label = @{ en = "Device PC-$i"; de = "Gerät PC-$i" }; state = 'Mode=Active'
        }
    }
    & $step "Build $n devices"
    foreach ($d in $items) { $d._filter = Get-WlDeviceFilter -Device $d; $d._search = Get-WlDeviceSearchText -Device $d }
    & $step "Get-WlDeviceFilter/-SearchText per device"
    $stats = Get-WlDeviceStats -Devices $items
    & $step "Get-WlDeviceStats (issues=$($stats.issues))"
    $m = Write-WlPagedCollection -Module 'endpoint' -Name 'devices' -Items $items -IndexColumns $script:WlDeviceIndexColumns -At 't1'
    & $step "Write-WlPagedCollection ($($m.pages) pages)"
    Write-Host ("  index {0:N1} MB, fingerprints {1:N1} MB, page 0 {2:N1} MB" -f ($script:Blobs['state/endpoint-devices.tsv'].Length / 1MB), ($script:Blobs['state/endpoint-devices-fp.json'].Length / 1MB), ($script:Blobs['state/endpoint-devices/0000.json'].Length / 1MB))
    $idx = (Get-WlPagedIndexRaw -Module 'endpoint' -Name 'devices').rows
    & $step "Get-WlPagedIndexRaw cold ($($idx.Count) rows)"
    $r = Search-WlDevices -Query 'pc-0012' -Size 200
    & $step "Search-WlDevices text (total=$($r.total))"
    $r = Search-WlDevices -Chart 'TamperProtection|off' -IssuesOnly -Size 200
    & $step "Search-WlDevices chart+issues (total=$($r.total))"
    $d = Get-WlDevice -DeviceId "d$([int]($n / 2))"
    & $step "Get-WlDevice ($($d.deviceName))"
    $old = @($script:Blobs['state/endpoint-devices-fp.json'] | ConvertFrom-Json)
    $items[7].fp = 'changed'
    $ch = Compare-WlCollection -Module 'endpoint' -Name 'devices' -Old $old -New $items -At 't2'
    & $step "Compare-WlCollection ($($ch.Count) change)"
    $f = @(1..($n / 10) | ForEach-Object { New-WlFinding -Severity 'High' -Category 'Device' -Title (New-WlText "Tamper Protection off on PC-$_" "Tamper Protection aus auf PC-$_") -Detail (New-WlText 'x' 'x') -Subject 'tamper-off' -DeviceId "d$_" -DeviceName "PC-$_" })
    $mf = @(Merge-WlDeviceFindings -Findings $f)
    & $step "Merge-WlDeviceFindings ($($f.Count) -> $($mf.Count))"
} $Devices
