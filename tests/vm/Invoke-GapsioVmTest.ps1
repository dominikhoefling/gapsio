#Requires -Version 7.2
<#
.SYNOPSIS
    Creates or removes local Defender exclusions on the test VM – without RDP, via "az vm run-command".

.DESCRIPTION
    Phases:
      Setup    Add four local exclusions (the way an admin or an installer would)
      Drift    Remove one of them again – Gapsio shows the change in its history
      Status   Show effective exclusions, running mode and tamper protection
      Cleanup  Remove all test exclusions

    Every change runs in its own powershell.exe process with the command on the command line, so Gapsio
    can attribute the caller from DeviceProcessEvents (otherwise the registry only shows MsMpEng.exe).
    Advanced Hunting shows the events after a few minutes; device state (tamper, running mode) only after hours.

.EXAMPLE
    ./tests/vm/Invoke-GapsioVmTest.ps1 -ResourceGroup rg-gapsio-testvm -VmName wl-test-win11 -Phase Setup
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup = 'rg-gapsio-testvm',
    [string]$VmName = 'wl-test-win11',
    [Parameter(Mandatory)][ValidateSet('Setup', 'Drift', 'Status', 'Cleanup')][string]$Phase
)
$ErrorActionPreference = 'Stop'

$exclusions = @(
    @{ Param = 'ExclusionPath'; Value = 'C:\Users\Public\GapsioTest' }   # user-writable folder -> High
    @{ Param = 'ExclusionPath'; Value = 'C:\GapsioTemp' }                # removed in phase Drift
    @{ Param = 'ExclusionProcess'; Value = 'powershell.exe' }              # interpreter -> Critical
    @{ Param = 'ExclusionExtension'; Value = '.gapsiotest' }                   # harmless test extension -> Medium
)

function New-Call {
    param([string]$Verb, [hashtable]$E)
    # Every change as its own process so the command is visible in DeviceProcessEvents
    "Start-Process -FilePath powershell.exe -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-Command','$Verb-MpPreference -$($E.Param) ''$($E.Value)'''"
}

$status = @'
"--- Effective exclusions ---"
$p = Get-MpPreference
"Paths:       $($p.ExclusionPath -join ', ')"
"Processes:   $($p.ExclusionProcess -join ', ')"
"Extensions:  $($p.ExclusionExtension -join ', ')"
"--- State ---"
$s = Get-MpComputerStatus
"Running Mode:      $($s.AMRunningMode)"
"Tamper Protection: $($s.IsTamperProtected) (source: $($s.TamperProtectionSource))"
"Real-time:         $($s.RealTimeProtectionEnabled)"
"Sense (EDR):       $((Get-Service Sense -ErrorAction SilentlyContinue).Status)"
'@

$body = switch ($Phase) {
    'Setup' {
        @("New-Item -ItemType Directory -Force -Path 'C:\Users\Public\GapsioTest','C:\GapsioTemp' | Out-Null") + ($exclusions | ForEach-Object { New-Call 'Add' $_ })
    }
    'Drift' { @(New-Call 'Remove' $exclusions[1]) }
    'Cleanup' { @($exclusions | ForEach-Object { New-Call 'Remove' $_ }) + @("Remove-Item -Recurse -Force 'C:\Users\Public\GapsioTest','C:\GapsioTemp' -ErrorAction SilentlyContinue") }
    'Status' { @() }
}
$script = (@($body | Where-Object { $_ }) + @('Start-Sleep -Seconds 3', $status)) -join "`n"

$file = Join-Path ([IO.Path]::GetTempPath()) "wl-vmtest-$([guid]::NewGuid().ToString('n')).ps1"
Set-Content -Path $file -Value $script -Encoding utf8
try {
    Write-Host "▶ $Phase on $VmName …" -ForegroundColor Cyan
    $out = & az vm run-command invoke -g $ResourceGroup -n $VmName --command-id RunPowerShellScript --scripts "@$file" --query 'value[].message' -o tsv --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($out | Out-String) }
    $out | Out-String | Write-Host
}
finally { Remove-Item $file -Force -ErrorAction SilentlyContinue }

switch ($Phase) {
    'Setup' { Write-Host 'After about 15–30 minutes, click "Collect now" in the Gapsio portal.' -ForegroundColor Green }
    'Drift' { Write-Host "Collect again after about 15–30 minutes – 'C:\GapsioTemp' shows up under Changes as removed." -ForegroundColor Green }
}
