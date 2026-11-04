# Gapsio – inventory of local Defender exclusions (Intune Remediations, detection script only)
# Read-only, changes nothing. Runs as SYSTEM (64-bit).
# Output: compact JSON (max. ~2000 characters) that Gapsio reads via Microsoft Graph.
#   v  format version     m  DisableLocalAdminMerge effective (1/0)
#   tp Tamper Protection  rm running mode          n  number of entries   tr 1 = truncated
#   x  list [type, origin, value]  type: P path, R process, E extension, I IP, T temporary path, A ASR, C CFA
#                                   origin: L local, G Group Policy
# Exit code 1 when local exclusions exist (shows in Intune as "with issues").
$ErrorActionPreference = 'SilentlyContinue'

$roots = @(
    @{ o = 'L'; r = 'HKLM:\SOFTWARE\Microsoft\Windows Defender' },
    @{ o = 'G'; r = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' }
)
$keys = @(
    @{ t = 'P'; k = 'Exclusions\Paths' },
    @{ t = 'R'; k = 'Exclusions\Processes' },
    @{ t = 'E'; k = 'Exclusions\Extensions' },
    @{ t = 'I'; k = 'Exclusions\IpAddresses' },
    @{ t = 'T'; k = 'Exclusions\TemporaryPaths' },
    @{ t = 'A'; k = 'Windows Defender Exploit Guard\ASR\ASROnlyExclusions' },
    @{ t = 'C'; k = 'Windows Defender Exploit Guard\Controlled Folder Access\AllowedApplications' }
)

$x = New-Object System.Collections.ArrayList
foreach ($root in $roots) {
    foreach ($key in $keys) {
        $path = Join-Path $root.r $key.k
        if (Test-Path -LiteralPath $path) {
            foreach ($name in (Get-Item -LiteralPath $path).Property) {
                [void]$x.Add(@($key.t, $root.o, [string]$name))
            }
        }
    }
}

$merge = 0
foreach ($p in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender', 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Policy Manager')) {
    $v = (Get-ItemProperty -LiteralPath $p -Name DisableLocalAdminMerge).DisableLocalAdminMerge
    if ($v -eq 1) { $merge = 1 }
}

$s = Get-MpComputerStatus
$out = [ordered]@{
    v  = 1
    m  = $merge
    tp = [int][bool]$s.IsTamperProtected
    rm = [string]$s.AMRunningMode
    n  = $x.Count
    tr = 0
    x  = @($x)
}
$json = $out | ConvertTo-Json -Compress -Depth 4
while ($json.Length -gt 2000 -and $x.Count -gt 0) {
    $x.RemoveAt($x.Count - 1)
    $out.x = @($x); $out.tr = 1
    $json = $out | ConvertTo-Json -Compress -Depth 4
}
Write-Output $json
if (@($x | Where-Object { $_[1] -eq 'L' }).Count -gt 0) { exit 1 } else { exit 0 }
