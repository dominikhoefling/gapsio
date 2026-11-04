# Run triggered manually ("Collect now" in the portal). Message: {"module":"endpoint|agents|access|licensing|officepreview|all"}
param($QueueItem, $TriggerMetadata)
Import-Module Gapsio

$module = 'all'
try {
    $msg = if ($QueueItem -is [string]) { $QueueItem | ConvertFrom-Json } else { $QueueItem }
    $m = if ($msg -is [System.Collections.IDictionary]) { $msg['module'] } else { $msg.module }
    if ($m -in 'endpoint', 'agents', 'access', 'licensing', 'officepreview', 'all') { $module = $m }
}
catch { Write-Warning "Unreadable message, running all modules: $($_.Exception.Message)" }

Write-Information "Manual run: $module" -InformationAction Continue
Invoke-GapsioCollection -Module $module | Out-Null
