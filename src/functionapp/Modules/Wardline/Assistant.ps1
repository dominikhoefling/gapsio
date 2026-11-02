# Wardline Assistant: optional chat helper in the portal (explains findings, navigates). Azure OpenAI in the customer's
# subscription, called with the managed identity (no keys). Off unless WL_ASSISTANT=true and an endpoint/deployment is set.
# The model only ever sees a compact, server-built summary of the stored snapshots – never raw lists, never tenant secrets.

function Test-WlAssistant {
    <#
    .SYNOPSIS
    True when the assistant is enabled and configured (WL_ASSISTANT, WL_AI_ENDPOINT, WL_AI_DEPLOYMENT).
    #>
    (Get-WlSetting -Name 'WL_ASSISTANT' -Default 'false') -eq 'true' -and
    -not [string]::IsNullOrWhiteSpace((Get-WlSetting -Name 'WL_AI_ENDPOINT')) -and
    -not [string]::IsNullOrWhiteSpace((Get-WlSetting -Name 'WL_AI_DEPLOYMENT'))
}

# Portal views the assistant may link to. Keep in sync with NAV in www/app.js.
$script:WlAssistantViews = @(
    @{ view = 'overview'; module = 'endpoint'; en = 'Endpoint overview: counts, charts, fleet facts' }
    @{ view = 'findings'; module = 'endpoint'; en = 'Endpoint findings list with severity, device and recommendation; filter by category/severity' }
    @{ view = 'exclusions'; module = 'endpoint'; en = 'Defender AV exclusions from Intune policies, local registry/mdatp and allow indicators; usage (unused), scope' }
    @{ view = 'asr'; module = 'endpoint'; en = 'Attack surface reduction rules: target vs effective mode per rule and device' }
    @{ view = 'devices'; module = 'endpoint'; en = 'Device list with search (?q=name), issues, OS, groups; device detail (#/device?id=)' }
    @{ view = 'baseline'; module = 'endpoint'; en = 'MDAV baseline comparison (what you want vs what Intune configures)' }
    @{ view = 'agents'; module = 'agents'; en = 'AI agents inventory: Entra Agent ID, Agent 365, local agents' }
    @{ view = 'agentca'; module = 'agents'; en = 'Conditional Access coverage for agents' }
    @{ view = 'access'; module = 'access'; en = 'Admin roles and paths: active, PIM-eligible, access packages' }
    @{ view = 'whocan'; module = 'access'; en = 'Who can do what: role to principal lookup' }
    @{ view = 'licensing'; module = 'licensing'; en = 'Defender for Endpoint licence indication: SKUs, licensed users, devices without licensed user' }
    @{ view = 'changes'; module = $null; en = 'Changes between runs (added/changed/removed), per module and day' }
    @{ view = 'accepted'; module = $null; en = 'Accepted risks (acceptances) and their log' }
    @{ view = 'license'; module = $null; en = 'Wardline licence key and tier' }
    @{ view = 'officepreview'; module = $null; en = 'Office 365 private preview (Exchange/Teams telemetry readiness)' }
)

function Get-WlAssistantFindingText {
    param($Finding, [string]$Lang)
    $pick = { param($o) if ($null -eq $o) { '' } elseif ($o -is [string]) { $o } else { $v = Get-WlProp $o $Lang; if (-not $v) { $v = Get-WlProp $o 'en' }; [string]$v } }
    $parts = @("[$($Finding.severity)] $(& $pick $Finding.title)")
    if ($Finding.deviceName) { $parts += "device=$($Finding.deviceName)" }
    if ($Finding.subject) { $parts += "subject=$($Finding.subject)" }
    $d = & $pick $Finding.detail; if ($d) { $parts += "detail=$($d.Substring(0, [Math]::Min($d.Length, 240)))" }
    $r = & $pick $Finding.recommendation; if ($r) { $parts += "fix=$($r.Substring(0, [Math]::Min($r.Length, 240)))" }
    $parts += "category=$($Finding.category)"
    $parts -join ' | '
}

function Get-WlAssistantContext {
    <#
    .SYNOPSIS
    Compact, deterministic context for the model: enabled modules, view catalogue, per-module summary, top findings,
    and – when the question names a device – up to five matching devices. Size is capped (~14k chars).
    #>
    param([string]$Question, [string]$Lang = 'en')
    $modules = @(Get-WlModules)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("Wardline version: $(Get-WlVersion). Enabled modules: $($modules -join ', '). Licence tier: $(Get-WlLicenseTier).")
    [void]$sb.AppendLine('Portal views (route => purpose):')
    foreach ($v in $script:WlAssistantViews) { if (-not $v.module -or $modules -contains $v.module) { [void]$sb.AppendLine("  #/$($v.view) => $($v.en)") } }

    $sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $modules) {
        $snap = $null; try { $snap = Get-WlBlob -Container 'state' -Name "$m-latest.json" } catch { $snap = $null }
        if (-not $snap) { [void]$sb.AppendLine("Module ${m}: no data yet (no run)."); continue }
        $sum = $null; try { $sum = $snap.summary | ConvertTo-Json -Compress -Depth 4 } catch { $sum = '' }
        if ($sum.Length -gt 1500) { $sum = $sum.Substring(0, 1500) + '…' }
        [void]$sb.AppendLine("Module ${m}: generatedAt=$($snap.generatedAt) summary=$sum")
        foreach ($f in @($snap.findings)) { $all.Add([pscustomobject]@{ module = $m; f = $f; o = $(if ($sevOrder.ContainsKey([string]$f.severity)) { $sevOrder[[string]$f.severity] } else { 9 }) }) }
    }
    $top = @($all | Sort-Object o | Select-Object -First 40)
    if ($top.Count) {
        [void]$sb.AppendLine("Top findings ($($top.Count) of $($all.Count), highest severity first):")
        foreach ($x in $top) { [void]$sb.AppendLine("  [$($x.module)] $(Get-WlAssistantFindingText -Finding $x.f -Lang $Lang)") }
    }

    # Device lookup: words that look like host names (letters/digits/dashes, 3+ chars, not plain English) are tried against the device search.
    if ($modules -contains 'endpoint' -and $Question) {
        $cands = @([regex]::Matches($Question, '[A-Za-z0-9][A-Za-z0-9\-\.]{2,62}') | ForEach-Object { $_.Value } | Where-Object { $_ -match '\d|-' } | Select-Object -Unique -First 3)
        foreach ($c in $cands) {
            try {
                $res = Search-WlDevices -Query $c -Page 0 -Size 5
                if ($res -and @($res.rows).Count) {
                    [void]$sb.AppendLine("Devices matching '$c':")
                    foreach ($d in @($res.rows)) { [void]$sb.AppendLine("  $(($d | Select-Object deviceName, osPlatform, riskScore, exposure, asrBelowMinimum, localExclusionsPresent, tamperProtection, findings -ErrorAction SilentlyContinue | ConvertTo-Json -Compress -Depth 2))") }
                }
            }
            catch { }
        }
    }
    $text = $sb.ToString()
    if ($text.Length -gt 14000) { $text = $text.Substring(0, 14000) + '…' }
    $text
}

function Invoke-WlAssistant {
    <#
    .SYNOPSIS
    Answers a portal question with Azure OpenAI (chat completions, JSON output). Returns @{ answer; links = @(@{view;label}) ; usage }.
    #>
    param([Parameter(Mandatory)][string]$Question, $History, [string]$Lang = 'en', [string]$User = '')
    if (-not (Test-WlAssistant)) { throw [System.InvalidOperationException]::new('The assistant is not enabled in this installation.') }
    $Question = $Question.Trim()
    if (-not $Question) { throw [System.ArgumentException]::new('Question is empty.') }
    if ($Question.Length -gt 2000) { throw [System.ArgumentException]::new('Question is too long (max 2000 characters).') }
    if ($Lang -notin 'en', 'de') { $Lang = 'en' }

    $endpoint = (Get-WlSetting -Name 'WL_AI_ENDPOINT').TrimEnd('/')
    $deployment = Get-WlSetting -Name 'WL_AI_DEPLOYMENT'
    $apiVersion = Get-WlSetting -Name 'WL_AI_API_VERSION' -Default '2024-10-21'
    $context = Get-WlAssistantContext -Question $Question -Lang $Lang
    $langName = $(if ($Lang -eq 'de') { 'German' } else { 'English' })

    $system = @"
You are the Wardline Assistant inside the Wardline portal, a read-only security posture tool for Microsoft Defender for Endpoint, Intune, Entra ID and AI agents, self-hosted in the customer's Azure subscription.
Rules:
- Answer only from the CONTEXT below. If the context does not contain the information, say so and point to the view where the user can look, or suggest starting a run ("Collect now").
- Never invent devices, numbers, policies or findings. Quote numbers exactly as given.
- Wardline is read-only: never claim it changed or will change anything. Recommendations are for the admin to apply in Intune / Defender / Entra.
- Be concise (max ~180 words), use short bullet points when listing. Reply in $langName.
- When a portal view helps, add it to "links" (only routes that appear in the CONTEXT view list; devices may use #/devices?q=<name> and #/device?id=<deviceId>).
- Output strictly JSON: {"answer": string, "links": [{"view": "#/route", "label": string}]}.
CONTEXT:
$context
"@
    $messages = [System.Collections.Generic.List[object]]::new()
    $messages.Add(@{ role = 'system'; content = $system })
    foreach ($h in @($History | Select-Object -Last 6)) {
        $r = [string](Get-WlProp $h 'role'); $c = [string](Get-WlProp $h 'content')
        if ($r -in 'user', 'assistant' -and $c) { $messages.Add(@{ role = $r; content = $c.Substring(0, [Math]::Min($c.Length, 1500)) }) }
    }
    $messages.Add(@{ role = 'user'; content = $Question })

    $body = @{ messages = $messages.ToArray(); temperature = 0.2; max_tokens = 700; response_format = @{ type = 'json_object' }; user = $(if ($User) { Get-WlHash $User } else { 'portal' }) }
    $token = Get-WlToken -Resource 'https://cognitiveservices.azure.com'
    $uri = "$endpoint/openai/deployments/$([uri]::EscapeDataString($deployment))/chat/completions?api-version=$apiVersion"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = Invoke-RestMethod -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 8 -Compress) -TimeoutSec 60
    }
    catch {
        $msg = $_.Exception.Message
        try { $err = $_.ErrorDetails.Message | ConvertFrom-Json; if ($err.error.message) { $msg = [string]$err.error.message } } catch { }
        throw [System.Exception]::new("Azure OpenAI call failed: $msg")
    }
    $content = [string]$r.choices[0].message.content
    $answer = $content; $links = @()
    try {
        $j = $content | ConvertFrom-Json
        if ($j.answer) { $answer = [string]$j.answer }
        $allowed = @($script:WlAssistantViews | ForEach-Object { $_.view }) + @('device', 'devices')
        $links = @(@($j.links) | Where-Object { $_ -and $_.view } | ForEach-Object {
                $v = [string]$_.view; $v = $v -replace '^#?/?', ''
                $name = ($v -split '\?')[0]
                if ($name -in $allowed -and $v -notmatch '[<>"'']') { [ordered]@{ view = "#/$v"; label = [string]$(if ($_.label) { $_.label } else { $name }) } }
            } | Select-Object -First 5)
    }
    catch { }
    [ordered]@{
        answer   = $answer
        links    = @($links)
        model    = [string]$r.model
        usage    = $(if ($r.usage) { [ordered]@{ prompt = $r.usage.prompt_tokens; completion = $r.usage.completion_tokens } } else { $null })
        tookMs   = $sw.ElapsedMilliseconds
    }
}
