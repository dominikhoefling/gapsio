# Gapsio Assistant: optional chat helper in the portal (explains findings, navigates). Azure OpenAI in the customer's
# subscription, called with the managed identity (no keys). Off unless GAPSIO_ASSISTANT=true and an endpoint/deployment is set.
# The model only ever sees a compact, server-built summary of the stored snapshots – never raw lists, never tenant secrets.

function Test-GapsioAssistant {
    <#
    .SYNOPSIS
    True when the assistant is enabled and configured (GAPSIO_ASSISTANT, GAPSIO_AI_ENDPOINT, GAPSIO_AI_DEPLOYMENT).
    #>
    (Get-GapsioSetting -Name 'GAPSIO_ASSISTANT' -Default 'false') -eq 'true' -and
    -not [string]::IsNullOrWhiteSpace((Get-GapsioSetting -Name 'GAPSIO_AI_ENDPOINT')) -and
    -not [string]::IsNullOrWhiteSpace((Get-GapsioSetting -Name 'GAPSIO_AI_DEPLOYMENT'))
}

# Portal views the assistant may link to. Keep in sync with NAV in www/app.js.
$script:GapsioAssistantViews = @(
    @{ view = 'overview'; module = 'endpoint'; en = 'Endpoint overview: counts, charts, fleet facts' }
    @{ view = 'findings'; module = 'endpoint'; en = 'Endpoint findings list with severity, device and recommendation; filter by category/severity' }
    @{ view = 'exclusions'; module = 'endpoint'; en = 'Defender AV exclusions from Intune policies, local registry/mdatp and allow indicators; usage (unused), scope' }
    @{ view = 'asr'; module = 'endpoint'; en = 'Attack surface reduction rules: target vs effective mode per rule and device' }
    @{ view = 'devices'; module = 'endpoint'; en = 'Device list with search (?q=name), issues, OS, groups; device detail (#/device?id=)' }
    @{ view = 'baseline'; module = 'endpoint'; en = 'MDAV baseline comparison (what you want vs what Intune configures)' }
    @{ view = 'conflicts'; module = 'endpoint'; en = 'Policy conflicts: the same setting with different values from two or more Intune policies' }
    @{ view = 'devicecontrol'; module = 'endpoint'; en = 'Device control: USB storage in use versus device control policies' }
    @{ view = 'disruption'; module = 'endpoint'; en = 'Attack disruption readiness: prerequisites that can be verified and those only visible in the Defender portal' }
    @{ view = 'detections'; module = 'endpoint'; en = 'Custom detection rules: switched off automatically, failed, disabled' }
    @{ view = 'officepreview'; module = 'officepreview'; en = 'Defender for Office 365: phishing and malware still in inboxes, threats delivered by an allow, Safe Links click-through, own-domain spoofing' }
    @{ view = 'officeantiphish'; module = 'officepreview'; en = 'Anti-phish policy drift: who changed which setting, weaker or stronger, delivered phishing before and after' }
    @{ view = 'officepolicymap'; module = 'officepreview'; en = 'Policy map: which protection acted on inbound mail, organisation-level and mailbox policies' }
    @{ view = 'officechanges'; module = 'officepreview'; en = 'Changes to all Defender for Office 365 protection policies, rated when they weaken protection' }
    @{ view = 'officequarantine'; module = 'officepreview'; en = 'Quarantine: releases, release requests, who released mail with a phishing or malware verdict' }
    @{ view = 'officeteams'; module = 'officepreview'; en = 'Teams protection: Teams messages rated phishing or malware, delivered and not removed' }
    @{ view = 'purview'; module = 'purviewpreview'; en = 'Purview DLP overview (private preview)' }
    @{ view = 'agents'; module = 'agents'; en = 'AI agents inventory: Entra Agent ID, Agent 365, local agents' }
    @{ view = 'agentca'; module = 'agents'; en = 'Conditional Access coverage for agents' }
    @{ view = 'access'; module = 'access'; en = 'Admin roles and paths: active, PIM-eligible, access packages' }
    @{ view = 'whocan'; module = 'access'; en = 'Who can do what: role to principal lookup' }
    @{ view = 'licensing'; module = 'licensing'; en = 'Defender for Endpoint licence indication: SKUs, licensed users, devices without licensed user' }
    @{ view = 'changes'; module = $null; en = 'Changes between runs (added/changed/removed), per module and day' }
    @{ view = 'accepted'; module = $null; en = 'Accepted risks (acceptances) and their log' }
    @{ view = 'evidence'; module = $null; en = 'Audit evidence: open findings and accepted risks by ISO 27001 and NIS2 control' }
    @{ view = 'license'; module = $null; en = 'Gapsio licence key and tier' }
)

function Get-GapsioAssistantSnapshotName {
    # Blob name of a module's latest snapshot (the Purview preview keeps its older name).
    param([Parameter(Mandatory)][string]$Module)
    if ($Module -eq 'purviewpreview') { 'purview-preview-latest.json' } else { "$Module-latest.json" }
}

function ConvertTo-GapsioAssistantTime {
    # Dates for the model: always "yyyy-MM-dd HH:mm UTC". ConvertFrom-Json and the device index turn ISO timestamps
    # into DateTime values or culture-formatted strings ("11/02/2026 …"), which read as the wrong day.
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    try { (ConvertTo-GapsioUtc $Value).ToString('yyyy-MM-dd HH:mm') + ' UTC' } catch { [string]$Value }
}

function ConvertTo-GapsioAssistantDevice {
    <#
    .SYNOPSIS
    Compact device record for the model from a device row of the endpoint snapshot: identity, last report, protection
    state and the checks that failed. Uses the field names of the snapshot (os, lastUser, localExclusions, checks …).
    #>
    param($Device)
    if (-not $Device) { return $null }
    $g = { param($n) Get-GapsioProp $Device $n }
    $checks = & $g 'checks'
    $failed = @()
    if ($checks -is [System.Collections.IDictionary]) { $failed = @($checks.Keys | Where-Object { $checks[$_] -eq 'BAD' }) }
    elseif ($checks) { $failed = @($checks.PSObject.Properties | Where-Object { $_.Value -eq 'BAD' } | ForEach-Object { $_.Name }) }
    $reporting = & $g 'reporting'
    $all = [ordered]@{
        deviceId = [string](& $g 'deviceId'); deviceName = [string](& $g 'deviceName'); os = [string](& $g 'os'); osVersion = [string](& $g 'osVersion')
        deviceGroup = [string](& $g 'deviceGroup'); lastUser = [string](& $g 'lastUser'); lastSeen = (ConvertTo-GapsioAssistantTime (& $g 'lastSeen'))
        reporting = $(if ($reporting -eq $false -or "$reporting" -eq 'false') { 'not reporting – the state below is the last known one' } elseif ($null -eq $reporting -or "$reporting" -eq '') { 'unknown' } else { 'reporting' })
        antivirusMode = [string](& $g 'avModeText'); sensorHealth = [string](& $g 'sensorHealth'); exposure = [string](& $g 'exposure')
        failedChecks = $failed
        asrRulesBelowTarget = (& $g 'asrBelowMinimum'); localExclusions = (& $g 'localExclusions'); localExclusionsHighRisk = (& $g 'localExclusionsHighRisk'); policyExclusions = (& $g 'policyExclusions')
        tamperingEvents30d = (& $g 'tampering30d'); internetFacing = (& $g 'internetFacing')
    }
    # Values Defender did not report are left out – an empty field would read as "none"
    $out = [ordered]@{}
    foreach ($k in $all.Keys) { $v = $all[$k]; if ($null -ne $v -and "$v" -ne '' -or $k -eq 'failedChecks') { $out[$k] = $v } }
    $out
}

function Get-GapsioAssistantFindingText {
    # One line per finding. -Short (context): title, device, category and the start of the detail – the tool
    # search_findings returns the full line with the fix.
    param($Finding, [string]$Lang, [switch]$Short)
    $pick = { param($o) if ($null -eq $o) { '' } elseif ($o -is [string]) { $o } else { $v = Get-GapsioProp $o $Lang; if (-not $v) { $v = Get-GapsioProp $o 'en' }; [string]$v } }
    $parts = @("[$($Finding.severity)] $(& $pick $Finding.title)")
    if ($Finding.deviceName) { $parts += "device=$($Finding.deviceName)" }
    if (Get-GapsioProp $Finding 'stale') { $parts += 'state=last known (the device is not reporting)' }
    if ($Finding.subject -and -not $Short) { $parts += "subject=$($Finding.subject)" }
    $max = $(if ($Short) { 160 } else { 240 })
    $d = & $pick $Finding.detail; if ($d) { $parts += "detail=$($d.Substring(0, [Math]::Min($d.Length, $max)))$(if ($d.Length -gt $max) { '…' })" }
    if (-not $Short) { $r = & $pick $Finding.recommendation; if ($r) { $parts += "fix=$($r.Substring(0, [Math]::Min($r.Length, 240)))$(if ($r.Length -gt 240) { '…' })" } }
    $parts += "category=$($Finding.category)"
    $parts -join ' | '
}

function Get-GapsioAssistantContext {
    <#
    .SYNOPSIS
    Compact, deterministic context for the model: enabled modules, view catalogue, per-module summary, the devices
    the question names (up to five each) and the top findings as far as they fit into about 12,000 characters.
    #>
    param([string]$Question, [string]$Lang = 'en')
    $modules = @(Get-GapsioModules)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("Gapsio version: $(Get-GapsioVersion). Enabled modules: $($modules -join ', '). Licence tier: $(Get-GapsioLicenseTier).")
    [void]$sb.AppendLine('Portal views (route => purpose):')
    foreach ($v in $script:GapsioAssistantViews) { if (-not $v.module -or $modules -contains $v.module) { [void]$sb.AppendLine("  #/$($v.view) => $($v.en)") } }

    $sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $modules) {
        $snap = $null; try { $snap = Get-GapsioBlob -Container 'state' -Name (Get-GapsioAssistantSnapshotName -Module $m) } catch { $snap = $null }
        if (-not $snap) { [void]$sb.AppendLine("Module ${m}: no data yet (no run)."); continue }
        $sum = $null; try { $sum = $snap.summary | ConvertTo-Json -Compress -Depth 4 } catch { $sum = '' }
        if ($sum.Length -gt 1500) { $sum = $sum.Substring(0, 1500) + '…' }
        [void]$sb.AppendLine("Module ${m}: snapshot of $(ConvertTo-GapsioAssistantTime $snap.generatedAt) summary=$sum")
        if ($m -eq 'endpoint') {
            # Spelled out, because the model otherwise answers "how many devices do not report" from other numbers
            $quiet = [int](Get-GapsioProp $snap.summary 'devicesNotReporting')
            if ($quiet -gt 0) { [void]$sb.AppendLine("  Note: $quiet of $([int](Get-GapsioProp $snap.summary 'devices')) devices are NOT REPORTING (no device information in the lookback). They carry the label 'not reporting' in the device list (#/devices) and are listed as 'sensor inactive' under its tab Coverage gaps (#/devices?tab=coverage); there is no separate filter for them. Protection state and findings for them are the last known state.") }
        }
        foreach ($f in @($snap.findings)) { if ($f) { $all.Add([pscustomobject]@{ module = $m; f = $f; o = $(if ($sevOrder.ContainsKey([string]$f.severity)) { $sevOrder[[string]$f.severity] } else { 9 }) }) } }
    }

    # Device lookup: words that look like host names (letters/digits/dashes, 3+ chars, not plain English) are tried
    # against the device search. Before the findings, so the answer to "why is device X flagged" is never cut off.
    if ($modules -contains 'endpoint' -and $Question) {
        $cands = @([regex]::Matches($Question, '[A-Za-z0-9][A-Za-z0-9\-\.]{2,62}') | ForEach-Object { $_.Value } | Where-Object { $_ -match '\d|-' } | Select-Object -Unique -First 3)
        foreach ($c in $cands) {
            try {
                $res = Search-GapsioDevices -Query $c -Page 0 -Size 5
                if ($res -and @($res.rows).Count) {
                    [void]$sb.AppendLine("Devices matching '$c':")
                    foreach ($d in @($res.rows)) { [void]$sb.AppendLine("  $((ConvertTo-GapsioAssistantDevice -Device $d) | ConvertTo-Json -Compress -Depth 3)") }
                }
            }
            catch { }
        }
    }

    # Top findings, highest severity first, whole lines only, within the size budget
    $budget = 12000
    $lines = [System.Collections.Generic.List[string]]::new()
    $used = $sb.Length
    foreach ($x in @($all | Sort-Object o | Select-Object -First 40)) {
        $line = "  [$($x.module)] $(Get-GapsioAssistantFindingText -Finding $x.f -Lang $Lang -Short)"
        if ($used + $line.Length + 2 -gt $budget) { break }
        $lines.Add($line); $used += $line.Length + 2
    }
    if ($all.Count) {
        [void]$sb.AppendLine("Top findings ($($lines.Count) of $($all.Count), highest severity first; use search_findings for the rest, for details and for the fix):")
        foreach ($l in $lines) { [void]$sb.AppendLine($l) }
    }
    $sb.ToString()
}


#region Azure OpenAI calls
function Send-GapsioOpenAIRequest {
    # One HTTP call to the Azure OpenAI data-plane. Returns @{ ok; data } or @{ ok = $false; status; retryAfter; message }.
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][string]$Json, [int]$TimeoutSec = 60)
    try {
        @{ ok = $true; data = (Invoke-RestMethod -Method Post -Uri $Uri -Headers @{ Authorization = "Bearer $Token" } -ContentType 'application/json' -Body $Json -TimeoutSec $TimeoutSec) }
    }
    catch {
        $msg = $_.Exception.Message; $status = 0; $retry = $null
        try { $status = [int]$_.Exception.Response.StatusCode } catch { }
        try { $delta = $_.Exception.Response.Headers.RetryAfter.Delta; if ($delta) { $retry = [int][Math]::Ceiling($delta.TotalSeconds) } } catch { }
        try { $err = $_.ErrorDetails.Message | ConvertFrom-Json; if ($err.error.message) { $msg = [string]$err.error.message } } catch { }
        @{ ok = $false; status = $status; retryAfter = $retry; message = $msg }
    }
}

$script:GapsioOpenAIMaxWaitSeconds = 20

function Invoke-GapsioOpenAI {
    <#
    .SYNOPSIS
    One call to the Azure OpenAI data-plane (chat/completions or embeddings) with the managed identity. Throws with the
    service's error message. A rate limit (HTTP 429) is retried once when the service asks for a short wait; otherwise
    the error says what to do: the deployment has too few tokens per minute.
    #>
    param([Parameter(Mandatory)][ValidateSet('chat/completions', 'embeddings')][string]$Operation, [Parameter(Mandatory)][string]$Deployment, [Parameter(Mandatory)]$Body, [int]$TimeoutSec = 60)
    $endpoint = (Get-GapsioSetting -Name 'GAPSIO_AI_ENDPOINT').TrimEnd('/')
    $apiVersion = Get-GapsioSetting -Name 'GAPSIO_AI_API_VERSION' -Default '2024-10-21'
    $token = Get-GapsioToken -Resource 'https://cognitiveservices.azure.com'
    $uri = "$endpoint/openai/deployments/$([uri]::EscapeDataString($Deployment))/${Operation}?api-version=$apiVersion"
    $json = $Body | ConvertTo-Json -Depth 12 -Compress
    for ($attempt = 1; ; $attempt++) {
        $r = Send-GapsioOpenAIRequest -Uri $uri -Token $token -Json $json -TimeoutSec $TimeoutSec
        if ($r.ok) { return $r.data }
        if ($r.status -eq 429 -or [string]$r.message -match 'rate limit') {
            $wait = if ($null -ne $r.retryAfter) { [int]$r.retryAfter } elseif ([string]$r.message -match 'retry after (\d+) second') { [int]$Matches[1] } else { 10 }
            if ($attempt -eq 1 -and $wait -le $script:GapsioOpenAIMaxWaitSeconds) { if ($wait -gt 0) { Start-Sleep -Seconds $wait }; continue }
            throw [System.Exception]::new("Azure OpenAI rate limit: the deployment '$Deployment' has too few tokens per minute for this question (a question with tool calls needs 6,000 to 12,000 tokens). Wait a minute and ask again, or raise the capacity of the deployment – 50 (50,000 tokens per minute) is a sensible size; see docs/operations. [$($r.message)]")
        }
        throw [System.Exception]::new("Azure OpenAI $Operation failed: $($r.message)")
    }
}

function Get-GapsioEmbeddings {
    # Returns float[][] for the given texts, or $null when no embedding deployment is configured.
    param([Parameter(Mandatory)][string[]]$Texts)
    $dep = Get-GapsioSetting -Name 'GAPSIO_AI_EMBEDDING_DEPLOYMENT'
    if ([string]::IsNullOrWhiteSpace($dep)) { return $null }
    $out = [System.Collections.Generic.List[object]]::new()
    # 64 texts per request: the whole knowledge index is a handful of calls instead of a dozen
    for ($i = 0; $i -lt $Texts.Count; $i += 64) {
        $batch = @($Texts[$i..([Math]::Min($i + 63, $Texts.Count - 1))])
        $r = Invoke-GapsioOpenAI -Operation 'embeddings' -Deployment $dep -Body @{ input = $batch } -TimeoutSec 90
        foreach ($d in @($r.data | Sort-Object index)) { $out.Add([float[]]$d.embedding) }
    }
    $out.ToArray()
}

function Get-GapsioCosine {
    param([float[]]$A, [float[]]$B)
    if (-not $A -or -not $B -or $A.Length -ne $B.Length) { return 0.0 }
    [double]$dot = 0; [double]$na = 0; [double]$nb = 0
    for ($i = 0; $i -lt $A.Length; $i++) { $dot += $A[$i] * $B[$i]; $na += $A[$i] * $A[$i]; $nb += $B[$i] * $B[$i] }
    if ($na -eq 0 -or $nb -eq 0) { return 0.0 }
    $dot / ([Math]::Sqrt($na) * [Math]::Sqrt($nb))
}
#endregion

#region Knowledge index (docs + baseline → chunks → embeddings in blob state/assistant-index.json)
function Get-GapsioKnowledgeSources {
    <#
    .SYNOPSIS
    Text chunks the assistant may cite: the product docs shipped in config/knowledge/*.md (copies of the pages under
    docs/, a test keeps them identical) split by heading, plus one chunk per MDAV baseline setting. No tenant data.
    #>
    $chunks = [System.Collections.Generic.List[object]]::new()
    $root = Join-Path $PSScriptRoot '..' '..' 'config'
    $kdir = Join-Path $root 'knowledge'
    if (Test-Path $kdir) {
        foreach ($f in Get-ChildItem -Path $kdir -Filter '*.md' -File | Sort-Object Name) {
            $doc = $f.BaseName
            $title = $doc; $buf = [System.Text.StringBuilder]::new(); $section = ''
            $flush = {
                $t = $buf.ToString().Trim()
                if ($t.Length -gt 80) {
                    # long sections → ~1500-char windows so one chunk stays focused
                    $pos = 0
                    while ($pos -lt $t.Length) {
                        $len = [Math]::Min(1500, $t.Length - $pos)
                        if ($pos + $len -lt $t.Length) { $nl = $t.LastIndexOf("`n", $pos + $len, $len); if ($nl -gt $pos + 400) { $len = $nl - $pos } }
                        $chunks.Add([ordered]@{ source = "docs/$doc.md"; title = $(if ($section) { "$title › $section" } else { $title }); text = $t.Substring($pos, $len).Trim() })
                        $pos += $len
                    }
                }
                [void]$buf.Clear()
            }
            foreach ($line in Get-Content -Path $f.FullName -Encoding utf8) {
                if ($line -match '^#\s+(.+)') { & $flush; $title = $Matches[1].Trim(); $section = ''; continue }
                if ($line -match '^##+\s+(.+)') { & $flush; $section = $Matches[1].Trim(); continue }
                [void]$buf.AppendLine($line)
            }
            & $flush
        }
    }
    $bl = Join-Path $root 'mdav-baseline.json'
    if (Test-Path $bl) {
        try {
            $b = Get-Content -Path $bl -Raw -Encoding utf8 | ConvertFrom-Json
            $both = { param($v) $x = ConvertTo-GapsioText $v; if (-not $x) { return '' }; if ($x.de -and $x.de -ne $x.en) { "$($x.en) (DE: $($x.de))" } else { [string]$x.en } }
            foreach ($c in @($b.checks)) {
                if (-not $c) { continue }
                $title = [string](ConvertTo-GapsioText (Get-GapsioProp $c 'title')).en; if (-not $title) { $title = [string](Get-GapsioProp $c 'id') }
                $parts = @("MDAV baseline check: $(& $both (Get-GapsioProp $c 'title'))",
                    "id: $(Get-GapsioProp $c 'id'); platform: $(Get-GapsioProp $c 'platform'); severity: $(Get-GapsioProp $c 'severity'); category: $([string](ConvertTo-GapsioText (Get-GapsioProp $c 'category')).en)")
                foreach ($k in @(@('expectText', 'Expected'), @('rationale', 'Why'), @('remediation', 'How to fix'))) { $v = & $both (Get-GapsioProp $c $k[0]); if ($v) { $parts += "$($k[1]): $v" } }
                $chunks.Add([ordered]@{ source = 'config/mdav-baseline.json'; title = "Baseline › $title ($(Get-GapsioProp $c 'platform'))"; text = ($parts -join "`n") })
            }
            $asr = @($b.asrRules | Where-Object { $_ })
            if ($asr.Count) {
                $names = @{}; foreach ($r in $script:GapsioAsrRules) { $names[[string]$r.id] = [string]$r.name }
                # All rules in one chunk: a question like "which rules must be in block mode" needs the whole list
                $rows = @($asr | ForEach-Object { $id = [string](Get-GapsioProp $_ 'id'); "- $(if ($names[$id]) { $names[$id] } else { $id }): minimum $(Get-GapsioProp $_ 'minimum'), recommended $(Get-GapsioProp $_ 'recommended'), severity $(Get-GapsioProp $_ 'severity'). $([string](ConvertTo-GapsioText (Get-GapsioProp $_ 'note')).en)" })
                $chunks.Add([ordered]@{ source = 'config/mdav-baseline.json'; title = 'Baseline › Attack surface reduction (ASR) rules: expected and recommended mode'; text = "MDAV baseline: all $($rows.Count) attack surface reduction (ASR) rules with the mode Gapsio expects at least (minimum: Block, Audit or Warn) and the mode it recommends. ASR-Regeln der Baseline mit Mindest- und empfohlenem Modus.`n" + ($rows -join "`n") })
            }
        }
        catch { Write-Warning "Assistant knowledge: the baseline could not be read: $($_.Exception.Message)" }
    }
    $chunks.ToArray()
}

function Get-GapsioKnowledgeHash {
    param($Chunks)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($c in $Chunks) { [void]$sb.Append($c.title).Append('|').Append($c.text).Append(';') }
    [void]$sb.Append((Get-GapsioSetting -Name 'GAPSIO_AI_EMBEDDING_DEPLOYMENT' -Default ''))
    Get-GapsioHash $sb.ToString()
}

$script:GapsioAssistantIndexCache = $null
$script:GapsioAssistantSources = $null

function Update-GapsioAssistantIndex {
    <#
    .SYNOPSIS
    (Re)builds state/assistant-index.json when the sources or the embedding deployment changed. Returns the index.
    Without an embedding deployment – or when embedding fails (rate limit, deployment gone) – the index holds the
    chunks only and search falls back to keyword scoring; embedding is tried again after 30 minutes. The index of
    the current sources is kept in memory, so a question does not download it again.
    #>
    param([switch]$Force)
    # The pages ship with the Function App and only change with a new version: read and split them once per worker
    if ($Force -or -not $script:GapsioAssistantSources) { $c = @(Get-GapsioKnowledgeSources); $script:GapsioAssistantSources = @{ chunks = $c; hash = (Get-GapsioKnowledgeHash -Chunks $c); deployment = (Get-GapsioSetting -Name 'GAPSIO_AI_EMBEDDING_DEPLOYMENT' -Default '') } }
    if ($script:GapsioAssistantSources.deployment -ne (Get-GapsioSetting -Name 'GAPSIO_AI_EMBEDDING_DEPLOYMENT' -Default '')) { $script:GapsioAssistantSources.hash = Get-GapsioKnowledgeHash -Chunks $script:GapsioAssistantSources.chunks; $script:GapsioAssistantSources.deployment = (Get-GapsioSetting -Name 'GAPSIO_AI_EMBEDDING_DEPLOYMENT' -Default '') }
    $chunks = @($script:GapsioAssistantSources.chunks)
    $hash = $script:GapsioAssistantSources.hash
    $wantVectors = -not [string]::IsNullOrWhiteSpace((Get-GapsioSetting -Name 'GAPSIO_AI_EMBEDDING_DEPLOYMENT' -Default ''))
    $current = {
        param($ix)
        if (-not $ix -or $ix.hash -ne $hash) { return $false }
        if ($ix.embedded -or -not $wantVectors) { return $true }
        $built = [DateTime]::MinValue; try { $built = ConvertTo-GapsioUtc $ix.builtAt } catch { }
        $built -gt [DateTime]::UtcNow.AddMinutes(-30)   # keyword-only index: try the embedding again later
    }
    if (-not $Force -and (& $current $script:GapsioAssistantIndexCache)) { return $script:GapsioAssistantIndexCache }
    $ix = $null; try { $ix = Get-GapsioBlob -Container 'state' -Name 'assistant-index.json' } catch { $ix = $null }
    if (-not $Force -and (& $current $ix)) { $script:GapsioAssistantIndexCache = $ix; return $ix }
    $vecs = $null; $embedError = $null
    if ($chunks.Count -and $wantVectors) {
        try { $vecs = Get-GapsioEmbeddings -Texts @($chunks | ForEach-Object { "$($_.title)`n$($_.text)" }) }
        catch { $vecs = $null; $embedError = [string]$_.Exception.Message; Write-Warning "Assistant knowledge index: embedding failed, keyword search is used. $embedError" }
        if ($vecs -and @($vecs).Count -ne $chunks.Count) { $vecs = $null; $embedError = 'The embedding deployment returned fewer vectors than texts.' }
    }
    $items = for ($i = 0; $i -lt $chunks.Count; $i++) {
        [ordered]@{ id = $i; source = $chunks[$i].source; title = $chunks[$i].title; text = $chunks[$i].text; vec = $(if ($vecs) { $vecs[$i] } else { $null }) }
    }
    $ix = [ordered]@{ builtAt = [DateTime]::UtcNow.ToString('o'); hash = $hash; embedded = [bool]$vecs; embedError = $embedError; embeddingDeployment = (Get-GapsioSetting -Name 'GAPSIO_AI_EMBEDDING_DEPLOYMENT' -Default ''); count = $chunks.Count; chunks = @($items) }
    try { Set-GapsioBlob -Container 'state' -Name 'assistant-index.json' -Object $ix } catch { Write-Warning "Assistant knowledge index could not be stored: $($_.Exception.Message)" }
    $script:GapsioAssistantIndexCache = $ix
    $ix
}

function Search-GapsioKnowledge {
    <#
    .SYNOPSIS
    Semantic search over the knowledge index (cosine similarity on embeddings), keyword fallback. Returns top chunks.
    #>
    param([Parameter(Mandatory)][string]$Query, [int]$Top = 4)
    $ix = Update-GapsioAssistantIndex
    if (-not $ix -or -not $ix.chunks) { return @() }
    $scored = [System.Collections.Generic.List[object]]::new()
    $qv = $null
    if ($ix.embedded) { try { $qv = @(Get-GapsioEmbeddings -Texts @($Query))[0] } catch { $qv = $null } }   # no vector for the question: keyword scoring below
    $terms = @(($Query.ToLowerInvariant() -split '[^\p{L}\p{Nd}]+') | Where-Object { $_.Length -gt 2 } | Select-Object -Unique)
    foreach ($c in $ix.chunks) {
        $s = 0.0
        if ($qv -and $c.vec) { $s = Get-GapsioCosine -A ([float[]]$c.vec) -B $qv }
        else {
            $hay = ("$($c.title) $($c.text)").ToLowerInvariant()
            foreach ($t in $terms) { if ($hay.Contains($t)) { $s += 1.0 + $(if ($c.title.ToLowerInvariant().Contains($t)) { 1.0 } else { 0.0 }) } }
            if ($terms.Count) { $s = $s / (2.0 * $terms.Count) }
        }
        if ($s -gt 0) { $scored.Add([pscustomobject]@{ score = $s; chunk = $c }) }
    }
    @($scored | Sort-Object score -Descending | Select-Object -First $Top | ForEach-Object {
            [ordered]@{ source = [string]$_.chunk.source; title = [string]$_.chunk.title; score = [Math]::Round($_.score, 3); text = [string]$_.chunk.text }
        })
}
#endregion

#region Tools (what the model may call; every tool is read-only and bounded)
$script:GapsioAssistantTools = @(
    @{ type = 'function'; function = @{ name = 'search_findings'; description = 'Search the stored findings of the last run. Use for questions about problems, severities, categories, counts, a specific device or subject.'; parameters = @{ type = 'object'; properties = @{
                    module   = @{ type = 'string'; description = 'endpoint | agents | access | licensing | officepreview (omit for all)' }
                    severity = @{ type = 'string'; enum = @('Critical', 'High', 'Medium', 'Low') }
                    category = @{ type = 'string'; description = 'finding category as shown in the portal, e.g. exclusions, asr, baseline, coverage, hygiene, updates' }
                    query    = @{ type = 'string'; description = 'free text matched against title, device, subject and detail' }
                    limit    = @{ type = 'integer'; minimum = 1; maximum = 50 }
                }; required = @() } } }
    @{ type = 'function'; function = @{ name = 'search_devices'; description = 'Find devices in the endpoint inventory by name, user, OS, group. Returns the protection state, the failed checks, whether the device still reports, and the device id for #/device?id=.'; parameters = @{ type = 'object'; properties = @{
                    query      = @{ type = 'string' }
                    issuesOnly = @{ type = 'boolean' }
                    limit      = @{ type = 'integer'; minimum = 1; maximum = 25 }
                }; required = @('query') } } }
    @{ type = 'function'; function = @{ name = 'get_device'; description = 'Full stored record of one device (settings, ASR, exclusions, tamper protection, findings) by device id or exact name.'; parameters = @{ type = 'object'; properties = @{
                    deviceId = @{ type = 'string' }; name = @{ type = 'string' } }; required = @() } } }
    @{ type = 'function'; function = @{ name = 'device_live_status'; description = 'LIVE data from Microsoft Defender Advanced Hunting for one device (not from the snapshot): last seen, OS, onboarding/health, sensor state, alerts in the last 7 days, failed secure-configuration checks. Use when the user asks what is happening now / today / currently.'; parameters = @{ type = 'object'; properties = @{
                    deviceName = @{ type = 'string'; description = 'host name as shown in Defender, e.g. PC-0123' } }; required = @('deviceName') } } }
    @{ type = 'function'; function = @{ name = 'tenant_live_summary'; description = 'LIVE tenant-wide numbers from Defender Advanced Hunting (last 7 days): onboarded devices seen, devices with high/critical alerts, devices with inactive sensors, top failed secure-configuration checks. Use for "how are we doing right now" questions.'; parameters = @{ type = 'object'; properties = @{}; required = @() } } }
    @{ type = 'function'; function = @{ name = 'search_docs'; description = 'Semantic search in the Gapsio documentation and the MDAV baseline rationale (what a setting means, why Gapsio recommends it, how a view works, permissions, limitations). Cite the returned titles.'; parameters = @{ type = 'object'; properties = @{
                    query = @{ type = 'string' }; limit = @{ type = 'integer'; minimum = 1; maximum = 6 } }; required = @('query') } } }
)

function ConvertTo-GapsioKqlString { param([string]$Value) '"' + ($Value -replace '\\', '\\\\' -replace '"', '\"') + '"' }

function Invoke-GapsioAssistantTool {
    <#
    .SYNOPSIS
    Executes one tool call. Returns an object (serialised for the model, capped). Never throws – errors go back to
    the model as { error } so it can tell the user.
    #>
    param([Parameter(Mandatory)][string]$Name, $Arguments, [string]$Lang = 'en')
    $modules = @(Get-GapsioModules)
    # One live hunting query (last 7 days). Returns the rows as an array – or @{ error } when the query failed, so
    # the model never mistakes a failed query for "nothing found".
    $live = {
        param([string]$Query)
        try { , @(Invoke-GapsioHunting -Query $Query -Timespan 'P7D' | Where-Object { $_ }) }
        catch { @{ error = "This live query failed: $(Get-GapsioErrorText -Exception $_.Exception -Context 'assistant ThreatHunting.Read.All')" } }
    }
    try {
        switch ($Name) {
            'search_findings' {
                $mods = $(if ($Arguments.module) { @([string]$Arguments.module) } else { $modules })
                $limit = [Math]::Min(50, [Math]::Max(1, [int]$(if ($Arguments.limit) { $Arguments.limit } else { 20 })))
                $q = ([string]$Arguments.query).Trim().ToLowerInvariant()
                $hits = [System.Collections.Generic.List[object]]::new(); $total = 0
                $sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
                foreach ($m in $mods) {
                    if ($m -notin $modules) { continue }
                    $snap = $null; try { $snap = Get-GapsioBlob -Container 'state' -Name (Get-GapsioAssistantSnapshotName -Module $m) } catch { }
                    foreach ($f in @($snap.findings)) {
                        if ($Arguments.severity -and [string]$f.severity -ne [string]$Arguments.severity) { continue }
                        if ($Arguments.category -and [string]$f.category -notlike "*$($Arguments.category)*") { continue }
                        $line = Get-GapsioAssistantFindingText -Finding $f -Lang $Lang
                        if ($q -and -not $line.ToLowerInvariant().Contains($q)) { continue }
                        $total++
                        $hits.Add([pscustomobject]@{ o = $(if ($sevOrder.ContainsKey([string]$f.severity)) { $sevOrder[[string]$f.severity] } else { 9 }); module = $m; text = $line; deviceId = [string]$f.deviceId; id = [string]$f.id })
                    }
                }
                $rows = @($hits | Sort-Object o | Select-Object -First $limit | ForEach-Object { [ordered]@{ module = $_.module; finding = $_.text; deviceId = $_.deviceId } })
                return [ordered]@{ total = $total; returned = $rows.Count; findings = $rows }
            }
            'search_devices' {
                if ($modules -notcontains 'endpoint') { return @{ error = 'endpoint module not enabled' } }
                $limit = [Math]::Min(25, [Math]::Max(1, [int]$(if ($Arguments.limit) { $Arguments.limit } else { 10 })))
                $res = Search-GapsioDevices -Query ([string]$Arguments.query) -IssuesOnly:([bool]$Arguments.issuesOnly) -Page 0 -Size $limit
                $rows = @(@($res.rows) | ForEach-Object { ConvertTo-GapsioAssistantDevice -Device $_ })
                return [ordered]@{ total = $res.total; returned = $rows.Count; devices = $rows }
            }
            'get_device' {
                if ($modules -notcontains 'endpoint') { return @{ error = 'endpoint module not enabled' } }
                $d = $null
                if ($Arguments.deviceId) { $d = Get-GapsioDevice -DeviceId ([string]$Arguments.deviceId) }
                elseif ($Arguments.name) {
                    # The exact name wins over partial matches (WIN-01 vs WIN-010). Kept in a variable: inside a
                    # Where-Object block $args is the block's own automatic variable.
                    $wanted = ([string]$Arguments.name).Trim()
                    $r = Search-GapsioDevices -Query $wanted -Page 0 -Size 25
                    $d = @($r.rows) | Where-Object { [string]$_.deviceName -eq $wanted } | Select-Object -First 1
                    if (-not $d -and @($r.rows).Count -eq 1) { $d = $r.rows[0] }
                    if ($d -and $d.deviceId) { $full = Get-GapsioDevice -DeviceId ([string]$d.deviceId); if ($full) { $d = $full } }
                }
                if (-not $d) { return @{ error = 'device not found in the snapshot' } }
                # Same date format as everywhere else; the stored record keeps its other fields as they are
                $copy = [ordered]@{}
                foreach ($prop in $(if ($d -is [System.Collections.IDictionary]) { $d.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Name = $_.Key; Value = $_.Value } } } else { $d.PSObject.Properties })) {
                    if ($prop.Name.StartsWith('_') -or $prop.Name -in 'key', 'fp', 'label', 'state') { continue }
                    $copy[$prop.Name] = $(if ($prop.Value -is [datetime] -or ($prop.Value -is [string] -and $prop.Value -match '^\d{1,2}/\d{1,2}/\d{4} \d{2}:\d{2}:\d{2}$') -or $prop.Name -in 'lastSeen', 'inventoryAt', 'troubleshootingLast', 'tamperingLast') { ConvertTo-GapsioAssistantTime $prop.Value } else { $prop.Value })
                }
                $json = $copy | ConvertTo-Json -Depth 6 -Compress
                if ($json.Length -gt 9000) { $json = $json.Substring(0, 9000) + '…(truncated)' }
                return [ordered]@{ device = $json }
            }
            'device_live_status' {
                $name = ([string]$Arguments.deviceName).Trim()
                if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9\-\._]{0,62}$') { return @{ error = 'invalid device name' } }
                if (-not (Test-GapsioFeature -Name 'hunting')) { return @{ error = 'Advanced Hunting (ThreatHunting.Read.All) is not enabled in this installation – live data unavailable; use the snapshot tools.' } }
                $n = ConvertTo-GapsioKqlString $name
                $info = & $live @"
DeviceInfo
| where DeviceName =~ $n or DeviceName startswith strcat($n, ".")
| summarize arg_max(Timestamp, OSPlatform, OSVersionInfo, OnboardingStatus, SensorHealthState, IsAzureADJoined, JoinType, MachineGroup, LoggedOnUsers, ExposureLevel, DeviceId) by DeviceName
| project DeviceName, DeviceId, LastSeen = Timestamp, OSPlatform, OSVersionInfo, OnboardingStatus, SensorHealthState, IsAzureADJoined, JoinType, MachineGroup, ExposureLevel
"@
                $alerts = & $live @"
AlertEvidence
| where DeviceName =~ $n or DeviceName startswith strcat($n, ".")
| join kind=inner (AlertInfo | project AlertId, Title, Severity, Category, DetectionSource, Timestamp) on AlertId
| summarize Count = count(), Last = max(Timestamp) by Title, Severity, Category, DetectionSource
| top 10 by Last desc
"@
                $cfg = & $live @"
DeviceTvmSecureConfigurationAssessment
| where DeviceName =~ $n or DeviceName startswith strcat($n, ".")
| where IsCompliant == 0 and IsApplicable == 1
| join kind=leftouter (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, ConfigurationImpact, RiskDescription) on ConfigurationId
| project ConfigurationId, ConfigurationName, ConfigurationImpact
| top 15 by ConfigurationImpact desc
"@
                $out = [ordered]@{ asOf = [DateTime]::UtcNow.ToString('o'); source = 'Microsoft Defender Advanced Hunting (live, last 7 days)'; device = $info; alertsLast7d = $alerts; failedSecureConfiguration = $cfg }
                if ($info -is [array] -and -not $info.Count) { $out.note = 'No device information in the last 7 days: the device did not report in that time, or the name is not known to Defender. The secure configuration list is the last assessment Defender keeps.' }
                elseif ($info -is [array]) { $out.device = $info[0] }
                return $out
            }
            'tenant_live_summary' {
                if (-not (Test-GapsioFeature -Name 'hunting')) { return @{ error = 'Advanced Hunting (ThreatHunting.Read.All) is not enabled in this installation – live data unavailable.' } }
                $dev = & $live @"
DeviceInfo
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, SensorHealthState, OSPlatform) by DeviceId
| summarize DevicesSeen7d = dcount(DeviceId), InactiveSensors = dcountif(DeviceId, SensorHealthState != "Active"), Windows = dcountif(DeviceId, OSPlatform startswith "Windows"), macOS = dcountif(DeviceId, OSPlatform == "macOS"), Linux = dcountif(DeviceId, OSPlatform == "Linux")
"@
                $al = & $live @"
AlertInfo
| summarize Alerts = count(), High = countif(Severity == "High"), Medium = countif(Severity == "Medium"), Low = countif(Severity == "Low"), Informational = countif(Severity == "Informational")
"@
                $alDev = & $live @"
AlertEvidence
| where EntityType == "Machine" and isnotempty(DeviceId)
| join kind=inner (AlertInfo | where Severity in ("High", "Medium") | project AlertId) on AlertId
| summarize DevicesWithHighMediumAlerts = dcount(DeviceId)
"@
                $cfg = & $live @"
DeviceTvmSecureConfigurationAssessment
| where IsCompliant == 0 and IsApplicable == 1
| summarize Devices = dcount(DeviceId) by ConfigurationId
| join kind=leftouter (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, ConfigurationImpact) on ConfigurationId
| top 10 by Devices desc
| project ConfigurationId, ConfigurationName, Devices, ConfigurationImpact
"@
                $first = { param($x) if ($x -is [array]) { if ($x.Count) { $x[0] } else { $null } } else { $x } }
                $out = [ordered]@{ asOf = [DateTime]::UtcNow.ToString('o'); source = 'Microsoft Defender Advanced Hunting (live, last 7 days)'; devices = (& $first $dev); alerts = (& $first $al); alertDevices = (& $first $alDev); topFailedSecureConfiguration = $cfg }
                $seen = Get-GapsioProp $out.devices 'DevicesSeen7d'
                if ($dev -is [array] -and (-not $dev.Count -or [int]$seen -eq 0)) { $out.note = 'NO onboarded device reported in the last 7 days. The numbers here are empty because nothing reported – they do not mean that sensors are healthy or that the configuration is fine. Use the snapshot (devices not reporting, coverage gaps) for the last known state.' }
                return $out
            }
            'search_docs' {
                $limit = [Math]::Min(6, [Math]::Max(1, [int]$(if ($Arguments.limit) { $Arguments.limit } else { 4 })))
                $hits = @(Search-GapsioKnowledge -Query ([string]$Arguments.query) -Top $limit)
                return [ordered]@{ returned = $hits.Count; results = $hits }
            }
            default { return @{ error = "unknown tool $Name" } }
        }
    }
    catch { return @{ error = [string]$_.Exception.Message } }
}
#endregion

function Resolve-GapsioAssistantLink {
    <#
    .SYNOPSIS
    Portal route for a link the model proposed, or $null. Only known views pass. Device links are checked against the
    snapshot: #/device?id= needs a device ID that exists – a device name or an unknown ID becomes a search in the
    device list (#/devices?q=), and #/devices?id= is corrected to the device page.
    #>
    param([string]$View, [string[]]$Allowed)
    $v = $View.Trim() -replace '^#?/?', ''
    if (-not $v -or $v -match '[<>"''\s]') { return $null }
    $name, $query = $v -split '\?', 2
    if ($name -notin $Allowed) { return $null }
    if ($name -notin 'device', 'devices') { return $v }
    $value = ''; $key = ''
    if ($query -match '^(id|q)=([^&]+)') { $key = $Matches[1]; $value = [uri]::UnescapeDataString($Matches[2]) }
    if (-not $value) { return 'devices' }
    if ($key -eq 'id' -or $name -eq 'device') {
        $exists = $false
        try { $exists = [bool](Get-GapsioDevice -DeviceId $value) } catch { $exists = $false }
        if ($exists) { return "device?id=$([uri]::EscapeDataString($value))" }
    }
    "devices?q=$([uri]::EscapeDataString($value))"
}

function Invoke-GapsioAssistant {
    <#
    .SYNOPSIS
    Answers a portal question with Azure OpenAI using tool calling: the model may look up stored findings/devices,
    query Defender Advanced Hunting live and search the Gapsio docs, then answers as JSON.
    Returns @{ answer; links = @(@{view;label}); sources; tools; usage; tookMs }.
    #>
    param([Parameter(Mandatory)][string]$Question, $History, [string]$Lang = 'en', [string]$User = '')
    if (-not (Test-GapsioAssistant)) { throw [System.InvalidOperationException]::new('The assistant is not enabled in this installation.') }
    $Question = $Question.Trim()
    if (-not $Question) { throw [System.ArgumentException]::new('Question is empty.') }
    if ($Question.Length -gt 2000) { throw [System.ArgumentException]::new('Question is too long (max 2000 characters).') }
    if ($Lang -notin 'en', 'de') { $Lang = 'en' }

    $deployment = Get-GapsioSetting -Name 'GAPSIO_AI_DEPLOYMENT'
    $maxRounds = [Math]::Min(6, [Math]::Max(0, [int](Get-GapsioSetting -Name 'GAPSIO_AI_TOOL_ROUNDS' -Default '4')))
    $context = Get-GapsioAssistantContext -Question $Question -Lang $Lang
    $langName = $(if ($Lang -eq 'de') { 'German' } else { 'English' })
    $hunting = [bool](Test-GapsioFeature -Name 'hunting')

    $system = @"
You are the Gapsio Assistant inside the Gapsio portal, a read-only security posture tool for Microsoft Defender for Endpoint, Defender for Office 365, Intune, Entra ID and AI agents, self-hosted in the customer's Azure subscription.
You have tools. Use them instead of guessing:
- search_findings / search_devices / get_device read the stored snapshot of the last Gapsio run (the same data the portal shows).
- device_live_status / tenant_live_summary query Microsoft Defender Advanced Hunting LIVE$(if (-not $hunting) { ' (NOT available in this installation – say so if asked for live data)' }). Use them when the user asks about "now", "today", "currently", alerts, last seen, or wants to verify a snapshot finding against the current state. Always state that these numbers are live and from which time window.
- search_docs explains Gapsio views, the MDAV baseline rationale, permissions and limitations. Cite the titles you used.
Rules:
- Never invent devices, numbers, policies or findings. Quote numbers exactly as returned. If a tool returns an error or nothing, say so and point to the view where the user can look, or suggest starting a run ("Collect now"). A part of a tool result that carries "error" was NOT read – never report it as zero or as "none".
- A device marked "not reporting" has not sent data for days: say that its state is the last known one.
- Distinguish snapshot data (generatedAt in CONTEXT) from live data (tool asOf).
- Gapsio is read-only: never claim it changed or will change anything. Recommendations are for the admin to apply in Intune / Defender / Entra.
- Be concise (max ~200 words), use short bullet points when listing. Reply in $langName.
- When a portal view helps, add it to "links" (only routes from the CONTEXT view list; devices may use #/devices?q=<name> and #/device?id=<deviceId>).
- Final output strictly JSON: {"answer": string, "links": [{"view": "#/route", "label": string}], "sources": [string]} where sources lists doc titles or "live: Advanced Hunting" / "snapshot" as applicable.
CONTEXT:
$context
"@
    $messages = [System.Collections.Generic.List[object]]::new()
    $messages.Add(@{ role = 'system'; content = $system })
    foreach ($h in @($History | Select-Object -Last 6)) {
        $r = [string](Get-GapsioProp $h 'role'); $c = [string](Get-GapsioProp $h 'content')
        if ($r -in 'user', 'assistant' -and $c) { $messages.Add(@{ role = $r; content = $c.Substring(0, [Math]::Min($c.Length, 1500)) }) }
    }
    $messages.Add(@{ role = 'user'; content = $Question })

    $userTag = $(if ($User) { Get-GapsioHash $User } else { 'portal' })
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $toolsUsed = [System.Collections.Generic.List[object]]::new()
    $promptTokens = 0; $completionTokens = 0; $model = ''
    $r = $null
    for ($round = 0; $round -le $maxRounds; $round++) {
        # JSON mode in every round: an answer is always the JSON object the portal expects, also when the model
        # answers straight after a tool call. In the last round the tools are withheld, so it has to answer.
        $body = @{ messages = $messages.ToArray(); temperature = 0.2; max_tokens = 900; user = $userTag; response_format = @{ type = 'json_object' } }
        if ($round -lt $maxRounds) { $body.tools = $script:GapsioAssistantTools; $body.tool_choice = 'auto' }
        $r = Invoke-GapsioOpenAI -Operation 'chat/completions' -Deployment $deployment -Body $body -TimeoutSec 90
        if ($r.usage) { $promptTokens += [int]$r.usage.prompt_tokens; $completionTokens += [int]$r.usage.completion_tokens }
        $model = [string]$r.model
        $choice = $r.choices[0]
        # A final answer has no tool_calls property at all – @($null) would count as one (empty) call
        $calls = @($choice.message.tool_calls | Where-Object { $_ -and $_.function -and $_.function.name })
        if (-not $calls.Count) { break }
        # echo the assistant turn (with tool_calls) then one tool message per call
        $messages.Add(@{ role = 'assistant'; content = $(if ($choice.message.content) { [string]$choice.message.content } else { $null }); tool_calls = @($calls | ForEach-Object { @{ id = $_.id; type = 'function'; function = @{ name = $_.function.name; arguments = [string]$_.function.arguments } } }) })
        foreach ($c in $calls) {
            $toolArgs = @{}
            try { if ($c.function.arguments) { $toolArgs = $c.function.arguments | ConvertFrom-Json } } catch { $toolArgs = @{} }
            $tsw = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Invoke-GapsioAssistantTool -Name $c.function.name -Arguments $toolArgs -Lang $Lang
            $json = $result | ConvertTo-Json -Depth 8 -Compress
            if ($json.Length -gt 12000) { $json = $json.Substring(0, 12000) + '…(truncated)' }
            $toolsUsed.Add([ordered]@{ name = $c.function.name; args = $toolArgs; ms = $tsw.ElapsedMilliseconds; ok = -not [bool](Get-GapsioProp $result 'error') })
            $messages.Add(@{ role = 'tool'; tool_call_id = $c.id; content = $json })
        }
    }
    $content = [string]$r.choices[0].message.content
    $finish = [string]$r.choices[0].finish_reason
    if ([string]::IsNullOrWhiteSpace($content)) { throw [System.Exception]::new("The model returned no answer (finish reason: $(if ($finish) { $finish } else { 'unknown' })). Ask again or rephrase the question.") }
    $answer = $content; $links = @(); $sources = @()
    try {
        $j = $content | ConvertFrom-Json
        if ($j.answer) { $answer = [string]$j.answer }
        $allowed = @($script:GapsioAssistantViews | ForEach-Object { $_.view }) + @('device', 'devices')
        $links = @(@($j.links) | Where-Object { $_ -and $_.view } | ForEach-Object {
                $v = Resolve-GapsioAssistantLink -View ([string]$_.view) -Allowed $allowed
                if ($v) { [ordered]@{ view = "#/$v"; label = [string]$(if ($_.label) { $_.label } else { ($v -split '\?')[0] }) } }
            } | Select-Object -First 5)
        $sources = @(@($j.sources) | Where-Object { $_ } | ForEach-Object { ([string]$_).Substring(0, [Math]::Min(([string]$_).Length, 120)) } | Select-Object -First 8)
    }
    catch {
        # Not valid JSON: either prose despite the instruction (strip a stray code fence), or JSON cut off at the token
        # limit – then show the answer text that is there instead of raw JSON
        $answer = ($content -replace '^\s*```(json)?\s*', '' -replace '\s*```\s*$', '').Trim()
        if ($answer -match '(?s)^\{\s*"answer"\s*:\s*"((?:[^"\\]|\\.)*)') {
            $text = $Matches[1]
            try { $text = [string]("`"$text`"" | ConvertFrom-Json) } catch { $text = $text -replace '\\n', "`n" -replace '\\"', '"' }
            $answer = $text.Trim() + $(if ($finish -eq 'length') { ' …' } else { '' })
        }
    }
    [ordered]@{
        answer   = $answer
        links    = @($links)
        sources  = @($sources)
        tools    = @($toolsUsed)
        model    = $model
        usage    = [ordered]@{ prompt = $promptTokens; completion = $completionTokens }
        tookMs   = $sw.ElapsedMilliseconds
    }
}
