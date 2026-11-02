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


#region Azure OpenAI calls
function Invoke-WlOpenAI {
    <#
    .SYNOPSIS
    One call to the Azure OpenAI data-plane (chat/completions or embeddings) with the managed identity. Throws with the
    service's error message.
    #>
    param([Parameter(Mandatory)][ValidateSet('chat/completions', 'embeddings')][string]$Operation, [Parameter(Mandatory)][string]$Deployment, [Parameter(Mandatory)]$Body, [int]$TimeoutSec = 60)
    $endpoint = (Get-WlSetting -Name 'WL_AI_ENDPOINT').TrimEnd('/')
    $apiVersion = Get-WlSetting -Name 'WL_AI_API_VERSION' -Default '2024-10-21'
    $token = Get-WlToken -Resource 'https://cognitiveservices.azure.com'
    $uri = "$endpoint/openai/deployments/$([uri]::EscapeDataString($Deployment))/${Operation}?api-version=$apiVersion"
    try {
        Invoke-RestMethod -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 12 -Compress) -TimeoutSec $TimeoutSec
    }
    catch {
        $msg = $_.Exception.Message
        try { $err = $_.ErrorDetails.Message | ConvertFrom-Json; if ($err.error.message) { $msg = [string]$err.error.message } } catch { }
        throw [System.Exception]::new("Azure OpenAI $Operation failed: $msg")
    }
}

function Get-WlEmbeddings {
    # Returns float[][] for the given texts, or $null when no embedding deployment is configured.
    param([Parameter(Mandatory)][string[]]$Texts)
    $dep = Get-WlSetting -Name 'WL_AI_EMBEDDING_DEPLOYMENT'
    if ([string]::IsNullOrWhiteSpace($dep)) { return $null }
    $out = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $Texts.Count; $i += 16) {
        $batch = @($Texts[$i..([Math]::Min($i + 15, $Texts.Count - 1))])
        $r = Invoke-WlOpenAI -Operation 'embeddings' -Deployment $dep -Body @{ input = $batch } -TimeoutSec 90
        foreach ($d in @($r.data | Sort-Object index)) { $out.Add([float[]]$d.embedding) }
    }
    $out.ToArray()
}

function Get-WlCosine {
    param([float[]]$A, [float[]]$B)
    if (-not $A -or -not $B -or $A.Length -ne $B.Length) { return 0.0 }
    [double]$dot = 0; [double]$na = 0; [double]$nb = 0
    for ($i = 0; $i -lt $A.Length; $i++) { $dot += $A[$i] * $B[$i]; $na += $A[$i] * $A[$i]; $nb += $B[$i] * $B[$i] }
    if ($na -eq 0 -or $nb -eq 0) { return 0.0 }
    $dot / ([Math]::Sqrt($na) * [Math]::Sqrt($nb))
}
#endregion

#region Knowledge index (docs + baseline → chunks → embeddings in blob state/assistant-index.json)
function Get-WlKnowledgeSources {
    <#
    .SYNOPSIS
    Text chunks the assistant may cite: the product docs shipped in config/knowledge/*.md (copied from docs/ by the
    package build) split by heading, plus one chunk per MDAV baseline setting. No tenant data.
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
            foreach ($s in @($b.settings)) {
                $name = [string](Get-WlProp $s 'name'); if (-not $name) { $name = [string](Get-WlProp $s 'id') }
                $parts = @("MDAV baseline setting: $name")
                foreach ($k in 'id', 'definitionId', 'expected', 'minimum', 'severity', 'category', 'why', 'rationale', 'description', 'reference', 'docs') { $v = Get-WlProp $s $k; if ($v) { $parts += "${k}: $($v | ConvertTo-Json -Compress -Depth 3)" } }
                $chunks.Add([ordered]@{ source = 'config/mdav-baseline.json'; title = "Baseline › $name"; text = ($parts -join "`n") })
            }
        }
        catch { }
    }
    $chunks.ToArray()
}

function Get-WlKnowledgeHash {
    param($Chunks)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($c in $Chunks) { [void]$sb.Append($c.title).Append('|').Append($c.text.Length).Append(';') }
    [void]$sb.Append((Get-WlSetting -Name 'WL_AI_EMBEDDING_DEPLOYMENT' -Default ''))
    Get-WlHash $sb.ToString()
}

function Update-WlAssistantIndex {
    <#
    .SYNOPSIS
    (Re)builds state/assistant-index.json when the sources or the embedding deployment changed. Returns the index.
    Without an embedding deployment the index holds the chunks only and search falls back to keyword scoring.
    #>
    param([switch]$Force)
    $chunks = @(Get-WlKnowledgeSources)
    $hash = Get-WlKnowledgeHash -Chunks $chunks
    $ix = $null; try { $ix = Get-WlBlob -Container 'state' -Name 'assistant-index.json' } catch { $ix = $null }
    if (-not $Force -and $ix -and $ix.hash -eq $hash) { return $ix }
    $vecs = $null
    if ($chunks.Count) { $vecs = Get-WlEmbeddings -Texts @($chunks | ForEach-Object { "$($_.title)`n$($_.text)" }) }
    $items = for ($i = 0; $i -lt $chunks.Count; $i++) {
        [ordered]@{ id = $i; source = $chunks[$i].source; title = $chunks[$i].title; text = $chunks[$i].text; vec = $(if ($vecs) { $vecs[$i] } else { $null }) }
    }
    $ix = [ordered]@{ builtAt = [DateTime]::UtcNow.ToString('o'); hash = $hash; embedded = [bool]$vecs; embeddingDeployment = (Get-WlSetting -Name 'WL_AI_EMBEDDING_DEPLOYMENT' -Default ''); count = $chunks.Count; chunks = @($items) }
    Set-WlBlob -Container 'state' -Name 'assistant-index.json' -Object $ix
    $ix
}

function Search-WlKnowledge {
    <#
    .SYNOPSIS
    Semantic search over the knowledge index (cosine similarity on embeddings), keyword fallback. Returns top chunks.
    #>
    param([Parameter(Mandatory)][string]$Query, [int]$Top = 4)
    $ix = Update-WlAssistantIndex
    if (-not $ix -or -not $ix.chunks) { return @() }
    $scored = [System.Collections.Generic.List[object]]::new()
    $qv = $null
    if ($ix.embedded) { try { $qv = (Get-WlEmbeddings -Texts @($Query))[0] } catch { $qv = $null } }
    $terms = @(($Query.ToLowerInvariant() -split '[^\p{L}\p{Nd}]+') | Where-Object { $_.Length -gt 2 } | Select-Object -Unique)
    foreach ($c in $ix.chunks) {
        $s = 0.0
        if ($qv -and $c.vec) { $s = Get-WlCosine -A ([float[]]$c.vec) -B $qv }
        else {
            $hay = ("$($c.title) $($c.text)").ToLowerInvariant()
            foreach ($t in $terms) { if ($hay.Contains($t)) { $s += 1.0 + $(if ($c.title.ToLowerInvariant().Contains($t)) { 1.0 } else { 0.0 }) } }
            if ($terms.Count) { $s = $s / (2.0 * $terms.Count) }
        }
        if ($s -gt 0) { $scored.Add([pscustomobject]@{ score = $s; chunk = $c }) }
    }
    @($scored | Sort-Object score -Descending | Select-Object -First $Top | ForEach-Object {
            [ordered]@{ source = $_.chunk.source; title = $_.chunk.title; score = [Math]::Round($_.score, 3); text = $_.chunk.text }
        })
}
#endregion

#region Tools (what the model may call; every tool is read-only and bounded)
$script:WlAssistantTools = @(
    @{ type = 'function'; function = @{ name = 'search_findings'; description = 'Search the stored findings of the last run. Use for questions about problems, severities, categories, counts, a specific device or subject.'; parameters = @{ type = 'object'; properties = @{
                    module   = @{ type = 'string'; description = 'endpoint | agents | access | licensing | officepreview (omit for all)' }
                    severity = @{ type = 'string'; enum = @('Critical', 'High', 'Medium', 'Low') }
                    category = @{ type = 'string'; description = 'finding category as shown in the portal, e.g. exclusions, asr, baseline, coverage, hygiene, updates' }
                    query    = @{ type = 'string'; description = 'free text matched against title, device, subject and detail' }
                    limit    = @{ type = 'integer'; minimum = 1; maximum = 50 }
                }; required = @() } } }
    @{ type = 'function'; function = @{ name = 'search_devices'; description = 'Find devices in the endpoint inventory by name, user, OS, group. Returns risk, issues and the device id for #/device?id=.'; parameters = @{ type = 'object'; properties = @{
                    query      = @{ type = 'string' }
                    issuesOnly = @{ type = 'boolean' }
                    limit      = @{ type = 'integer'; minimum = 1; maximum = 25 }
                }; required = @('query') } } }
    @{ type = 'function'; function = @{ name = 'get_device'; description = 'Full stored record of one device (settings, ASR, exclusions, tamper protection, findings) by device id or exact name.'; parameters = @{ type = 'object'; properties = @{
                    deviceId = @{ type = 'string' }; name = @{ type = 'string' } }; required = @() } } }
    @{ type = 'function'; function = @{ name = 'device_live_status'; description = 'LIVE data from Microsoft Defender Advanced Hunting for one device (not from the snapshot): last seen, OS, onboarding/health, sensor state, alerts in the last 7 days, failed secure-configuration checks. Use when the user asks what is happening now / today / currently.'; parameters = @{ type = 'object'; properties = @{
                    deviceName = @{ type = 'string'; description = 'host name as shown in Defender, e.g. PC-0123' } }; required = @('deviceName') } } }
    @{ type = 'function'; function = @{ name = 'tenant_live_summary'; description = 'LIVE tenant-wide numbers from Defender Advanced Hunting (last 7 days): onboarded devices seen, devices with high/critical alerts, devices with inactive sensors, top failed secure-configuration checks. Use for "how are we doing right now" questions.'; parameters = @{ type = 'object'; properties = @{}; required = @() } } }
    @{ type = 'function'; function = @{ name = 'search_docs'; description = 'Semantic search in the Wardline documentation and the MDAV baseline rationale (what a setting means, why Wardline recommends it, how a view works, permissions, limitations). Cite the returned titles.'; parameters = @{ type = 'object'; properties = @{
                    query = @{ type = 'string' }; limit = @{ type = 'integer'; minimum = 1; maximum = 6 } }; required = @('query') } } }
)

function ConvertTo-WlKqlString { param([string]$Value) '"' + ($Value -replace '\\', '\\\\' -replace '"', '\"') + '"' }

function Invoke-WlAssistantTool {
    <#
    .SYNOPSIS
    Executes one tool call. Returns an object (serialised for the model, capped). Never throws – errors go back to
    the model as { error } so it can tell the user.
    #>
    param([Parameter(Mandatory)][string]$Name, $Args, [string]$Lang = 'en')
    $modules = @(Get-WlModules)
    try {
        switch ($Name) {
            'search_findings' {
                $mods = $(if ($Args.module) { @([string]$Args.module) } else { $modules })
                $limit = [Math]::Min(50, [Math]::Max(1, [int]$(if ($Args.limit) { $Args.limit } else { 20 })))
                $q = ([string]$Args.query).Trim().ToLowerInvariant()
                $hits = [System.Collections.Generic.List[object]]::new(); $total = 0
                $sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
                foreach ($m in $mods) {
                    if ($m -notin $modules) { continue }
                    $snap = $null; try { $snap = Get-WlBlob -Container 'state' -Name "$m-latest.json" } catch { }
                    foreach ($f in @($snap.findings)) {
                        if ($Args.severity -and [string]$f.severity -ne [string]$Args.severity) { continue }
                        if ($Args.category -and [string]$f.category -notlike "*$($Args.category)*") { continue }
                        $line = Get-WlAssistantFindingText -Finding $f -Lang $Lang
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
                $limit = [Math]::Min(25, [Math]::Max(1, [int]$(if ($Args.limit) { $Args.limit } else { 10 })))
                $res = Search-WlDevices -Query ([string]$Args.query) -IssuesOnly:([bool]$Args.issuesOnly) -Page 0 -Size $limit
                $rows = @(@($res.rows) | ForEach-Object { $_ | Select-Object deviceId, deviceName, osPlatform, osVersion, deviceGroup, primaryUser, riskScore, exposure, lastSeen, asrBelowMinimum, localExclusionsPresent, tamperProtection, findings -ErrorAction SilentlyContinue })
                return [ordered]@{ total = $res.total; returned = $rows.Count; devices = $rows }
            }
            'get_device' {
                if ($modules -notcontains 'endpoint') { return @{ error = 'endpoint module not enabled' } }
                $d = $null
                if ($Args.deviceId) { $d = Get-WlDevice -DeviceId ([string]$Args.deviceId) }
                elseif ($Args.name) { $r = Search-WlDevices -Query ([string]$Args.name) -Page 0 -Size 5; $d = @($r.rows) | Where-Object { $_.deviceName -eq [string]$Args.name } | Select-Object -First 1; if (-not $d -and @($r.rows).Count -eq 1) { $d = $r.rows[0] }; if ($d -and $d.deviceId) { $full = Get-WlDevice -DeviceId ([string]$d.deviceId); if ($full) { $d = $full } } }
                if (-not $d) { return @{ error = 'device not found in the snapshot' } }
                $json = $d | ConvertTo-Json -Depth 6 -Compress
                if ($json.Length -gt 9000) { $json = $json.Substring(0, 9000) + '…(truncated)' }
                return [ordered]@{ device = $json }
            }
            'device_live_status' {
                $name = ([string]$Args.deviceName).Trim()
                if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9\-\._]{0,62}$') { return @{ error = 'invalid device name' } }
                if (-not (Test-WlFeature -Name 'hunting')) { return @{ error = 'Advanced Hunting (ThreatHunting.Read.All) is not enabled in this installation – live data unavailable; use the snapshot tools.' } }
                $n = ConvertTo-WlKqlString $name
                $info = Invoke-WlHuntingSafe -NoShard -Context 'assistant device_live_status' -Timespan 'P7D' -Query @"
DeviceInfo
| where DeviceName =~ $n or DeviceName startswith strcat($n, ".")
| summarize arg_max(Timestamp, OSPlatform, OSVersionInfo, OnboardingStatus, SensorHealthState, IsAzureADJoined, JoinType, MachineGroup, LoggedOnUsers, ExposureLevel, DeviceId) by DeviceName
| project DeviceName, DeviceId, LastSeen = Timestamp, OSPlatform, OSVersionInfo, OnboardingStatus, SensorHealthState, IsAzureADJoined, JoinType, MachineGroup, ExposureLevel
"@
                $alerts = Invoke-WlHuntingSafe -NoShard -Context 'assistant device_live_status alerts' -Timespan 'P7D' -Query @"
AlertEvidence
| where DeviceName =~ $n or DeviceName startswith strcat($n, ".")
| join kind=inner (AlertInfo | project AlertId, Title, Severity, Category, DetectionSource, Timestamp) on AlertId
| summarize Count = count(), Last = max(Timestamp) by Title, Severity, Category, DetectionSource
| top 10 by Last desc
"@
                $cfg = Invoke-WlHuntingSafe -NoShard -Context 'assistant device_live_status config' -Timespan 'P7D' -Query @"
DeviceTvmSecureConfigurationAssessment
| where DeviceName =~ $n or DeviceName startswith strcat($n, ".")
| where IsCompliant == 0 and IsApplicable == 1
| join kind=leftouter (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, ConfigurationImpact, RiskDescription) on ConfigurationId
| project ConfigurationId, ConfigurationName, ConfigurationImpact
| top 15 by ConfigurationImpact desc
"@
                return [ordered]@{ asOf = [DateTime]::UtcNow.ToString('o'); source = 'Microsoft Defender Advanced Hunting (live)'; device = @($info | Select-Object -First 1); alertsLast7d = @($alerts); failedSecureConfiguration = @($cfg) }
            }
            'tenant_live_summary' {
                if (-not (Test-WlFeature -Name 'hunting')) { return @{ error = 'Advanced Hunting (ThreatHunting.Read.All) is not enabled in this installation – live data unavailable.' } }
                $dev = Invoke-WlHuntingSafe -NoShard -Context 'assistant tenant_live_summary devices' -Timespan 'P7D' -Query @"
DeviceInfo
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, SensorHealthState, OSPlatform) by DeviceId
| summarize DevicesSeen7d = dcount(DeviceId), InactiveSensors = dcountif(DeviceId, SensorHealthState != "Active"), Windows = dcountif(DeviceId, OSPlatform startswith "Windows"), macOS = dcountif(DeviceId, OSPlatform == "macOS"), Linux = dcountif(DeviceId, OSPlatform == "Linux")
"@
                $al = Invoke-WlHuntingSafe -NoShard -Context 'assistant tenant_live_summary alerts' -Timespan 'P7D' -Query @"
AlertInfo
| summarize Alerts = count(), High = countif(Severity == "High"), Medium = countif(Severity == "Medium"), Low = countif(Severity == "Low"), Informational = countif(Severity == "Informational")
"@
                $alDev = Invoke-WlHuntingSafe -NoShard -Context 'assistant tenant_live_summary alertdevices' -Timespan 'P7D' -Query @"
AlertEvidence
| where EntityType == "Machine" and isnotempty(DeviceId)
| join kind=inner (AlertInfo | where Severity in ("High", "Medium") | project AlertId) on AlertId
| summarize DevicesWithHighMediumAlerts = dcount(DeviceId)
"@
                $cfg = Invoke-WlHuntingSafe -NoShard -Context 'assistant tenant_live_summary config' -Timespan 'P7D' -Query @"
DeviceTvmSecureConfigurationAssessment
| where IsCompliant == 0 and IsApplicable == 1
| summarize Devices = dcount(DeviceId) by ConfigurationId
| join kind=leftouter (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, ConfigurationImpact) on ConfigurationId
| top 10 by Devices desc
| project ConfigurationId, ConfigurationName, Devices, ConfigurationImpact
"@
                return [ordered]@{ asOf = [DateTime]::UtcNow.ToString('o'); source = 'Microsoft Defender Advanced Hunting (live, last 7 days)'; devices = @($dev | Select-Object -First 1); alerts = @($al | Select-Object -First 1); alertDevices = @($alDev | Select-Object -First 1); topFailedSecureConfiguration = @($cfg) }
            }
            'search_docs' {
                $limit = [Math]::Min(6, [Math]::Max(1, [int]$(if ($Args.limit) { $Args.limit } else { 4 })))
                $hits = @(Search-WlKnowledge -Query ([string]$Args.query) -Top $limit)
                return [ordered]@{ returned = $hits.Count; results = $hits }
            }
            default { return @{ error = "unknown tool $Name" } }
        }
    }
    catch { return @{ error = [string]$_.Exception.Message } }
}
#endregion

function Invoke-WlAssistant {
    <#
    .SYNOPSIS
    Answers a portal question with Azure OpenAI using tool calling: the model may look up stored findings/devices,
    query Defender Advanced Hunting live and search the Wardline docs, then answers as JSON.
    Returns @{ answer; links = @(@{view;label}); sources; tools; usage; tookMs }.
    #>
    param([Parameter(Mandatory)][string]$Question, $History, [string]$Lang = 'en', [string]$User = '')
    if (-not (Test-WlAssistant)) { throw [System.InvalidOperationException]::new('The assistant is not enabled in this installation.') }
    $Question = $Question.Trim()
    if (-not $Question) { throw [System.ArgumentException]::new('Question is empty.') }
    if ($Question.Length -gt 2000) { throw [System.ArgumentException]::new('Question is too long (max 2000 characters).') }
    if ($Lang -notin 'en', 'de') { $Lang = 'en' }

    $deployment = Get-WlSetting -Name 'WL_AI_DEPLOYMENT'
    $maxRounds = [Math]::Min(6, [Math]::Max(0, [int](Get-WlSetting -Name 'WL_AI_TOOL_ROUNDS' -Default '4')))
    $context = Get-WlAssistantContext -Question $Question -Lang $Lang
    $langName = $(if ($Lang -eq 'de') { 'German' } else { 'English' })
    $hunting = [bool](Test-WlFeature -Name 'hunting')

    $system = @"
You are the Wardline Assistant inside the Wardline portal, a read-only security posture tool for Microsoft Defender for Endpoint, Intune, Entra ID and AI agents, self-hosted in the customer's Azure subscription.
You have tools. Use them instead of guessing:
- search_findings / search_devices / get_device read the stored snapshot of the last Wardline run (the same data the portal shows).
- device_live_status / tenant_live_summary query Microsoft Defender Advanced Hunting LIVE$(if (-not $hunting) { ' (NOT available in this installation – say so if asked for live data)' }). Use them when the user asks about "now", "today", "currently", alerts, last seen, or wants to verify a snapshot finding against the current state. Always state that these numbers are live and from which time window.
- search_docs explains Wardline views, the MDAV baseline rationale, permissions and limitations. Cite the titles you used.
Rules:
- Never invent devices, numbers, policies or findings. Quote numbers exactly as returned. If a tool returns an error or nothing, say so and point to the view where the user can look, or suggest starting a run ("Collect now").
- Distinguish snapshot data (generatedAt in CONTEXT) from live data (tool asOf).
- Wardline is read-only: never claim it changed or will change anything. Recommendations are for the admin to apply in Intune / Defender / Entra.
- Be concise (max ~200 words), use short bullet points when listing. Reply in $langName.
- When a portal view helps, add it to "links" (only routes from the CONTEXT view list; devices may use #/devices?q=<name> and #/device?id=<deviceId>).
- Final output strictly JSON: {"answer": string, "links": [{"view": "#/route", "label": string}], "sources": [string]} where sources lists doc titles or "live: Advanced Hunting" / "snapshot" as applicable.
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

    $userTag = $(if ($User) { Get-WlHash $User } else { 'portal' })
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $toolsUsed = [System.Collections.Generic.List[object]]::new()
    $promptTokens = 0; $completionTokens = 0; $model = ''
    $r = $null
    for ($round = 0; $round -le $maxRounds; $round++) {
        $body = @{ messages = $messages.ToArray(); temperature = 0.2; max_tokens = 900; user = $userTag }
        if ($round -lt $maxRounds) { $body.tools = $script:WlAssistantTools; $body.tool_choice = 'auto' }
        else { $body.response_format = @{ type = 'json_object' } }   # last round: force the final JSON answer
        $r = Invoke-WlOpenAI -Operation 'chat/completions' -Deployment $deployment -Body $body -TimeoutSec 90
        if ($r.usage) { $promptTokens += [int]$r.usage.prompt_tokens; $completionTokens += [int]$r.usage.completion_tokens }
        $model = [string]$r.model
        $choice = $r.choices[0]
        $calls = @($choice.message.tool_calls)
        if (-not $calls.Count) { break }
        # echo the assistant turn (with tool_calls) then one tool message per call
        $messages.Add(@{ role = 'assistant'; content = $(if ($choice.message.content) { [string]$choice.message.content } else { $null }); tool_calls = @($calls | ForEach-Object { @{ id = $_.id; type = 'function'; function = @{ name = $_.function.name; arguments = [string]$_.function.arguments } } }) })
        foreach ($c in $calls) {
            $args = @{}
            try { if ($c.function.arguments) { $args = $c.function.arguments | ConvertFrom-Json } } catch { $args = @{} }
            $tsw = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Invoke-WlAssistantTool -Name $c.function.name -Args $args -Lang $Lang
            $json = $result | ConvertTo-Json -Depth 8 -Compress
            if ($json.Length -gt 12000) { $json = $json.Substring(0, 12000) + '…(truncated)' }
            $toolsUsed.Add([ordered]@{ name = $c.function.name; args = $args; ms = $tsw.ElapsedMilliseconds; ok = -not [bool](Get-WlProp $result 'error') })
            $messages.Add(@{ role = 'tool'; tool_call_id = $c.id; content = $json })
        }
    }
    $content = [string]$r.choices[0].message.content
    $answer = $content; $links = @(); $sources = @()
    try {
        $j = $content | ConvertFrom-Json
        if ($j.answer) { $answer = [string]$j.answer }
        $allowed = @($script:WlAssistantViews | ForEach-Object { $_.view }) + @('device', 'devices')
        $links = @(@($j.links) | Where-Object { $_ -and $_.view } | ForEach-Object {
                $v = [string]$_.view; $v = $v -replace '^#?/?', ''
                $name = ($v -split '\?')[0]
                if ($name -in $allowed -and $v -notmatch '[<>"'']') { [ordered]@{ view = "#/$v"; label = [string]$(if ($_.label) { $_.label } else { $name }) } }
            } | Select-Object -First 5)
        $sources = @(@($j.sources) | Where-Object { $_ } | ForEach-Object { ([string]$_).Substring(0, [Math]::Min(([string]$_).Length, 120)) } | Select-Object -First 8)
    }
    catch {
        # model answered in prose despite the instruction – strip a stray code fence and return as is
        $answer = ($content -replace '^\s*```(json)?\s*', '' -replace '\s*```\s*$', '').Trim()
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
