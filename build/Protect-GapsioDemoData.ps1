#Requires -Version 7.2
<#
.SYNOPSIS
    Pseudonymises Gapsio data for a public demo and checks the result for leaks.

.DESCRIPTION
    Replaces everything that identifies a tenant, consistently (the same original always gets the same pseudonym, so
    the demo still makes sense):
      - device names (also inside titles, labels, states and command lines) -> WS-1042, SRV-2017, MBP-3051, LNX-4008
      - users / UPNs / e-mail addresses -> fictitious people @contoso.example
      - group, policy, agent and blueprint names -> neutral names
      - tenant domains and FQDNs -> contoso.example
      - GUIDs and Defender device IDs -> random (Microsoft's public IDs, e.g. ASR rules and setting IDs, are kept)
      - IPv4/IPv6 addresses -> documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)
      - user profile paths (C:\Users\<name>, /Users/<name>, /home/<name>) and Windows SIDs
      - every term from -DenyTerms (e.g. company name) -> Contoso

    Then it scans the result: any original value, any deny term, any IP outside the documentation ranges or any e-mail
    outside contoso.example makes the check fail.

    Dot-source this file to get Protect-GapsioDemoData and Test-GapsioDemoLeaks.
#>

$script:DemoFirst = @('Alex', 'Ben', 'Carla', 'Daniel', 'Elena', 'Felix', 'Greta', 'Hannah', 'Ivan', 'Julia', 'Kai', 'Lena', 'Marco', 'Nina', 'Oskar', 'Paula', 'Quentin', 'Rosa', 'Sven', 'Tara', 'Uwe', 'Vera', 'Willi', 'Yara', 'Zoe')
$script:DemoLast = @('Adler', 'Becker', 'Conrad', 'Dietz', 'Engel', 'Fuchs', 'Graf', 'Hahn', 'Imhof', 'Jung', 'Keller', 'Lorenz', 'Maier', 'Neumann', 'Ott', 'Peters', 'Roth', 'Seidel', 'Thiel', 'Ulrich', 'Vogt', 'Weber', 'Zander')
$script:DemoDomain = 'contoso.example'
$script:GuidRx = '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
$script:Ipv4Rx = '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
$script:EmailRx = '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'

# Property names whose whole value is identifying (case-insensitive)
$script:DemoFields = @{
    device = @('deviceName', 'computerName', 'hostName', 'machineName', 'computerDnsName')
    user   = @('upn', 'userPrincipalName', 'user', 'lastUser', 'account', 'acceptedBy', 'revokedBy', 'setBy', 'by', 'createdBy', 'mail', 'loggedOnUser', 'initiatedBy')
    person = @('userDisplayName', 'ownerName', 'sponsor', 'sponsorName')
    group  = @('groupName', 'deviceGroup', 'machineGroup', 'groupDisplayName')
    policy = @('policyName', 'profileName', 'configurationName', 'scriptName')
    agent  = @('agentName', 'blueprintName', 'appName', 'appDisplayName')
    tenant = @('tenantId', 'tenantDomain', 'tenant')
    domain = @('publisher', 'blueprintPublisher', 'publisherDomain', 'verifiedPublisher', 'domain', 'domainName', 'fqdn')
}

function New-DemoMapper {
    param([int]$Seed = 4711, [string[]]$KeepGuids = @())
    [pscustomobject]@{
        Rand = [Random]::new($Seed); Map = [ordered]@{}; Used = @{}; Counter = @{}
        KeepGuids = @{} + (@($KeepGuids | ForEach-Object { $_.ToLowerInvariant() }) | Group-Object -AsHashTable -AsString)
    }
}

function Get-DemoPseudonym {
    param([Parameter(Mandatory)]$M, [Parameter(Mandatory)][string]$Kind, [AllowEmptyString()][AllowNull()][string]$Value)
    $v = $Value.Trim()
    if (-not $v -or $v -in @('–', '-', 'n/a', 'N/A', 'null', 'System', 'SYSTEM', 'NT AUTHORITY\SYSTEM', 'LocalSystem')) { return $Value }
    if ($v -match "(^|[@.])$([regex]::Escape($script:DemoDomain))$" -or $v -match '\.example$') { return $Value }   # already fictitious
    if ($M.Used.ContainsKey($v)) { return $Value }   # a pseudonym we created
    $k = "$Kind|$($v.ToLowerInvariant())"
    if ($M.Map.Contains($k)) { return $M.Map[$k].new }
    $n = ++$M.Counter[$Kind]
    $new = switch ($Kind) {
        'device' {
            $short = ($v -split '\.')[0]
            $prefix = if ($short -match 'mac|mbp|imac') { 'MBP' } elseif ($short -match 'lnx|linux|ubu|rhel|deb|cent') { 'LNX' } elseif ($short -match 'srv|server|dc\d|sql|app|web') { 'SRV' } elseif ($short -match 'print|prn') { 'PRN' } else { 'WS' }
            do { $c = "$prefix-$($M.Rand.Next(1000, 9999))" } while ($M.Used.ContainsKey($c))
            if ($v -match '\.') { "$c.$($script:DemoDomain)".ToLowerInvariant() } else { $c }
        }
        'user' {
            $local = if ($v -match '^(.+?)@') { $Matches[1] } elseif ($v -match '\\(.+)$') { $Matches[1] } else { $v }
            if ($local -match 'agent|bot|svc|service|app') { "agent-$('{0:d2}' -f $n)@$($script:DemoDomain)" }
            else {
                do { $c = "$($script:DemoFirst[$M.Rand.Next($script:DemoFirst.Count)]).$($script:DemoLast[$M.Rand.Next($script:DemoLast.Count)])".ToLowerInvariant() } while ($M.Used.ContainsKey($c))
                $M.Used[$c] = $true
                if ($v -match '@') { "$c@$($script:DemoDomain)" } elseif ($v -match '\\') { "CONTOSO\$c" } else { $c }
            }
        }
        'person' { "$($script:DemoFirst[$M.Rand.Next($script:DemoFirst.Count)]) $($script:DemoLast[$M.Rand.Next($script:DemoLast.Count)])" }
        'group' { "Demo group $('{0:d2}' -f $n)" }
        'policy' { "Demo policy $('{0:d2}' -f $n)" }
        'agent' { "Demo agent $('{0:d2}' -f $n)" }
        'tenant' { if ($v -match $script:GuidRx) { [guid]::NewGuid().ToString() } else { $script:DemoDomain } }
        'domain' { if ($v -match 'onmicrosoft') { 'contoso.onmicrosoft.example' } else { $script:DemoDomain } }
        'guid' { $b = [byte[]]::new(16); $M.Rand.NextBytes($b); ([guid]::new($b)).ToString() }
        'hex' { -join (1..$v.Length | ForEach-Object { '0123456789abcdef'[$M.Rand.Next(16)] }) }
        'ip4' { $r = @('192.0.2', '198.51.100', '203.0.113')[$M.Rand.Next(3)]; "$r.$($M.Rand.Next(10, 250))" }
        'ip6' { '2001:db8::{0:x}' -f $M.Rand.Next(1, 65535) }
        'sid' { "S-1-5-21-1000000000-2000000000-3000000000-$(1000 + $n)" }
        'profile' { "user$('{0:d2}' -f $n)" }
        'term' { 'Contoso' }
        default { "demo-$n" }
    }
    $M.Used[[string]$new] = $true
    $M.Map[$k] = @{ old = $v; new = [string]$new; kind = $Kind }
    [string]$new
}

function Test-DemoTextReplace {
    # Which collected originals are also replaced inside free text
    param($Entry)
    if ($Entry.kind -in 'hex', 'guid', 'ip4', 'ip6', 'sid') { return $false }
    if ($Entry.kind -in 'group', 'policy', 'agent') { return $Entry.old.Length -ge 8 -or $Entry.old -match '[\d_-]' }
    $Entry.old.Length -ge 3
}

function Protect-DemoString {
    # Regex based replacements for free text (titles, labels, states, command lines, …)
    param($M, [string]$Text, [string]$Name)
    if (-not $Text) { return $Text }
    $s = $Text
    # Known originals (longest first), case-insensitive, whole token. Short generic names (e.g. a device group "Server")
    # are only replaced in their own fields, not in free text.
    foreach ($e in ($M.Map.Values | Where-Object { Test-DemoTextReplace $_ } | Sort-Object { $_.old.Length } -Descending)) {
        $s = [regex]::Replace($s, "(?<![A-Za-z0-9])$([regex]::Escape($e.old))(?![A-Za-z0-9])", $e.new.Replace('$', '$$'), 'IgnoreCase')
    }
    $s = [regex]::Replace($s, $script:EmailRx, { param($x) if ($x.Value -match "@$([regex]::Escape($script:DemoDomain))$") { $x.Value } else { Get-DemoPseudonym $M 'user' $x.Value } })
    $s = [regex]::Replace($s, $script:GuidRx, { param($x) if ($M.KeepGuids.ContainsKey($x.Value.ToLowerInvariant())) { $x.Value } else { Get-DemoPseudonym $M 'guid' $x.Value } })
    if ($Name -notmatch '(?i)version|ver$|build') {
        $s = [regex]::Replace($s, $script:Ipv4Rx, { param($x) if ($x.Value -match '^(192\.0\.2|198\.51\.100|203\.0\.113)\.|^127\.|^0\.0\.0\.0$') { $x.Value } else { Get-DemoPseudonym $M 'ip4' $x.Value } })
    }
    $s = [regex]::Replace($s, '\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b', { param($x) if ($x.Value -match '^2001:db8') { $x.Value } else { Get-DemoPseudonym $M 'ip6' $x.Value } })
    $s = [regex]::Replace($s, 'S-1-5-21-\d+-\d+-\d+-\d+', { param($x) Get-DemoPseudonym $M 'sid' $x.Value })
    $s = [regex]::Replace($s, '(?i)(\\Users\\|/Users/|/home/)(?!Public\b|Default\b|Shared\b|All Users\b|\*)([^\\/"\s]+)', { param($x) "$($x.Groups[1].Value)$(Get-DemoPseudonym $M 'profile' $x.Groups[2].Value)" })
    $s = [regex]::Replace($s, '(?i)\b[\w-]+\.onmicrosoft\.com\b', { param($x) Get-DemoPseudonym $M 'domain' $x.Value })
    $s
}

function Protect-DemoNode {
    param($M, $Node, [string]$Name, [int]$Pass)
    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Collections.IDictionary]) {
        foreach ($k in @($Node.Keys)) { $Node[$k] = Protect-DemoNode -M $M -Node $Node[$k] -Name ([string]$k) -Pass $Pass }
        return $Node
    }
    if ($Node -is [System.Collections.IList] -and $Node -isnot [string]) {
        for ($i = 0; $i -lt $Node.Count; $i++) { $Node[$i] = Protect-DemoNode -M $M -Node $Node[$i] -Name $Name -Pass $Pass }
        return , $Node
    }
    if ($Node -isnot [string]) { return $Node }
    if ($Pass -eq 1) {
        # Pass 1: identifying fields get a pseudonym (collects the originals)
        if ($Name -match '(?i)publisher' -and $Node -match '(?i)^(microsoft|github|openai|anthropic|google|amazon|adobe|atlassian|salesforce|servicenow)\b') { return $Node }
        foreach ($kind in $script:DemoFields.Keys) {
            if ($script:DemoFields[$kind] -contains $Name) { return (Get-DemoPseudonym $M $kind $Node) }
        }
        if ($Node -match '^(Group|Excluded): (.+)$') { return "$($Matches[1]): $(Get-DemoPseudonym $M 'group' $Matches[2])" }
        if ($Name -eq 'name' -and $Node -match '^[A-Za-z0-9][A-Za-z0-9-]{1,14}$' -and $Node -match '\d' -and $Node -cmatch '^[A-Z0-9-]+$') { return (Get-DemoPseudonym $M 'device' $Node) }
        if ($Name -eq 'displayName' -and $Node -match '^[A-ZÄÖÜ][a-zäöüß]+ [A-ZÄÖÜ][a-zäöüß-]+$') { return (Get-DemoPseudonym $M 'person' $Node) }
        if ($Node -match '^[0-9a-f]{40}$') { return (Get-DemoPseudonym $M 'hex' $Node) }
        return $Node
    }
    # Pass 2: free text
    if ($Name -match '^(key|fp|lid)$' -and $Node -match '^[0-9a-f]{8,64}$') { return $Node }   # hashes of keys stay stable
    if ($Node -match '^[0-9a-f]{40}$') { return (Get-DemoPseudonym $M 'hex' $Node) }
    Protect-DemoString -M $M -Text $Node -Name $Name
}

function Protect-GapsioDemoData {
    <#
    .SYNOPSIS
    Pseudonymises a hashtable tree (ConvertFrom-Json -AsHashtable) in place and returns the mapper (for the leak check).
    #>
    param(
        [Parameter(Mandatory)]$Data,
        [string[]]$DenyTerms = @(),
        [string[]]$KeepGuids = @(),
        [int]$Seed = 4711
    )
    $m = New-DemoMapper -Seed $Seed -KeepGuids $KeepGuids
    foreach ($t in @($DenyTerms | Where-Object { $_ -and $_.Length -ge 3 })) { $null = Get-DemoPseudonym $m 'term' $t }
    $null = Protect-DemoNode -M $m -Node $Data -Name '' -Pass 1
    $null = Protect-DemoNode -M $m -Node $Data -Name '' -Pass 2
    $m
}

function Test-GapsioDemoLeaks {
    <#
    .SYNOPSIS
    Returns the problems found in the serialised demo data (empty = clean).
    #>
    param([Parameter(Mandatory)][string]$Json, $Mapper, [string[]]$DenyTerms = @())
    $issues = [System.Collections.Generic.List[string]]::new()
    $originals = if ($Mapper) { @($Mapper.Map.Values | Where-Object { (Test-DemoTextReplace $_) -and $_.old.Length -ge 4 -and $_.old -ne $_.new } | ForEach-Object old) } else { @() }
    foreach ($o in @($originals + $DenyTerms | Where-Object { $_ -and $_.Length -ge 3 } | Sort-Object -Unique)) {
        if ($Json -match "(?i)(?<![A-Za-z0-9])$([regex]::Escape($o))(?![A-Za-z0-9])") { $issues.Add("Original value still present: $o") }
    }
    foreach ($e in [regex]::Matches($Json, $script:EmailRx) | ForEach-Object Value | Sort-Object -Unique) {
        if ($e -notmatch "@$([regex]::Escape($script:DemoDomain))$" -and $e -notmatch '^[^@]+@\d') { $issues.Add("E-mail outside $($script:DemoDomain): $e") }
    }
    foreach ($ip in [regex]::Matches($Json, $script:Ipv4Rx) | ForEach-Object Value | Sort-Object -Unique) {
        if ($ip -notmatch '^(192\.0\.2|198\.51\.100|203\.0\.113)\.|^127\.|^0\.0\.0\.0$') {
            # version numbers such as 1.427.230.0 are fine
            if ($Json -notmatch "(?i)(version|ver|engine|platform|signature)[^,]{0,40}$([regex]::Escape($ip))") { $issues.Add("IP address outside documentation ranges: $ip") }
        }
    }
    if ($Json -match '(?i)\b[\w-]+\.onmicrosoft\.com\b') { $issues.Add("Tenant domain: $($Matches[0])") }
    @($issues)
}
