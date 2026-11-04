# Builds Settings Catalog settings from the definitions in Microsoft Graph.
# Instead of guessing option values, every definition is queried (deviceManagement/configurationSettings) and the
# matching option is picked by suffix. Missing IDs or options are logged instead of failing the policy –
# so creating the test policies doubles as an ID check.

$script:WlDefCache = @{}

function Get-WlDefinition {
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][scriptblock]$Fetch)
    if ($script:WlDefCache.ContainsKey($Id)) { return $script:WlDefCache[$Id] }
    $d = $null
    try { $d = & $Fetch $Id } catch { $d = $null }
    $script:WlDefCache[$Id] = $d
    $d
}

function New-WlSettingInstance {
    <#
    .SYNOPSIS
    Creates a settingInstance for a definition.
      Choice:                     -Value 'audit'  -> option whose itemId ends with '_audit'
      Simple value:               -Value 50 or 'text'
      List (SimpleCollection):    -Value @('a','b')
      Group collection:           -Value @( @{ '<child suffix>' = <value>; ... }, ... )
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        $Value,
        [Parameter(Mandatory)][scriptblock]$Fetch,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Log
    )
    $def = Get-WlDefinition -Id $Id -Fetch $Fetch
    if (-not $def) { $Log.Add("MISSING    $Id"); return $null }
    $type = [string]$def.'@odata.type'

    if ($type -like '*ChoiceSettingDefinition') {
        # Several alternatives possible: 'true|1' or '0|path'
        $spec = [string]$Value
        $opts = @($def.options)
        $opt = $null
        foreach ($alt in ($spec -split '\|')) {
            $opt = $opts | Where-Object { [string]$_.itemId -match "(^|_)$([regex]::Escape($alt))$" } | Select-Object -First 1
            if ($opt) { break }
        }
        if (-not $opt) {
            foreach ($alt in ($spec -split '\|')) {
                $opt = $opts | Where-Object { [string]$_.displayName -match "^$([regex]::Escape($alt))$" } | Select-Object -First 1
                if ($opt) { break }
            }
        }
        if (-not $opt) { $Log.Add("OPTION?    $Id = '$spec' (available: $(($opts | ForEach-Object { $_.itemId }) -join ', '))"); return $null }
        $Log.Add("ok         $Id = $($opt.itemId)")
        return [ordered]@{
            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = $Id
            choiceSettingValue  = [ordered]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'; value = [string]$opt.itemId; children = @() }
        }
    }

    if ($type -like '*ChoiceSettingCollectionDefinition') {
        # Mehrfachauswahl, z. B. Linux "scopes" = epp, global
        $opts = @($def.options)
        $vals = foreach ($alt in @($Value)) {
            $o = $opts | Where-Object { [string]$_.itemId -match "(^|_)$([regex]::Escape([string]$alt))$" -or [string]$_.displayName -match "^$([regex]::Escape([string]$alt))$" } | Select-Object -First 1
            if ($o) { [ordered]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'; value = [string]$o.itemId; children = @() } }
            else { $Log.Add("OPTION?    $Id = '$alt' (available: $(($opts | ForEach-Object { $_.itemId }) -join ', '))") }
        }
        $vals = @($vals)
        if (-not $vals.Count) { return $null }
        $Log.Add("ok         $Id = $(($vals | ForEach-Object { $_.value }) -join ', ')")
        return [ordered]@{
            '@odata.type'                = '#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance'
            settingDefinitionId          = $Id
            choiceSettingCollectionValue = $vals
        }
    }

    if ($type -like '*SimpleSettingCollectionDefinition') {
        $Log.Add("ok         $Id = $(@($Value).Count) value(s)")
        return [ordered]@{
            '@odata.type'                = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'
            settingDefinitionId          = $Id
            simpleSettingCollectionValue = @(@($Value) | ForEach-Object { [ordered]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = [string]$_ } })
        }
    }

    if ($type -like '*SimpleSettingDefinition') {
        $isInt = ([string]$def.valueDefinition.'@odata.type') -like '*Integer*'
        $Log.Add("ok         $Id = $Value")
        $val = if ($isInt) { [ordered]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationIntegerSettingValue'; value = [int]$Value } }
        else { [ordered]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'; value = [string]$Value } }
        return [ordered]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = $Id; simpleSettingValue = $val }
    }

    if ($type -like '*SettingGroupCollectionDefinition') {
        $childIds = @($def.childIds)
        $items = foreach ($item in @($Value)) {
            $children = foreach ($k in @($item.Keys)) {
                $cid = $childIds | Where-Object { $_ -eq "$($Id)_$k" } | Select-Object -First 1
                if (-not $cid) { $cid = $childIds | Where-Object { $_ -like "*_$k" } | Select-Object -First 1 }
                # Settings that depend on an option (e.g. ASR per-rule exclusions) are not in childIds but exist as
                # definitions; Move-WlDependentSettings nests them under the option afterwards.
                if (-not $cid -and (Get-WlDefinition -Id "$($Id)_$k" -Fetch $Fetch)) { $cid = "$($Id)_$k" }
                if (-not $cid) { $Log.Add("CHILD MISSING $Id › $k (available: $($childIds -join ', '))"); continue }
                $ci = New-WlSettingInstance -Id $cid -Value $item[$k] -Fetch $Fetch -Log $Log
                if ($ci) { $ci }
            }
            $children = @($children | Where-Object { $_ })
            # An item whose children depend on a parent setting that did not resolve (e.g. Linux exclusions without
            # a valid $type) would be rejected by Intune – skip it instead.
            $have = @($children | ForEach-Object { [string]$_['settingDefinitionId'] })
            $orphan = $children | Where-Object {
                $d = Get-WlDefinition -Id $_['settingDefinitionId'] -Fetch $Fetch
                $parents = @(@($d.dependentOn) | ForEach-Object { [string]$_.parentSettingId } | Where-Object { $_ })
                $parents.Count -and -not @($parents | Where-Object { $have -contains $_ }).Count
            } | Select-Object -First 1
            if ($orphan) { $Log.Add("ITEM SKIPPED $Id › $([string]$orphan['settingDefinitionId']) requires a parent setting that did not resolve"); continue }
            $children = @(Move-WlDependentSettings -Instances @($children) -Fetch $Fetch)
            if ($children.Count) { [ordered]@{ children = $children } }
        }
        $items = @($items)
        if (-not $items.Count) { return $null }
        return [ordered]@{
            '@odata.type'               = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'
            settingDefinitionId         = $Id
            groupSettingCollectionValue = $items
        }
    }

    $Log.Add("TYPE?      $Id ($type) is not supported")
    $null
}

function Move-WlDependentSettings {
    <#
    .SYNOPSIS
    Intune requires settings that depend on a selected option (dependedOnBy) to be passed as children of that
    option – not as siblings (e.g. macOS exclusions: $type = Path -> path, isDirectory).
    #>
    param([object[]]$Instances, [Parameter(Mandatory)][scriptblock]$Fetch)
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($i in @($Instances)) { if ($i) { $list.Add($i) } }
    foreach ($ci in @($list.ToArray())) {
        if (-not $list.Contains($ci)) { continue }
        $csv = $ci['choiceSettingValue']
        if (-not $csv) { continue }
        $def = Get-WlDefinition -Id $ci['settingDefinitionId'] -Fetch $Fetch
        $opt = @($def.options) | Where-Object { $_.itemId -eq $csv['value'] } | Select-Object -First 1
        $deps = @(@($opt.dependedOnBy) | ForEach-Object { [string]$_.dependedOnBy } | Where-Object { $_ })
        if (-not $deps.Count) { continue }
        $moved = @($list | Where-Object { $_ -ne $ci -and $deps -contains [string]$_['settingDefinitionId'] })
        if (-not $moved.Count) { continue }
        foreach ($m in $moved) { [void]$list.Remove($m) }
        $csv['children'] = @(@($csv['children']) + $moved | Where-Object { $_ })
    }
    $list.ToArray()
}

function New-WlSettingsList {
    <#
    .SYNOPSIS
    Converts an ordered list of Id = value into the settings array of a configurationPolicy.
    For several candidate IDs (e.g. macOS) the key can be 'id1|id2' – the first one that exists is used.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Spec, [Parameter(Mandatory)][scriptblock]$Fetch, [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Log)
    $out = foreach ($key in @($Spec.Keys)) {
        $candidates = $key -split '\|'
        $id = $candidates | Where-Object { Get-WlDefinition -Id $_ -Fetch $Fetch } | Select-Object -First 1
        if (-not $id) { $Log.Add("MISSING    $($candidates -join ' | ')"); continue }
        $inst = New-WlSettingInstance -Id $id -Value $Spec[$key] -Fetch $Fetch -Log $Log
        if ($inst) { [ordered]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSetting'; settingInstance = $inst } }
    }
    @($out)
}
