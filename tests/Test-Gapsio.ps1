#Requires -Version 7.2
<#
.SYNOPSIS
    Logic and end-to-end tests for Gapsio without Azure: Graph, Advanced Hunting, the Defender API and
    storage are replaced with sample data in the module scope.
    Usage: pwsh ./tests/Test-Gapsio.ps1 [-OutDir <folder for generated snapshots>]
#>
param([string]$OutDir)
$ErrorActionPreference = 'Stop'
$env:GAPSIO_UPDATE_CHECK = 'false'   # no live GitHub calls during tests; the update test enables it explicitly
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'src/functionapp/Modules/Gapsio/Gapsio.psd1') -Force
$mod = Get-Module Gapsio

$script:failed = 0; $script:passed = 0
function Assert { param([bool]$Condition, [string]$Message) if ($Condition) { $script:passed++ } else { $script:failed++; Write-Host "  FAILED: $Message" -ForegroundColor Red } }

Write-Host '== Unit tests' -ForegroundColor Cyan
& $mod {
    param($A)
    # Risk rating
    $r = Get-GapsioExclusionRisk -Type 'Process' -Value 'powershell.exe'
    & $A ($r.level -eq 'Critical') "powershell.exe as process exclusion should be Critical, is $($r.level)"
    $r = Get-GapsioExclusionRisk -Type 'Path' -Value 'C:\'
    & $A ($r.level -eq 'Critical') "Drive C:\ should be Critical, is $($r.level)"
    $r = Get-GapsioExclusionRisk -Type 'Path' -Value 'C:\Program Files\App\app.exe\:{PathType:file,ScanTrigger:OnAccess}'
    & $A ($r.level -eq 'Low') "Contextual file exclusion should be Low, is $($r.level)"
    $r = Get-GapsioExclusionRisk -Type 'Extension' -Value '.ps1'
    & $A ($r.level -eq 'Critical') ".ps1 extension should be Critical, is $($r.level)"
    $r = Get-GapsioExclusionRisk -Type 'Path' -Value '/tmp/tools' -Origin 'Local'
    & $A ($r.level -in 'High', 'Critical') "Local /tmp exclusion should be High, is $($r.level)"

    # Baseline comparison
    & $A (Test-GapsioBaselineValue -Value 'device_vendor_msft_policy_config_defender_cloudblocklevel_4' -Expect ([pscustomobject]@{ op = 'gte'; value = 2 })) 'cloudblocklevel_4 >= 2'
    & $A (-not (Test-GapsioBaselineValue -Value 'device_vendor_msft_policy_config_defender_cloudblocklevel_0' -Expect ([pscustomobject]@{ op = 'gte'; value = 2 }))) 'cloudblocklevel_0 < 2'
    & $A (Test-GapsioBaselineValue -Value '50' -Expect ([pscustomobject]@{ op = 'gte'; value = 50 })) 'timeout 50'
    & $A (Test-GapsioBaselineValue -Value 'x_submitsamplesconsent_3' -Expect ([pscustomobject]@{ op = 'in'; values = @(1, 3) })) 'samples in (1,3)'
    & $A (Test-GapsioBaselineValue -Value 'com.apple.managedclient.preferences_exclusionsmergepolicy_admin_only' -Expect ([pscustomobject]@{ op = 'match'; pattern = 'admin_?only$' })) 'mac admin_only'

    # mdatp commands
    $m = ConvertFrom-GapsioMdatpCommand 'mdatp exclusion folder add --path "/Users/Shared/my tools" --scope global'
    & $A ($m.Type -eq 'Path' -and $m.Value -eq '/Users/Shared/my tools' -and $m.Scope -eq 'Global' -and $m.Action -eq 'add') 'mdatp folder add with spaces and global scope'
    $m = ConvertFrom-GapsioMdatpCommand 'sudo mdatp exclusion process remove --name java'
    & $A ($m.Type -eq 'Process' -and $m.Action -eq 'remove' -and $m.Value -eq 'java') 'mdatp process remove'
    $m = ConvertFrom-GapsioMdatpCommand 'mdatp threat allowed add --name EICAR-Test-File'
    & $A ($m.Type -eq 'AllowedThreat') 'mdatp threat allowed'
    & $A ($null -eq (ConvertFrom-GapsioMdatpCommand 'mdatp health')) 'mdatp health ignored'

    # Settings Catalog parsing
    $inst = [pscustomobject]@{
        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'; settingDefinitionId = 'linux_mdatp_managed_exclusions'
        groupSettingCollectionValue = @([pscustomobject]@{ children = @(
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = 'linux_mdatp_managed_exclusions_path'; simpleSettingValue = [pscustomobject]@{ value = '/opt/agent' } },
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'; settingDefinitionId = 'linux_mdatp_managed_exclusions_scope'; choiceSettingValue = [pscustomobject]@{ value = 'linux_mdatp_managed_exclusions_scope_global'; children = @() } }
                ) })
    }
    $v = Get-GapsioSettingValues -Instance $inst
    & $A ($v.Count -eq 2 -and ($v | Where-Object kind -eq 'simple').value -eq '/opt/agent' -and $v[0].group -eq $v[1].group) 'Group settings are split with a shared group'

    $bl = [pscustomobject]@{ checks = @([pscustomobject]@{ id = 'x'; platform = 'Windows'; title = 'X'; severity = 'High'; definitionId = 'def_x'; expect = [pscustomobject]@{ op = 'eq'; value = 1 } }) }
    $r = Test-GapsioBaseline -Baseline $bl -SettingValues @([pscustomobject]@{ policyId = 'p'; policyName = 'P'; platform = 'Windows'; definitionId = 'def_x'; value = 'def_x_1'; kind = 'choice'; group = ''; assignments = @() }) -Devices @{}
    & $A ($r[0].status -eq 'NotAssigned') "Baseline without assignment -> 'NotAssigned', is $($r[0].status)"
    $r = Test-GapsioBaseline -Baseline $bl -SettingValues @([pscustomobject]@{ policyId = 'p'; policyName = 'P'; platform = 'Windows'; definitionId = 'def_x'; value = 'def_x_1'; kind = 'choice'; group = ''; assignments = @('Group: A') }) -Devices @{}
    & $A ($r[0].status -eq 'OK') "Baseline with assignment -> OK, is $($r[0].status)"
} ${function:Assert}

Write-Host '== Settings Catalog builder (test data script)' -ForegroundColor Cyan
. (Join-Path $PSScriptRoot 'tenant/SettingsCatalog.ps1')
$defs = @{
    'x_cloudblocklevel' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition'; options = @([pscustomobject]@{ itemId = 'x_cloudblocklevel_0'; displayName = 'Default' }, [pscustomobject]@{ itemId = 'x_cloudblocklevel_2'; displayName = 'High' }) }
    'x_timeout'         = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingDefinition'; valueDefinition = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationIntegerSettingValueDefinition' } }
    'x_paths'           = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionDefinition'; valueDefinition = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValueDefinition' } }
    'x_asr'             = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSettingGroupCollectionDefinition'; childIds = @('x_asr_rulea', 'x_asr_ruleb') }
    'x_asr_rulea'       = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition'; options = @([pscustomobject]@{ itemId = 'x_asr_rulea_block' }, [pscustomobject]@{ itemId = 'x_asr_rulea_audit'; dependedOnBy = @([pscustomobject]@{ dependedOnBy = 'x_asr_rulea_perruleexclusions'; required = $false }) }) }
    'x_asr_rulea_perruleexclusions' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionDefinition'; valueDefinition = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValueDefinition' }; dependentOn = @([pscustomobject]@{ dependentOn = 'x_asr_rulea_audit'; parentSettingId = 'x_asr_rulea' }) }
    'mac_excl'          = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSettingGroupCollectionDefinition'; childIds = @('mac_excl_item_$type', 'mac_excl_item_path') }
    'mac_excl_item_$type' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition'; options = @([pscustomobject]@{ itemId = 'mac_excl_item_$type_excluded_path'; displayName = 'Path'; dependedOnBy = @([pscustomobject]@{ dependedOnBy = 'mac_excl_item_path'; required = $true }) }) }
    'mac_excl_item_path' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingDefinition'; valueDefinition = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValueDefinition' }; dependentOn = @([pscustomobject]@{ dependentOn = 'mac_excl_item_$type_excluded_path'; parentSettingId = 'mac_excl_item_$type' }) }
}
$fetchFake = { param($id) if ($defs.ContainsKey($id)) { $defs[$id] } else { throw 'nf' } }.GetNewClosure()
$log = [System.Collections.Generic.List[string]]::new()
$set = New-GapsioSettingsList -Fetch $fetchFake -Log $log -Spec ([ordered]@{
        'x_cloudblocklevel' = '2'; 'x_timeout' = 50; 'x_paths' = @('C:\a', 'D:\b'); 'x_missing|x_cloudblocklevel' = '0'
        'x_asr' = @([ordered]@{ rulea = 'audit'; rulea_perruleexclusions = @('C:\x.exe'); rulez = 'block' })
        'mac_excl' = @([ordered]@{ '$type' = '0|path'; path = '/tmp/x' }, [ordered]@{ '$type' = 'nope'; path = '/tmp/orphan' })
        'gibtsnicht' = '1'
    })
Assert ($set.Count -eq 6) "6 settings expected, $($set.Count): $($log -join ' / ')"
Assert ($set[0].settingInstance.choiceSettingValue.value -eq 'x_cloudblocklevel_2') 'Choice by suffix'
Assert ($set[1].settingInstance.simpleSettingValue.'@odata.type' -match 'Integer' -and $set[1].settingInstance.simpleSettingValue.value -eq 50) 'Integer value'
Assert ($set[2].settingInstance.simpleSettingCollectionValue.Count -eq 2) 'String list'
Assert ($set[3].settingInstance.choiceSettingValue.value -eq 'x_cloudblocklevel_0') 'Candidate ID fallback'
Assert ($set[4].settingInstance.groupSettingCollectionValue[0].children.Count -eq 1 -and $set[4].settingInstance.groupSettingCollectionValue[0].children[0].choiceSettingValue.value -eq 'x_asr_rulea_audit') 'Group with unknown child'
Assert ($set[4].settingInstance.groupSettingCollectionValue[0].children[0].choiceSettingValue.children[0].settingDefinitionId -eq 'x_asr_rulea_perruleexclusions') 'Per-rule exclusions (not in childIds) nested under the rule option'
Assert ($set[5].settingInstance.groupSettingCollectionValue.Count -eq 1 -and @($log | Where-Object { $_ -like 'ITEM SKIPPED*mac_excl_item_path*' }).Count -eq 1) 'Item whose parent option did not resolve is skipped'
Assert ($set[5].settingInstance.groupSettingCollectionValue[0].children[0].choiceSettingValue.value -eq 'mac_excl_item_$type_excluded_path') 'Choice by display name (Path)'
Assert ($set[5].settingInstance.groupSettingCollectionValue[0].children.Count -eq 1 -and $set[5].settingInstance.groupSettingCollectionValue[0].children[0].choiceSettingValue.children[0].settingDefinitionId -eq 'mac_excl_item_path') 'Dependent setting (path) nested under the option'
Assert (@($log | Where-Object { $_ -like 'CHILD MISSING*rulez*' }).Count -eq 1 -and @($log | Where-Object { $_ -like 'MISSING*gibtsnicht*' }).Count -eq 1) 'Missing IDs are logged'
$json = $set | ConvertTo-Json -Depth 40
Assert ($json -match '"@odata.type":\s*"#microsoft.graph.deviceManagementConfigurationSetting"') 'Payload serialisable'

# ---------------------------------------------------------------- Sample data
function FxS { param($id, $value) [pscustomobject]@{ settingInstance = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = $id; simpleSettingValue = [pscustomobject]@{ value = $value } } } }
function FxC { param($id, $value) [pscustomobject]@{ settingInstance = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'; settingDefinitionId = $id; choiceSettingValue = [pscustomobject]@{ value = $value; children = @() } } } }
function FxL { param($id, [string[]]$values) [pscustomobject]@{ settingInstance = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'; settingDefinitionId = $id; simpleSettingCollectionValue = @($values | ForEach-Object { [pscustomobject]@{ value = $_ } }) } } }
function FxG { param($id, [object[]]$items) [pscustomobject]@{ settingInstance = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'; settingDefinitionId = $id; groupSettingCollectionValue = @($items | ForEach-Object { [pscustomobject]@{ children = @($_) } }) } } }
function FxCi { param($id, $value) [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'; settingDefinitionId = $id; choiceSettingValue = [pscustomobject]@{ value = $value; children = @() } } }
function FxLi { param($id, [string[]]$values) [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'; settingDefinitionId = $id; simpleSettingCollectionValue = @($values | ForEach-Object { [pscustomobject]@{ value = $_ } }) } }
function FxCc { param($id, $value, [object[]]$children) [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'; settingDefinitionId = $id; choiceSettingValue = [pscustomobject]@{ value = $value; children = @($children) } } }
function FxSi { param($id, $value) [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = $id; simpleSettingValue = [pscustomobject]@{ value = $value } } }

$p = 'device_vendor_msft_policy_config_defender_'
$fixtures = @{
    policies = @(
        [pscustomobject]@{ id = 'pol-win'; name = 'MDAV Baseline Clients'; platforms = 'windows10'; technologies = 'mdm,microsoftSense'; lastModifiedDateTime = '2026-09-01T10:00:00Z'; templateReference = [pscustomobject]@{ templateDisplayName = 'Microsoft Defender Antivirus' } },
        [pscustomobject]@{ id = 'pol-mac'; name = 'Defender macOS'; platforms = 'macOS'; technologies = 'mdm'; lastModifiedDateTime = '2026-08-01T10:00:00Z'; templateReference = $null },
        [pscustomobject]@{ id = 'pol-lnx'; name = 'Linux Global Exclusions'; platforms = 'linux'; technologies = 'microsoftSense'; lastModifiedDateTime = '2026-07-01T10:00:00Z'; templateReference = [pscustomobject]@{ templateDisplayName = 'Microsoft Defender Global Exclusions (AV+EDR)' } },
        [pscustomobject]@{ id = 'pol-edge'; name = 'Edge Settings'; platforms = 'windows10'; technologies = 'mdm'; lastModifiedDateTime = '2026-07-01T10:00:00Z'; templateReference = $null },
        [pscustomobject]@{ id = 'pol-asr'; name = 'ASR Clients'; platforms = 'windows10'; technologies = 'mdm,microsoftSense'; lastModifiedDateTime = '2026-06-10T10:00:00Z'; templateReference = [pscustomobject]@{ templateDisplayName = 'Attack Surface Reduction Rules' } },
        [pscustomobject]@{ id = 'pol-asr2'; name = 'ASR Pilot'; platforms = 'windows10'; technologies = 'mdm,microsoftSense'; lastModifiedDateTime = '2026-09-11T10:00:00Z'; templateReference = [pscustomobject]@{ templateDisplayName = 'Attack Surface Reduction Rules' } },
        [pscustomobject]@{ id = 'pol-lnx2'; name = 'Linux AV'; platforms = 'linux'; technologies = 'mdm,microsoftSense'; lastModifiedDateTime = '2026-09-12T10:00:00Z'; templateReference = [pscustomobject]@{ templateDisplayName = 'Microsoft Defender Antivirus' } },
        # Posture checks: two policies for all devices that disagree (conflict), one device control policy for a pilot group
        [pscustomobject]@{ id = 'pol-scan1'; name = 'MDAV Scan Settings'; platforms = 'windows10'; technologies = 'mdm,microsoftSense'; lastModifiedDateTime = '2026-05-02T10:00:00Z'; templateReference = [pscustomobject]@{ templateDisplayName = 'Microsoft Defender Antivirus' } },
        [pscustomobject]@{ id = 'pol-scan2'; name = 'MDAV Scan Settings Pilot'; platforms = 'windows10'; technologies = 'mdm,microsoftSense'; lastModifiedDateTime = '2026-10-20T10:00:00Z'; templateReference = [pscustomobject]@{ templateDisplayName = 'Microsoft Defender Antivirus' } },
        [pscustomobject]@{ id = 'pol-dc'; name = 'Device Control Pilot'; platforms = 'windows10'; technologies = 'mdm,microsoftSense'; lastModifiedDateTime = '2026-10-01T10:00:00Z'; templateReference = [pscustomobject]@{ templateDisplayName = 'Device Control' } }
    )
    definitions = @{
        'linux_mdatp_managed_antivirusengine_enforcementlevel' = [pscustomobject]@{ id = 'linux_mdatp_managed_antivirusengine_enforcementlevel'; options = @(
                [pscustomobject]@{ itemId = 'linux_mdatp_managed_antivirusengine_enforcementlevel_0'; displayName = 'Real time'; optionValue = [pscustomobject]@{ value = 'real_time' } },
                [pscustomobject]@{ itemId = 'linux_mdatp_managed_antivirusengine_enforcementlevel_1'; displayName = 'On demand'; optionValue = [pscustomobject]@{ value = 'on_demand' } },
            [pscustomobject]@{ itemId = 'linux_mdatp_managed_antivirusengine_enforcementlevel_2'; displayName = 'Passive'; optionValue = [pscustomobject]@{ value = 'passive' } },
            [pscustomobject]@{ itemId = 'linux_mdatp_managed_antivirusengine_enforcementlevel_3'; displayName = 'Audit'; optionValue = [pscustomobject]@{ value = 'audit' } }) }
        'linux_mdatp_managed_tamperprotection_enforcementlevel' = [pscustomobject]@{ id = 'linux_mdatp_managed_tamperprotection_enforcementlevel'; options = @(
            [pscustomobject]@{ itemId = 'linux_mdatp_managed_tamperprotection_enforcementlevel_0'; displayName = 'Block'; optionValue = [pscustomobject]@{ value = 'block' } },
            [pscustomobject]@{ itemId = 'linux_mdatp_managed_tamperprotection_enforcementlevel_1'; displayName = 'Audit'; optionValue = [pscustomobject]@{ value = 'audit' } }) }
        'linux_mdatp_managed_exclusionsettings_mergepolicy' = [pscustomobject]@{ id = 'x'; options = @(
                [pscustomobject]@{ itemId = 'linux_mdatp_managed_exclusionsettings_mergepolicy_0'; displayName = 'merge'; optionValue = [pscustomobject]@{ value = 'merge' } },
                [pscustomobject]@{ itemId = 'linux_mdatp_managed_exclusionsettings_mergepolicy_1'; displayName = 'admin_only'; optionValue = [pscustomobject]@{ value = 'admin_only' } }) }
    }
    settings = @{
        'pol-win' = @(
            (FxC "${p}allowrealtimemonitoring" "${p}allowrealtimemonitoring_1"),
            (FxC "${p}allowcloudprotection" "${p}allowcloudprotection_1"),
            (FxC "${p}cloudblocklevel" "${p}cloudblocklevel_2"),
            (FxS "${p}cloudextendedtimeout" 50),
            (FxC "${p}submitsamplesconsent" "${p}submitsamplesconsent_1"),
            (FxC "${p}puaprotection" "${p}puaprotection_2"),
            (FxC "${p}enablenetworkprotection" "${p}enablenetworkprotection_1"),
            (FxL "${p}excludedpaths" @('C:\Users\*\AppData\Local\Temp\', 'D:\SQLData\db.mdf', 'C:\Program Files\App\app.exe\:{PathType:file,ScanTrigger:OnAccess}')),
            (FxL "${p}excludedprocesses" @('powershell.exe', 'C:\Program Files\Vendor\svc.exe')),
            (FxL "${p}excludedextensions" @('.ps1', '.log')),
            (FxG "${p}attacksurfacereductionrules" @((FxCi "${p}attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts" "${p}attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_audit")))
        )
        'pol-mac' = @(
            (FxC 'com.apple.managedclient.preferences_enforcementlevel_tamperprotection' 'com.apple.managedclient.preferences_enforcementlevel_tamperprotection_1'),
            (FxC 'com.apple.managedclient.preferences_enforcementlevel_antivirusengine' 'com.apple.managedclient.preferences_enforcementlevel_antivirusengine_2'),
            (FxC 'com.apple.managedclient.preferences_enforcementlevel' 'com.apple.managedclient.preferences_enforcementlevel_0'),
            (FxC 'com.apple.managedclient.preferences_exclusionsmergepolicy' 'com.apple.managedclient.preferences_exclusionsmergepolicy_0'),
            (FxC 'com.apple.managedclient.preferences_enabled' 'com.apple.managedclient.preferences_enabled_true'),
            (FxG 'com.apple.managedclient.preferences_exclusions' @(@(
                        (FxCi 'com.apple.managedclient.preferences_exclusions_item_$type' 'com.apple.managedclient.preferences_exclusions_item_$type_0'),
                        (FxSi 'com.apple.managedclient.preferences_exclusions_item_path' '/Users/Shared/tools'),
                        (FxCi 'com.apple.managedclient.preferences_exclusions_item_isdirectory' 'com.apple.managedclient.preferences_exclusions_item_isdirectory_true')), @(
                        (FxCi 'com.apple.managedclient.preferences_exclusions_item_$type' 'com.apple.managedclient.preferences_exclusions_item_$type_2'),
                        (FxSi 'com.apple.managedclient.preferences_exclusions_item_name' 'python3')))),
            (FxG 'com.apple.managedclient.preferences_threattypesettings' @(@(
                        (FxCi 'com.apple.managedclient.preferences_threattypesettings_item_key' 'com.apple.managedclient.preferences_threattypesettings_item_key_0'),
                        (FxCi 'com.apple.managedclient.preferences_threattypesettings_item_value' 'com.apple.managedclient.preferences_threattypesettings_item_value_0')), @(
                        (FxCi 'com.apple.managedclient.preferences_threattypesettings_item_key' 'com.apple.managedclient.preferences_threattypesettings_item_key_1'),
                        (FxCi 'com.apple.managedclient.preferences_threattypesettings_item_value' 'com.apple.managedclient.preferences_threattypesettings_item_value_1')))),
            (FxG 'com.apple.managedclient.preferences_exclusions_tamperprotection' @(@(
                        (FxSi 'com.apple.managedclient.preferences_exclusions_item_path_tamperprotection' '/usr/local/bin/contoso-agent'),
                        (FxSi 'com.apple.managedclient.preferences_exclusions_item_teamid_tamperprotection' 'ABCDE12345')))),
            (FxL 'com.apple.managedclient.preferences_allowedthreats' @('EICAR-Test-File (not a virus)')),
            (FxC 'com.apple.managedclient.preferences_smartscreenenabled' 'com.apple.managedclient.preferences_smartscreenenabled_true')
        )
        'pol-lnx' = @(
            (FxG 'linux_mdatp_managed_exclusions' @(@((FxSi 'linux_mdatp_managed_exclusions_path' '/opt/agent'), (FxCi 'linux_mdatp_managed_exclusions_scope' 'linux_mdatp_managed_exclusions_scope_global'))))
        )
        'pol-edge' = @((FxC 'device_vendor_msft_policy_config_microsoft_edge_homepage' 'x'))
        'pol-scan1' = @((FxC "${p}allowfullscanremovabledrivescanning" "${p}allowfullscanremovabledrivescanning_1"), (FxS "${p}avgcpuloadfactor" 50), (FxC "${p}allowarchivescanning" "${p}allowarchivescanning_1"))
        'pol-scan2' = @((FxC "${p}allowfullscanremovabledrivescanning" "${p}allowfullscanremovabledrivescanning_0"), (FxS "${p}avgcpuloadfactor" 20), (FxC "${p}allowarchivescanning" "${p}allowarchivescanning_1"))
        'pol-dc' = @((FxC 'device_vendor_msft_defender_configuration_devicecontrolenabled' 'device_vendor_msft_defender_configuration_devicecontrolenabled_1'), (FxC 'device_vendor_msft_defender_configuration_defaultenforcement' 'device_vendor_msft_defender_configuration_defaultenforcement_2'))
        'pol-asr' = @(
            (FxG "${p}attacksurfacereductionrules" @(@(
                        (FxCi "${p}attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem" "${p}attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem_block"),
                        (FxCc "${p}attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses" "${p}attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses_warn" @(
                            (FxLi "${p}attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses_perruleexclusions" @('C:\Program Files\Addin\addin.exe')))),
                        (FxCi "${p}attacksurfacereductionrules_blockprocesscreationsfrompsexecandwmicommands" "${p}attacksurfacereductionrules_blockprocesscreationsfrompsexecandwmicommands_audit"))))
        )
        'pol-asr2' = @(
            (FxG "${p}attacksurfacereductionrules" @(@(
                        (FxCi "${p}attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses" "${p}attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses_block"))))
        )
        'pol-lnx2' = @(
            (FxC 'linux_mdatp_managed_antivirusengine_enforcementlevel' 'linux_mdatp_managed_antivirusengine_enforcementlevel_3'),
            (FxC 'linux_mdatp_managed_tamperprotection_enforcementlevel' 'linux_mdatp_managed_tamperprotection_enforcementlevel_1'),
            (FxC 'linux_mdatp_managed_exclusionsettings_mergepolicy' 'linux_mdatp_managed_exclusionsettings_mergepolicy_1'),
            (FxG 'linux_mdatp_managed_exclusionsettings_exclusions' @(@(
                        (FxCi 'linux_mdatp_managed_exclusionsettings_exclusions_item_$type' 'linux_mdatp_managed_exclusionsettings_exclusions_item_$type_0'),
                        (FxSi 'linux_mdatp_managed_exclusionsettings_exclusions_item_path' '/srv/app'),
                        (FxCi 'linux_mdatp_managed_exclusionsettings_exclusions_item_isdirectory' 'linux_mdatp_managed_exclusionsettings_exclusions_item_isdirectory_true'),
                        (FxLi 'linux_mdatp_managed_exclusionsettings_exclusions_item_scopes' @('epp', 'global'))), @(
                        (FxCi 'linux_mdatp_managed_exclusionsettings_exclusions_item_$type' 'linux_mdatp_managed_exclusionsettings_exclusions_item_$type_0'),
                        (FxSi 'linux_mdatp_managed_exclusionsettings_exclusions_item_path' '/home/*/git'),
                        (FxLi 'linux_mdatp_managed_exclusionsettings_exclusions_item_scopes' @('epp')))))
        )
    }
    assignmentsByPolicy = @{
        'pol-lnx'   = @()
        'pol-scan1' = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })
        'pol-scan2' = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })
        'pol-dc'    = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-dc' } })
    }
    detectionRules = @(
        [pscustomobject]@{ id = 'dr-1'; displayName = 'Encoded PowerShell from Office'; status = 'enabled'; createdBy = 'alice@contoso.com'; lastModifiedBy = 'alice@contoso.com'; lastModifiedDateTime = '2026-09-25T10:15:00Z'
            schedule = [pscustomobject]@{ frequency = 'PT1H' }; queryCondition = [pscustomobject]@{ queryText = 'DeviceProcessEvents | where FileName == "powershell.exe"' }
            detectionAction = [pscustomobject]@{ alertTemplate = [pscustomobject]@{ title = 'Encoded PowerShell from Office'; severity = 'high' }; automatedActions = [pscustomobject]@{ isolateDevices = @([pscustomobject]@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' }); initiateInvestigations = @([pscustomobject]@{ deviceIdColumn = 'DeviceId' }) } } },
        [pscustomobject]@{ id = 'dr-2'; displayName = 'LSASS access by unsigned process'; status = 'autoDisabled'; createdBy = 'bob@contoso.com'; lastModifiedBy = 'bob@contoso.com'; lastModifiedDateTime = '2026-03-02T08:00:00Z'
            schedule = [pscustomobject]@{ frequency = 'PT3H' }; detectionAction = [pscustomobject]@{ alertTemplate = [pscustomobject]@{ title = 'LSASS access by unsigned process'; severity = 'medium' }; automatedActions = [pscustomobject]@{} } },
        [pscustomobject]@{ id = 'dr-3'; displayName = 'USB copy of finance files'; status = 'disabled'; createdBy = 'alice@contoso.com'; lastModifiedBy = 'carol@contoso.com'; lastModifiedDateTime = '2026-08-14T13:30:00Z'
            schedule = [pscustomobject]@{ frequency = 'P1D' }; detectionAction = [pscustomobject]@{ alertTemplate = [pscustomobject]@{ title = 'USB copy of finance files'; severity = 'low' } } },
        [pscustomobject]@{ id = 'dr-4'; displayName = 'New local administrator on server'; isEnabled = $true; createdBy = 'alice@contoso.com'; lastModifiedBy = 'alice@contoso.com'; lastModifiedDateTime = '2026-06-01T09:00:00Z'
            schedule = [pscustomobject]@{ period = '24H' }; lastRunDetails = [pscustomobject]@{ status = 'failed'; lastRunDateTime = (Get-Date).ToUniversalTime().AddHours(-5).ToString('o'); errorCode = 'queryTimeout'; failureReason = 'Query timed out' }
            detectionAction = [pscustomobject]@{ alertTemplate = [pscustomobject]@{ title = 'New local administrator on {{DeviceName}}'; severity = 'medium' }; organizationalScope = [pscustomobject]@{ deviceGroups = @('Server') } } }
    )
    managedDevices = @(
        [pscustomobject]@{ id = 'int-win1'; deviceName = 'WIN-01'; operatingSystem = 'Windows'; azureADDeviceId = 'AAD-WIN1'; lastSyncDateTime = ([DateTime]::UtcNow.AddDays(-1).ToString("o")); userPrincipalName = 'alice@contoso.com' },
        [pscustomobject]@{ id = 'int-gap1'; deviceName = 'LAPTOP-NEW'; operatingSystem = 'Windows'; azureADDeviceId = 'AAD-GAP1'; lastSyncDateTime = ([DateTime]::UtcNow.AddDays(-2).ToString("o")); userPrincipalName = 'bob@contoso.com' },
        [pscustomobject]@{ id = 'int-old'; deviceName = 'LAPTOP-RETIRED'; operatingSystem = 'Windows'; azureADDeviceId = 'AAD-RET'; lastSyncDateTime = ([DateTime]::UtcNow.AddDays(-90).ToString("o")); userPrincipalName = 'carol@contoso.com' },
        [pscustomobject]@{ id = 'int-ios'; deviceName = 'iPhone'; operatingSystem = 'iOS'; azureADDeviceId = 'AAD-IOS'; lastSyncDateTime = ([DateTime]::UtcNow.AddDays(-1).ToString("o")); userPrincipalName = 'dave@contoso.com' }
    )
    healthScripts = @([pscustomobject]@{ id = 'hs1'; displayName = 'Gapsio – local Defender exclusions (read-only)' }, [pscustomobject]@{ id = 'hs2'; displayName = 'Other script' })
    skus = @(
        [pscustomobject]@{ skuId = 'sku-p2'; skuPartNumber = 'WIN_DEF_ATP'; capabilityStatus = 'Enabled'; appliesTo = 'User'; consumedUnits = 12; prepaidUnits = [pscustomobject]@{ enabled = 10; suspended = 0; warning = 0 }; servicePlans = @([pscustomobject]@{ servicePlanId = '871d91ec-ec1a-452b-a83f-bd76c7d770ef'; servicePlanName = 'WINDEFATP'; provisioningStatus = 'Success' }) },
        [pscustomobject]@{ skuId = 'sku-p1'; skuPartNumber = 'DEFENDER_ENDPOINT_P1'; capabilityStatus = 'Enabled'; appliesTo = 'User'; consumedUnits = 1; prepaidUnits = [pscustomobject]@{ enabled = 5; suspended = 0; warning = 0 }; servicePlans = @([pscustomobject]@{ servicePlanId = '292cc034-7b7c-4950-aaf5-943befd3f1d4'; servicePlanName = 'MDE_LITE'; provisioningStatus = 'Success' }) },
        [pscustomobject]@{ skuId = 'sku-e3'; skuPartNumber = 'SPE_E3'; capabilityStatus = 'Enabled'; appliesTo = 'User'; consumedUnits = 50; prepaidUnits = [pscustomobject]@{ enabled = 60 }; servicePlans = @([pscustomobject]@{ servicePlanId = '00000000-0000-0000-0000-00000000aaaa'; servicePlanName = 'EXCHANGE_S_ENTERPRISE' }) },
        [pscustomobject]@{ skuId = 'sku-mdo1'; skuPartNumber = 'ATP_ENTERPRISE'; capabilityStatus = 'Enabled'; appliesTo = 'User'; consumedUnits = 3; prepaidUnits = [pscustomobject]@{ enabled = 2; suspended = 0; warning = 0 }; servicePlans = @([pscustomobject]@{ servicePlanId = 'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'; servicePlanName = 'ATP_ENTERPRISE'; provisioningStatus = 'Success' }) },
        [pscustomobject]@{ skuId = 'sku-mdo2'; skuPartNumber = 'THREAT_INTELLIGENCE'; capabilityStatus = 'Enabled'; appliesTo = 'User'; consumedUnits = 1; prepaidUnits = [pscustomobject]@{ enabled = 5; suspended = 0; warning = 0 }; servicePlans = @([pscustomobject]@{ servicePlanId = '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'; servicePlanName = 'THREAT_INTELLIGENCE'; provisioningStatus = 'Success' }) }
    )
    runStates = @(
        [pscustomobject]@{ lastStateUpdateDateTime = [DateTime]::UtcNow.AddMinutes(-30).ToString('o'); managedDevice = [pscustomobject]@{ deviceName = 'WIN-01'; azureADDeviceId = 'aad-win1' }
            preRemediationDetectionScriptOutput = '{"v":1,"m":1,"tp":0,"rm":"Normal","n":2,"tr":0,"x":[["P","L","C:\\Users\\Public\\x"],["P","L","C:\\Legacy\\Tool"]]}' },
        [pscustomobject]@{ lastStateUpdateDateTime = [DateTime]::UtcNow.AddMinutes(-30).ToString('o'); managedDevice = [pscustomobject]@{ deviceName = 'win-02'; azureADDeviceId = '' }
            preRemediationDetectionScriptOutput = '{"v":1,"m":0,"tp":1,"rm":"Passive Mode","n":2,"tr":0,"x":[["P","L","C:\\Users\\Public\\GapsioTest"],["E","G",".bak"]]}' },
        [pscustomobject]@{ lastStateUpdateDateTime = [DateTime]::UtcNow.ToString('o'); managedDevice = [pscustomobject]@{ deviceName = 'UNKNOWN-99'; azureADDeviceId = 'x' }; preRemediationDetectionScriptOutput = 'not json' }
    )
    assignments = @(
        [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-clients' } },
        [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'g-servers' } }
    )
    groups = @{ 'g-clients' = 'All clients'; 'g-servers' = 'Server'; 'g1' = 'Helpdesk-Team'; 'g2' = 'PIM-SecOps'; 'g4' = 'Service desk candidates'; 'g-dc' = 'USB pilot devices' }
    deviceConfigurations = @(
        [pscustomobject]@{ id = 'dc-1'; displayName = 'Legacy Endpoint Protection'; '@odata.type' = '#microsoft.graph.windows10EndpointProtectionConfiguration'; lastModifiedDateTime = '2024-01-01T00:00:00Z'; defenderProcessesToExclude = @('cmd.exe') }
    )
    indicators = @(
        [pscustomobject]@{ indicatorValue = 'ab12cd'; indicatorType = 'CertificateThumbprint'; action = 'Allowed'; title = 'Vendor-Zertifikat'; createdBy = 'admin@contoso.com'; creationTimeDateTimeUtc = '2025-01-01T00:00:00Z'; expirationTime = $null; rbacGroupNames = @() },
        [pscustomobject]@{ indicatorValue = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; indicatorType = 'FileSha256'; action = 'Allowed'; title = 'Tool'; createdBy = 'admin@contoso.com'; creationTimeDateTimeUtc = '2025-01-01T00:00:00Z'; expirationTime = '2027-01-01T00:00:00Z'; rbacGroupNames = @('IT') },
        [pscustomobject]@{ indicatorValue = 'bad.example'; indicatorType = 'DomainName'; action = 'Block'; title = 'Block'; createdBy = 'x' },
        [pscustomobject]@{ indicatorValue = '10.1.2.3'; indicatorType = 'IpAddress'; action = 'Allowed'; title = 'Internal'; createdBy = 'x'; creationTimeDateTimeUtc = '2025-01-01T00:00:00Z' },
        [pscustomobject]@{ indicatorValue = 'cdn.example/tools/agent.exe'; indicatorType = 'Url'; action = 'Allowed'; title = 'Path'; createdBy = 'x'; creationTimeDateTimeUtc = '2025-01-01T00:00:00Z' },
        [pscustomobject]@{ indicatorValue = 'AB12CD'; indicatorType = 'CertificateThumbprint'; action = 'Block'; title = 'Conflict'; createdBy = 'x' }
    )
}

$now = [DateTime]::UtcNow
function T { param([int]$DaysAgo) $now.AddDays(-$DaysAgo).ToString('o') }
$hunting = @{
    DeviceInfo = @(
        [pscustomobject]@{ DeviceId = 'd-win1'; DeviceName = 'WIN-01'; OSPlatform = 'Windows11'; OSVersion = '10.0.26100'; OSBuild = '26100'; ConnectivityType = 'Streamlined'; MachineGroup = 'Clients'; DeviceType = 'Workstation'; AadDeviceId = 'AAD-WIN1'; ManagedBy = 'Intune'; LastSeen = (T 0); DeviceManualTags = '["Finance Dept","VIP"]'; IsInternetFacing = 'false' },
        [pscustomobject]@{ DeviceId = 'd-win2'; DeviceName = 'WIN-02'; OSPlatform = 'Windows11'; OSVersion = '10.0.26100'; MachineGroup = 'Clients'; DeviceType = 'Workstation'; LastSeen = (T 0); IsExcluded = 'true'; ExclusionReason = 'Duplicate device' },
        [pscustomobject]@{ DeviceId = 'd-mac1'; DeviceName = 'MAC-01'; OSPlatform = 'macOS'; OSVersion = '15.6'; MachineGroup = 'Mac'; DeviceType = 'Workstation'; LastSeen = (T 0) },
        [pscustomobject]@{ DeviceId = 'd-win3'; DeviceName = 'SRV-01'; OSPlatform = 'WindowsServer2022'; OSVersion = '10.0.20348'; ConnectivityType = 'Standard'; MachineGroup = 'Server'; DeviceType = 'Server'; LastSeen = (T 0); IsInternetFacing = 'true'; ExposureLevel = 'High'; AssetValue = 'High'; RegistryDeviceTag = 'DMZ' },
        [pscustomobject]@{ DeviceId = 'd-lnx1'; DeviceName = 'LNX-01'; OSPlatform = 'Linux'; OSVersion = 'Ubuntu 24.04'; MachineGroup = 'Server'; DeviceType = 'Server'; LastSeen = (T 0) }
    )
    # Defender for Office 365 (office module): one fixture per probe key
    Office = @{
        threat_in_inbox = @([pscustomobject]@{ messages = 412; inInbox = 7; inboxPhish = 6; inboxMalware = 1; inboxRecipients = 5; deliveredThenRemoved = 38 })
        threat_allowed = @([pscustomobject]@{ messages = 23; delivered = 19; byOrgPolicy = 15; byMailboxPolicy = 8; recipients = 11 })
        threat_allowed_policies = @(
            [pscustomobject]@{ Level = 'Organisation'; Policy = 'Tenant Allow/Block List: partner-portal.example'; messages = 12; delivered = 12; recipients = 6 },
            [pscustomobject]@{ Level = 'Mailbox'; Policy = 'Safe senders list'; messages = 8; delivered = 5; recipients = 4 },
            [pscustomobject]@{ Level = 'Organisation'; Policy = 'Transport rule: Skip filtering for scanner'; messages = 3; delivered = 2; recipients = 2 })
        safelinks_clicks = @([pscustomobject]@{ clicks = 1830; threatClicks = 41; clickedThrough = 9; clickThroughUsers = 6; clickThroughUrls = 8 })
        safelinks_by_workload = @([pscustomobject]@{ Workload = 'Email'; clicks = 1510; threatClicks = 36; clickedThrough = 7 }, [pscustomobject]@{ Workload = 'Teams'; clicks = 260; threatClicks = 5; clickedThrough = 2 }, [pscustomobject]@{ Workload = 'Office'; clicks = 60; threatClicks = 0; clickedThrough = 0 })
        own_domain_spoof = @([pscustomobject]@{ messages = 96; dmarcFail = 14; dmarcFailDelivered = 3; domains = 1; recipients = 3 })
        post_delivery = @([pscustomobject]@{ events = 61; messages = 44; phishZap = 31; malwareZap = 7; manual = 23 })
        threat_trend_daily = @(foreach ($d in 29..0) { [pscustomobject]@{ day = (T $d); bucket = 'Phish'; events = 9 + ($d % 5) * 3 }; [pscustomobject]@{ day = (T $d); bucket = 'Malware'; events = 1 + ($d % 3) }; [pscustomobject]@{ day = (T $d); bucket = 'Spam'; events = 60 + ($d % 7) * 8 } })
        action_trend_daily = @(foreach ($d in 29..0) { [pscustomobject]@{ day = (T $d); bucket = 'Allow'; events = 900 + ($d % 6) * 40 }; [pscustomobject]@{ day = (T $d); bucket = 'Junk'; events = 70 + ($d % 4) * 9 }; [pscustomobject]@{ day = (T $d); bucket = 'Quarantine'; events = 12 + ($d % 5) * 2 }; [pscustomobject]@{ day = (T $d); bucket = 'Block'; events = 25 + ($d % 3) * 5 } })
        threat_themes = @(
            [pscustomobject]@{ ThreatTypes = 'Phish'; ThreatClassification = 'Invoice'; events = 131; delivered = 4; recipients = 77 },
            [pscustomobject]@{ ThreatTypes = 'Phish'; ThreatClassification = 'Payroll'; events = 88; delivered = 2; recipients = 51 },
            [pscustomobject]@{ ThreatTypes = 'Malware'; ThreatClassification = ''; events = 44; delivered = 1; recipients = 30 })
        policy_actions = @(
            [pscustomobject]@{ EmailActionPolicy = 'Antispam'; EmailAction = 'Move message to junk mail folder'; messages = 2210; recipients = 380 },
            [pscustomobject]@{ EmailActionPolicy = 'Anti-phishing spoof'; EmailAction = 'Send to quarantine'; messages = 190; recipients = 95 },
            [pscustomobject]@{ EmailActionPolicy = 'Safe Attachments'; EmailAction = 'Send to quarantine'; messages = 31; recipients = 22 })
        org_policies = @(
            [pscustomobject]@{ OrgLevelPolicy = 'Tenant Allow/Block List: partner-portal.example'; OrgLevelAction = 'Allow'; messages = 240; withThreat = 12; delivered = 240; recipients = 60 },
            [pscustomobject]@{ OrgLevelPolicy = 'Tenant Allow/Block List: bad-sender.example'; OrgLevelAction = 'Block'; messages = 75; withThreat = 40; delivered = 0; recipients = 31 })
        mailbox_policies = @(
            [pscustomobject]@{ UserLevelPolicy = 'Safe senders list'; UserLevelAction = 'Allow'; messages = 510; withThreat = 8; delivered = 505; recipients = 90 },
            [pscustomobject]@{ UserLevelPolicy = 'Blocked senders list'; UserLevelAction = 'Block'; messages = 120; withThreat = 3; delivered = 0; recipients = 41 })
        antiphish_changes = @(
            [pscustomobject]@{ Timestamp = $now.AddDays(-20); ActionType = 'New-AntiPhishPolicy'; Policy = 'Executives'; Actor = 'alice@contoso.com'; Result = 'True'; Params = (@(@{ Name = 'Name'; Value = 'Executives' }, @{ Name = 'PhishThresholdLevel'; Value = '3' }, @{ Name = 'TargetedUserProtectionAction'; Value = 'Quarantine' }) | ConvertTo-Json -Compress) },
            [pscustomobject]@{ Timestamp = $now.AddDays(-10); ActionType = 'Set-AntiPhishPolicy'; Policy = 'Executives'; Actor = 'carol@contoso.com'; Result = 'True'; Params = (@(@{ Name = 'Identity'; Value = 'Executives' }, @{ Name = 'PhishThresholdLevel'; Value = '1' }, @{ Name = 'TargetedUserProtectionAction'; Value = 'MoveToJmf' }) | ConvertTo-Json -Compress) })
        antiphish_outcomes = @(foreach ($d in 29..0) {
                $del = if ($d -le 10) { 9 } else { 2 }
                [pscustomobject]@{ day = $now.Date.AddDays(-$d); Policy = 'Executives'; Method = 'Impersonation user'; Outcome = 'Delivered'; Confidence = 'Normal'; events = $del }
                [pscustomobject]@{ day = $now.Date.AddDays(-$d); Policy = 'Executives'; Method = 'Impersonation user'; Outcome = 'Quarantine'; Confidence = 'High'; events = 6 }
            })
    }
    OfficeFail = @()
    UsbMounts = @(
        [pscustomobject]@{ DeviceId = 'd-win1'; Name = 'WIN-01'; Mounts = 12; Drives = 3; LastMount = (T 1) },
        [pscustomobject]@{ DeviceId = 'd-win2'; Name = 'WIN-02'; Mounts = 5; Drives = 2; LastMount = (T 3) },
        [pscustomobject]@{ DeviceId = 'd-mac1'; Name = 'MAC-01'; Mounts = 2; Drives = 1; LastMount = (T 9) }
    )
    DeviceControl = @([pscustomobject]@{ DeviceId = 'd-win1'; Name = 'WIN-01'; Triggers = 7; Denied = 3; Policies = @('Block unapproved USB'); LastTrigger = (T 1) })
    Mdi = @([pscustomobject]@{ Events = 1250 })
    Disruption = @(
        [pscustomobject]@{ ActionType = 'ContainedUserLogonBlocked'; ReportType = 'Prevented'; Events = 14; Devices = 2; Last = (T 6) },
        [pscustomobject]@{ ActionType = 'ContainedUserSmbFileOpenBlocked'; ReportType = 'Prevented'; Events = 3; Devices = 1; Last = (T 6) }
    )
    DetectionAlerts = @(
        [pscustomobject]@{ Title = 'encoded powershell from office'; Alerts = 4; Last = (T 2) },
        [pscustomobject]@{ Title = 'Some built-in alert'; Alerts = 9; Last = (T 1) }
    )
    Troubleshooting = @(
        [pscustomobject]@{ DeviceId = 'd-win1'; Starts = 4; Name = 'WIN-01'; Timestamp = (T 2); Reason = 'Troubleshooting mode ended' },
        [pscustomobject]@{ DeviceId = 'd-win2'; Starts = 1; Name = 'WIN-02'; Timestamp = $now.AddHours(-1).ToString('o'); Reason = 'Troubleshooting mode started by admin' }
    )
    Tampering = @(
        [pscustomobject]@{ DeviceId = 'd-win1'; Attempts = 3; Last = (T 1); Name = 'WIN-01' },
        [pscustomobject]@{ DeviceId = 'd-win3'; Attempts = 12; Last = (T 1); Name = 'SRV-01' }
    )
    AsrTelemetry = @(
        [pscustomobject]@{ Rule = 'ObfuscatedScript'; Kind = 'Audited'; Events = 4; Devices = 1; Top = '["powershell.exe (4)"]' }
    )
    Wsl = @([pscustomobject]@{ DeviceId = 'd-win1'; Wsl = 1; Plugin = 0 })
    BrowserExtensions = @([pscustomobject]@{ ExtensionId = 'abcdefghijklmnop'; ExtensionName = 'Free VPN Unlimited'; Risk = 'High'; Devices = 2; Ids = '["d-win1","d-win2"]'; Browsers = '["Edge","Chrome"]'; Vendor = 'Unknown Vendor' })
    ThreatActions = @([pscustomobject]@{ DeviceId = 'd-win1'; Name = 'WIN-01'; RegistryKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatIdDefaultAction'; RegistryValueName = '2147519003'; RegistryValueData = '6'; Timestamp = (T 2); InitiatingProcessFileName = 'reg.exe' })
    ThirdPartyAv = @(
        [pscustomobject]@{ DeviceId = 'd-win1'; Products = '["CrowdStrike Falcon Sensor"]' },
        [pscustomobject]@{ DeviceId = 'd-win2'; Products = @('SentinelOne Sentinel Agent') }
    )
    LicDevices = @(
        [pscustomobject]@{ DeviceId = 'd-win1'; DeviceName = 'WIN-01'; OSPlatform = 'Windows11'; DeviceType = 'Workstation'; AadDeviceId = 'AAD-WIN1'; MachineGroup = 'Clients'; LastSeen = (T 0); LoggedOnUsers = '[{"UserName":"alice","DomainName":"CONTOSO"}]' },
        [pscustomobject]@{ DeviceId = 'd-win2'; DeviceName = 'WIN-02'; OSPlatform = 'Windows11'; DeviceType = 'Workstation'; AadDeviceId = 'AAD-WIN2'; MachineGroup = 'Clients'; LastSeen = (T 0) },
        [pscustomobject]@{ DeviceId = 'd-mac1'; DeviceName = 'MAC-01'; OSPlatform = 'macOS'; DeviceType = 'Workstation'; MachineGroup = 'Mac'; LastSeen = (T 0) },
        [pscustomobject]@{ DeviceId = 'd-win3'; DeviceName = 'SRV-01'; OSPlatform = 'WindowsServer2022'; DeviceType = 'Server'; MachineGroup = 'Server'; LastSeen = (T 0) },
        [pscustomobject]@{ DeviceId = 'd-lnx1'; DeviceName = 'LNX-01'; OSPlatform = 'Linux'; DeviceType = 'Server'; MachineGroup = 'Server'; LastSeen = (T 0) }
    )
    LicLogons = @(
        [pscustomobject]@{ DeviceId = 'd-win2'; AccountName = 'zed'; Logons = 4; Last = (T 1) },
        [pscustomobject]@{ DeviceId = 'd-mac1'; AccountName = 'hank'; Logons = 2; Last = (T 2) }
    )
    AsrInfo = @(
        [pscustomobject]@{ DeviceId = 'd-win1'; Asr = '{"LsassCredentialTheft":"Block","ObfuscatedScript":"Audit","OfficeChildProcess":"Warn","VulnerableSignedDriver":"Off","BlockWebshellCreation":""}' },
        [pscustomobject]@{ DeviceId = 'd-win2'; Asr = '{"LsassCredentialTheft":"Off","ObfuscatedScript":"Audit","OfficeChildProcess":"Off","VulnerableSignedDriver":"Off","BlockWebshellCreation":""}' }
    )
    AsrTvm = @(
        [pscustomobject]@{ DeviceId = 'd-win3'; Modes = [pscustomobject]@{ 'scid-2509' = 'Block'; 'scid-2505' = 'Block'; 'scid-2515' = 'Off'; 'scid-2516' = 'Block' } },
        [pscustomobject]@{ DeviceId = 'd-win1'; Modes = [pscustomobject]@{ 'scid-2509' = 'Off'; 'scid-2510' = 'Audit' } }
    )
    MdatpConfig = @(
        [pscustomobject]@{ Timestamp = (T 2); DeviceId = 'd-lnx1'; DeviceName = 'LNX-01'; ProcessCommandLine = 'mdatp config real-time-protection --value disabled'; AccountName = 'root' },
        [pscustomobject]@{ Timestamp = (T 3); DeviceId = 'd-lnx1'; DeviceName = 'LNX-01'; ProcessCommandLine = 'mdatp config behavior-monitoring --value disabled'; AccountName = 'root' },
        [pscustomobject]@{ Timestamp = (T 1); DeviceId = 'd-lnx1'; DeviceName = 'LNX-01'; ProcessCommandLine = 'mdatp config behavior-monitoring --value enabled'; AccountName = 'root' }
    )
    FileEvents = @(
        [pscustomobject]@{ Timestamp = (T 2); DeviceId = 'd-lnx1'; DeviceName = 'LNX-01'; ActionType = 'FileModified'; FolderPath = '/etc/opt/microsoft/mdatp/managed/mdatp_managed.json'; InitiatingProcessFileName = 'python3'; InitiatingProcessCommandLine = 'python3 /usr/bin/ansible-playbook site.yml'; InitiatingProcessAccountName = 'root' }
    )
    Tvm = @(
        foreach ($d in 'd-win1', 'd-win2') {
            foreach ($s in 'scid-2010', 'scid-2012', 'scid-91', 'scid-2016', 'scid-2013', 'scid-2003', 'scid-2011', 'scid-2002') {
                $bad = ($d -eq 'd-win1' -and $s -eq 'scid-2003')
                [pscustomobject]@{ DeviceId = $d; DeviceName = ($(if ($d -eq 'd-win1') { 'WIN-01' } else { 'WIN-02' })); OSPlatform = 'Windows11'; ConfigurationId = $s; IsApplicable = $true; IsCompliant = (-not $bad) }
            }
        }
    )
    TvmMac = @(
        [pscustomobject]@{ DeviceId = 'd-mac1'; DeviceName = 'MAC-01'; OSPlatform = 'macOS'; ConfigurationId = 'scid-5001'; ConfigurationName = 'Turn on tamper protection'; IsApplicable = $true; IsCompliant = $false },
        [pscustomobject]@{ DeviceId = 'd-mac1'; DeviceName = 'MAC-01'; OSPlatform = 'macOS'; ConfigurationId = 'scid-5002'; ConfigurationName = 'Enable real-time protection'; IsApplicable = $true; IsCompliant = $true },
        [pscustomobject]@{ DeviceId = 'd-mac1'; DeviceName = 'MAC-01'; OSPlatform = 'macOS'; ConfigurationId = 'scid-5003'; ConfigurationName = 'Grant Full Disk Access to Microsoft Defender'; IsApplicable = $true; IsCompliant = $true }
    )
    AgentVersions = @([pscustomobject]@{ DeviceId = 'd-mac1'; DeviceName = 'MAC-01'; SoftwareVersion = '101.2510.0001' })
    Info = @(
        [pscustomobject]@{ DeviceId = 'd-win1'; AvMode = '0'; AvSig = 'true'; AvPlat = 'true'; AvEng = 'true'; AvPlatVer = '4.18.25090.3'; AvEngVer = '1.1.25090.2'; AvSigVer = '1.435.100.0'; AvSigTime = (T 0); AvScan = ('{"Quick":{"ScanStatus":"Completed","Timestamp":"' + (T 20) + '"},"Full":{"ScanStatus":"Completed","Timestamp":"' + (T 40) + '"}}') },
        [pscustomobject]@{ DeviceId = 'd-win2'; AvMode = '1'; AvSig = 'true'; AvPlat = 'true'; AvEng = 'true'; AvPlatVer = '4.18.25040.1'; AvEngVer = '1.1.25040.1'; AvSigVer = '1.430.10.0'; AvSigTime = (T 10) },
        [pscustomobject]@{ DeviceId = 'd-win3'; AvMode = '0'; AvSig = 'true'; AvPlat = 'true'; AvEng = 'true'; AvPlatVer = '4.18.25080.2'; AvSigTime = (T 1); AvScan = ('{"Quick":{"ScanStatus":"Completed","Timestamp":"' + (T 1) + '"}}') },
        [pscustomobject]@{ DeviceId = 'd-mac1'; AvMode = '0'; AvSig = 'true'; AvPlat = 'true'; AvEng = 'true' }
    )
    Alerts = @([pscustomobject]@{ DeviceId = 'd-win1'; Alerts = 1; LastAlert = (T 2) })
    TvmWin = @(
        [pscustomobject]@{ DeviceId = 'd-win1'; DeviceName = 'WIN-01'; OSPlatform = 'Windows11'; ConfigurationId = 'scid-96'; ConfigurationName = 'Turn on Microsoft Defender Antivirus network protection'; IsApplicable = $true; IsCompliant = $false },
        [pscustomobject]@{ DeviceId = 'd-win2'; DeviceName = 'WIN-02'; OSPlatform = 'Windows11'; ConfigurationId = 'scid-96'; ConfigurationName = 'Turn on Microsoft Defender Antivirus network protection'; IsApplicable = $true; IsCompliant = $true },
        [pscustomobject]@{ DeviceId = 'd-win1'; DeviceName = 'WIN-01'; OSPlatform = 'Windows11'; ConfigurationId = 'scid-2021'; ConfigurationName = 'Turn on EDR in block mode'; IsApplicable = $true; IsCompliant = $true }
    )
    NpEvents = @(
        [pscustomobject]@{ DeviceId = 'd-win3'; Blocked = 2; Audited = 0; Last = (T 1) },
        [pscustomobject]@{ DeviceId = 'd-win1'; Blocked = 0; Audited = 5; Last = (T 1) }
    )
    Coverage = @(
        [pscustomobject]@{ DeviceId = 'd-old1'; DeviceName = 'OLD-01'; OSPlatform = 'Windows10'; OnboardingStatus = 'Onboarded'; AadDeviceId = 'AAD-OLD1'; DeviceType = 'Workstation'; LastSeen = (T 20) },
        [pscustomobject]@{ DeviceId = 'd-disc1'; DeviceName = 'PRINTER-7'; OSPlatform = 'Windows10'; OnboardingStatus = 'Can be onboarded'; AadDeviceId = ''; DeviceType = 'Workstation'; LastSeen = (T 1) },
        [pscustomobject]@{ DeviceId = 'd-disc2'; DeviceName = 'win-01.contoso.local'; OSPlatform = 'Windows11'; OnboardingStatus = 'Can be onboarded'; AadDeviceId = ''; DeviceType = 'Workstation'; LastSeen = (T 1) },
        [pscustomobject]@{ DeviceId = 'd-win1'; DeviceName = 'WIN-01'; OSPlatform = 'Windows11'; OnboardingStatus = 'Onboarded'; AadDeviceId = 'AAD-WIN1'; DeviceType = 'Workstation'; LastSeen = (T 0) }
    )
    Usage = @(
        [pscustomobject]@{ Key = 'n|powershell.exe'; Hits = 1234; Last = (T 0) },
        [pscustomobject]@{ Key = 'e|.ps1'; Hits = 77; Last = (T 1) }
    )
    Ps = @(
        [pscustomobject]@{ Timestamp = (T 3).Replace('Z',''); DeviceId = 'd-win2'; FileName = 'powershell.exe'; ProcessCommandLine = 'powershell.exe -c Add-MpPreference -ExclusionPath "C:\Users\Public\GapsioTest"'; AccountName = 'system' }
    )
    Registry = @(
        [pscustomobject]@{ Timestamp = (T 3); DeviceId = 'd-win2'; DeviceName = 'WIN-02'; ActionType = 'RegistryValueSet'; RegistryKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'; RegistryValueName = 'C:\Users\Public\GapsioTest'; InitiatingProcessFileName = 'MsMpEng.exe'; InitiatingProcessCommandLine = 'MsMpEng.exe'; InitiatingProcessAccountName = 'system' },
        [pscustomobject]@{ Timestamp = (T 10); DeviceId = 'd-win1'; DeviceName = 'WIN-01'; ActionType = 'RegistryValueSet'; RegistryKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'; RegistryValueName = 'C:\Users\Public\x'; InitiatingProcessFileName = 'powershell.exe'; InitiatingProcessCommandLine = 'powershell.exe Add-MpPreference -ExclusionPath C:\Users\Public\x'; InitiatingProcessAccountName = 'admin' },
        [pscustomobject]@{ Timestamp = (T 9); DeviceId = 'd-win1'; DeviceName = 'WIN-01'; ActionType = 'RegistryValueSet'; RegistryKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes'; RegistryValueName = 'cmd.exe'; InitiatingProcessFileName = 'setup.exe'; InitiatingProcessCommandLine = 'setup.exe /quiet'; InitiatingProcessAccountName = 'system' },
        [pscustomobject]@{ Timestamp = (T 8); DeviceId = 'd-win2'; DeviceName = 'WIN-02'; ActionType = 'RegistryValueSet'; RegistryKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'; RegistryValueName = 'D:\Temp\'; InitiatingProcessFileName = 'powershell.exe'; InitiatingProcessCommandLine = 'x'; InitiatingProcessAccountName = 'admin' },
        [pscustomobject]@{ Timestamp = (T 7); DeviceId = 'd-win2'; DeviceName = 'WIN-02'; ActionType = 'RegistryValueDeleted'; RegistryKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'; RegistryValueName = 'D:\Temp\'; InitiatingProcessFileName = 'powershell.exe'; InitiatingProcessCommandLine = 'x'; InitiatingProcessAccountName = 'admin' },
        [pscustomobject]@{ Timestamp = (T 6); DeviceId = 'd-win2'; DeviceName = 'WIN-02'; ActionType = 'RegistryValueSet'; RegistryKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions'; RegistryValueName = '.bak'; InitiatingProcessFileName = 'svchost.exe'; InitiatingProcessCommandLine = 'svchost.exe -k netsvcs -p -s gpsvc'; InitiatingProcessAccountName = 'system' }
    )
    Process = @(
        [pscustomobject]@{ Timestamp = (T 5); DeviceId = 'd-mac1'; DeviceName = 'MAC-01'; OSPlatform = 'macOS'; ProcessCommandLine = 'mdatp exclusion folder add --path /tmp/tools --scope epp'; AccountName = 'root' },
        [pscustomobject]@{ Timestamp = (T 4); DeviceId = 'd-mac1'; DeviceName = 'MAC-01'; OSPlatform = 'macOS'; ProcessCommandLine = 'mdatp threat allowed add --name EICAR-Test-File'; AccountName = 'root' }
    )
}

# Access
$users = @{
    'u-alice' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-alice'; userPrincipalName = 'alice@contoso.com'; displayName = 'Alice'; userType = 'Member'; accountEnabled = $true; assignedPlans = @([pscustomobject]@{ servicePlanId = '871d91ec-ec1a-452b-a83f-bd76c7d770ef'; servicePlanName = 'WINDEFATP'; capabilityStatus = 'Enabled' }, [pscustomobject]@{ servicePlanId = '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'; servicePlanName = 'THREAT_INTELLIGENCE'; capabilityStatus = 'Enabled' }) }
    'u-olga'  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-olga'; userPrincipalName = 'olga@contoso.com'; displayName = 'Olga'; userType = 'Member'; accountEnabled = $false; assignedPlans = @([pscustomobject]@{ servicePlanId = 'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'; servicePlanName = 'ATP_ENTERPRISE'; capabilityStatus = 'Enabled' }) }
    'u-bob'   = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-bob'; userPrincipalName = 'bob@contoso.com'; displayName = 'Bob'; userType = 'Member'; accountEnabled = $true; assignedPlans = @([pscustomobject]@{ servicePlanId = '292cc034-7b7c-4950-aaf5-943befd3f1d4'; servicePlanName = 'MDE_LITE'; capabilityStatus = 'Enabled' }) }
    'u-carol' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-carol'; userPrincipalName = 'carol@contoso.com'; displayName = 'Carol'; userType = 'Member'; accountEnabled = $true; assignedPlans = @([pscustomobject]@{ servicePlanId = '871d91ec-ec1a-452b-a83f-bd76c7d770ef'; servicePlanName = 'WINDEFATP'; capabilityStatus = 'Enabled' }) }
    'u-dave'  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-dave'; userPrincipalName = 'dave@contoso.com'; displayName = 'Dave'; userType = 'Member'; accountEnabled = $true; assignedPlans = @([pscustomobject]@{ servicePlanId = '871d91ec-ec1a-452b-a83f-bd76c7d770ef'; servicePlanName = 'WINDEFATP'; capabilityStatus = 'Deleted' }) }
    'u-erin'  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-erin'; userPrincipalName = 'erin@contoso.com'; displayName = 'Erin'; userType = 'Member' }
    'u-frank' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-frank'; userPrincipalName = 'frank@contoso.com'; displayName = 'Frank'; userType = 'Member' }
    'u-gina'  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-gina'; userPrincipalName = 'gina@contoso.com'; displayName = 'Gina'; userType = 'Member' }
    'u-hank'  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-hank'; userPrincipalName = 'hank@contoso.com'; displayName = 'Hank'; userType = 'Member' }
}
$grp = { param($id, $name) [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = $id; displayName = $name } }
$GA = '62e90394-69f5-4237-9190-012177145e10'; $SR = '5d6b6bb7-de71-4623-b4af-96380a352509'
$XSO = 'xdr-secops'; $XRD = 'xdr-reader'; $XCF = 'xdr-config'
$xdrRole = { param($id, $name, $actions) [pscustomobject]@{ id = $id; displayName = $name; description = ''; isBuiltIn = $true; rolePermissions = @([pscustomobject]@{ allowedResourceActions = @($actions) }) } }
$access = @{
    groups = @{ 'g1' = (& $grp 'g1' 'Helpdesk-Team'); 'g4' = (& $grp 'g4' 'Helpdesk-Candidates') }
    roleDefs = @(
        (& $xdrRole $XSO 'SecOps Responder' @('microsoft.xdr/secops/securitydata/basic/read', 'microsoft.xdr/secops/securitydata/alerts/manage', 'microsoft.xdr/secops/securitydata/response/manage', 'microsoft.xdr/secops/securitydata/liveresponse-basic/manage')),
        (& $xdrRole $XRD 'Defender Reader' @('microsoft.xdr/secops/securitydata/basic/read', 'microsoft.xdr/securityposture/posturemanagement/read')),
        (& $xdrRole $XCF 'Defender Settings Admin' @('microsoft.xdr/configuration/security/manage'))
    )
    # unifiedRoleAssignmentMultiple: principalIds + appScopeIds ("/" = all data sources, "Mde" = Defender for Endpoint)
    assignments = @(
        [pscustomobject]@{ id = 'xa1'; displayName = 'SecOps – everything'; roleDefinitionId = $XSO; principalIds = @('u-alice'); appScopeIds = @('/') },
        [pscustomobject]@{ id = 'xa2'; displayName = 'SecOps – endpoints'; roleDefinitionId = $XSO; principalIds = @('g1'); appScopeIds = @('Mde') },
        [pscustomobject]@{ id = 'xa3'; displayName = 'Readers'; roleDefinitionId = $XRD; principalIds = @('u-bob'); appScopeIds = @('Mde', 'Mdi') },
        [pscustomobject]@{ id = 'xa4'; displayName = 'Settings'; roleDefinitionId = $XCF; principalIds = @('u-carol'); appScopeIds = @('/') }
    )
    members = @{ 'g1' = @($users['u-dave'], $users['u-erin']); 'g4' = @($users['u-hank']) }
    pimGroups = @{ 'g1' = @([pscustomobject]@{ groupId = 'g1'; principalId = 'u-gina'; accessId = 'member'; endDateTime = (T -30) }) }
    pimActivations = @{ 'g1' = @([pscustomobject]@{ groupId = 'g1'; principalId = 'u-gina'; accessId = 'member'; action = 'selfActivate'; createdDateTime = (T 10) }) }
    signIns = @(
        [pscustomobject]@{ userId = 'u-alice'; createdDateTime = (T 2) },
        [pscustomobject]@{ userId = 'u-alice'; createdDateTime = (T 9) },
        [pscustomobject]@{ userId = 'u-gina'; createdDateTime = (T 10) }
    )
    # Entra roles bypassing unified RBAC
    entraBypass = @(
        [pscustomobject]@{ principalId = 'u-alice'; roleDefinitionId = $GA; directoryScopeId = '/'; principal = $users['u-alice'] },
        [pscustomobject]@{ principalId = 'u-bob'; roleDefinitionId = $SR; directoryScopeId = '/'; principal = $users['u-bob'] }
    )
    aps = @(
        [pscustomobject]@{ id = 'ap1'; displayName = 'Helpdesk access'; assignmentPolicies = @([pscustomobject]@{ id = 'pol1'; displayName = 'Candidates'; allowedTargetScope = 'specificDirectoryUsers'; requestorSettings = [pscustomobject]@{ enableTargetsToSelfAddAccess = $true }; specificAllowedTargets = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupMembers'; groupId = 'g4' }) }) },
        [pscustomobject]@{ id = 'ap2'; displayName = 'SecOps for everyone'; assignmentPolicies = @([pscustomobject]@{ id = 'pol2'; displayName = 'All employees'; allowedTargetScope = 'allMemberUsers'; requestorSettings = [pscustomobject]@{ enableTargetsToSelfAddAccess = $true }; specificAllowedTargets = @() }) }
    )
    apDetail = @{
        'ap1' = [pscustomobject]@{ resourceRoleScopes = @([pscustomobject]@{ role = [pscustomobject]@{ originSystem = 'AadGroup'; originId = 'Member_g1'; resource = [pscustomobject]@{ originId = 'g1' } }; scope = [pscustomobject]@{ originId = 'g1' } }) }
        'ap2' = [pscustomobject]@{ resourceRoleScopes = @([pscustomobject]@{ role = [pscustomobject]@{ originSystem = 'AadGroup'; originId = 'Member_g1'; resource = [pscustomobject]@{ originId = 'g1' } }; scope = [pscustomobject]@{ originId = 'g1' } }) }
    }
    apAssignments = @([pscustomobject]@{ state = 'delivered'; accessPackage = [pscustomobject]@{ id = 'ap1'; displayName = 'Helpdesk access' }; target = [pscustomobject]@{ objectId = 'u-erin'; principalName = 'erin@contoso.com'; displayName = 'Erin' }; schedule = [pscustomobject]@{ expiration = [pscustomobject]@{ endDateTime = (T -90) } } })
}

# AI agents (Entra Agent ID, Agent 365 Registry, Defender AgentsInfo, Conditional Access)
$agentFx = @{
    blueprints = @([pscustomobject]@{ id = 'bp-obj-1'; appId = 'bp-app-1'; displayName = 'Contoso Helpdesk Blueprint'; publisherDomain = 'contoso.com'; createdDateTime = '2026-05-01T00:00:00Z' })
    principals = @([pscustomobject]@{ id = 'bpp-1'; appId = 'bp-app-1'; displayName = 'Contoso Helpdesk Blueprint'; accountEnabled = $true })
    identities = @(
        [pscustomobject]@{ id = 'ai-1'; appId = 'ai-app-1'; displayName = 'Helpdesk Agent'; accountEnabled = $true; agentIdentityBlueprintId = 'bp-app-1'; createdDateTime = '2026-06-01T00:00:00Z'; sponsors = @([pscustomobject]@{ id = 'u-alice'; displayName = 'Alice'; userPrincipalName = 'alice@contoso.com' }) },
        [pscustomobject]@{ id = 'ai-2'; appId = 'ai-app-2'; displayName = 'Report Agent'; accountEnabled = $true; agentIdentityBlueprintId = 'bp-app-1'; createdDateTime = '2026-06-02T00:00:00Z'; sponsors = @() },
        [pscustomobject]@{ id = 'ai-3'; appId = 'ai-app-3'; displayName = 'Legacy Agent'; accountEnabled = $true; agentIdentityBlueprintId = 'bp-unknown'; createdDateTime = '2026-06-03T00:00:00Z'; sponsors = @([pscustomobject]@{ id = 'u-bob'; displayName = 'Bob' }) }
    )
    users = @(
        [pscustomobject]@{ id = 'au-1'; displayName = 'Helpdesk Agent'; userPrincipalName = 'helpdesk-agent@contoso.com'; accountEnabled = $true; identityParentId = 'ai-1' },
        [pscustomobject]@{ id = 'au-2'; displayName = 'Report Agent'; userPrincipalName = 'report-agent@contoso.com'; accountEnabled = $true; identityParentId = 'ai-2' },
        [pscustomobject]@{ id = 'au-3'; displayName = 'Orphan'; userPrincipalName = 'orphan-agent@contoso.com'; accountEnabled = $true; identityParentId = 'ai-gone' }
    )
    registry = @(
        [pscustomobject]@{ id = 'reg-1'; displayName = 'Helpdesk Agent'; agentIdentityId = 'ai-1'; agentIdentityBlueprintId = 'bp-obj-1'; agentUserId = 'au-1'; originatingStore = 'Copilot Studio'; ownerIds = @('u-alice') },
        [pscustomobject]@{ id = 'reg-2'; displayName = 'Sales Agent'; originatingStore = 'Copilot Studio'; sourceAgentId = 'cs-77'; ownerIds = @('u-carol') }
    )
    policies = @(
        [pscustomobject]@{ id = 'ca-1'; displayName = 'Agents: approved only'; state = 'enabled'; conditions = [pscustomobject]@{ clientApplications = [pscustomobject]@{ includeAgentIdServicePrincipals = @('All'); excludeAgentIdServicePrincipals = @('ai-3') }; applications = [pscustomobject]@{ includeApplications = @('All') } }; grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('block') } },
        [pscustomobject]@{ id = 'ca-2'; displayName = 'Agent users: compliant device'; state = 'enabledForReportingButNotEnforced'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('AllAgentIdUsers'); excludeUsers = @('au-2') }; applications = [pscustomobject]@{ includeApplications = @('All') } }; grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('compliantDevice') } },
        [pscustomobject]@{ id = 'ca-3'; displayName = 'All users: MFA'; state = 'enabled'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All') }; applications = [pscustomobject]@{ includeApplications = @('All') } }; grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('mfa') } },
        [pscustomobject]@{ id = 'ca-4'; displayName = 'Agents: high risk (disabled)'; state = 'disabled'; conditions = [pscustomobject]@{ clientApplications = [pscustomobject]@{ includeAgentIdServicePrincipals = @('All') }; agentIdRiskLevels = @('high') }; grantControls = [pscustomobject]@{ builtInControls = @('block') } }
    )
}
foreach ($cv in @(@('d-win1', '10.8750.26100.4061'), @('d-win2', '10.8295.22621.1'), @('d-win3', '10.8760.20348.1'))) { $hunting.DeviceInfo | Where-Object DeviceId -eq $cv[0] | Add-Member -NotePropertyName ClientVersion -NotePropertyValue $cv[1] -Force }
$hunting.AgentsInfo = @(
    [pscustomobject]@{ AgentId = 'mde-1'; Name = 'Report Agent'; Platform = 'Microsoft Foundry'; EntraAgentId = 'ai-2'; EntraBlueprintId = 'bp-app-1'; PublishedStatus = 'Published'; LifecycleStatus = 'Active'
        Model = 'gpt-5'; Guardrails = '[]'; Endpoints = '[{"url":"https://agent.contoso.com/api","transport":"https","isExternal":true}]'; Owners = '[{"displayName":"Bob","userPrincipalName":"bob@contoso.com"}]'
        DeclaredTools = '[{"name":"search"},{"name":"mail"}]'; McpServers = '[{"name":"crm","url":"https://mcp.contoso.com","transport":"http"}]' },
    [pscustomobject]@{ AgentId = 'mde-2'; Name = 'Local Agent'; Platform = 'LocalAgents'; EntraAgentId = ''; EntraBlueprintId = ''; PublishedStatus = ''; LifecycleStatus = ''; IsLocal = $true
        Vendor = 'OpenAI'; LocalDeviceId = 'd-win1'; LocalDeviceName = 'WIN-01'; LocalOs = 'Windows11'; LocalUser = 'alice@contoso.com'; AutoApprove = 'true'; TrustedProcess = 'true'; Process = 'codex.exe'
        LocalMcps = '[{"name":"filesystem","commandName":"npx","commandArgs":["-y","@modelcontextprotocol/server-filesystem"]},{"name":"pinned","commandName":"npx","commandArgs":["tool@1.2.3"]}]'; McpServers = '[]' }
)
$fixtures.agents = $agentFx
$access.members['g-dc'] = @([pscustomobject]@{ id = 'dev-obj-win1'; deviceId = 'AAD-WIN1' })

Write-Host '== HTTP layer (real local server)' -ForegroundColor Cyan
# Checks Invoke-GapsioRest with the real cmdlets (Invoke-WebRequest/-RestMethod) – parameter errors only show up this way.
$port = Get-Random -Minimum 20000 -Maximum 40000
$listener = [System.Net.HttpListener]::new(); $listener.Prefixes.Add("http://127.0.0.1:$port/"); $listener.Start()
$ps = [powershell]::Create().AddScript({
    param($l)
    for ($i = 0; $i -lt 4; $i++) {
        $c = $l.GetContext()
        $code = if ($c.Request.Url.AbsolutePath -like '*missing*') { 404 } else { 200 }
        $body = if ($code -eq 200) { '{"ok":true,"text":"äö"}' } else { '{"error":"nope"}' }
        $bytes = [Text.Encoding]::UTF8.GetBytes($body)
        $c.Response.StatusCode = $code; $c.Response.ContentType = 'application/json; charset=utf-8'
        $c.Response.OutputStream.Write($bytes, 0, $bytes.Length); $c.Response.Close()
    }
}).AddArgument($listener)
$async = $ps.BeginInvoke()
try {
    & $mod {
        param($A, $Port)
        function Get-GapsioToken { param($Resource) 'test-token' }
        $base = "http://127.0.0.1:$Port"
        $raw = Invoke-GapsioRest -Uri "$base/blob" -Resource 'https://storage.azure.com' -Raw -MaxRetries 0
        & $A ($raw -is [string] -and $raw -match '"ok":true') "Invoke-GapsioRest -Raw returns text ($raw)"
        $obj = Invoke-GapsioRest -Uri "$base/obj" -Resource 'https://graph.microsoft.com' -MaxRetries 0
        & $A ($obj.ok -eq $true -and $obj.text -eq 'äö') 'Invoke-GapsioRest returns an object with UTF-8'
        $st = $null; try { Invoke-GapsioRest -Uri "$base/missing" -Resource 'https://storage.azure.com' -Raw -MaxRetries 0 | Out-Null } catch { $st = $_.Exception.Data['Status'] ; if (-not $st) { $st = [string]$_ } }
        & $A ([string]$st -match '404') "Invoke-GapsioRest -Raw reports 404 ($st)"
        $st = $null; try { Invoke-GapsioRest -Uri "$base/missing" -Resource 'https://graph.microsoft.com' -MaxRetries 0 | Out-Null } catch { $st = $_.Exception.Data['Status'] ; if (-not $st) { $st = [string]$_ } }
        & $A ([string]$st -match '404') "Invoke-GapsioRest reports 404 ($st)"
    } ${function:Assert} $port
}
finally { $listener.Stop(); $ps.Dispose() }

Write-Host '== Least privilege: features and federated data app' -ForegroundColor Cyan
& $mod {
    param($A)
    $saved = @{}; foreach ($n in 'GAPSIO_FEATURES', 'GAPSIO_DEVICE_INVENTORY', 'GAPSIO_DATA_APP_ID', 'GAPSIO_TENANT_ID', 'IDENTITY_ENDPOINT', 'IDENTITY_HEADER', 'GAPSIO_CLIENT_ID') { $saved[$n] = [Environment]::GetEnvironmentVariable($n) }
    try {
        $env:GAPSIO_FEATURES = $null; $env:GAPSIO_DEVICE_INVENTORY = $null
        & $A ((Test-GapsioFeature 'hunting') -and (Test-GapsioFeature 'indicators') -and -not (Test-GapsioFeature 'inventory')) 'Default features: hunting + indicators, no inventory'
        $env:GAPSIO_FEATURES = 'indicators'
        & $A (-not (Test-GapsioFeature 'Hunting') -and (Test-GapsioFeature 'INDICATORS')) 'GAPSIO_FEATURES limits features (case-insensitive)'
        & $A ($null -eq (Invoke-GapsioHuntingSafe -Query 'DeviceInfo' -Context 'x')) 'Hunting off -> no Advanced Hunting call'
        $env:GAPSIO_DEVICE_INVENTORY = 'true'
        & $A (Test-GapsioFeature 'inventory') 'Legacy GAPSIO_DEVICE_INVENTORY still enables inventory'

        $calls = [System.Collections.Generic.List[object]]::new()
        function Invoke-RestMethod { param($Method, $Uri, $ContentType, $Body, $Headers)
            $calls.Add([pscustomobject]@{ Uri = [string]$Uri; Body = $Body })
            if ($Uri -like '*oauth2/v2.0/token') { return [pscustomobject]@{ access_token = "app-token-$($Body.scope)"; expires_in = 3600 } }
            [pscustomobject]@{ access_token = 'mi-assertion'; expires_on = [DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds() }
        }
        $env:IDENTITY_ENDPOINT = 'http://mi.local/msi/token'; $env:IDENTITY_HEADER = 'h'; $env:GAPSIO_CLIENT_ID = 'mi-client'
        $env:GAPSIO_DATA_APP_ID = 'data-app-1'; $env:GAPSIO_TENANT_ID = 'tenant-1'
        $script:GapsioTokens.Clear()
        $t = Get-GapsioToken -Resource 'https://graph.microsoft.com'
        $ex = @($calls | Where-Object { $_.Uri -like '*oauth2*' })[0]
        & $A ($t -eq 'app-token-https://graph.microsoft.com/.default') "Graph token comes from the data app ($t)"
        & $A ($ex.Uri -eq 'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token' -and $ex.Body.client_id -eq 'data-app-1' -and $ex.Body.client_assertion -eq 'mi-assertion' -and $ex.Body.client_assertion_type -like '*jwt-bearer') 'Token exchange: client assertion from the managed identity'
        & $A (@($calls | Where-Object { $_.Uri -like '*AzureADTokenExchange*' -and $_.Uri -like '*client_id=mi-client*' }).Count -eq 1) 'Assertion requested for api://AzureADTokenExchange'
        $n = $calls.Count
        $s = Get-GapsioToken -Resource 'https://storage.azure.com'
        & $A ($s -eq 'mi-assertion' -and @($calls | Select-Object -Skip $n | Where-Object { $_.Uri -like '*oauth2*' }).Count -eq 0) 'Storage keeps using the managed identity directly'
        $n = $calls.Count; $null = Get-GapsioToken -Resource 'https://graph.microsoft.com'
        & $A ($calls.Count -eq $n) 'Data app token is cached'
        $env:GAPSIO_DATA_APP_ID = $null; $script:GapsioTokens.Clear()
        & $A ((Get-GapsioToken -Resource 'https://graph.microsoft.com') -eq 'mi-assertion') 'Without GAPSIO_DATA_APP_ID: managed identity token'
    }
    finally {
        foreach ($n in $saved.Keys) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
        $script:GapsioTokens.Clear()
        Remove-Item function:Invoke-RestMethod -ErrorAction SilentlyContinue
    }
} ${function:Assert}

& $mod {
    param($A)
    $b64 = { param($o) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $iat = [DateTimeOffset]::new(2026, 10, 30, 6, 0, 0, [TimeSpan]::Zero).ToUnixTimeSeconds()
    $jwt = 'eyJhbGciOiJub25lIn0.' + (& $b64 @{ iat = $iat; roles = @('Policy.Read.All', 'ThreatHunting.Read.All') }) + '.sig'
    $script:GapsioTokens['https://graph.microsoft.com'] = @{ Token = $jwt; ExpiresOn = [DateTime]::UtcNow.AddMinutes(30) }
    $e403 = New-GapsioHttpException -Status 403 -Message 'HTTP 403 for GET https://graph.microsoft.com/beta/x :: {"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}'
    $t = Get-GapsioErrorText -Exception $e403 -Context 'Agent identities (AgentIdentity.Read.All)'
    & $A ($t -like 'HTTP 403 (Authorization_RequestDenied)*' -and $t -like '*Token issued 2026-10-30 06:00 UTC with 2 permission(s)*' -and $t -like '*Not in the token: AgentIdentity.Read.All*' -and $t -like '*up to 24 hours*') "403 notice explains the token ($t)"
    $t = Get-GapsioErrorText -Exception $e403 -Context 'Conditional Access policies (Policy.Read.All)'
    & $A ($t -like '*The token contains Policy.Read.All*') '403 notice: permission present in the token'
    $e404 = New-GapsioHttpException -Status 404 -Message 'HTTP 404 for GET x :: nf'
    & $A ((Get-GapsioErrorText -Exception $e404 -Context 'X') -eq 'HTTP 404 for GET x :: nf') 'Other errors keep their message'
    $eTable = [Exception]::new('HTTP 400 for POST https://graph.microsoft.com/v1.0/security/runHuntingQuery :: {"error":{"code":"BadRequest","message":"''where'' operator: Failed to resolve table expression named ''[\"TvmBrowserExtensions\"]'' in Database=''''. Fix semantic errors in your query."}}'); $eTable.Data['Status'] = 400
    $t = Get-GapsioErrorText -Exception $eTable -Context 'Advanced Hunting browser extensions'
    & $A ($t -match '^The Advanced Hunting table TvmBrowserExtensions does not exist in this tenant' -and $t -match 'check is skipped' -and $t -match '\[HTTP 400\]$' -and $t -notmatch 'semantic|request-id|graph\.microsoft') 'Missing hunting table: calm notice instead of the raw HTTP 400'
    $script:GapsioTokens.Clear()
    $saved = @{ IDENTITY_ENDPOINT = $env:IDENTITY_ENDPOINT; IDENTITY_HEADER = $env:IDENTITY_HEADER }
    try {
        function Invoke-RestMethod { [pscustomobject]@{ access_token = 'long'; expires_on = [DateTimeOffset]::UtcNow.AddHours(24).ToUnixTimeSeconds() } }
        $env:IDENTITY_ENDPOINT = 'http://mi.local/msi/token'; $env:IDENTITY_HEADER = 'h'
        $null = Get-GapsioToken -Resource 'https://graph.microsoft.com'
        & $A ($script:GapsioTokens['https://graph.microsoft.com'].ExpiresOn -le [DateTime]::UtcNow.AddMinutes(61)) 'Managed identity tokens are cached for at most an hour'
    }
    finally {
        foreach ($n in $saved.Keys) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
        $script:GapsioTokens.Clear()
        Remove-Item function:Invoke-RestMethod -ErrorAction SilentlyContinue
    }
} ${function:Assert}

Write-Host '== Setup: permission model' -ForegroundColor Cyan
. (Join-Path $root 'setup/GapsioSetup.ps1')
Assert ((Resolve-GapsioFeatures -Features 'hunting', 'Hunting') -join ',' -eq 'Core,Hunting') 'Resolve-GapsioFeatures: Core always, names normalised, no duplicates'
$threw = $false; try { Resolve-GapsioFeatures -Features 'Everything' | Out-Null } catch { $threw = $true }
Assert $threw 'Unknown feature is rejected'
$ps = @(Get-GapsioPermissionSet -Features 'Core', 'Hunting' | ForEach-Object Value)
Assert (($ps -contains 'ThreatHunting.Read.All') -and ($ps -contains 'DeviceManagementConfiguration.Read.All') -and -not ($ps -contains 'Policy.Read.All') -and -not ($ps -contains 'Ti.Read.All')) "Core + Hunting grants only their permissions ($($ps -join ', '))"
$permModel = Get-Content -Raw (Join-Path $root 'setup/permissions.json') | ConvertFrom-Json
$allPerms = @($permModel.features | ForEach-Object { $_.permissions } | ForEach-Object value)
Assert (@($allPerms | Where-Object { $_ -notmatch '\.Read(Basic)?\.' }).Count -eq 0) "All Gapsio permissions are read-only ($(@($allPerms | Where-Object { $_ -notmatch '\.Read(Basic)?\.' }) -join ', '))"
Assert (@($permModel.features | Where-Object required).id -join ',' -eq 'Core') 'Only Core is required'
Assert (@($permModel.features | ForEach-Object { $_.permissions } | Where-Object { -not $permModel.resources.($_.resource) }).Count -eq 0) 'Every permission references a known resource'

$blobs = @{}
$queue = [System.Collections.Generic.List[string]]::new()
& $mod {
    param($Fx, $Hunt, $Acc, $Users, $Blobs, $Queue)
    $script:Fx = $Fx; $script:Hunt = $Hunt; $script:Acc = $Acc; $script:Users = $Users; $script:Blobs = $Blobs; $script:Queue = $Queue
    $script:HuntQueries = [System.Collections.Generic.List[string]]::new()
    $script:GapsioHuntingCallsPerMinute = 1000000   # the hunting API is simulated: do not wait for the real 45-calls-per-minute budget
    $env:GAPSIO_STORAGE_ACCOUNT = 'teststorage'; $env:GAPSIO_TENANT_ID = '00000000-0000-0000-0000-000000000001'; $env:GAPSIO_FEATURES = 'hunting,indicators,coverage,response,detections'

    function script:V { param($Items) [pscustomobject]@{ value = @($Items) } }

    function script:Invoke-GapsioRest {
        param([string]$Uri, [string]$Method = 'GET', $Body, [string]$Resource, [hashtable]$Headers = @{}, [string]$ContentType, [switch]$Raw, [int]$MaxRetries)
        if ($Uri -match '\.blob\.core\.windows\.net/(.+)$') {
            $k = $Matches[1]
            if ($Method -eq 'PUT') { $script:Blobs[$k] = [string]$Body; return '' }
            if ($Method -eq 'DELETE') { if ($script:Blobs.ContainsKey($k)) { $script:Blobs.Remove($k); return '' }; throw (New-GapsioHttpException -Status 404 -Message "404 $k") }
            if (-not $script:Blobs.ContainsKey($k)) { throw (New-GapsioHttpException -Status 404 -Message "404 $k") }
            if ($Raw) { return $script:Blobs[$k] } else { return ($script:Blobs[$k] | ConvertFrom-Json) }
        }
        if ($Uri -match '\.queue\.core\.windows\.net/') { $script:Queue.Add([string]$Body); return '' }
        if ($Uri -match 'runHuntingQuery') {
            $q = [string]$Body.Query
            $script:HuntQueries.Add($q)
            $rows = if ($q -match '^AgentsInfo') { $script:Hunt.AgentsInfo }
            elseif ($q -match '// GapsioOffice:(\w+)') { $ok = $Matches[1]; if ($script:Hunt.OfficeFail -contains $ok) { throw (New-GapsioHttpException -Status 400 -Message "Failed to resolve table for $ok") }; $script:Hunt.Office[$ok] }
            elseif ($q -match '// GapsioUsbMounts') { $script:Hunt.UsbMounts }
            elseif ($q -match '// GapsioDeviceControl') { $script:Hunt.DeviceControl }
            elseif ($q -match '// GapsioMdi') { if ($script:Hunt.MdiMissing) { throw "Failed to resolve table expression named 'IdentityDirectoryEvents'" }; $script:Hunt.Mdi }
            elseif ($q -match '// GapsioDisruption') { $script:Hunt.Disruption }
            elseif ($q -match '// GapsioDetectionAlerts') { $script:Hunt.DetectionAlerts }
            elseif ($q -match '// GapsioAsrTelemetry') { $script:Hunt.AsrTelemetry }
            elseif ($q -match '// GapsioWsl') { $script:Hunt.Wsl }
            elseif ($q -match '// GapsioBrowserExtensions') { $script:Hunt.BrowserExtensions }
            elseif ($q -match '// GapsioThreatActions') { $script:Hunt.ThreatActions }
            elseif ($q -match '// GapsioCoverage') { $script:Hunt.Coverage }
            elseif ($q -match '// GapsioFleetTroubleshooting') { $script:Hunt.Troubleshooting }
            elseif ($q -match '// GapsioFleetTampering') { $script:Hunt.Tampering }
            elseif ($q -match '// GapsioThirdPartyAv') { $script:Hunt.ThirdPartyAv }
            elseif ($q -match '// GapsioLicensingDevices') { $script:Hunt.LicDevices }
            elseif ($q -match '// GapsioLicensingLogons') { $script:Hunt.LicLogons }
            elseif ($q -match '// GapsioUsage') { $script:Hunt.Usage }
            elseif ($q -match '// GapsioNetworkProtection') { $script:Hunt.NpEvents }
            elseif ($q -match 'startswith "Windows"') { $script:Hunt.TvmWin }
            elseif ($q -match 'AsrConfigurationStates') { $script:Hunt.AsrInfo }
            elseif ($q -match 'Attack Surface Reduction') { $script:Hunt.AsrTvm }
            elseif ($q -match 'DeviceFileEvents') { $script:Hunt.FileEvents }
            elseif ($q -match '"--value"') { $script:Hunt.MdatpConfig }
            elseif ($q -match 'DeviceRegistryEvents') { $script:Hunt.Registry }
            elseif ($q -match 'MpPreference') { $script:Hunt.Ps }
            elseif ($q -match 'DeviceProcessEvents') { $script:Hunt.Process }
            elseif ($q -match 'DeviceTvmSoftwareInventory') { $script:Hunt.AgentVersions }
            elseif ($q -match 'DeviceTvmSecureConfigurationAssessmentKB') { $script:Hunt.TvmMac }
            elseif ($q -match 'DeviceTvmSecureConfigurationAssessment') { $script:Hunt.Tvm }
            elseif ($q -match 'DeviceTvmInfoGathering') { $script:Hunt.Info }
            elseif ($q -match 'AlertInfo') { $script:Hunt.Alerts }
            elseif ($q -match 'DeviceInfo') { if ($script:Hunt.DeviceInfoFail) { throw 'HTTP 500 for POST runHuntingQuery :: test' }; $script:Hunt.DeviceInfo }
            else { throw "Unbekannte Hunting-Abfrage" }
            return [pscustomobject]@{ schema = @(); results = @($rows) }
        }
        if ($Uri -match 'api.securitycenter.microsoft.com/api/indicators') { return (V $script:Fx.indicators) }
        if ($Uri -match 'api.securitycenter.microsoft.com/api/machineactions') { return (V $script:Fx.machineActions) }
        if ($Uri -match 'api.securitycenter.microsoft.com/api/alerts') { return (V $script:Fx.mdeAlerts) }
        if ($Uri -match 'api.securitycenter.microsoft.com/api/machines\?') {
            if ($Uri -notmatch "healthStatus eq 'Inactive' and lastSeen lt ") { throw "machines filter unexpected: $Uri" }
            return (V @([pscustomobject]@{ id = 'd-old9'; computerDnsName = 'OLD-09'; osPlatform = 'Windows10'; lastSeen = ([DateTime]::UtcNow.AddDays(-120).ToString('o')); rbacGroupName = 'Clients'; onboardingStatus = 'Onboarded'; healthStatus = 'Inactive' }))
        }

        $path = ($Uri -replace '^https://graph.microsoft.com/(v1.0|beta)/', '')
        switch -Regex ($path) {
            '^deviceManagement/configurationPolicies\?' { return (V $script:Fx.policies) }
            '^applications/microsoft.graph.agentIdentityBlueprint' { return (V $script:Fx.agents.blueprints) }
            '^servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal' { return (V $script:Fx.agents.principals) }
            '^servicePrincipals/microsoft.graph.agentIdentity\?' { return (V $script:Fx.agents.identities) }
            '^users/microsoft.graph.agentUser' { return (V $script:Fx.agents.users) }
            '^copilot/admin/catalog/packages' {
                if ($script:Fx.agents.packages) { return (V $script:Fx.agents.packages) }
                throw (New-GapsioHttpException -Status 403 -Message 'HTTP 403 Forbidden')
            }
            '^agentRegistry/agentInstances' { if ($script:Fx.agents.registry404) { throw (New-GapsioHttpException -Status 404 -Message 'HTTP 404 Not Found') }; return (V $script:Fx.agents.registry) }
            '^deviceManagement/managedDevices\?' { return (V $script:Fx.managedDevices) }
            '^subscribedSkus' { return (V $script:Fx.skus) }
            '^security/rules/detectionRules' { if ($Uri -notmatch '/v1\.0/') { throw 'detection rules must be read from v1.0 first' }; return (V $script:Fx.detectionRules) }
            '^users\?\$select=id,userPrincipalName,displayName,accountEnabled,userType,assignedPlans' { return (V @($script:Users.Values)) }
            '^identity/conditionalAccess/policies' { return (V $script:Fx.agents.policies) }
            '^policies/identitySecurityDefaultsEnforcementPolicy' { return [pscustomobject]@{ isEnabled = $false } }
            "^deviceManagement/configurationSettings\('([^']+)'\)" { if ($script:Fx.definitions.ContainsKey($Matches[1])) { return $script:Fx.definitions[$Matches[1]] }; throw (New-GapsioHttpException -Status 404 -Message 'nf') }
            "^deviceManagement/configurationPolicies\('([^']+)'\)/settings" { return (V $script:Fx.settings[$Matches[1]]) }
            "^deviceManagement/configurationPolicies\('([^']+)'\)/assignments" { if ($script:Fx.assignmentsByPolicy -and $script:Fx.assignmentsByPolicy.ContainsKey($Matches[1])) { return (V $script:Fx.assignmentsByPolicy[$Matches[1]]) }; return (V $script:Fx.assignments) }
            '^deviceManagement/intents\?' { return (V @()) }
            '^deviceManagement/deviceHealthScripts\?' { return (V $script:Fx.healthScripts) }
            '^deviceManagement/deviceHealthScripts/([^/]+)/deviceRunStates' { return (V $script:Fx.runStates) }
            '^deviceManagement/deviceConfigurations$' { return (V $script:Fx.deviceConfigurations) }
            '^deviceManagement/deviceConfigurations/[^/]+/assignments' { return (V @($script:Fx.assignments[0])) }
            '^groups/([^/?]+)\?\$select=id,displayName' { $id = $Matches[1]; return [pscustomobject]@{ id = $id; displayName = $script:Fx.groups[$id] } }
            '^groups/([^/]+)/transitiveMembers' { return (V $script:Acc.members[$Matches[1]]) }
            '^roleManagement/defender/roleDefinitions' { return (V $script:Acc.roleDefs) }
            '^roleManagement/defender/roleAssignments' { return (V $script:Acc.assignments) }
            '^roleManagement/directory/roleAssignments\?' {
                if ($Path -match ' in \(') { throw 'HTTP 400 Multiple roleDefinitionId in filter not supported.' }
                if ($Path -match "roleDefinitionId eq '([^']+)'") { $rid = $Matches[1]; return (V @($script:Acc.entraBypass | Where-Object { $_.roleDefinitionId -eq $rid })) }
                return (V $script:Acc.entraBypass)
            }
            "^identityGovernance/privilegedAccess/group/eligibilityScheduleInstances\?\`$filter=groupId eq '([^']+)'" { return (V $script:Acc.pimGroups[$Matches[1]]) }
            "^identityGovernance/privilegedAccess/group/assignmentScheduleRequests\?\`$filter=groupId eq '([^']+)'" { return (V $script:Acc.pimActivations[$Matches[1]]) }
            '^auditLogs/signIns\?' { if ($Uri -notmatch '80ccca67-54bd-44ab-8625-4b79c4dc7775') { throw 'sign-in filter without Defender portal appId' }; return (V $script:Acc.signIns) }
            '^identityGovernance/entitlementManagement/accessPackages\?' { return (V $script:Acc.aps) }
            '^identityGovernance/entitlementManagement/accessPackages/([^?]+)\?' { return $script:Acc.apDetail[$Matches[1]] }
            '^identityGovernance/entitlementManagement/assignments' { return (V $script:Acc.apAssignments) }
            '^directoryObjects/getByIds' {
                if ($Method -ne 'POST') { throw 'getByIds must be POST' }
                return (V @(foreach ($id in @($Body.ids)) { if ($script:Users.ContainsKey($id)) { $script:Users[$id] } elseif ($script:Acc.groups.ContainsKey($id)) { $script:Acc.groups[$id] } }))
            }
            '^directoryObjects/(.+)$' { $id = $Matches[1]; if ($script:Users.ContainsKey($id)) { return $script:Users[$id] }; if ($script:Acc.groups.ContainsKey($id)) { return $script:Acc.groups[$id] }; throw (New-GapsioHttpException -Status 404 -Message 'nf') }
            '^users\?\$filter=startswith\(displayName,''([^'']*)''\)' { $q = $Matches[1]; return (V @($script:Users.Values | Where-Object { [string]$_.displayName -like "$q*" })) }
            '^groups\?\$filter=startswith\(displayName,''([^'']*)''\)' { $q = $Matches[1]; return (V @($script:Acc.groups.Values | Where-Object { [string]$_.displayName -like "$q*" })) }
            '^users/([^?]+)\?' { return $script:Users[$Matches[1]] }
            "^servicePrincipals\(appId='([^']+)'\)" {
                $rid = $Matches[1]
                $roles = switch ($rid) {
                    'fc780465-2017-40d4-a0c5-307022471b92' { @([pscustomobject]@{ id = 'r-off'; value = 'Machine.Offboard' }, [pscustomobject]@{ id = 'r-read'; value = 'Machine.Read.All' }) }
                    '00000003-0000-0000-c000-000000000000' { @([pscustomobject]@{ id = 'g-hunt'; value = 'ThreatHunting.Read.All' }, [pscustomobject]@{ id = 'g-mail'; value = 'Mail.Read' }) }
                    default { @() }
                }
                return [pscustomobject]@{ id = "res-$rid"; appId = $rid; displayName = $rid; appRoles = $roles }
            }
            '^servicePrincipals/res-([^/]+)/appRoleAssignedTo' {
                $rows = switch ($Matches[1]) {
                    'fc780465-2017-40d4-a0c5-307022471b92' { @([pscustomobject]@{ principalType = 'ServicePrincipal'; principalId = 'sp-auto'; principalDisplayName = 'SOAR automation'; appRoleId = 'r-off' }, [pscustomobject]@{ principalType = 'ServicePrincipal'; principalId = 'sp-wl'; principalDisplayName = 'Gapsio'; appRoleId = 'r-read' }) }
                    '00000003-0000-0000-c000-000000000000' { @([pscustomobject]@{ principalType = 'ServicePrincipal'; principalId = 'sp-wl'; principalDisplayName = 'Gapsio'; appRoleId = 'g-hunt' }, [pscustomobject]@{ principalType = 'ServicePrincipal'; principalId = 'sp-mail'; principalDisplayName = 'Mail app'; appRoleId = 'g-mail' }) }
                    default { @() }
                }
                return (V $rows)
            }
            '^servicePrincipals/(sp-[^/?]+)\?' { $id = $Matches[1]; return [pscustomobject]@{ id = $id; appId = "app-$id"; displayName = $id; appOwnerOrganizationId = (Get-GapsioSetting -Name 'GAPSIO_TENANT_ID'); accountEnabled = $true } }
            "^applications\(appId='app-sp-auto'\)" { return [pscustomobject]@{ id = 'obj-auto'; passwordCredentials = @([pscustomobject]@{ startDateTime = [DateTime]::UtcNow.AddDays(-10).ToString('o'); endDateTime = [DateTime]::UtcNow.AddYears(3).ToString('o') }); keyCredentials = @() } }
            "^applications\(appId='app-sp-wl'\)" { return [pscustomobject]@{ id = 'obj-wl'; passwordCredentials = @(); keyCredentials = @([pscustomobject]@{ startDateTime = [DateTime]::UtcNow.AddDays(-10).ToString('o'); endDateTime = [DateTime]::UtcNow.AddDays(355).ToString('o') }) } }
            '^applications/obj-auto/owners' { return (V @()) }
            '^applications/obj-wl/owners' { return (V @([pscustomobject]@{ id = 'u-alice'; userPrincipalName = 'alice@contoso.com' })) }
            '^identityGovernance/accessReviews/definitions' { return (V @()) }
            '^deviceManagement/mobileThreatDefenseConnectors' { return (V @([pscustomobject]@{ id = 'fc780465-2017-40d4-a0c5-307022471b92'; partnerState = 'enabled'; windowsEnabled = $true; macEnabled = $false; iosEnabled = $true; androidEnabled = $true; lastHeartbeatDateTime = [DateTime]::UtcNow.AddHours(-3).ToString('o') })) }
            '^deviceManagement/deviceCompliancePolicies' { return (V @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'cp-win'; displayName = 'Windows compliance'; deviceThreatProtectionEnabled = $true; deviceThreatProtectionRequiredSecurityLevel = 'medium'; assignments = @([pscustomobject]@{ id = 'a1' }) })) }
            '^policies/roleManagementPolicyAssignments' {
                return [pscustomobject]@{ value = @([pscustomobject]@{ policy = [pscustomobject]@{ rules = @(
                                    [pscustomobject]@{ id = 'Enablement_EndUser_Assignment'; enabledRules = @('Justification') },
                                    [pscustomobject]@{ id = 'Expiration_EndUser_Assignment'; maximumDuration = 'PT10H' },
                                    [pscustomobject]@{ id = 'Approval_EndUser_Assignment'; setting = [pscustomobject]@{ isApprovalRequired = $false } }) } }) }
            }
            default { throw "Nicht simulierter Aufruf: $Method $Uri" }
        }
    }
} $fixtures $hunting $access $users $blobs $queue

# ---------------------------------------------------------------- End-to-end
Write-Host '== End-to-end: endpoint' -ForegroundColor Cyan
# Device collections are stored in pages (large fleets); this reassembles the snapshot as the older inline format for the assertions.
function Get-EpSnapshot {
    $s = $blobs['state/endpoint-latest.json'] | ConvertFrom-Json -Depth 64
    foreach ($c in 'devices', 'coverage') {
        $items = & $mod { param($n, $s) Get-GapsioPagedCollection -Module 'endpoint' -Name $n -Snapshot $s } $c $s
        $s | Add-Member -NotePropertyName $c -NotePropertyValue @($items) -Force
    }
    $s
}
$r1 = Invoke-GapsioEndpointCollection 6>$null
$ep = Get-EpSnapshot
Assert ($null -eq ($blobs['state/endpoint-latest.json'] | ConvertFrom-Json -Depth 64).devices -and $ep.devicesPages.count -eq 5 -and $ep.devicesPages.pages -eq 1) "Devices are paged, not inline (pages=$($ep.devicesPages.pages), count=$($ep.devicesPages.count))"
Assert ($blobs.ContainsKey('state/endpoint-devices/0000.json') -and $blobs.ContainsKey('state/endpoint-devices.tsv') -and $blobs.ContainsKey('state/endpoint-devices-fp.json')) 'Device page, index and fingerprint blobs written'
Assert (($blobs['state/endpoint-devices.tsv'] -split "`n")[0] -like "deviceId`tdeviceName`t*`tchecks`t*`ttags`t*`t_filter`t_search`tpage") 'Device index header'
Assert ($ep.deviceStats.devices -eq 5 -and $ep.deviceStats.charts.os.Windows11 -eq 2 -and $ep.deviceStats.charts.TamperProtection.on -ge 1 -and $ep.deviceStats.groups.Server -eq 2) "deviceStats aggregates (devices=$($ep.deviceStats.devices), Windows11=$($ep.deviceStats.charts.os.Windows11))"
Assert ($ep.warnings.Count -eq 0) "Warnings in the endpoint run: $($ep.warnings -join ' | ')"
Assert ($ep.summary.devices -eq 5) "5 devices expected, $($ep.summary.devices)"
$pe = @($ep.policyExclusions)
Assert ($pe.Count -eq 16) "16 policy exclusions expected, found $($pe.Count): $(($pe | ForEach-Object { "$($_.platform):$($_.type):$($_.value)" }) -join ', ')"
Assert (@($pe | Where-Object { $_.platform -eq 'macOS' -and $_.type -eq 'Process' -and $_.value -eq 'python3' }).Count -eq 1) 'macOS file name exclusion as process'
Assert (@($pe | Where-Object { $_.type -eq 'TamperException' -and $_.value -eq '/usr/local/bin/contoso-agent' -and $_.risk.level -in 'High','Critical' }).Count -eq 1) 'macOS tamper exception detected and rated High'
Assert (@($pe | Where-Object { $_.value -eq 'ABCDE12345' }).Count -eq 0) 'TeamID is not a separate exclusion'
Assert (@($pe | Where-Object { $_.type -eq 'AllowedThreat' -and $_.platform -eq 'macOS' }).Count -eq 1) 'macOS allowedThreats detected'
Assert (@($pe | Where-Object { $_.value -eq 'true' }).Count -eq 0) 'isdirectory=true must not be an exclusion'
Assert (@($pe | Where-Object { $_.platform -eq 'Linux' -and $_.scope -eq 'Global' -and $_.value -eq '/opt/agent' }).Count -eq 1) 'Linux global exclusion detected'
Assert (@($pe | Where-Object { $_.platform -eq 'macOS' -and $_.value -eq '/Users/Shared/tools' }).Count -eq 1) 'macOS exclusion detected'
Assert (@($pe | Where-Object { $_.value -eq 'powershell.exe' -and $_.risk.level -eq 'Critical' }).Count -eq 1) 'powershell.exe Critical'
Assert (@($pe | Where-Object { $_.value -eq 'cmd.exe' -and $_.source -eq 'IntuneLegacy' }).Count -eq 1) 'Legacy exclusion detected'
Assert (@($pe | Where-Object { $_.assignments -contains 'Group: All clients' }).Count -gt 0) 'Assignments with group names'
Assert (@($pe | Where-Object { $_.assignments -contains 'Group: Server' }).Count -eq 0) 'Exclusion group not listed as an assignment as well'
$le = @($ep.localExclusions)
Assert ($le.Count -eq 7) "7 local exclusions expected, $($le.Count)"
Assert (@($le | Where-Object { $_.value -eq 'D:\Temp\' -and -not $_.present }).Count -eq 1) 'Deleted local exclusion marked as removed'
Assert (@($le | Where-Object { $_.origin -eq 'GPO' -and $_.value -eq '.bak' }).Count -eq 1) 'GPO exclusion detected'
Assert (@($le | Where-Object { $_.platform -eq 'macOS' -and $_.type -eq 'AllowedThreat' }).Count -eq 1) 'mdatp threat allowed detected'
Assert (@($ep.indicators).Count -eq 4) 'Allow indicators only'
$f = @($ep.findings)
Assert (@($f | Where-Object { $_.title.en -eq 'Tamper Protection off and local exclusions present' -and $_.deviceName -eq 'WIN-01' }).Count -eq 1) 'Combined finding TP + local for WIN-01'
Assert (@($f | Where-Object { $_.title.en -eq 'Microsoft Defender Antivirus in passive mode' -and $_.deviceName -eq 'WIN-02' }).Count -eq 1) 'Passive mode WIN-02'
# Dependency findings (book-derived: configured but inert)
$dep = @($f | Where-Object { $_.category -eq 'Dependency' })
Assert (@($dep | Where-Object { $_.title.en -match '^Passive mode' -and $_.deviceName -eq 'WIN-02' }).Count -eq 1) 'Dependency: passive mode leaves protections inert (WIN-02)'
Assert (@($dep | Where-Object { $_.title.en -match 'private IP' -and $_.title.en -match '10\.1\.2\.3' }).Count -eq 1) 'Dependency: RFC1918 indicator'
Assert (@($dep | Where-Object { $_.title.en -match 'URL indicator with a path' }).Count -eq 1) 'Dependency: URL path indicator'
Assert (@($dep | Where-Object { $_.title.en -match 'Allow and block indicator' -and $_.title.en -match 'ab12cd' }).Count -eq 1) 'Dependency: allow/block conflict (case-insensitive)'
Assert (@($dep | Where-Object { $_.title.en -eq 'File indicators without EnableFileHashComputation' }).Count -eq 1) 'Dependency: file hash computation'
Assert (@($dep | Where-Object { $_.title.en -match 'cloud block level below High' }).Count -eq 0) 'Dependency: no block-level finding when cloudblocklevel_2 is set'
Assert (@($dep | Where-Object { $_.deviceName -eq 'MAC-01' -or $_.deviceName -eq 'LNX-01' }).Count -eq 0) 'Dependency: Windows-only device findings'
# Update findings (platform age vs. fleet, signature age, rings)
$upd = @($f | Where-Object { $_.category -eq 'Updates' })
Assert (@($upd | Where-Object { $_.title.en -match 'supported window' -and $_.deviceName -eq 'WIN-02' -and $_.severity -eq 'Medium' }).Count -eq 1) 'Updates: WIN-02 platform 5 releases behind'
Assert (@($upd | Where-Object { $_.title.en -match 'supported window' -and $_.deviceName -ne 'WIN-02' }).Count -eq 0) 'Updates: SRV-01 (N-1) and WIN-01 (newest) not flagged'
Assert (@($upd | Where-Object { $_.title.en -match 'Security intelligence older' -and $_.deviceName -eq 'WIN-02' -and $_.severity -eq 'High' }).Count -eq 1) 'Updates: WIN-02 signatures 10 days old'
Assert (@($upd | Where-Object { $_.title.en -match 'Security intelligence older' }).Count -eq 1) 'Updates: only one signature-age finding'
Assert (@($upd | Where-Object { $_.title.en -match 'update rings' }).Count -eq 0) 'Updates: ring findings suppressed for small fleets'
# Inventory findings (grouping, duplicates, management channel, eternal audit)
$inv = @($f | Where-Object { $_.category -eq 'Inventory' })
Assert (@($ep.devices | Where-Object { $_.deviceName -eq 'WIN-01' -and $_.managedBy -eq 'Intune' }).Count -eq 1) 'Inventory: ManagedBy collected from DeviceInfo'
Assert (@($inv | Where-Object { $_.title.en -match 'device group|Duplicate|management channel' }).Count -eq 0) 'Inventory: clean fixture -> no grouping/duplicate/unmanaged findings'
Assert (@($inv | Where-Object { $_.title.en -match '^ASR rule in audit mode for 1\d\d\+ days' }).Count -eq 1) 'Inventory: eternal audit for pol-asr (psexec-wmi), not for the 59-day-old pol-win'
Assert (@($inv | Where-Object { $_.title.en -eq 'Linux antivirus in audit mode (preview)' -and $_.detail.en -match 'Linux AV' -and $_.detail.en -match 'Group: All clients' }).Count -eq 1) 'Inventory: Linux antivirus audit mode preview finding'
Assert (@($inv | Where-Object { $_.title.en -eq 'Linux tamper protection in audit mode (preview)' -and $_.detail.en -match 'Linux AV' -and $_.detail.en -match 'Group: All clients' }).Count -eq 1) 'Inventory: Linux tamper audit mode preview finding'
Assert (@($f | Where-Object { $_.title.en -match 'Tamper' -and $_.deviceName -eq 'MAC-01' }).Count -eq 1) 'macOS tamper finding'
# Fleet (tags, internet-facing, TVM exclusion, troubleshooting mode, tampering attempts, inactive devices)
$flt = @($f | Where-Object { $_.category -eq 'Fleet' })
$dw1 = @($ep.devices | Where-Object { $_.deviceName -eq 'WIN-01' })[0]; $ds1 = @($ep.devices | Where-Object { $_.deviceName -eq 'SRV-01' })[0]

# Policy exclusions per device: policy platform is a family ("Windows"), device OS a product ("Windows11", "WindowsServer2025")
& $mod {
    param($A)
    $devs = @{}
    foreach ($p in @(@('w11', 'Windows11'), @('srv', 'WindowsServer2025'), @('mac', 'macOS'))) { $devs[$p[0]] = New-GapsioDevice -Id $p[0] -Name $p[0] -Os $p[1] }
    $xs = @([pscustomobject]@{ policyId = 'pw'; platform = 'Windows'; assigned = $true; value = 'C:\a' }, [pscustomobject]@{ policyId = 'pw'; platform = 'Windows'; assigned = $true; value = 'C:\b' },
        [pscustomobject]@{ policyId = 'pm'; platform = 'macOS'; assigned = $true; value = '/tmp' })
    $tg = @{ pw = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }); pm = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }) }
    Set-GapsioDevicePolicyExclusions -Devices $devs -Exclusions $xs -Targets $tg
    & $A ($devs['w11'].policyExclusions -eq 2 -and $devs['srv'].policyExclusions -eq 2 -and $devs['mac'].policyExclusions -eq 1) "Policy exclusions per device match by platform family (w11=$($devs['w11'].policyExclusions), srv=$($devs['srv'].policyExclusions), mac=$($devs['mac'].policyExclusions))"
} ${function:Assert}
Assert (@($dw1.tags) -contains 'Finance Dept' -and @($dw1.tags) -contains 'VIP' -and @($ds1.tags) -contains 'DMZ' -and $dw1.internetFacing -eq $false -and $ds1.internetFacing -eq $true) "Fleet: tags and internet-facing parsed (WIN-01: $(@($dw1.tags) -join ','))"
Assert ($dw1.troubleshooting30d -eq 4 -and -not $dw1.troubleshootingActive -and $dw1.tampering30d -eq 3) 'Fleet: troubleshooting/tampering counters on WIN-01'
Assert (@($flt | Where-Object { $_.title.en -eq 'Internet-facing device with high exposure' -and $_.deviceName -eq 'SRV-01' -and $_.severity -eq 'Medium' }).Count -eq 1) 'Fleet: internet-facing + high exposure (SRV-01)'
Assert (@($flt | Where-Object { $_.title.en -eq 'Troubleshooting mode active' -and $_.deviceName -eq 'WIN-02' -and $_.severity -eq 'High' }).Count -eq 1) 'Fleet: troubleshooting mode active (started 1h ago)'
Assert (@($flt | Where-Object { $_.title.en -match '^Troubleshooting mode used 4 times' -and $_.deviceName -eq 'WIN-01' }).Count -eq 1) 'Fleet: repeated troubleshooting mode'
Assert (@($flt | Where-Object { $_.title.en -eq '3 tampering attempt(s) in 30 days' -and $_.deviceName -eq 'WIN-01' -and $_.severity -eq 'High' }).Count -eq 1) 'Fleet: tampering on device with tamper protection off -> High'
Assert (@($flt | Where-Object { $_.title.en -eq '12 tampering attempt(s) in 30 days' -and $_.deviceName -eq 'SRV-01' -and $_.severity -eq 'High' }).Count -eq 1) 'Fleet: 10+ tampering attempts -> High'
Assert (@($flt | Where-Object { $_.title.en -eq '1 device(s) excluded from Vulnerability Management' -and $_.detail.en -match 'WIN-02' -and $_.detail.en -match 'Duplicate device' }).Count -eq 1) 'Fleet: TVM-excluded devices'
Assert (@($flt | Where-Object { $_.title.en -match 'without a device tag' }).Count -eq 0) 'Fleet: tag finding suppressed for small fleets'
Assert (@($flt | Where-Object { $_.title.en -eq '1 device(s) inactive for 90+ days still in the inventory' -and $_.detail.en -match 'OLD-09' }).Count -eq 1) 'Fleet: inactive devices from MDE API'
Assert ($ep.summary.fleet.internetFacingHigh -eq 1 -and $ep.summary.fleet.tampering30d -eq 2 -and $ep.summary.fleet.troubleshootingActive -eq 1 -and $ep.summary.fleet.tvmExcluded -eq 1 -and $ep.summary.fleet.tagged -eq 2 -and $ep.summary.fleet.inactive90d -eq 1) "Fleet summary ($($ep.summary.fleet | ConvertTo-Json -Compress))"
Assert (@($ep.inactiveDevices).Count -eq 1 -and $ep.inactiveDevices[0].deviceName -eq 'OLD-09') 'Fleet: inactive devices in snapshot'
# Hygiene: scans, connectivity, WSL, threat actions, ASR telemetry, end of support
Assert (@($flt | Where-Object { $_.title.en -eq '1 device(s) without a quick scan in 14 days' -and $_.detail.en -match 'WIN-01' }).Count -eq 1) 'Hygiene: quick scan older than 14 days (WIN-01)'
Assert (@($flt | Where-Object { $_.title.en -eq '1 device(s) never completed a full scan' -and $_.detail.en -match 'SRV-01' }).Count -eq 1) 'Hygiene: never a full scan (SRV-01)'
Assert (@($flt | Where-Object { $_.title.en -eq '1 device(s) still on standard connectivity' -and $_.detail.en -match 'SRV-01' }).Count -eq 1) 'Hygiene: standard connectivity (SRV-01)'
Assert (@($flt | Where-Object { $_.title.en -eq '1 device(s) run WSL without the Defender plug-in' -and $_.detail.en -match 'WIN-01' }).Count -eq 1) 'Hygiene: WSL without plug-in'
Assert (@($ep.findings | Where-Object { $_.title.en -eq 'Detected threats are allowed to run' -and $_.deviceName -eq 'WIN-01' -and $_.severity -eq 'High' }).Count -eq 1) 'Hygiene: ThreatIdDefaultAction = Allow (registry)'
Assert (@($flt | Where-Object { $_.title.en -eq "High-risk browser extension 'Free VPN Unlimited' on 2 device(s)" -and $_.severity -eq 'Medium' -and $_.detail.en -match 'Chrome/Edge' -and $_.detail.en -match 'WIN-01, WIN-02' -and $_.deviceCount -eq 2 }).Count -eq 1) 'Hygiene: high-risk browser extension aggregated per extension'
$obf = @($ep.asrRules | Where-Object { $_.id -eq 'obfuscated' })[0]
Assert ($obf.telemetry.audited -eq 4 -and @($obf.telemetry.topAudited) -contains 'powershell.exe (4)') 'ASR telemetry attached to rule (obfuscated: 4 audit events)'
$eos = & $mod {
    @(
        (Get-GapsioOsSupportState -Device ([pscustomobject]@{ os = 'Windows10'; osBuild = '19045' }) -NewestMacMajor 0).name,
        [string](Get-GapsioOsSupportState -Device ([pscustomobject]@{ os = 'Windows10'; osBuild = '17763' }) -NewestMacMajor 0),
        (Get-GapsioOsSupportState -Device ([pscustomobject]@{ os = 'Windows11'; osBuild = '22621' }) -NewestMacMajor 0).name,
        [string](Get-GapsioOsSupportState -Device ([pscustomobject]@{ os = 'Windows11'; osBuild = '26100' }) -NewestMacMajor 0),
        (Get-GapsioOsSupportState -Device ([pscustomobject]@{ os = 'macOS'; osVersion = '13.6' }) -NewestMacMajor 26).name,
        [string](Get-GapsioOsSupportState -Device ([pscustomobject]@{ os = 'macOS'; osVersion = '15.6' }) -NewestMacMajor 26),
        (Get-GapsioOsSupportState -Device ([pscustomobject]@{ os = 'WindowsServer2012R2'; osBuild = '9600' }) -NewestMacMajor 0).name)
}
Assert ($eos[0] -eq 'Windows 10' -and -not $eos[1] -and $eos[2] -eq 'Windows 11 22H2' -and -not $eos[3] -and $eos[4] -eq 'macOS 13' -and -not $eos[5] -and $eos[6] -eq 'Windows Server 2012 R2') "End of support: Win10 22H2 yes, LTSC 2019 no, Win11 22H2 yes, 24H2 no, macOS n-3 yes, n-2 no, 2012 R2 yes ($($eos -join ' | '))"
$auditF = & $mod { Get-GapsioDefenderAuditFindings -Audit ([pscustomobject]@{ summary = [pscustomobject]@{ events = @(
                    [pscustomobject]@{ kind = 'Offboarding'; operation = 'DownloadOffboardingPkg'; user = 'eve@contoso.com'; at = '2026-10-01T10:00:00Z' },
                    [pscustomobject]@{ kind = 'LiveResponse'; operation = 'RunLiveResponseSession'; user = 'bob@contoso.com'; at = '2026-10-02T10:00:00Z' }) } }) }
Assert (@($auditF | Where-Object { $_.title.en -eq 'Offboarding package downloaded 1 time(s) in 30 days' -and $_.detail.en -match 'eve@' }).Count -eq 1 -and @($auditF | Where-Object { $_.title.en -like '1 live response action(s) by 1 person(s)*' }).Count -eq 1) 'Audit log: offboarding download and live response findings'
$scanAge = & $mod { Get-GapsioScanAge -ScanResults ('{"Quick":{"Timestamp":"' + [DateTime]::UtcNow.AddDays(-3).ToString('o') + '"}}') -Kind 'Quick' }
Assert ($scanAge -eq 3) "Scan age from AvScanResults ($scanAge)"
$cov = @($ep.findings | Where-Object { $_.category -eq 'Coverage' })
Assert (@($cov | Where-Object { $_.title.en -eq 'Defender connector off for 1 platform(s) in use' -and $_.detail.en -match 'macOS' }).Count -eq 1) 'Intune connector: macOS toggle off while macOS devices exist'
Assert (@($cov | Where-Object { $_.title.en -eq 'Defender device risk not part of compliance for 1 platform(s)' -and $_.detail.en -match 'macOS' }).Count -eq 1) 'Compliance: no macOS policy with machine risk score'
Assert (@($cov | Where-Object { $_.title.en -eq '1 compliance policy(ies) tolerate medium or high device risk' }).Count -eq 1) 'Compliance: Windows policy allows medium risk'
# Third-party AV/EDR (software inventory)
$dw2 = @($ep.devices | Where-Object { $_.deviceName -eq 'WIN-02' })[0]
Assert (@($dw1.thirdPartyAv) -contains 'CrowdStrike Falcon Sensor' -and @($dw2.thirdPartyAv) -contains 'SentinelOne Sentinel Agent' -and @($ds1.thirdPartyAv).Count -eq 0) 'Fleet: third-party products parsed (JSON string and array)'
Assert (@($flt | Where-Object { $_.title.en -eq 'Third-party AV/EDR alongside active Defender Antivirus' -and $_.deviceName -eq 'WIN-01' -and $_.severity -eq 'Medium' }).Count -eq 1) 'Fleet: third-party AV + Defender active -> Medium (WIN-01)'
Assert (@($flt | Where-Object { $_.title.en -eq 'Third-party AV/EDR alongside active Defender Antivirus' -and $_.deviceName -eq 'WIN-02' }).Count -eq 0) 'Fleet: no double-AV finding when Defender is passive (WIN-02)'
Assert (@($flt | Where-Object { $_.title.en -eq '2 onboarded device(s) with a third-party AV/EDR product' -and $_.deviceCount -eq 2 -and $_.detail.en -match 'CrowdStrike \(1\)' -and $_.detail.en -match '1 device\(s\) run Defender in passive' }).Count -eq 1) 'Fleet: aggregated third-party AV finding'
Assert ($ep.summary.fleet.thirdPartyAv -eq 2) 'Fleet summary: thirdPartyAv count'
# ASR
$asr = @{}; foreach ($x in $ep.asrRules) { $asr[$x.id] = $x }
Assert (@($ep.asrRules).Count -eq 19) "19 ASR rules expected, $(@($ep.asrRules).Count)"
Assert ($asr['office-child'].status -eq 'Conflict') "office-child conflict (Warn vs. Block), is $($asr['office-child'].status)"
Assert ($asr['lsass'].status -eq 'DeviceDeviation' -and $asr['lsass'].belowMinimum -eq 1 -and $asr['lsass'].effective.Block -eq 2) "lsass: 1 device below target, 2 Block (InfoGathering before TVM), is $($asr['lsass'].status) $($asr['lsass'].belowMinimum) $($asr['lsass'].effective.Block)"
Assert ($asr['vulnerable-driver'].status -eq 'NotConfigured' -and $asr['vulnerable-driver'].belowMinimum -eq 3) "vulnerable-driver not configured, 3 devices below target, is $($asr['vulnerable-driver'].status)/$($asr['vulnerable-driver'].belowMinimum)"
Assert ($asr['obfuscated'].status -eq 'BlockRecommended') "obfuscated: Audit meets the minimum, is $($asr['obfuscated'].status)"
Assert ($asr['psexec-wmi'].configured[0].mode -eq 'Audit') 'psexec-wmi configured Audit'
Assert ($asr['webshell'].effective.NotApplicable -eq 2 -and $asr['webshell'].effective.Block -eq 1) 'Webshell: Clients n/a, Server Block'
$ag = @{}; foreach ($x in $ep.asrGroups) { $ag[$x.group] = $x }
Assert ($ag['Clients'].devices -eq 2 -and $ag['Server'].devices -eq 1 -and $ag['Clients'].rules.lsass.below -eq 1) 'ASR per device group (Windows only)'
Assert (@($pe | Where-Object { $_.type -eq 'ASR' -and $_.scope -eq 'ASR' -and $_.asrRule -eq 'office-child' -and $_.value -eq 'C:\Program Files\Addin\addin.exe' }).Count -eq 1) 'Per-rule ASR exclusion detected'
Assert (@($f | Where-Object { $_.category -eq 'ASR' -and $_.title.en -match 'conflict' }).Count -eq 1) 'Finding ASR conflict'
Assert (@($f | Where-Object { $_.category -eq 'ASR' -and $_.title.en -match 'not configured: Block abuse' }).Count -eq 1) 'Finding ASR not configured'
$dWin1 = @($ep.devices | Where-Object { $_.deviceId -eq 'd-win1' })[0]
Assert ($dWin1.asr.lsass -eq 'Block' -and $dWin1.asr.'psexec-wmi' -eq 'Audit') 'Device: ASR modes (InfoGathering + TVM fallback)'
# Linux
Assert (@($pe | Where-Object { $_.platform -eq 'Linux' -and $_.value -eq '/srv/app' -and $_.scope -eq 'Global' }).Count -eq 1) 'Linux: scopes [epp, global] -> Global'
Assert (@($pe | Where-Object { $_.platform -eq 'Linux' -and $_.value -eq '/home/*/git' -and $_.scope -eq 'AV' }).Count -eq 1) 'Linux: scopes [epp] -> AV'
Assert (@($pe | Where-Object { $_.value -in 'epp', 'global' }).Count -eq 0) 'Linux: scope values are not exclusions'
Assert (@($f | Where-Object { $_.title.en -eq 'Defender weakened locally: real-time-protection = disabled' -and $_.deviceName -eq 'LNX-01' }).Count -eq 1) 'Linux: mdatp config real-time-protection disabled'
Assert (@($f | Where-Object { $_.title.en -match 'behavior-monitoring' }).Count -eq 0) 'Linux: re-enabled later -> no finding'
Assert (@($f | Where-Object { $_.title.en -eq 'Managed Defender configuration changed locally' }).Count -eq 1) 'Linux: mdatp_managed.json changed'
Assert ($ep.summary.edrExclusions -ge 3) "EDR-effective exclusions counted ($($ep.summary.edrExclusions))"
Assert (@($f | Where-Object { $_.category -eq 'Indicator' -and $_.title.en -match 'CertificateThumbprint' }).Count -eq 1) 'Certificate indicator'
$b = @{}; foreach ($x in $ep.baseline) { $b[$x.id] = $x }
Assert ($b['cloud-block-level'].status -eq 'OK') "cloud-block-level OK, is $($b['cloud-block-level'].status)"
Assert ($b['pua-protection'].status -eq 'Deviation') "PUA deviation (Audit), is $($b['pua-protection'].status)"
Assert ($b['disable-local-admin-merge'].status -eq 'NotConfigured') 'DisableLocalAdminMerge not configured'
Assert ($b['tamper-protection'].status -eq 'DeviceDeviation' -and $b['tamper-protection'].effective.bad -eq 1) 'Tamper effective: 1 device bad (Windows only)'
Assert ($b['running-mode'].effective.bad -eq 1) 'Running mode: 1 device passive'
Assert ($b['mac-tamper-protection'].status -eq 'Deviation') "macOS tamper audit -> Deviation, is $($b['mac-tamper-protection'].status)"
Assert ($b['mac-enforcement-level'].status -eq 'OK') "macOS real_time OK, is $($b['mac-enforcement-level'].status)"
Assert ($b['mac-exclusions-merge-policy'].status -eq 'Deviation') "macOS merge -> Deviation, is $($b['mac-exclusions-merge-policy'].status)"
Assert ($b['mac-pua'].status -eq 'Deviation') "macOS PUA audit (archive_bomb block does not count) -> Deviation, is $($b['mac-pua'].status)"
Assert ($b['mac-network-protection'].status -eq 'Deviation') "macOS network protection disabled -> Deviation, is $($b['mac-network-protection'].status)"
Assert ($b['mac-cloud'].status -eq 'OK') "macOS cloud enabled -> OK, is $($b['mac-cloud'].status)"
Assert ($b['linux-enforcement-level'].status -eq 'Deviation' -and $b['linux-enforcement-level'].configured[0].value -match 'audit') "Linux enforcementLevel audit -> Deviation (display name), is $($b['linux-enforcement-level'].status) / $($b['linux-enforcement-level'].configured[0].value)"
Assert ($b['linux-exclusions-merge-policy'].status -eq 'OK') "Linux mergePolicy admin_only -> OK, is $($b['linux-exclusions-merge-policy'].status)"
Assert ($b['linux-tamper-protection'].status -in 'NoData', 'OK', 'DeviceDeviation' -and -not $b['linux-tamper-protection'].configured.Count) "Linux tamper is effective-only (no Settings Catalog setting), is $($b['linux-tamper-protection'].status)"
Assert ($b['linux-enforcement-level'].definitionId -eq 'linux_mdatp_managed_antivirusengine_enforcementlevel') 'Linux checks carry the exact Settings Catalog ID'
Assert ($b['mac-cloud-block-level'].status -eq 'NotConfigured') "macOS cloud block level not configured, is $($b['mac-cloud-block-level'].status)"
Assert (@($ep.seenDefenderSettings | Where-Object { $_ -match 'smartscreen' }).Count -eq 0) 'Edge SmartScreen (mac) ignored'
Assert (@($ep.seenDefenderSettings | Where-Object { $_ -match 'edge' }).Count -eq 0) 'Edge settings ignored'
Assert ($ep.isFirstRun -eq $true) 'First run flagged'
$viaPs = @($le | Where-Object { $_.value -eq 'C:\Users\Public\GapsioTest' })
Assert ($viaPs.Count -eq 1 -and $viaPs[0].addedBy.process -eq 'powershell.exe' -and $viaPs[0].addedBy.commandLine -match 'Add-MpPreference') "Caller of Add-MpPreference detected instead of MsMpEng.exe (is: $($viaPs[0].addedBy.process))"
Assert (@($pe | Where-Object { $_.platform -eq 'Linux' -and $_.assigned -eq $false }).Count -eq 1) 'Unassigned Linux policy detected'
Assert (@($pe | Where-Object { $_.platform -eq 'Windows' -and $_.assigned -eq $true }).Count -ge 1) 'Windows policy detected as assigned'

# Posture checks (Posture.ps1): policy conflicts, device control, attack disruption readiness, detection rules
$epf = @($ep.findings)
$pc = @($ep.policyConflicts)
Assert ($pc.Count -eq 2 -and $ep.summary.policyConflicts -eq 2) "Two settings in conflict (same devices, different values), found $($pc.Count)"
$c1 = @($pc | Where-Object { $_.setting -eq 'avgcpuloadfactor' })[0]
Assert ($c1.devices -eq 3 -and $c1.overlap -eq 'Devices' -and @($c1.values).Count -eq 2 -and (@($c1.values | ForEach-Object value) -join ',') -eq '20,50' -and $c1.values[0].policies[0].name -eq 'MDAV Scan Settings Pilot') 'Conflict: number setting, 3 Windows devices, both policies named'
Assert (@($pc | Where-Object { $_.setting -match 'allowarchivescanning|cloudblocklevel|attacksurfacereduction' }).Count -eq 0) 'Same value in both policies, or policies for different devices: no conflict'
Assert (@($epf | Where-Object { $_.category -eq 'Conflict' -and $_.severity -eq 'Medium' -and $_.title.en -eq '2 Defender setting(s) reach the same devices with different values' -and $_.detail.en -match 'might|may not be applied' }).Count -eq 1) 'Conflict finding (one, aggregated)'
$dcx = $ep.deviceControl
Assert ($dcx.usage -eq 'ok' -and $dcx.summary.assignedPolicies -eq 1 -and $dcx.summary.usbDevices -eq 3 -and $dcx.summary.usbWithoutPolicy -eq 2 -and $dcx.summary.denied -eq 3) "Device control summary ($($dcx.summary | ConvertTo-Json -Compress))"
Assert (@($dcx.devices | Where-Object { $_.deviceName -eq 'WIN-01' -and $_.hasPolicy -eq $true -and $_.policies -contains 'Device Control Pilot' -and $_.triggers -eq 7 }).Count -eq 1) 'WIN-01 is in the pilot group: device control policy reaches it'
Assert (@($dcx.devices | Where-Object { $_.deviceName -eq 'WIN-02' -and $_.hasPolicy -eq $false -and $_.mounts -eq 5 }).Count -eq 1) 'WIN-02 mounts USB drives without a policy'
Assert (@($epf | Where-Object { $_.category -eq 'DeviceControl' -and $_.title.en -eq 'USB storage used on 2 device(s) without a device control policy' -and $_.detail.en -match 'WIN-02 \(5\)' -and $_.detail.en -notmatch 'WIN-01' }).Count -eq 1) 'Device control finding lists only devices without a policy'
Assert (@($ep.policies | Where-Object { $_.name -eq 'Device Control Pilot' }).Count -eq 1) 'Device control policy is collected'
$dis = $ep.disruption
function Chk { param($id) @($dis.checks | Where-Object { $_.id -eq $id })[0] }
Assert ((Chk 'sense').status -eq 'Gap' -and (Chk 'sense').count -eq 1 -and (Chk 'sense').total -eq 3 -and (Chk 'sense').devices[0] -match '^WIN-02 \(10\.8295') 'Disruption: one of three Windows devices below Sense 10.8470'
Assert ((Chk 'mdi').status -eq 'OK' -and (Chk 'onboarding').status -eq 'Gap') 'Disruption: Defender for Identity signals present, coverage gaps reported'
Assert (@($dis.checks | Where-Object { $_.status -eq 'NotMeasurable' } | ForEach-Object id) -join ',' -eq 'discovery,automation,exclusions' -and (Chk 'exclusions').where.en -match 'Automated response') 'Disruption: what Microsoft does not expose is "not measurable" with the portal path'
Assert ($dis.eventsStatus -eq 'ok' -and $dis.summary.events30d -eq 17 -and $dis.events[0].actionType -eq 'ContainedUserLogonBlocked') 'Disruption events of the last 30 days'
Assert (@($epf | Where-Object { $_.category -eq 'Response' -and $_.title.en -eq 'Contain User cannot be enforced on 1 Windows device(s)' }).Count -eq 1) 'Disruption finding for old Sense agents'
$dr = @($ep.detectionRules)
function Rule { param($n) @($dr | Where-Object { $_.name -eq $n })[0] }
Assert ($ep.detectionRulesStatus -eq 'ok' -and $dr.Count -eq 4 -and $dr[0].status -eq 'autoDisabled' -and $ep.summary.detectionRulesOff -eq 2) 'Detection rules: four rules, automatically disabled first'
Assert ((Rule 'Encoded PowerShell from Office').alerts30d -eq 4 -and ((Rule 'Encoded PowerShell from Office').impactActions -join ',') -eq 'isolateDevices' -and (Rule 'Encoded PowerShell from Office').frequency -eq 'PT1H') 'Detection rule: alerts matched by title (case-insensitive), impact actions, frequency'
Assert ($null -eq (Rule 'New local administrator on server').alerts30d -and (Rule 'New local administrator on server').status -eq 'enabled' -and (Rule 'New local administrator on server').lastRun.errorCode -eq 'queryTimeout' -and ((Rule 'New local administrator on server').deviceGroups -join ',') -eq 'Server') 'Detection rule: dynamic title gives no alert count; isEnabled and lastRunDetails still understood'
Assert (@($epf | Where-Object { $_.category -eq 'Detection' }).Count -eq 4 -and @($epf | Where-Object { $_.category -eq 'Detection' -and $_.severity -eq 'High' -and $_.title.en -match 'switched off automatically' -and $_.detail.en -match 'LSASS' }).Count -eq 1) 'Detection findings: auto-disabled (High), failed, disabled, automatic actions'

Write-Host '== End-to-end: protection features, coverage, exclusion usage' -ForegroundColor Cyan
$dWin2 = @($ep.devices | Where-Object { $_.deviceId -eq 'd-win2' })[0]
Assert ($dWin1.checks.NetworkProtection -eq 'BAD' -and $dWin2.checks.NetworkProtection -eq 'GOOD' -and $dWin1.checks.EdrBlockMode -eq 'GOOD') 'Network protection and EDR block mode per device (TVM by name)'
$dWin3 = @($ep.devices | Where-Object { $_.deviceId -eq 'd-win3' })[0]
Assert ($dWin3.checks.NetworkProtection -eq 'GOOD' -and $dWin3.networkProtectionSource -eq 'EventsBlock' -and -not $dWin1.networkProtectionSource) 'Network protection from block events when TVM has no assessment; TVM wins'
$npb = @($ep.baseline | Where-Object { $_.id -eq 'network-protection' })[0]
Assert ($npb.effective.check -eq 'NetworkProtection' -and $npb.effective.bad -eq 1 -and $npb.effective.good -eq 2) "Baseline network protection effective 1 bad / 2 good (TVM + events) ($($npb.effective.bad)/$($npb.effective.good))"
$cov = @($ep.coverage)
Assert (@($cov | Where-Object { $_.deviceName -eq 'LAPTOP-NEW' -and $_.status -eq 'NotOnboarded' -and $_.source -eq 'Intune' }).Count -eq 1) 'Coverage: Intune device not in Defender'
Assert (@($cov | Where-Object { $_.deviceName -in 'LAPTOP-RETIRED', 'iPhone', 'WIN-01' }).Count -eq 0) 'Coverage: stale, mobile and onboarded devices are not gaps'
Assert (@($cov | Where-Object { $_.deviceName -eq 'OLD-01' -and $_.status -eq 'SensorInactive' }).Count -eq 1) 'Coverage: onboarded device without recent data = sensor inactive'
Assert (@($cov | Where-Object { $_.deviceName -eq 'PRINTER-7' -and $_.status -eq 'CanBeOnboarded' }).Count -eq 1) 'Coverage: device discovery'
Assert (@($cov | Where-Object { $_.deviceId -eq 'd-disc2' }).Count -eq 0) 'Coverage: stale discovery row of an onboarded host (FQDN) is suppressed'
Assert ($dWin1.intuneDeviceId -eq 'int-win1') 'Intune device ID on the Defender device (deep link)'
Assert (@($f | Where-Object { $_.category -eq 'Coverage' -and $_.title.en -notmatch 'connector|compliance|Conditional Access' }).Count -eq 3 -and $ep.summary.coverageGaps -eq 2 -and $ep.summary.discoveredDevices -eq 1) "Coverage findings and summary ($($ep.summary.coverageGaps)/$($ep.summary.discoveredDevices))"
$ps = @($pe | Where-Object { $_.value -eq 'powershell.exe' })[0]
$svc = @($pe | Where-Object { $_.value -eq 'C:\Program Files\Vendor\svc.exe' })[0]
$wild = @($pe | Where-Object { $_.value -like '*`**' })[0]
Assert ($ps.usage -eq 'Used' -and $ps.usageHits -eq 1234) 'Usage: process exclusion seen in Advanced Hunting'
Assert ($svc.usage -eq 'Unused' -and $svc.usageHits -eq 0) 'Usage: process path without activity = unused'
Assert ($wild.usage -eq 'NotChecked') 'Usage: wildcard values are not checked'
Assert ($ep.summary.unusedExclusions -ge 1 -and @($f | Where-Object { $_.category -eq 'Hygiene' }).Count -eq 1) "Usage: summary and one hygiene finding ($($ep.summary.unusedExclusions))"
$uq = & $mod { @($script:HuntQueries | Where-Object { $_ -match '// GapsioUsage' })[0] }
Assert ($uq -match 'let paths = dynamic\(\[' -and $uq -match 'p startswith "c:\\\\program files\\\\app\\\\app.exe"' -and $uq -notmatch '\*') 'Usage query: normalised paths, prefilter, no wildcards'

Write-Host '== Accepted risks and notifications' -ForegroundColor Cyan
& $mod {
    param($A)
    $a1 = Set-GapsioAcceptance -Data ([pscustomobject]@{ key = 'cccc3333'; kind = 'finding'; module = 'endpoint'; title = 'Test'; justification = 'Known vendor requirement, ticket open'; owner = 'App team'; ticket = 'CHG-1'; expires = [DateTime]::UtcNow.AddDays(30).ToString('yyyy-MM-dd') }) -By 'alice@contoso.com'
    & $A ($a1.acceptedBy -eq 'alice@contoso.com' -and (Test-GapsioAcceptanceActive $a1)) 'Acceptance stored and active'
    $bad = $null; try { Set-GapsioAcceptance -Data ([pscustomobject]@{ key = 'dddd4444'; justification = 'short'; owner = 'x'; expires = '2099-01-01' }) -By 'a' | Out-Null } catch { $bad = $_.Exception.Message }
    & $A ($bad -match 'justification') "Acceptance validation ($bad)"
    $bad = $null; try { Set-GapsioAcceptance -Data ([pscustomobject]@{ key = 'dddd4444'; justification = 'long enough text'; owner = 'x'; expires = [DateTime]::UtcNow.AddYears(11).ToString('yyyy-MM-dd') }) -By 'a' | Out-Null } catch { $bad = $_.Exception.Message }
    & $A ($bad -match 'ten years') 'Acceptance at most ten years'
    $bad = $null; try { Set-GapsioAcceptance -Data ([pscustomobject]@{ key = 'dddd4444'; justification = 'long enough text'; owner = 'x'; expires = '2020-01-01' }) -By 'a' | Out-Null } catch { $bad = $_.Exception.Message }
    & $A ($bad -match 'future') 'Acceptance must be in the future'
    & $A (-not (Test-GapsioAcceptanceActive ([pscustomobject]@{ key = 'x'; expires = [DateTime]::UtcNow.AddDays(-1).ToString('yyyy-MM-dd') }))) 'Expired acceptance is not active'
    $unl = Set-GapsioAcceptance -Data ([pscustomobject]@{ key = 'ffff6666'; kind = 'finding'; module = 'endpoint'; title = 'Unlimited'; justification = 'Permanent compensating control in place'; owner = 'CISO'; expires = $null }) -By 'alice@contoso.com'
    & $A ($null -eq $unl.expires -and (Test-GapsioAcceptanceActive $unl)) 'Unlimited exception (no expiry) is active'
    $unl2 = Set-GapsioAcceptance -Data ([pscustomobject]@{ key = 'ffff6666'; kind = 'finding'; module = 'endpoint'; title = 'Unlimited'; justification = 'Permanent compensating control in place'; owner = 'CISO'; expires = 'never' }) -By 'alice@contoso.com'
    & $A ($null -eq $unl2.expires) "Expiry 'never' means unlimited"
    Set-GapsioAcceptance -Data ([pscustomobject]@{ key = 'ffff6666' }) -By 'alice@contoso.com' -Revoke | Out-Null

    # Assignments: user / group / distribution list / plain e-mail, one per key, audit-logged
    $as1 = Set-GapsioAssignment -Data ([pscustomobject]@{ key = 'aaaa1111'; kind = 'finding'; module = 'endpoint'; title = 'New high'; assignee = [pscustomobject]@{ type = 'user'; id = 'u-bob'; displayName = 'Bob'; mail = 'bob@contoso.com' }; note = 'Please check' }) -By 'alice@contoso.com'
    & $A ($as1.assignee.type -eq 'user' -and $as1.assignee.mail -eq 'bob@contoso.com' -and $as1.assignedBy -eq 'alice@contoso.com') 'Assignment to an Entra user stored'
    $as2 = Set-GapsioAssignment -Data ([pscustomobject]@{ key = 'bbbb2222'; assignee = 'secops@contoso.com' }) -By 'alice@contoso.com'
    & $A ($as2.assignee.type -eq 'email' -and $as2.assignee.displayName -eq 'secops@contoso.com' -and $null -eq $as2.assignee.id) 'Assignment to a plain e-mail address (string shorthand)'
    $as3 = Set-GapsioAssignment -Data ([pscustomobject]@{ key = 'bbbb2222'; assignee = [pscustomobject]@{ type = 'distributionList'; id = 'g-dl'; displayName = 'Workplace DL'; mail = 'workplace@contoso.com' } }) -By 'alice@contoso.com'
    & $A ($as3.assignee.type -eq 'distributionList' -and @(Get-GapsioAssignments | Where-Object { $_.key -eq 'bbbb2222' }).Count -eq 1) 'Re-assigning replaces the previous assignment (one per key)'
    $bad = $null; try { Set-GapsioAssignment -Data ([pscustomobject]@{ key = 'bbbb2222'; assignee = [pscustomobject]@{ type = 'email'; mail = 'not-an-address' } }) -By 'a' | Out-Null } catch { $bad = $_.Exception.Message }
    & $A ($bad -match 'e-mail') 'Assignment: invalid e-mail rejected'
    $bad = $null; try { Set-GapsioAssignment -Data ([pscustomobject]@{ key = 'bbbb2222'; assignee = [pscustomobject]@{ type = 'robot'; id = 'x'; displayName = 'y' } }) -By 'a' | Out-Null } catch { $bad = $_.Exception.Message }
    & $A ($bad -match 'type') 'Assignment: unknown assignee type rejected'
    $bad = $null; try { Set-GapsioAssignment -Data ([pscustomobject]@{ key = 'bbbb2222'; assignee = [pscustomobject]@{ type = 'group'; displayName = 'No id' } }) -By 'a' | Out-Null } catch { $bad = $_.Exception.Message }
    & $A ($bad -match 'object id') 'Assignment: group without directory id rejected'
    $bad = $null; try { Set-GapsioAssignment -Data ([pscustomobject]@{ key = 'bbbb2222' }) -By 'a' | Out-Null } catch { $bad = $_.Exception.Message }
    & $A ($bad -match 'assignee is required') 'Assignment: empty assignee rejected'

    # Directory search for the people picker
    $script:Dir = @{ users = @([pscustomobject]@{ id = 'u-bob'; displayName = 'Bob Builder'; mail = 'bob@contoso.com'; userPrincipalName = 'bob@contoso.com'; accountEnabled = $true }, [pscustomobject]@{ id = 'u-old'; displayName = 'Bobby Old'; mail = $null; userPrincipalName = 'old@contoso.com'; accountEnabled = $false })
        groups = @([pscustomobject]@{ id = 'g-sec'; displayName = 'Bob Security'; mail = $null; mailEnabled = $false; securityEnabled = $true; groupTypes = @() }, [pscustomobject]@{ id = 'g-dl'; displayName = 'Bob DL'; mail = 'bobdl@contoso.com'; mailEnabled = $true; securityEnabled = $false; groupTypes = @() }, [pscustomobject]@{ id = 'g-m365'; displayName = 'Bob Team'; mail = 'bobteam@contoso.com'; mailEnabled = $true; securityEnabled = $false; groupTypes = @('Unified') }) }
    function Invoke-GapsioGraph { param($Path, [switch]$Beta, [switch]$All, $Method, $Body, $Headers)
        if ($Path -match "^users\?.*startswith\(displayName,'Bob'\)") { return [pscustomobject]@{ value = $script:Dir.users } }
        if ($Path -match "^groups\?.*startswith\(displayName,'Bob'\)") { return [pscustomobject]@{ value = $script:Dir.groups } }
        if ($Path -match "^users\?.*O''Brien") { return [pscustomobject]@{ value = @() } }
        if ($Path -match "^groups\?") { throw (New-GapsioHttpException -Status 403 -Message 'HTTP 403 Forbidden') }
        throw "unexpected $Path"
    }
    $s = Search-GapsioDirectory -Query 'Bob'
    & $A (@($s.results).Count -eq 4 -and @($s.results | Where-Object { $_.id -eq 'u-old' }).Count -eq 0) 'Directory search: users + groups, disabled accounts skipped'
    & $A (($s.results | Where-Object { $_.id -eq 'g-dl' }).type -eq 'distributionList' -and ($s.results | Where-Object { $_.id -eq 'g-sec' }).type -eq 'group' -and ($s.results | Where-Object { $_.id -eq 'g-m365' }).type -eq 'group') 'Directory search: mail-enabled non-security group = distribution list; M365 group = group'
    & $A ($s.results[0].type -eq 'user' -and $s.results[0].mail -eq 'bob@contoso.com') 'Directory search: users first, mail resolved'
    $s = Search-GapsioDirectory -Query "O'Brien"
    & $A (@($s.results).Count -eq 0 -and @($s.notices).Count -eq 1 -and $s.notices[0] -match 'Groups') 'Directory search: quotes escaped, missing group permission becomes a notice'
    & $A (@((Search-GapsioDirectory -Query 'B').results).Count -eq 0) 'Directory search: needs at least two characters'
    Remove-Item function:Invoke-GapsioGraph

    $env:GAPSIO_NOTIFY_WEBHOOK = 'https://example.invalid/hook'; $env:GAPSIO_NOTIFY_MIN_SEVERITY = 'High'
    $script:posted = $null
    function Invoke-RestMethod { param($Method, $Uri, $ContentType, $Body, $TimeoutSec) $script:posted = $Body | ConvertFrom-Json -Depth 20 }
    $snap = [ordered]@{ findings = @(
            [pscustomobject]@{ key = 'aaaa1111'; severity = 'High'; category = 'Coverage'; title = (New-GapsioText 'New high' 'Neu hoch'); deviceName = 'PC1' },
            [pscustomobject]@{ key = 'bbbb2222'; severity = 'Low'; category = 'Hygiene'; title = (New-GapsioText 'New low' 'Neu niedrig') },
            [pscustomobject]@{ key = 'cccc3333'; severity = 'Critical'; category = 'Combined'; title = (New-GapsioText 'Accepted' 'Akzeptiert') },
            [pscustomobject]@{ key = 'eeee5555'; severity = 'Critical'; category = 'Combined'; title = (New-GapsioText 'Old' 'Alt') }) }
    $ch = @(
        [pscustomobject]@{ collection = 'findings'; change = 'Added'; key = 'aaaa1111' }, [pscustomobject]@{ collection = 'findings'; change = 'Added'; key = 'bbbb2222' },
        [pscustomobject]@{ collection = 'findings'; change = 'Added'; key = 'cccc3333' }, [pscustomobject]@{ collection = 'findings'; change = 'Changed'; key = 'eeee5555' })
    $n = Send-GapsioNotification -Module 'endpoint' -Changes $ch -Snapshot $snap
    & $A ($n -eq 1 -and @($script:posted.gapsio.findings).Count -eq 1 -and $script:posted.gapsio.findings[0].key -eq 'aaaa1111') 'Notification: only new findings >= High that are not accepted'
    & $A ($script:posted.gapsio.findings[0].assignee.mail -eq 'bob@contoso.com' -and $script:posted.attachments[0].content.body[1].text -match 'Bob <bob@contoso.com>') 'Notification: assignee included in payload and card'
    & $A ($script:posted.attachments[0].contentType -eq 'application/vnd.microsoft.card.adaptive' -and $script:posted.type -eq 'message') 'Notification: Teams adaptive card payload'
    $script:posted = $null
    $n = Send-GapsioNotification -Module 'endpoint' -Changes @([pscustomobject]@{ collection = 'findings'; change = 'Added'; key = 'bbbb2222' }) -Snapshot $snap
    & $A ($null -eq $n -and $null -eq $script:posted) 'Notification: nothing to send, no call'
    $env:GAPSIO_NOTIFY_WEBHOOK = 'http://insecure.example/hook'
    Reset-GapsioWarnings
    & $A ($null -eq (Send-GapsioNotification -Module 'endpoint' -Changes $ch -Snapshot $snap) -and @(Get-GapsioWarnings).Count -eq 1) 'Notification: http webhook refused'
    $env:GAPSIO_NOTIFY_WEBHOOK = $null; $env:GAPSIO_NOTIFY_MIN_SEVERITY = $null
    Remove-Item function:Invoke-RestMethod
    Set-GapsioAcceptance -Data ([pscustomobject]@{ key = 'cccc3333' }) -By 'alice@contoso.com' -Revoke | Out-Null
    & $A (-not (Test-GapsioAcceptanceActive (@(Get-GapsioAcceptances | Where-Object { $_.key -eq 'cccc3333' })[0]))) 'Revoked acceptance is not active'
} ${function:Assert}
$log = $blobs['state/acceptances-log.json'] | ConvertFrom-Json
Assert (@($log).Count -eq 8 -and $log[0].action -eq 'revoke' -and $log[-1].action -eq 'accept' -and @($log | Where-Object { $_.action -eq 'assign' }).Count -eq 3 -and $log[1].assignee.type -eq 'distributionList') 'Acceptance audit log (accept, revoke, assign with assignee)'

Write-Host '== End-to-end: drift' -ForegroundColor Cyan
$fixtures.settings['pol-win'][9] = (FxL "${p}excludedextensions" @('.log'))   # .ps1 removed
$r2 = Invoke-GapsioEndpointCollection 6>$null
$changes = $blobs['state/endpoint-changes.json'] | ConvertFrom-Json -Depth 64
Assert (@($changes | Where-Object { $_.change -eq 'Removed' -and $_.label.en -match "\.ps1" }).Count -ge 1) 'Removed .ps1 exclusion detected as a change'
Assert ($r2.changes -ge 1) 'Second run reports changes'
Assert (@($blobs.Keys | Where-Object { $_ -like 'snapshots/endpoint/*' }).Count -eq 2) 'Two dated snapshots'
$runIdx = @($blobs['state/runs.json'] | ConvertFrom-Json -Depth 64)
$lastRun = $runIdx[0]
Assert ($lastRun.drift.Removed -ge 1 -and ($lastRun.drift.Added + $lastRun.drift.Changed + $lastRun.drift.Removed) -eq $lastRun.changes) 'Run index: drift per kind'
Assert ($null -ne $lastRun.findings.Critical -and ($lastRun.findings.High + $lastRun.findings.Critical + $lastRun.findings.Medium + $lastRun.findings.Low) -ge 1) 'Run index: open findings per severity'
Assert ($lastRun.protection.devices -ge 4 -and $lastRun.protection.NetworkProtection.on -ge 1 -and $lastRun.protection.NetworkProtection.off -ge 1) 'Run index: devices per protection feature'
& $mod {
    param($A)
    $mk = { param($k, $p, $rem) [pscustomobject]@{ key = $k; present = $p; removedAt = $rem; state = $(if ($p) { 'present' } else { 'removed' }); fp = (Get-GapsioHash "$p"); label = (New-GapsioText "x $k" "x $k") } }
    $old = @((& $mk 'k1' $true $null), (& $mk 'k2' $false '2026-01-01'), (& $mk 'k3' $false '2026-01-01'), (& $mk 'k4' $true $null))
    $new = @((& $mk 'k1' $false '2026-02-01'), (& $mk 'k2' $false '2026-02-02'), (& $mk 'k4' $true $null), (& $mk 'k5' $false '2026-02-01'), (& $mk 'k6' $true $null))
    $c = @(Compare-GapsioCollection -Module 'endpoint' -Name 'localExclusions' -Old $old -New $new -At 'now')
    & $A (@($c | Where-Object { $_.key -eq 'k1' -and $_.change -eq 'Removed' -and $_.before -eq 'present' -and $null -eq $_.after }).Count -eq 1) 'Lifecycle: present -> removed is reported as Removed'
    & $A (@($c | Where-Object { $_.key -eq 'k2' }).Count -eq 0) 'Lifecycle: bookkeeping on an already removed entry is not a change'
    & $A (@($c | Where-Object { $_.key -eq 'k3' }).Count -eq 0) 'Lifecycle: 90-day clean-up of a removed entry is not a change'
    & $A (@($c | Where-Object { $_.key -eq 'k5' }).Count -eq 0) 'Lifecycle: entry first seen already removed is not Added'
    & $A (@($c | Where-Object { $_.key -eq 'k6' -and $_.change -eq 'Added' -and $_.after -eq 'present' }).Count -eq 1 -and $c.Count -eq 2) 'Lifecycle: new present entry is Added, nothing else'
    $c = @(Compare-GapsioCollection -Module 'endpoint' -Name 'localExclusions' -Old @((& $mk 'k1' $false '2026-01-01')) -New @((& $mk 'k1' $true $null)) -At 'now')
    & $A ($c.Count -eq 1 -and $c[0].change -eq 'Added') 'Lifecycle: removed -> present again is Added'
} ${function:Assert}

Write-Host '== End-to-end: device inventory (optional)' -ForegroundColor Cyan
Assert ($ep.localDetection -eq 'AdvancedHunting') 'Default: Advanced Hunting only'
$env:GAPSIO_DEVICE_INVENTORY = 'true'
$r3 = Invoke-GapsioEndpointCollection 6>$null
$env:GAPSIO_DEVICE_INVENTORY = $null
$ep3 = Get-EpSnapshot
Assert ($ep3.warnings.Count -eq 0) "Warnings with inventory: $($ep3.warnings -join ' | ')"
Assert ($ep3.localDetection -eq 'AdvancedHuntingAndInventory') 'Mode with inventory reported'
Assert ($ep3.summary.devicesWithInventory -eq 2) "2 devices with inventory (AAD ID and name), is $($ep3.summary.devicesWithInventory)"
$le3 = @($ep3.localExclusions)
$legacy = @($le3 | Where-Object { $_.value -eq 'C:\Legacy\Tool' })
Assert ($legacy.Count -eq 1 -and $legacy[0].present -and $legacy[0].source -eq 'DeviceInventory' -and $legacy[0].deviceName -eq 'WIN-01') 'Old exclusion detected by inventory only'
$cmd = @($le3 | Where-Object { $_.value -eq 'cmd.exe' -and $_.deviceName -eq 'WIN-01' })
Assert ($cmd.Count -eq 1 -and -not $cmd[0].present -and $cmd[0].removedBy.process -like '*inventory*') 'Exclusion removed according to inventory marked as removed'
$x3 = @($le3 | Where-Object { $_.value -eq 'C:\Users\Public\x' })
Assert ($x3.Count -eq 1 -and $x3[0].present -and $x3[0].confirmedAt) 'Present exclusion confirmed by inventory'
$w1 = @($ep3.devices | Where-Object { $_.deviceName -eq 'WIN-01' })[0]
Assert ($w1.localMergeDisabled -eq $true -and $w1.inventoryAt) 'DisableLocalAdminMerge per device from inventory'
$f3 = @($ep3.findings)
Assert (@($f3 | Where-Object { $_.title.en -eq 'Local exclusions are effective' -and $_.deviceName -eq 'WIN-01' }).Count -eq 0) 'WIN-01: merge disabled on device -> no finding'
Assert (@($f3 | Where-Object { $_.title.en -eq 'Local exclusions are effective' -and $_.deviceName -eq 'WIN-02' }).Count -eq 1) 'WIN-02: merge active -> finding'
$ch3 = $blobs['state/endpoint-changes.json'] | ConvertFrom-Json -Depth 64
Assert (@($ch3 | Where-Object { $_.change -eq 'Added' -and $_.label.en -match 'Legacy' }).Count -ge 1) 'Inventory hit appears as a change'

Write-Host '== End-to-end: agents' -ForegroundColor Cyan
$rg = Invoke-GapsioAgentsCollection 6>$null
$agSnap = $blobs['state/agents-latest.json'] | ConvertFrom-Json -Depth 64
Assert ($agSnap.warnings.Count -eq 0) "Warnings in the agent run: $($agSnap.warnings -join ' | ')"
$ags = @{}; foreach ($x in $agSnap.agents) { $ags[$x.name] = $x }
Assert (@($agSnap.agents).Count -eq 6) "6 agents expected, $(@($agSnap.agents).Count): $(($agSnap.agents | ForEach-Object name) -join ', ')"
$a1 = $ags['Helpdesk Agent']
Assert ($a1.blueprintAppId -eq 'bp-app-1' -and $a1.agentId -eq 'ai-1' -and $a1.agentUserId -eq 'au-1' -and $a1.blueprintName -eq 'Contoso Helpdesk Blueprint' -and $a1.blueprintPrincipalId -eq 'bpp-1') 'Helpdesk agent: blueprint, agent and agent user ID'
Assert ($a1.platform -eq 'Copilot Studio' -and @($a1.sources) -contains 'Agent365Registry') 'Registry match via agentIdentityId'
Assert ($a1.caIdentity.status -eq 'Protected' -and $a1.caUser.status -eq 'ReportOnly') "Helpdesk: CA agent protected, agent user report-only, is $($a1.caIdentity.status)/$($a1.caUser.status)"
Assert (@($a1.caUser.policies | Where-Object { $_.id -eq 'ca-3' }).Count -eq 0) '"All users" does not apply to agent users'
$a2 = $ags['Report Agent']
Assert ($a2.platform -eq 'Microsoft Foundry' -and @($a2.sources) -contains 'DefenderAgentsInfo') 'AgentsInfo match via EntraAgentId'
Assert ($a2.model -eq 'gpt-5' -and $a2.guardrails -eq 0 -and $a2.tools -eq 2 -and $null -eq $a2.permissions -and @($a2.owners) -contains 'Bob (bob@contoso.com)') "AgentsInfo details (model=$($a2.model) guardrails=$($a2.guardrails) tools=$($a2.tools) owners=$(@($a2.owners) -join ','))"
Assert (@($a2.endpoints).Count -eq 1 -and $a2.endpoints[0].external -eq $true -and $a2.endpoints[0].url -eq 'https://agent.contoso.com/api') 'AgentsInfo endpoints parsed'
Assert (@($a2.mcpServers).Count -eq 1 -and $a2.mcpServers[0].endpoint -eq 'https://mcp.contoso.com' -and $a2.mcpServers[0].kind -eq 'http') 'AgentsInfo McpServers parsed'
Assert ($a2.caUser.status -eq 'NotCovered') "Report agent user: excluded from report-only -> not covered, is $($a2.caUser.status)"
Assert ($ags['Legacy Agent'].caIdentity.status -eq 'Excluded') "Legacy agent excluded, is $($ags['Legacy Agent'].caIdentity.status)"
Assert ($ags['Sales Agent'].caIdentity.status -eq 'NoAgentId' -and $ags['Sales Agent'].agentType -eq 'Cloud') 'Agents without Entra Agent ID'
Assert ($ags['Orphan'].agentUserId -eq 'au-3' -and -not $ags['Orphan'].agentId -and $ags['Orphan'].caIdentity.status -eq 'IdentityMissing') 'Orphaned agent user'
Assert (@($agSnap.findings | Where-Object { $_.title.en -eq 'Orphaned agent user: orphan-agent@contoso.com' }).Count -eq 1) 'Finding: orphaned agent user'
$pol = @{}; foreach ($x in $agSnap.policies) { $pol[$x.id] = $x }
Assert ($pol['ca-1'].coveredIdentities -eq 2 -and $pol['ca-2'].coveredUsers -eq 2 -and -not $pol.ContainsKey('ca-3')) "CA summary (ca-1: $($pol['ca-1'].coveredIdentities), ca-2: $($pol['ca-2'].coveredUsers))"
$af = @($agSnap.findings)
Assert (@($af | Where-Object { $_.title.en -eq 'No enabled Conditional Access policy for agent users' }).Count -eq 1) 'Finding: no enabled policy for agent users'
Assert (@($af | Where-Object { $_.title.en -eq 'No enabled Conditional Access policy for agent identities' }).Count -eq 0) 'No finding for agent identities (ca-1 enabled)'
Assert (@($af | Where-Object { $_.title.en -eq 'Agent without sponsor: Report Agent' }).Count -eq 1) 'Finding: agent without sponsor'
Assert (@($af | Where-Object { $_.title.en -eq 'Agent excluded from Conditional Access: Legacy Agent' }).Count -eq 1) 'Finding: agent excluded'
Assert (@($af | Where-Object { $_.title.en -eq 'Blueprint unknown in this tenant: Legacy Agent' }).Count -eq 1) 'Finding: unknown blueprint'
Assert (@($af | Where-Object { $_.title.en -match '^Cloud agent without Entra Agent ID' }).Count -eq 1) 'Finding: agents without Entra Agent ID'
Assert (@($af | Where-Object { $_.title.en -eq 'Agent without guardrails: Report Agent' -and $_.severity -eq 'Low' }).Count -eq 1) 'Finding: agent without guardrails (explicit empty array)'
Assert (@($af | Where-Object { $_.title.en -eq 'Agent endpoint reachable from outside: Report Agent' -and $_.severity -eq 'Medium' }).Count -eq 1) 'Finding: externally reachable agent endpoint'
Assert (@($af | Where-Object { $_.title.en -match '^Agent without guardrails' }).Count -eq 1) 'No guardrail finding when Guardrails is unknown (null)'
$la = $ags['Local Agent']
Assert ($la.agentType -eq 'Local' -and $la.caIdentity.status -eq 'UserContext' -and $la.device.name -eq 'WIN-01' -and $la.user -eq 'alice@contoso.com' -and $la.autoApprove) 'Local agent with device, user and auto-approve'
Assert (@($la.mcpServers | Where-Object { $_.unpinned }).Count -eq 1) 'Local agent: one unpinned MCP server'
Assert (@($af | Where-Object { $_.category -eq 'LocalAgent' -and $_.title.en -match 'without confirmation: Local Agent' }).Count -eq 1) 'Finding: local agent auto-approve'
Assert (@($af | Where-Object { $_.title.en -match '^MCP server loaded unpinned' }).Count -eq 1) 'Finding: unpinned MCP server'
Assert (@($af | Where-Object { $_.category -eq 'Combined' -and $_.title.en -match 'weakened device: Local Agent' -and $_.severity -eq 'Critical' }).Count -eq 1) 'Finding: local agent on weakened device (tamper off + auto-approve)'
Assert ($agSnap.summary.localAgents -eq 1 -and $agSnap.summary.cloudAgents -eq 5) "Summary cloud/local ($($agSnap.summary.cloudAgents)/$($agSnap.summary.localAgents))"
Assert ($agSnap.summary.identitiesCovered -eq 2 -and $agSnap.summary.withEntraId -eq 3) 'Agents summary'
# Attribute filter
$fxp = [pscustomobject]@{ id = 'ca-f'; displayName = 'Filter'; state = 'enabled'; conditions = [pscustomobject]@{ clientApplications = [pscustomobject]@{ agentIdServicePrincipalFilter = [pscustomobject]@{ mode = 'include'; rule = 'CustomSecurityAttribute.Agents.Approved -eq "true"' } } } }
$cov = & $mod { param($p) Get-GapsioAgentCaCoverage -Policies @($p) -Kind Identity -Ids @('x') -DirectId 'x' -SecurityDefaults $false } $fxp
Assert ($cov.status -eq 'Unclear') "Attribute filter -> Unclear, is $($cov.status)"
$cov = & $mod { param($p) Get-GapsioAgentCaCoverage -Policies @($p) -Kind Identity -Ids @('x') -DirectId 'x' -SecurityDefaults $true } $fxp
Assert ($cov.status -eq 'SecurityDefaults') 'Security defaults override CA'
$bp2 = [pscustomobject]@{ id = 'ca-b'; displayName = 'Blueprint'; state = 'enabled'; conditions = [pscustomobject]@{ clientApplications = [pscustomobject]@{ includeAgentIdServicePrincipals = @('BP-OBJ-1') } } }
$cov = & $mod { param($p) Get-GapsioAgentCaCoverage -Policies @($p) -Kind Identity -Ids @('ai-9', 'bp-obj-1') -DirectId 'ai-9' -SecurityDefaults $false } $bp2
Assert ($cov.status -eq 'Protected' -and $cov.policies[0].via -eq 'Blueprint') 'Blueprint target covers the agent (case-insensitive)'

$fixtures.agents.registry404 = $true
$null = Invoke-GapsioAgentsCollection 6>$null 3>$null
$ag404 = $blobs['state/agents-latest.json'] | ConvertFrom-Json -Depth 64
Assert ($ag404.registryStatus -eq 'NotAvailable' -and @($ag404.warnings | Where-Object { $_ -match 'registry' }).Count -eq 0) 'Agent 365 registry 404: status, no warning'
Assert ($ag404.registryNote -match 'CopilotPackages.Read.All') 'Package API 403 is recorded as a note'
$fixtures.agents.registry404 = $false
Assert ($agSnap.registrySource -eq 'AgentRegistry') 'Legacy registry used when the package API is denied'

# Agent 365 Package Management API (successor of the registry)
$fixtures.agents.packages = @(
    [pscustomobject]@{ id = 'P_1'; displayName = 'Helpdesk Agent'; type = 'custom'; platform = 'Copilot Studio'; publisher = 'Contoso'; agentIdentityId = 'ai-1'; appId = 'app-ai-1'; manifestId = 'm-1'; isBlocked = $false; availableTo = 'all'; deployedTo = 'some'; supportedHosts = @('Copilot'); elementTypes = @('DeclarativeAgent'); lastModifiedDateTime = '2026-01-01T00:00:00Z' },
    [pscustomobject]@{ id = 'P_2'; displayName = 'Finance Agent'; type = 'custom'; platform = 'Microsoft 365 Copilot Agent Builder'; publisher = 'Contoso'; isBlocked = $true; availableTo = 'none'; deployedTo = 'none'; supportedHosts = @('Copilot'); elementTypes = @('DeclarativeAgent'); lastModifiedDateTime = '2026-02-01T00:00:00Z' }
)
$null = Invoke-GapsioAgentsCollection 6>$null 3>$null
$agP = $blobs['state/agents-latest.json'] | ConvertFrom-Json -Depth 64
Assert ($agP.registryStatus -eq 'Available' -and $agP.registrySource -eq 'Agent365Packages' -and -not $agP.registryNote) 'Package API used when available'
$agsP = @{}; foreach ($x in $agP.agents) { $agsP[$x.name] = $x }
Assert (@($agsP['Helpdesk Agent'].sources) -contains 'Agent365Packages' -and $agsP['Helpdesk Agent'].registryId -eq 'P_1' -and $agsP['Helpdesk Agent'].publisher -eq 'Contoso' -and $agsP['Helpdesk Agent'].deployedTo -eq 'some') 'Package matched to agent identity via agentIdentityId'
Assert ($agsP['Finance Agent'].blocked -eq $true -and $agsP['Finance Agent'].platform -eq 'Microsoft 365 Copilot Agent Builder' -and $agsP['Finance Agent'].caIdentity.status -eq 'NoAgentId') 'Package without agent identity listed as cloud agent'
$fixtures.agents.packages = $null

Write-Host '== End-to-end: access' -ForegroundColor Cyan
$env:GAPSIO_MODULES = 'endpoint,agents,access'
# Permission usage evidence (feature Response is on in these tests, Audit is off)
$fixtures.machineActions = @(
    [pscustomobject]@{ id = 'ma1'; type = 'Isolate'; status = 'Succeeded'; requestor = 'Alice@contoso.com'; creationDateTimeUtc = (T 3); machineId = 'd-win1'; computerDnsName = 'WIN-01' },
    [pscustomobject]@{ id = 'ma2'; type = 'RunAntiVirusScan'; status = 'Succeeded'; requestor = 'erin@contoso.com'; creationDateTimeUtc = (T 4); machineId = 'd-win2'; computerDnsName = 'WIN-02' },
    [pscustomobject]@{ id = 'ma3'; type = 'LiveResponse'; status = 'Succeeded'; requestor = 'Automation'; creationDateTimeUtc = (T 5); machineId = 'd-win2'; computerDnsName = 'WIN-02'; commands = @([pscustomobject]@{ command = [pscustomobject]@{ type = 'RunScript' } }) },
    [pscustomobject]@{ id = 'ma4'; type = 'Isolate'; status = 'Succeeded'; requestor = 'carol@contoso.com'; creationDateTimeUtc = (T 45); machineId = 'd-win2'; computerDnsName = 'WIN-02' },
    [pscustomobject]@{ id = 'ma5'; type = 'Offboard'; status = 'Succeeded'; requestor = 'alice@contoso.com'; creationDateTimeUtc = (T 6); machineId = 'd-old9'; computerDnsName = 'OLD-09' }
)
$fixtures.mdeAlerts = @(
    [pscustomobject]@{ id = 'al1'; status = 'Resolved'; assignedTo = 'alice@contoso.com'; resolvedTime = (T 2); lastUpdateTime = (T 2); comments = @([pscustomobject]@{ createdBy = 'alice@contoso.com'; createdTime = (T 2); comment = 'benign' }) },
    [pscustomobject]@{ id = 'al2'; status = 'New'; assignedTo = 'dave@contoso.com'; lastUpdateTime = (T 1); comments = @() }
)
$ra = Invoke-GapsioAccessCollection 6>$null
$ac = $blobs['state/access-latest.json'] | ConvertFrom-Json -Depth 64
Assert ($ac.warnings.Count -eq 0) "Warnings in the access run: $($ac.warnings -join ' | ')"
Assert ($ac.summary.apiApps -eq 2 -and $ac.summary.apiAppsHighImpact -eq 1) "API apps: 2 with Defender permissions, 1 with write permissions (Mail.Read app ignored) ($($ac.summary.apiApps)/$($ac.summary.apiAppsHighImpact))"
$apiF = @($ac.findings | Where-Object { $_.title.en -eq 'API app with Defender write permissions: SOAR automation' })
Assert ($apiF.Count -eq 1 -and $apiF[0].severity -eq 'High' -and $apiF[0].detail.en -match 'client secret' -and $apiF[0].detail.en -match 'no owner' -and $apiF[0].detail.en -match 'Machine.Offboard') 'API app: offboard permission with secret, 3-year credential, no owner -> High'
Assert (@($ac.findings | Where-Object { $_.title.en -match 'Gapsio' }).Count -eq 0) 'API app: read-only app with certificate -> no finding'
Assert (@($ac.findings | Where-Object { $_.title.en -match 'Defender role group\(s\) without an access review' }).Count -eq 1) 'Access reviews: role groups without review'
Assert (@($ac.findings | Where-Object { $_.title.en -like 'Weak PIM activation for Defender group:*' -and $_.detail.en -match 'no MFA' -and $_.detail.en -match '10 hours' }).Count -ge 1) 'PIM for Groups: activation without MFA, 10 hours'
$e = @($ac.entitlements)
function Has { param($upn, $role, $state, $via) @($e | Where-Object { $_.upn -eq $upn -and $_.role -eq $role -and $_.state -eq $state -and $_.via -like $via }).Count -ge 1 }
function Ent { param($upn, $role, $state) @($e | Where-Object { $_.upn -eq $upn -and $_.role -eq $role -and $_.state -eq $state })[0] }
Assert ($ac.summary.roles -eq 3 -and @($ac.roles | Where-Object { $_.platform -ne 'Defender' }).Count -eq 0) 'Only Defender unified RBAC roles'
Assert (@($ac.roles | Where-Object { $_.name -eq 'SecOps Responder' })[0].privileged -eq $true -and @($ac.roles | Where-Object { $_.name -eq 'Defender Reader' })[0].privileged -eq $false) 'Response/live response marks a role as privileged, read does not'
Assert ((@($ac.roles | Where-Object { $_.name -eq 'SecOps Responder' })[0].permissionGroups -join ',') -eq 'secops') 'Permission groups derived from microsoft.xdr/<group>/'
Assert (Has 'alice@contoso.com' 'SecOps Responder' 'Active' 'direct') 'Alice SecOps active direct'
Assert ((Ent 'alice@contoso.com' 'SecOps Responder' 'Active').allDataSources -eq $true -and (Ent 'alice@contoso.com' 'SecOps Responder' 'Active').assignment -eq 'SecOps – everything') 'Alice: "/" = all data sources, assignment name kept'
Assert (Has 'dave@contoso.com' 'SecOps Responder' 'Active' 'Group: Helpdesk-Team') 'Dave SecOps via group'
Assert ((Ent 'dave@contoso.com' 'SecOps Responder' 'Active').scope -eq 'Defender for Endpoint' -and ((Ent 'dave@contoso.com' 'SecOps Responder' 'Active').dataSources -join ',') -eq 'Mde') 'Group assignment scoped to Mde data source'
Assert ((Ent 'bob@contoso.com' 'Defender Reader' 'Active').scope -eq 'Defender for Endpoint, Defender for Identity') 'Multiple data sources listed'
Assert (Has 'gina@contoso.com' 'SecOps Responder' 'Eligible' 'PIM for groups: Helpdesk-Team') 'Gina SecOps eligible via PIM for groups'
Assert ((Ent 'gina@contoso.com' 'SecOps Responder' 'Eligible').lastActivated -and (Ent 'gina@contoso.com' 'SecOps Responder' 'Eligible').usage -eq 'Used') 'Gina: last PIM activation recorded, portal sign-in counts as used'
Assert (Has 'hank@contoso.com' 'SecOps Responder' 'Requestable' 'Access package: Helpdesk access*') 'Hank SecOps requestable via package'
Assert (Has 'erin@contoso.com' 'SecOps Responder' 'Active' 'Access package: Helpdesk access (assigned*') 'Erin assigned via package'
Assert (@($ac.audiences | Where-Object { $_.audience -eq 'allMemberUsers' -and $_.grants[0].role -eq 'SecOps Responder' }).Count -eq 1) 'Open package for all members'
Assert ((Ent 'alice@contoso.com' 'SecOps Responder' 'Active').usage -eq 'Used' -and ([datetime](Ent 'alice@contoso.com' 'SecOps Responder' 'Active').lastUsed).ToUniversalTime() -eq ([datetime](T 2)).ToUniversalTime()) 'Alice: latest portal sign-in is last used'
Assert ((Ent 'carol@contoso.com' 'Defender Settings Admin' 'Active').usage -eq 'Unused' -and -not (Ent 'carol@contoso.com' 'Defender Settings Admin' 'Active').lastUsed) 'Carol: no sign-in in 30 days = unused'
Assert (([datetime]$ac.principalUsage.'u-alice').ToUniversalTime() -eq ([datetime](T 2)).ToUniversalTime() -and $ac.usageObservedSince) 'Usage carried in snapshot for the next run'
$byp = @($ac.bypass)
Assert (@($byp | Where-Object { $_.upn -eq 'alice@contoso.com' -and $_.role -eq 'Global Administrator' -and $_.level -eq 'High' }).Count -eq 1) 'Alice GA listed as bypass (High)'
Assert (@($byp | Where-Object { $_.upn -eq 'bob@contoso.com' -and $_.role -eq 'Security Reader' -and $_.level -eq 'Low' }).Count -eq 1) 'Bob Security Reader listed as bypass (Low)'
Assert (@($e | Where-Object { $_.role -in 'Global Administrator', 'Security Reader' }).Count -eq 0) 'Entra roles not mixed into the unified RBAC table'
$af = @($ac.findings)
Assert (@($af | Where-Object { $_.category -notin 'LeastPrivilege', 'Platform' }).Count -eq 0 -and $af.Count -ge 5) "Access findings are LeastPrivilege/Platform ($($af.Count))"
Assert (@($af | Where-Object { $_.title.en -like 'Standing Defender permission never used: Carol' -and $_.severity -eq 'Medium' }).Count -eq 1) 'Finding: Carol holds settings permission but never used the portal'
Assert (@($af | Where-Object { $_.title.en -like 'Standing Defender permission never used: Dave' }).Count -eq 1) 'Finding: Dave (via group) never used the portal'
Assert (@($af | Where-Object { $_.title.en -like 'Standing Defender permission never used: Alice' }).Count -eq 0) 'No unused finding for Alice (used 2 days ago)'
Assert (@($af | Where-Object { $_.title.en -like 'Standing Defender permission never used: Bob' }).Count -eq 0) 'No unused finding for read-only role'
Assert (@($af | Where-Object { $_.title.en -like '*full Defender access through Entra roles' -and $_.severity -eq 'High' }).Count -eq 1) 'Finding: GA bypasses unified RBAC'
Assert (@($af | Where-Object { $_.title.en -like '*read all Defender data through Entra reader roles' }).Count -eq 1) 'Finding: Security Reader bypass'
Assert (@($af | Where-Object { $_.title.en -like '*permanent response permissions on all data sources' }).Count -eq 0) 'Standing finding needs 3+ people (only Alice and Carol)'
Assert (@($af | Where-Object { $_.title.en -like '*assignment(s) to individual users' }).Count -eq 1) 'Finding: direct user assignments'
Assert (@($af | Where-Object { $_.title.en -like 'Eligible Defender role never activated*' }).Count -eq 0) 'Gina activated her eligibility – no idle finding'
Assert ($ac.summary.standingPrivileged -eq 2 -and $ac.summary.unusedActive -ge 3 -and $ac.summary.bypassUsers -eq 2) "Access summary (standing $($ac.summary.standingPrivileged), unused $($ac.summary.unusedActive), bypass $($ac.summary.bypassUsers))"
# Held versus used
$cov = @($ac.permissionCoverage)
function Cov { param($upn, $perm) @($cov | Where-Object { $_.upn -eq $upn -and $_.permissionId -eq $perm })[0] }
Assert ($ac.permissionSourceState.actions -eq 'ok' -and $ac.permissionSourceState.alerts -eq 'ok' -and $ac.permissionSourceState.audit -eq 'off' -and (@($ac.permissionSources) -join ',') -eq 'Response actions,Alerts') 'Permission sources: response actions and alerts read, audit off'
Assert ((Cov 'alice@contoso.com' 'response').status -eq 'Used' -and (Cov 'alice@contoso.com' 'response').count -eq 1) 'Alice: isolation = Response used (requestor case-insensitive)'
Assert ((Cov 'alice@contoso.com' 'alerts').status -eq 'Used' -and (Cov 'alice@contoso.com' 'alerts').count -eq 2) 'Alice: resolved alert and comment = Alerts used'
Assert ((Cov 'alice@contoso.com' 'lr-basic').status -eq 'Unused' -and (Cov 'alice@contoso.com' 'lr-basic').reason -eq 'checked') 'Alice: basic live response held but not used'
Assert ((Cov 'erin@contoso.com' 'alerts').status -eq 'Used' -and (Cov 'erin@contoso.com' 'response').status -eq 'Unused') 'Erin: antivirus scan counts as Alerts (manage), not Response'
Assert ((Ent 'erin@contoso.com' 'SecOps Responder' 'Active').usage -eq 'Used') 'Erin: an action counts as use without a portal sign-in'
Assert ((Cov 'dave@contoso.com' 'alerts').status -eq 'Unused') 'Dave: an alert that is only assigned (New) is not use'
Assert ((Cov 'carol@contoso.com' 'coresettings').status -eq 'NotMeasurable' -and (Cov 'carol@contoso.com' 'coresettings').reason -eq 'off.audit') 'Carol: settings permission not measurable without the audit feature'
Assert (@($ac.permissionUsage | Where-Object { $_.upn -eq 'carol@contoso.com' }).Count -eq 0) 'Carol: action older than 30 days ignored'
Assert ((Cov 'bob@contoso.com' 'read').status -eq 'Unused' -and (Cov 'bob@contoso.com' 'read').reason -eq 'signIn') 'Bob: read access judged by portal sign-in'
Assert (@((Cov 'gina@contoso.com' 'response').states) -contains 'Eligible') 'Eligible permissions are listed'
Assert (@($cov | Where-Object { $_.upn -eq 'hank@contoso.com' }).Count -eq 0) 'Requestable permissions are not held'
Assert (@($ac.permissionUsage | Where-Object { $_.upn -eq 'alice@contoso.com' -and $_.permissionId -eq 'coresettings' -and @($_.actions | Where-Object action -eq 'Offboard').Count -eq 1 }).Count -eq 1 -and (Cov 'alice@contoso.com' 'coresettings') -eq $null) 'Offboarding counts as Core security settings (Microsoft: "onboard and offboard devices"); not held by Alice, so usage only'
Assert (@($ac.permissionUsage | Where-Object { $_.upn -notmatch '@' }).Count -eq 0 -and @($ac.permissionUsage | Where-Object { $_.upn -eq 'alice@contoso.com' -and $_.permission -eq 'Response (manage)' }).Count -eq 1) 'Usage table: catalog names, no automation requestors'
$pf = @($ac.findings | Where-Object { $_.title.en -like 'Defender permissions held but not used:*' })
Assert (@($pf | Where-Object { $_.title.en -like '*: Alice' -and $_.severity -eq 'Medium' -and $_.detail.en -match 'Basic live response' -and $_.detail.en -cnotmatch 'Alerts \(manage\)|Response \(manage\)' }).Count -eq 1) 'Finding: Alice holds live response but did not use it (Medium)'
Assert (@($pf | Where-Object { $_.title.en -like '*: Erin' -and $_.detail.en -match 'Response \(manage\)' }).Count -eq 1) 'Finding: Erin holds response but only scanned'
Assert (@($pf | Where-Object { $_.title.en -like '*: Dave' -or $_.title.en -like '*: Carol' -or $_.title.en -like '*: Gina' }).Count -eq 0) 'No permission finding for never-signed-in (already reported), not measurable or eligible-only'
Assert ($ac.summary.unusedPermissions -ge 3 -and $ac.summary.peopleWithUnusedPermissions -ge 2 -and $ac.summary.notMeasurablePermissions -ge 1) "Summary: unused $($ac.summary.unusedPermissions), people $($ac.summary.peopleWithUnusedPermissions), not measurable $($ac.summary.notMeasurablePermissions)"

# Second run: a previous snapshot with an older sign-in and an eligible user who never activated
$access.pimActivations['g1'] = @()
$access.signIns = @([pscustomobject]@{ userId = 'u-alice'; createdDateTime = (T 2) })
$ra2 = Invoke-GapsioAccessCollection 6>$null
$ac2 = $blobs['state/access-latest.json'] | ConvertFrom-Json -Depth 64
$e = @($ac2.entitlements)
Assert (([datetime](Ent 'gina@contoso.com' 'SecOps Responder' 'Eligible').lastUsed).ToUniversalTime() -eq ([datetime](T 10)).ToUniversalTime() -and (Ent 'gina@contoso.com' 'SecOps Responder' 'Eligible').usage -eq 'Used') 'Sign-in from the previous snapshot carried forward'
Assert (@($ac2.findings | Where-Object { $_.title.en -like 'Eligible Defender role never activated: Gina' }).Count -eq 0) 'Portal usage within window still counts for eligible user'
$access.pimActivations['g1'] = @([pscustomobject]@{ groupId = 'g1'; principalId = 'u-gina'; accessId = 'member'; action = 'selfActivate'; createdDateTime = (T 10) })
$access.signIns = @([pscustomobject]@{ userId = 'u-alice'; createdDateTime = (T 2) }, [pscustomobject]@{ userId = 'u-gina'; createdDateTime = (T 10) })
$e = @($ac.entitlements)
$fixtures.machineActions = $null; $fixtures.mdeAlerts = $null

Write-Host '== End-to-end: licensing (Defender for Endpoint)' -ForegroundColor Cyan
$env:GAPSIO_MODULES = 'endpoint,agents,access,licensing'
$rl = Invoke-GapsioLicensingCollection 6>$null
$lic = $blobs['state/licensing-latest.json'] | ConvertFrom-Json -Depth 64
Assert ($lic.module -eq 'licensing' -and $lic.scope -eq 'Defender for Endpoint, Defender for Office 365') 'Licensing snapshot written'
Assert ($lic.warnings.Count -eq 0) "Warnings in the licensing run: $($lic.warnings -join ' | ')"
Assert (@($lic.skus | Where-Object { $_.product -eq 'MDE' }).Count -eq 2 -and @($lic.skus | Where-Object { $_.skuPartNumber -eq 'SPE_E3' }).Count -eq 0) 'Only SKUs with an MDE plan are listed as MDE (E3 without MDE plan skipped)'
Assert (@($lic.skus | Where-Object { $_.product -eq 'MDO' }).Count -eq 2 -and @($lic.skus | Where-Object { $_.skuPartNumber -eq 'THREAT_INTELLIGENCE' })[0].skuName -eq 'Defender for Office 365 P2' -and @($lic.skus | Where-Object { $_.skuPartNumber -eq 'THREAT_INTELLIGENCE' })[0].tier -eq 'P2') 'MDO SKUs listed with product MDO and display name'
Assert ($lic.summary.mdoUsers -eq 2 -and $lic.summary.mdoUsersP2 -eq 1 -and $lic.summary.mdoUsersP1 -eq 1 -and $lic.summary.mdoUsersWithoutMde -eq 1 -and $lic.summary.mdoUsersDisabled -eq 1) "MDO users: $($lic.summary.mdoUsers) (P2 $($lic.summary.mdoUsersP2), P1 $($lic.summary.mdoUsersP1), without MDE $($lic.summary.mdoUsersWithoutMde))"
Assert ($lic.summary.mdoP1Enabled -eq 2 -and $lic.summary.mdoP1Consumed -eq 3 -and $lic.summary.mdoP2Enabled -eq 5) 'MDO units summed per tier'
Assert (@($lic.mdoUsers | Where-Object { $_.upn -eq 'olga@contoso.com' })[0].state -eq 'Disabled' -and -not @($lic.mdoUsers | Where-Object { $_.upn -eq 'olga@contoso.com' })[0].mdeTier) 'Olga: MDO-only, disabled account'
Assert (@($lic.users | Where-Object { $_.upn -eq 'olga@contoso.com' }).Count -eq 0) 'MDO-only users do not appear in the MDE user table'
$p2 = @($lic.skus | Where-Object { $_.skuPartNumber -eq 'WIN_DEF_ATP' })[0]
Assert ($p2.tier -eq 'P2' -and $p2.enabled -eq 10 -and $p2.consumed -eq 12 -and -not $p2.isServer) 'P2 SKU: tier, units'
Assert ($p2.skuName -eq 'Defender for Endpoint P2' -and @($lic.skus | Where-Object { $_.skuPartNumber -eq 'DEFENDER_ENDPOINT_P1' })[0].skuName -eq 'Defender for Endpoint P1') 'SKU display names: WIN_DEF_ATP -> Defender for Endpoint P2, DEFENDER_ENDPOINT_P1 -> P1'
Assert ((Get-GapsioSkuDisplayName -PartNumber 'CONTOSO_BUNDLE' -Tier 'P2') -eq 'Defender for Endpoint P2 (in CONTOSO_BUNDLE)' -and (Get-GapsioSkuDisplayName -PartNumber 'SPE_E5' -Tier 'P2') -eq 'Microsoft 365 E5') 'SKU display names: suites and unknown part numbers'
Assert ($lic.summary.licensedUsers -eq 3 -and $lic.summary.usersP2 -eq 2 -and $lic.summary.usersP1 -eq 1) "Licensed users: $($lic.summary.licensedUsers) (P2 $($lic.summary.usersP2), P1 $($lic.summary.usersP1)) – Dave's deleted plan does not count"
Assert ($lic.summary.servers -eq 2 -and $lic.summary.clients -eq 3) "Servers ($($lic.summary.servers)) are separated from clients ($($lic.summary.clients))"
$lw1 = @($lic.devices | Where-Object { $_.deviceName -eq 'WIN-01' })[0]
Assert ($lw1.state -eq 'Licensed' -and $lw1.licensedBy -eq 'alice@contoso.com' -and $lw1.confidence -eq 'Intune' -and $lw1.tier -eq 'P2') 'WIN-01 licensed via Intune primary user (exact match)'
$lw2 = @($lic.devices | Where-Object { $_.deviceName -eq 'WIN-02' })[0]
Assert ($lw2.state -eq 'Unlicensed' -and $lw2.confidence -eq 'Logon') 'WIN-02: only an unlicensed account (zed) logged on'
$lm1 = @($lic.devices | Where-Object { $_.deviceName -eq 'MAC-01' })[0]
Assert ($lm1.state -eq 'Unlicensed' -and $lm1.users[0].upn -eq 'hank' -and -not $lm1.users[0].tier) 'MAC-01: Hank (no MDE plan) seen by logon name, not licensed'
Assert (@($lic.users | Where-Object { $_.upn -eq 'carol@contoso.com' })[0].state -eq 'NoDevice') 'Carol licensed but no device'
Assert ($lic.summary.clientsUnlicensed -eq 2 -and $lic.summary.clientsLicensed -eq 1 -and $lic.summary.usersNoDevice -eq 2) "Licensing summary (unlicensed $($lic.summary.clientsUnlicensed), licensed $($lic.summary.clientsLicensed), noDevice $($lic.summary.usersNoDevice))"
$lf = @($lic.findings)
Assert (@($lf | Where-Object { $_.title.en -like 'More licences assigned than purchased: Defender for Endpoint P2' -and $_.severity -eq 'High' }).Count -eq 1) 'Finding: consumed > enabled'
Assert (@($lf | Where-Object { $_.title.en -like 'More licences assigned than purchased: Defender for Office 365 P1' -and $_.severity -eq 'High' }).Count -eq 1) 'Finding: MDO consumed > enabled'
Assert (@($lf | Where-Object { $_.subject -eq 'mdo-mixed' }).Count -eq 1 -and @($lf | Where-Object { $_.subject -eq 'mdo-disabled' }).Count -eq 1) 'Findings: MDO mixed plans and disabled account with plan'
Assert (@($lf | Where-Object { $_.title.en -like '2 onboarded client(s) used only by users without*' -and $_.deviceCount -eq 2 }).Count -eq 1) 'Finding: unlicensed clients (aggregated with device count)'
Assert (@($lf | Where-Object { $_.title.en -like '*licensed user(s) without an onboarded device*' }).Count -eq 1) 'Finding: licensed users without device'
Assert (@($lf | Where-Object { $_.title.en -like '*covered only by Plan 1*' }).Count -eq 0) 'No P1 finding (Bob has no device)'
Assert (@($lf | Where-Object { $_.title.en -like '2 onboarded server(s)*' }).Count -eq 1) 'Finding: servers without visible server SKU'
Assert (@($lf | Where-Object { $_.category -ne 'Licensing' }).Count -eq 0) 'All licensing findings use category Licensing'
Assert (@($lic.caveats).Count -ge 3 -and $lic.caveats[0].de) 'Caveats are bilingual'
$env:GAPSIO_LICENSING_DETAIL = 'aggregate'
$null = Invoke-GapsioLicensingCollection 6>$null
$lic2 = $blobs['state/licensing-latest.json'] | ConvertFrom-Json -Depth 64
Assert ($lic2.detail -eq 'aggregate' -and @($lic2.users | Where-Object { $_.upn -like '*@*' }).Count -eq 0 -and $null -eq $lic2.users[0].displayName) 'GAPSIO_LICENSING_DETAIL=aggregate pseudonymises users'
$env:GAPSIO_LICENSING_DETAIL = $null
$null = Invoke-GapsioLicensingCollection 6>$null
# Unit: plan tier resolution by name and by ID, best tier
& $mod {
    param($A)
    & $A ((Get-GapsioMdePlanTier ([pscustomobject]@{ servicePlanId = 'BFC1BBD9-981B-4F71-9B82-17C35FD0E2A4' })) -eq 'MDB') 'Plan tier by ID (case-insensitive)'
    & $A ((Get-GapsioMdePlanTier ([pscustomobject]@{ servicePlanName = 'mde_lite' })) -eq 'P1') 'Plan tier by name'
    & $A ($null -eq (Get-GapsioMdePlanTier ([pscustomobject]@{ servicePlanName = 'EXCHANGE_S_ENTERPRISE' }))) 'Non-MDE plan -> null'
    & $A ((Get-GapsioBestTier @('P1', 'MDB', 'P2', $null)) -eq 'P2' -and (Get-GapsioBestTier @('P1', 'MDB')) -eq 'MDB') 'Best tier ranking'
    $m = Get-GapsioLicensingModel -Skus @() -Users @() -Data @{ devices = @(); logons = @(); intune = @() }
    & $A ($m.summary.clients -eq 0 -and @($m.findings).Count -eq 0) 'Empty model: no findings'
    # Usage classification: shared (many people), kiosk (Intune self-deploying), VDI (model), service accounts ignored
    $usersX = @(1..6 | ForEach-Object { [pscustomobject]@{ id = "u$_"; upn = "user$_@contoso.com"; displayName = "User $_"; tier = 'P2'; accountEnabled = $true; userType = 'Member'; names = @("user$_") } })
    $devX = @(
        [pscustomobject]@{ DeviceId = 'x-shared'; DeviceName = 'PC-FLOOR1'; OSPlatform = 'Windows11'; DeviceType = 'Workstation'; MachineGroup = 'Clients'; LastSeen = (Get-Date).ToString('o') },
        [pscustomobject]@{ DeviceId = 'x-kiosk'; DeviceName = 'PC-0042'; OSPlatform = 'Windows11'; DeviceType = 'Workstation'; AadDeviceId = 'AAD-KIOSK'; MachineGroup = 'Clients'; LastSeen = (Get-Date).ToString('o') },
        [pscustomobject]@{ DeviceId = 'x-vdi'; DeviceName = 'PC-0043'; OSPlatform = 'Windows11'; DeviceType = 'Workstation'; MachineGroup = 'Clients'; Model = 'Virtual Machine'; Vendor = 'Microsoft Corporation'; LastSeen = (Get-Date).ToString('o') },
        [pscustomobject]@{ DeviceId = 'x-svc'; DeviceName = 'PC-0044'; OSPlatform = 'Windows11'; DeviceType = 'Workstation'; MachineGroup = 'Clients'; LastSeen = (Get-Date).ToString('o') }
    )
    $logX = @(1..5 | ForEach-Object { [pscustomobject]@{ DeviceId = 'x-shared'; AccountName = "user$_"; Logons = 1; Last = (Get-Date).ToString('o') } }) + @(
        [pscustomobject]@{ DeviceId = 'x-vdi'; AccountName = 'user6'; Logons = 1; Last = (Get-Date).ToString('o') },
        [pscustomobject]@{ DeviceId = 'x-svc'; AccountName = 'svc-backup'; Logons = 9; Last = (Get-Date).ToString('o') },
        [pscustomobject]@{ DeviceId = 'x-svc'; AccountName = 'kioskUser0'; Logons = 9; Last = (Get-Date).ToString('o') })
    $intX = @([pscustomobject]@{ id = 'i1'; azureADDeviceId = 'aad-kiosk'; userPrincipalName = $null; userId = $null; deviceEnrollmentType = 'windowsAzureADJoinUsingDeviceAuth'; enrollmentProfileName = 'Lobby kiosk'; model = 'OptiPlex'; manufacturer = 'Dell' })
    $mx = Get-GapsioLicensingModel -Skus @() -Users $usersX -Data @{ devices = $devX; logons = $logX; intune = $intX }
    $by = @{}; foreach ($d in $mx.devices) { $by[$d.deviceId] = $d }
    & $A ($by['x-shared'].usage -eq 'Shared' -and $by['x-shared'].distinctUsers -eq 5) 'Usage: 5 distinct people -> Shared'
    & $A ($by['x-kiosk'].usage -eq 'Kiosk' -and $by['x-kiosk'].state -eq 'NoUser') 'Usage: Intune self-deploying enrolment -> Kiosk'
    & $A ($by['x-vdi'].usage -eq 'VDI' -and $by['x-vdi'].state -eq 'Licensed') 'Usage: model "Virtual Machine" -> VDI, still licensed by its user'
    & $A ($by['x-svc'].usage -eq 'Personal' -and $by['x-svc'].state -eq 'NoUser' -and @($by['x-svc'].serviceAccounts).Count -eq 2) 'Service accounts are recorded but not counted as users'
    & $A ($mx.summary.clientsShared -eq 1 -and $mx.summary.clientsKiosk -eq 1 -and $mx.summary.clientsVdi -eq 1 -and $mx.summary.serviceAccounts -eq 2 -and $mx.summary.clientsNoUserPersonal -eq 1) 'Usage summary counters'
    $u1 = $mx.users | Where-Object upn -eq 'user1@contoso.com'; $u6 = $mx.users | Where-Object upn -eq 'user6@contoso.com'
    & $A ($u1.deviceCount -eq 0 -and $u1.sharedDeviceCount -eq 1 -and $u1.state -eq 'InUse') 'Shared device does not count against the per-user limit but keeps the user "in use"'
    & $A ($u6.deviceCount -eq 0 -and $u6.sharedDeviceCount -eq 1) 'VDI device is listed under shared devices for its user'
    & $A (@($mx.findings | Where-Object subject -eq 'clients-shared').Count -eq 1) 'Info finding for shared-like clients'
} ${function:Assert}

Write-Host '== Typographic quotes do not end strings' -ForegroundColor Cyan
# For PowerShell, typographic double quotes are string delimiters: inside a double-quoted string they end it and the
# rest of the text is silently lost (German finding texts were cut off this way). Allowed: in single-quoted strings,
# here-strings and comments, or escaped with a backtick.
$tq = '[' + (-join ([char]0x201C, [char]0x201D, [char]0x201E)) + ']'
$tqBad = @(foreach ($file in Get-ChildItem -Recurse -Filter *.ps1 -Path (Join-Path $root 'src'), (Join-Path $root 'setup'), (Join-Path $root 'build'), (Join-Path $root 'tools')) {
        $text = [IO.File]::ReadAllText($file.FullName)
        if ($text -notmatch $tq) { continue }
        $tokens = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$null)
        # Tokens and matches are both in text order: one pass with a moving token index
        $safe = [System.Collections.Generic.List[object]]::new()
        foreach ($tok in $tokens) { if ($tok.Kind -in 'StringLiteral', 'HereStringLiteral', 'HereStringExpandable', 'Comment') { $safe.Add($tok.Extent) } }
        $si = 0
        foreach ($m in [regex]::Matches($text, $tq)) {
            if ($m.Index -gt 0 -and $text[$m.Index - 1] -eq '`') { continue }
            while ($si -lt $safe.Count -and $safe[$si].EndOffset -le $m.Index) { $si++ }
            if ($si -ge $safe.Count -or $m.Index -lt $safe[$si].StartOffset) { "$($file.Name):$(($text.Substring(0, $m.Index) -split "`n").Count)" }
        }
    })
Assert ($tqBad.Count -eq 0) "Typographic quotes end a double-quoted string in: $(($tqBad | Select-Object -Unique -First 8) -join ', ')"

Write-Host '== Function entry points call exported functions only' -ForegroundColor Cyan
# The Function App scripts (timers, queue, HTTP) import the module and can only call what it exports.
$exported = @((Get-Module Gapsio).ExportedFunctions.Keys)
foreach ($entry in Get-ChildItem (Join-Path $root 'src/functionapp') -Recurse -Filter run.ps1) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($entry.FullName, [ref]$null, [ref]$null)
    $called = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -match '^[A-Za-z]+-Gapsio' } | Sort-Object -Unique)
    $local = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
    $missing = @($called | Where-Object { $_ -notin $exported -and $_ -notin $local })
    Assert ($missing.Count -eq 0) "$($entry.Directory.Name)/run.ps1 calls functions the module does not export: $($missing -join ', ')"
}

Write-Host '== End-to-end: office preview (Defender for Office 365)' -ForegroundColor Cyan
$env:GAPSIO_MODULES = 'endpoint,agents,access,licensing,officepreview'
$ro = Invoke-GapsioOfficePreviewCollection 6>$null
$of = $blobs['state/officepreview-latest.json'] | ConvertFrom-Json -Depth 64
Assert ($of.module -eq 'officepreview' -and $of.schema -eq 4 -and $of.errors -eq 0 -and $of.ok -ge 15 -and $of.warnings.Count -eq 0) "Office snapshot written with change history naming (ok $($of.ok), errors $($of.errors))"
Assert ($of.summary.threatsInInbox -eq 7 -and $of.summary.threatsAllowed -eq 23 -and $of.summary.clickThroughs -eq 9 -and $of.summary.ownDomainSpoofDelivered -eq 3 -and $of.summary.zapActions -eq 38) 'Office summary from the probes'
$offi = @($of.findings)
Assert (@($offi | Where-Object { -not $_.key -or -not $_.fp -or $_.category -ne 'Office' }).Count -eq 0 -and $offi.Count -eq 6) "Office findings carry key and fingerprint like every other finding ($($offi.Count))"
Assert (@($offi | Where-Object { $_.severity -eq 'High' -and $_.title.en -eq '7 message(s) rated phish or malware are still in inboxes' -and $_.detail.de -match 'Posteingang' }).Count -eq 1) 'Finding: threats still in inboxes (High, bilingual)'
Assert (@($offi | Where-Object { $_.severity -eq 'High' -and $_.title.en -like 'Allows let 23 message(s)*' -and $_.detail.en -match 'partner-portal.example \[Organisation\]: 12' -and $_.detail.en -match '8 through the recipient' }).Count -eq 1) 'Finding: allows that delivered threats, organisation and mailbox level kept apart'
Assert (@($offi | Where-Object { $_.title.en -like 'Users clicked through the Safe Links warning 9 time(s)' }).Count -eq 1 -and @($offi | Where-Object { $_.title.en -like '3 message(s) spoofing your own domains were delivered' }).Count -eq 1) 'Findings: Safe Links click-through and own-domain spoofing'
Assert (@($offi | Where-Object { $_.title.en -eq 'Anti-phish protection was weakened' }).Count -eq 1 -and $of.antiphish.changes.Count -eq 2) 'Anti-phish drift is part of the run and its findings are converted'
Assert (@($of.results | Where-Object { $_.key -match 'tabl|overlap|precedence|encrypted|first_contact' }).Count -eq 0) 'Probes on undocumented or misread columns are gone'
Assert (@(($blobs['state/runs.json'] | ConvertFrom-Json) | Where-Object { $_.module -eq 'officepreview' }).Count -eq 1) 'Office run is in the run index'
# A probe that fails is an error – not "no data" – and removes nothing silently
$hunting.OfficeFail = @('threat_in_inbox', 'own_domain_spoof')
$null = Invoke-GapsioOfficePreviewCollection 6>$null
$of2 = $blobs['state/officepreview-latest.json'] | ConvertFrom-Json -Depth 64
Assert ($of2.errors -eq 2 -and @($of2.results | Where-Object { $_.key -eq 'threat_in_inbox' -and $_.status -eq 'error' -and $_.error }).Count -eq 1 -and $null -eq $of2.summary.threatsInInbox) 'Failed probe: status error with text, summary value missing (not 0)'
Assert (@($of2.findings | Where-Object { $_.title.en -match 'still in inboxes|spoofing your own' }).Count -eq 0 -and @($of2.findings).Count -eq 4) 'Failed probe produces no finding'
Assert ($of2.changesSincePrevious -ge 2 -and @(($blobs['state/officepreview-changes.json'] | ConvertFrom-Json) | Where-Object { $_.change -eq 'Removed' }).Count -ge 2) 'Change history records what changed between office runs'
$hunting.OfficeFail = @()
$saved = $env:GAPSIO_FEATURES
try {
    $env:GAPSIO_FEATURES = 'indicators'
    $null = Invoke-GapsioOfficePreviewCollection 6>$null
    $of3 = $blobs['state/officepreview-latest.json'] | ConvertFrom-Json -Depth 64
    Assert ($of3.errors -eq 1 -and $of3.results[0].key -eq 'hunting' -and @($of3.findings).Count -eq 0) 'Office without the Hunting feature: one clear error, no findings'
}
finally { $env:GAPSIO_FEATURES = $saved }
$null = Invoke-GapsioOfficePreviewCollection 6>$null

Write-Host '== API' -ForegroundColor Cyan
Add-Type -TypeDefinition 'public class HttpResponseContext { public object StatusCode; public object Body; public string ContentType; public System.Collections.Hashtable Headers; }' -ErrorAction SilentlyContinue
$script:resp = $null
function global:Push-OutputBinding { param($Name, $Value) $global:GapsioTestResp = $Value }
$env:WEBSITE_AUTH_ENABLED = 'True'
function New-Principal { param([string[]]$Roles, [string]$Oid)
    $claims = @(@{ typ = 'http://schemas.microsoft.com/identity/claims/objectidentifier'; val = $Oid }, @{ typ = 'preferred_username'; val = "$Oid@contoso.com" }, @{ typ = 'name'; val = $Oid })
    $claims += @($Roles | ForEach-Object { @{ typ = 'roles'; val = $_ } })
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{ auth_typ = 'aad'; claims = $claims; role_typ = 'roles' } | ConvertTo-Json -Depth 5)))
}
$api = Join-Path $root 'src/functionapp/Api/run.ps1'
$env:PSModulePath = (Join-Path $root 'src/functionapp/Modules') + [IO.Path]::PathSeparator + $env:PSModulePath
function Call { param($Seg, $Method = 'GET', $Principal, $Query = @{}, $Headers = @{}, $Body)
    $h = @{ 'x-ms-client-principal' = $Principal }; foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
    & $api -Request ([pscustomobject]@{ Params = @{ segments = $Seg }; Method = $Method; Query = $Query; Headers = $h; Body = $Body }) -TriggerMetadata $null
    $global:GapsioTestResp
}
$adminP = New-Principal -Roles 'Gapsio.Admin' -Oid 'u-alice'
$userP = New-Principal -Roles @() -Oid 'u-hank'
$r = Call 'me' -Principal $adminP; Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json).isAdmin) 'api/me Admin'
$r = Call 'endpoint' -Principal $userP; Assert ([int]$r.StatusCode -eq 403) 'Non-admin gets 403 on endpoint'
$r = Call 'endpoint' -Principal $adminP; Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json).module -eq 'endpoint') 'Admin gets endpoint'
$r = Call 'officepreview' -Principal $adminP; Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json -Depth 64).schema -eq 4) 'api/officepreview serves the office snapshot'
$keep = $blobs['state/officepreview-latest.json']; $blobs.Remove('state/officepreview-latest.json'); $blobs['state/office-preview-latest.json'] = '{"version":3,"results":[]}'
$r = Call 'officepreview' -Principal $adminP; Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json).version -eq 3) 'api/officepreview falls back to the earlier file name until the module has run'
$blobs['state/officepreview-latest.json'] = $keep; $blobs.Remove('state/office-preview-latest.json')
$r = Call 'controls' -Principal $userP; Assert ([int]$r.StatusCode -eq 403) 'Non-admin gets 403 on the control mapping'
$r = Call 'controls' -Principal $adminP; $cm = $r.Body | ConvertFrom-Json -Depth 16
Assert ([int]$r.StatusCode -eq 200 -and $cm.source -eq 'default' -and (@($cm.frameworks | ForEach-Object id) -join ',') -eq 'iso27001,nis2' -and $cm.note.de) 'api/controls: shipped control mapping (ISO 27001, NIS2)'
$epCats = @(($blobs['state/endpoint-latest.json'] | ConvertFrom-Json -Depth 64).findings | ForEach-Object { "endpoint:$($_.category)" } | Sort-Object -Unique)
$mapped = @($cm.frameworks | ForEach-Object { $_.controls } | ForEach-Object { $_.match } | Sort-Object -Unique)
Assert (@($epCats | Where-Object { $_ -notin $mapped }).Count -eq 0) "Every endpoint finding category is mapped to a control (missing: $(@($epCats | Where-Object { $_ -notin $mapped }) -join ', '))"
Assert (@($cm.frameworks | ForEach-Object { $_.controls } | Where-Object { -not $_.id -or -not $_.title.en -or -not $_.title.de -or -not @($_.match).Count }).Count -eq 0) 'Every control has an ID, a title in both languages and at least one category'
$r = Call 'devices' -Principal $userP; Assert ([int]$r.StatusCode -eq 403) 'Non-admin gets 403 on devices'
$r = Call 'devices' -Principal $adminP -Query @{ page = '0' }; $pg0 = @($r.Body | ConvertFrom-Json -Depth 64); Assert ([int]$r.StatusCode -eq 200 -and $pg0.Count -eq 5 -and @($pg0 | Where-Object { $_.deviceName -eq 'WIN-01' })[0].checks.TamperProtection) "devices?page=0 returns the stored page ($($pg0.Count))"
$r = Call 'devices' -Principal $adminP -Query @{ page = '7' }; Assert ([int]$r.StatusCode -eq 200 -and $r.Body -eq '[]') 'devices: missing page is an empty list'
$nWin0 = @($ep.devices | Where-Object { $_.deviceName -like 'WIN-0*' }).Count
$r = Call 'devices' -Principal $adminP -Query @{ q = 'win-0' ; size = '1' }; $sr = $r.Body | ConvertFrom-Json -Depth 64
Assert ([int]$r.StatusCode -eq 200 -and $sr.total -eq $nWin0 -and $sr.pages -eq $nWin0 -and @($sr.rows).Count -eq 1 -and $sr.rows[0].checks.TamperProtection -and $null -eq $sr.rows[0].page) "devices search: total=$($sr.total) pages=$($sr.pages) rows=$(@($sr.rows).Count)"
$r = Call 'devices' -Principal $adminP -Query @{ os = 'Windows11'; issues = '1' }; $sr = $r.Body | ConvertFrom-Json -Depth 64; Assert ($sr.total -ge 1 -and @($sr.rows | Where-Object { $_.os -ne 'Windows11' }).Count -eq 0) "devices search: platform + issues filter ($($sr.total))"
$r = Call 'devices' -Principal $adminP -Query @{ chart = 'TamperProtection|off' }; $sr = $r.Body | ConvertFrom-Json -Depth 64; Assert ($sr.total -eq $ep.deviceStats.charts.TamperProtection.off -and @($sr.rows | Where-Object { $_.checks.TamperProtection -ne 'BAD' }).Count -eq 0) "devices search: chart segment filter ($($sr.total))"
$r = Call 'device' -Principal $adminP -Query @{ id = 'd-win1' }; $dv = ($r.Body | ConvertFrom-Json -Depth 64).device; Assert ([int]$r.StatusCode -eq 200 -and $dv.deviceName -eq 'WIN-01' -and $dv.asr) 'device?id= returns the full device from its page'
$r = Call 'device' -Principal $adminP -Query @{ id = 'nope' }; Assert ([int]$r.StatusCode -eq 404) 'device?id= unknown -> 404'
$r = Call 'coverage' -Principal $adminP -Query @{ page = '0' }; Assert ([int]$r.StatusCode -eq 200 -and @($r.Body | ConvertFrom-Json -Depth 64).Count -eq $ep.coveragePages.count) 'coverage?page=0 returns the stored page'
$r = Call 'access/me' -Principal $userP; $m = $r.Body | ConvertFrom-Json
Assert ([int]$r.StatusCode -eq 200 -and @($m.entitlements | Where-Object { $_.state -eq 'Requestable' }).Count -ge 1 -and @($m.audiences).Count -eq 1) 'My access for Hank (requestable + open package)'
$r = Call 'agents' -Principal $adminP; Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json).module -eq 'agents') 'Admin gets agents'
$r = Call 'licensing' -Principal $adminP; Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json).module -eq 'licensing') 'Admin gets licensing'
$r = Call 'licensing' -Principal $userP; Assert ([int]$r.StatusCode -eq 403) 'Non-admin gets 403 on licensing'
$env:GAPSIO_MODULES = 'endpoint,agents,access'
$r = Call 'licensing' -Principal $adminP; Assert ([int]$r.StatusCode -eq 404) 'licensing route is 404 when the module is not enabled'
$env:GAPSIO_MODULES = 'endpoint,agents,access,licensing'
$r = Call 'changes' -Principal $adminP -Query @{ module = 'agents' }; Assert ([int]$r.StatusCode -eq 200) 'changes?module=agents'
$r = Call 'run' -Method 'POST' -Principal $adminP -Query @{ module = 'endpoint' }; Assert ([int]$r.StatusCode -eq 400) 'POST without X-Gapsio is rejected'
$r = Call 'run' -Method 'POST' -Principal $adminP -Query @{ module = 'endpoint' } -Headers @{ 'X-Gapsio' = '1' }; Assert ([int]$r.StatusCode -eq 202 -and $queue.Count -eq 1) 'POST run creates a queue message'
$r = Call 'run' -Method 'POST' -Principal $adminP -Query @{ module = 'endpoint' } -Headers @{ 'X-Gapsio' = '1' }; Assert ([int]$r.StatusCode -eq 202 -and $queue.Count -eq 1 -and ($r.Body | ConvertFrom-Json).queued -eq $false) 'A second run request within two minutes is not queued again'

Write-Host '== Community edition (no licence)' -ForegroundColor Cyan
$r = Call 'me' -Principal $userP; $m = $r.Body | ConvertFrom-Json; Assert ($m.tier -eq 'Community' -and $m.communityRows -eq 10) 'api/me: tier Community with row limit for everyone'
& $mod {
    param($A)
    $items = @(1..25 | ForEach-Object { [pscustomobject]@{ id = "id-$_"; deviceName = "PC-$_"; severity = 'High'; os = 'Windows11'; count = $_; checks = [pscustomobject]@{ TamperProtection = 'GOOD' }; tags = @('a', 'b'); seen = '2026-01-01T00:00:00Z' } })
    $p = @(Protect-GapsioCommunityList -Items $items)
    & $A ($p.Count -eq 25 -and $p[9].deviceName -eq 'PC-10' -and -not $p[9].PSObject.Properties['_masked']) 'Community: first 10 rows untouched'
    $m = $p[10]
    & $A ($m._masked -and $m.deviceName -ne 'PC-11' -and $m.id -ne 'id-11' -and $m.severity -eq 'High' -and $m.os -eq 'Windows11' -and $m.count -eq 11 -and $m.checks.TamperProtection -eq 'GOOD' -and $m.seen -eq '2026-01-01T00:00:00Z' -and @($m.tags)[0] -ne 'a') 'Community: identifiers and tags masked, codes/numbers/dates kept'
    $p2 = @(Protect-GapsioCommunityList -Items $items[10..14] -Offset 10)
    & $A (@($p2 | Where-Object { $_._masked }).Count -eq 5) 'Community: offset counts across pages'
    $snap = [pscustomobject]@{ module = 'x'; summary = [pscustomobject]@{ devices = 25 }; devices = $items; findings = $items[0..2]; warnings = @(1..12 | ForEach-Object { "w$_" }) }
    $c = Protect-GapsioCommunity -Snapshot $snap
    & $A ($c.tier -eq 'Community' -and $c.summary.devices -eq 25 -and @($c.devices | Where-Object { $_._masked }).Count -eq 15 -and @($c.findings | Where-Object { $_._masked }).Count -eq 0 -and $c.warnings[11] -eq 'w12') 'Community snapshot: lists masked beyond 10, summary/warnings complete'
    & $A ((Get-GapsioLicenseTier -License ([pscustomobject]@{ status = 'Expired'; daysLeft = -10 })) -eq 'Full' -and (Get-GapsioLicenseTier -License ([pscustomobject]@{ status = 'Expired'; daysLeft = -40 })) -eq 'Community' -and (Get-GapsioLicenseTier -License ([pscustomobject]@{ status = 'ExpiringSoon' })) -eq 'Full' -and (Get-GapsioLicenseTier -License ([pscustomobject]@{ status = 'WrongTenant' })) -eq 'Community') 'Licence tier: grace period after expiry, otherwise Community'
    & $A ((Get-GapsioLicenseTier -License ([pscustomobject]@{ status = 'Expired'; daysLeft = -6; plan = 'Monthly' })) -eq 'Full' -and (Get-GapsioLicenseTier -License ([pscustomobject]@{ status = 'Expired'; daysLeft = -8; plan = 'Monthly' })) -eq 'Community' -and (Get-GapsioLicenseTier -License ([pscustomobject]@{ status = 'Expired'; daysLeft = -29; plan = 'Annual' })) -eq 'Full') 'Licence tier: 7-day grace for Monthly, 30 days for Annual'
} ${function:Assert}
$r = Call 'endpoint' -Principal $adminP; $cs = $r.Body | ConvertFrom-Json -Depth 64; Assert ($cs.tier -eq 'Community' -and $cs.module -eq 'endpoint' -and $cs.summary) 'api/endpoint: Community snapshot keeps summary'
$r = Call 'devices' -Principal $adminP -Query @{ q = '' ; size = '3'; page = '4' }; $sr = $r.Body | ConvertFrom-Json -Depth 64; Assert ($sr.tier -eq 'Community' -and @($sr.rows | Where-Object { -not $_._masked }).Count -eq 0 -or $sr.total -le 12) "devices search: rows beyond 10 masked in Community ($($sr.total))"

Write-Host '== Licence keys' -ForegroundColor Cyan
$licEc = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
$licPem = Join-Path ([IO.Path]::GetTempPath()) "gapsio-lic-$([guid]::NewGuid().ToString('n')).pem"
Set-Content -Path $licPem -Value $licEc.ExportPkcs8PrivateKeyPem() -NoNewline
$licPub = [Convert]::ToBase64String($licEc.ExportSubjectPublicKeyInfo())
$tenant = '00000000-0000-0000-0000-000000000001'
$licTool = Join-Path $root 'build/New-GapsioLicense.ps1'
$k1 = & $licTool -PrivateKeyPath $licPem -TenantId $tenant -Customer 'Contoso GmbH' -Plan Annual -Months 12 -NoLedger 6>$null
$k2 = & $licTool -PrivateKeyPath $licPem -TenantId '11111111-2222-3333-4444-555555555555' -Customer 'Other' -NoLedger 6>$null
$k3 = & $licTool -PrivateKeyPath $licPem -TenantId $tenant -Customer 'Soon' -Plan Pilot -Expires ([DateTime]::UtcNow.AddDays(10).ToString('yyyy-MM-dd')) -NoLedger 6>$null
Assert ((& $licTool -Inspect $k1).cust -eq 'Contoso GmbH') 'Licence tool: inspect shows the payload'
Remove-Item $licPem -Force
& $mod {
    param($A, $Pub, $K1, $K2, $K3, $Tenant)
    $savedPub = $script:GapsioLicensePublicKey
    $script:GapsioLicensePublicKey = $Pub
    & $A ((Test-GapsioLicenseKey -Key $K1 -TenantId $Tenant).status -eq 'Valid') 'Licence: valid key for this tenant'
    & $A ((Test-GapsioLicenseKey -Key $K1 -TenantId $Tenant.ToUpper()).status -eq 'Valid') 'Licence: tenant id compared case-insensitively'
    & $A ((Test-GapsioLicenseKey -Key $K2 -TenantId $Tenant).status -eq 'WrongTenant') 'Licence: key of another tenant'
    $s3 = Test-GapsioLicenseKey -Key $K3 -TenantId $Tenant
    & $A ($s3.status -eq 'ExpiringSoon' -and $s3.daysLeft -ge 10 -and $s3.daysLeft -le 11 -and $s3.plan -eq 'Pilot') "Licence: expiring soon ($($s3.daysLeft) days)"
    & $A ((Test-GapsioLicenseKey -Key $K1 -TenantId $Tenant -Now ([DateTime]::UtcNow.AddMonths(13))).status -eq 'Expired') 'Licence: expired after the expiry date'
    $p = $K1 -split '\.'
    $forged = [Text.Encoding]::UTF8.GetString((ConvertFrom-GapsioBase64Url $p[1])) -replace 'Contoso GmbH', 'Evil Corp'
    $forgedKey = "GP1.$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($forged)).TrimEnd('=').Replace('+','-').Replace('/','_')).$($p[2])"
    & $A ((Test-GapsioLicenseKey -Key $forgedKey -TenantId $Tenant).status -eq 'Invalid') 'Licence: tampered payload is rejected'
    & $A ((Test-GapsioLicenseKey -Key $K1 -TenantId $Tenant -PublicKey $savedPub).status -eq 'Invalid') 'Licence: key signed by another key is rejected'
    & $A ((Test-GapsioLicenseKey -Key 'garbage' -TenantId $Tenant).status -eq 'Invalid' -and (Test-GapsioLicenseKey -Key '' -TenantId $Tenant).status -eq 'None') 'Licence: garbage invalid, empty none'
} ${function:Assert} $licPub $k1 $k2 $k3 $tenant
$r = Call 'me' -Principal $adminP; Assert (($r.Body | ConvertFrom-Json).license.status -eq 'None') 'api/me: no licence yet'
$r = Call 'license' -Method 'POST' -Principal $adminP -Headers @{ 'X-Gapsio' = '1' } -Body (@{ key = $k2 } | ConvertTo-Json); Assert ([int]$r.StatusCode -eq 400) 'api/license: key of another tenant rejected'
$r = Call 'license' -Method 'POST' -Principal $userP -Headers @{ 'X-Gapsio' = '1' } -Body (@{ key = $k1 } | ConvertTo-Json); Assert ([int]$r.StatusCode -eq 403) 'api/license: non-admin gets 403'
$r = Call 'license' -Method 'POST' -Principal $adminP -Headers @{ 'X-Gapsio' = '1' } -Body (@{ key = $k1 } | ConvertTo-Json); Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json).status -eq 'Valid') 'api/license: valid key stored'
$r = Call 'me' -Principal $adminP; $lm = ($r.Body | ConvertFrom-Json).license; Assert ($lm.status -eq 'Valid' -and $lm.customer -eq 'Contoso GmbH' -and $lm.plan -eq 'Annual') 'api/me: licence summary for admins'
$r = Call 'me' -Principal $userP; $mu = $r.Body | ConvertFrom-Json; Assert ($null -eq $mu.license -and $mu.tier -eq 'Full') 'api/me: no licence details for users, but tier Full'
$r = Call 'endpoint' -Principal $adminP; Assert ($null -eq ($r.Body | ConvertFrom-Json -Depth 64).tier) 'api/endpoint: licensed snapshot is served unchanged'
$r = Call 'license' -Principal $adminP; Assert (($r.Body | ConvertFrom-Json).source -eq 'Portal' -and ($r.Body | ConvertFrom-Json).setBy -eq 'u-alice@contoso.com') 'api/license: source and who set it'
& $mod { param($Pub) $script:GapsioLicensePublicKey = $Pub } $licPub

Write-Host '== Public demo: pseudonymisation' -ForegroundColor Cyan
. (Join-Path $root 'build/Protect-GapsioDemoData.ps1')
$asrGuid = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
$real = @{
    me = @{ upn = 'max.mustermann@fabrikam.de'; tenantId = '11111111-2222-3333-4444-555555555555' }
    endpoint = @{
        devices = @(@{ deviceId = 'aabbccddeeff00112233445566778899aabbccdd'; deviceName = 'DE-MUC-LT-0042.corp.fabrikam.de'; aadDeviceId = '0f0f0f0f-1111-2222-3333-444444444444'; lastUser = 'FABRIKAM\max.mustermann'; deviceGroup = 'Munich Laptops'; avSignatureVersion = '1.421.123.0'; ip = '10.20.30.40' })
        findings = @(@{ title = @{ en = 'Local exclusion on DE-MUC-LT-0042.corp.fabrikam.de'; de = 'Lokale Exclusion auf DE-MUC-LT-0042.corp.fabrikam.de' }; key = 'abcdef0123456789' })
        localExclusions = @(@{ value = 'C:\Users\max.mustermann\AppData\Local\Tool'; addedBy = @{ account = 'max.mustermann@fabrikam.de'; commandLine = 'powershell.exe Add-MpPreference -ExclusionPath C:\Users\max.mustermann\AppData -Server 10.20.30.40' } })
        policyExclusions = @(@{ policyName = 'Fabrikam - Defender AV Windows'; assignments = @('Group: GRP-Fabrikam-Clients', 'All devices'); asrRule = $asrGuid })
        agents = @(@{ name = 'HR Assistant'; publisher = 'fabrikam.onmicrosoft.com'; owner = 'erika.musterfrau@fabrikam.de' })
    }
}
$mp = Protect-GapsioDemoData -Data $real -DenyTerms @('Fabrikam') -KeepGuids @($asrGuid)
$js = $real | ConvertTo-Json -Depth 20 -Compress
$leaks = @(Test-GapsioDemoLeaks -Json $js -Mapper $mp -DenyTerms @('Fabrikam'))
Assert ($leaks.Count -eq 0) "Demo: no leaks after pseudonymisation ($($leaks -join ' | '))"
Assert ($js -notmatch '(?i)fabrikam|mustermann|musterfrau|DE-MUC|10\.20\.30\.40|0f0f0f0f|aabbccddeeff|Munich') "Demo: names, people, IPs and IDs replaced ($js)"
$d0 = $real.endpoint.devices[0]
Assert ($real.endpoint.findings[0].title.en -match [regex]::Escape($d0.deviceName.Split('.')[0])) 'Demo: device name replaced consistently in free text'
Assert ($d0.avSignatureVersion -eq '1.421.123.0' -and $real.endpoint.policyExclusions[0].asrRule -eq $asrGuid -and $real.endpoint.findings[0].key -eq 'abcdef0123456789') 'Demo: versions, Microsoft IDs and keys kept'
Assert ($real.endpoint.localExclusions[0].value -match '^C:\\Users\\user\d+\\AppData' -and $d0.ip -match '^(192\.0\.2|198\.51\.100|203\.0\.113)\.') 'Demo: profile paths and IPs pseudonymised'
Assert (@(Test-GapsioDemoLeaks -Json '{"a":"max@fabrikam.de","b":"10.1.2.3"}' -DenyTerms @('Fabrikam')).Count -ge 3) 'Demo: leak check catches e-mail, IP and deny term'

Write-Host '== Graph v1.0 first with beta fallback' -ForegroundColor Cyan
& $mod {
    param($A)
    $saved = $script:GapsioV1Unavailable.Clone(); $script:GapsioV1Unavailable.Clear()
    $script:v1Calls = [System.Collections.Generic.List[string]]::new()
    function Invoke-GapsioGraph { param($Path, [switch]$Beta, [switch]$All, $Headers)
        $script:v1Calls.Add("$(if ($Beta) { 'beta' } else { 'v1' }):$Path")
        if ($Path -like 'betaonly/*' -and -not $Beta) { throw 'Resource not found for the segment' }
        if ($Path -like 'broken/*') { throw 'Forbidden' }
        @([pscustomobject]@{ id = 'x'; api = $(if ($Beta) { 'beta' } else { 'v1' }) })
    }
    $r = Invoke-GapsioGraphV1First -Path 'stable/items?$select=id' -All -Context 't'
    & $A ($r[0].api -eq 'v1' -and $script:v1Calls.Count -eq 1) 'v1.0 is used when it works'
    $r = Invoke-GapsioGraphV1First -Path 'betaonly/items' -All -Context 't'
    & $A ($r[0].api -eq 'beta') 'Falls back to beta when v1.0 fails'
    $n = $script:v1Calls.Count
    $r = Invoke-GapsioGraphV1First -Path "betaonly/items('abc')/settings" -All -Context 't'
    & $A ($r[0].api -eq 'beta' -and $script:v1Calls.Count -eq $n + 1) 'Fallback is remembered per endpoint (no second v1.0 attempt)'
    Reset-GapsioWarnings
    $r = Invoke-GapsioGraphV1First -Path 'broken/items' -Context 'Broken endpoint'
    & $A ($null -eq $r -and @(Get-GapsioWarnings | Where-Object { $_ -like 'Broken endpoint*' }).Count -eq 1) 'Both failing: $null and one warning'
    Remove-Item function:Invoke-GapsioGraph
    $script:GapsioV1Unavailable.Clear(); foreach ($k in $saved.Keys) { $script:GapsioV1Unavailable[$k] = $saved[$k] }
} ${function:Assert}

Write-Host '== Update rings (unit)' -ForegroundColor Cyan
& $mod {
    param($A)
    $devs = @{}
    1..12 | ForEach-Object { $d = New-GapsioDevice -Id "r$_" -Name "RING-$_" -Os 'Windows11'; $d.avPlatformVersion = '4.18.25090.1'; $devs["r$_"] = $d }
    $sv = { param($id, $v) [pscustomobject]@{ definitionId = "device_vendor_msft_policy_config_defender_$id"; value = "device_vendor_msft_policy_config_defender_${id}_$v"; assignments = @('All devices'); policyId = 'p1'; policyName = 'Ring policy' } }
    $u = @(Get-GapsioUpdateFindings -Devices $devs -SettingValues @())
    & $A (@($u | Where-Object { $_.title.en -eq 'No Defender update rings defined' }).Count -eq 1) 'Rings: none configured with 12 devices'
    $u = @(Get-GapsioUpdateFindings -Devices $devs -SettingValues @((& $sv 'platformupdateschannel' 5), (& $sv 'engineupdateschannel' 6), (& $sv 'securityintelligenceupdateschannel' 5), (& $sv 'disablegradualrelease' 1)))
    & $A (@($u | Where-Object { $_.title.en -match 'without a pilot group' }).Count -eq 1) 'Rings: Broad only -> no pilot'
    & $A (@($u | Where-Object { $_.title.en -match 'Critical' }).Count -eq 1) 'Rings: critical channel flagged'
    & $A (@($u | Where-Object { $_.title.en -match 'Broad channel' }).Count -eq 1) 'Rings: SI broad flagged'
    & $A (@($u | Where-Object { $_.title.en -match 'Gradual release disabled' }).Count -eq 1) 'Rings: gradual release off'
    $u = @(Get-GapsioUpdateFindings -Devices $devs -SettingValues @((& $sv 'platformupdateschannel' 3)))
    & $A (@($u | Where-Object { $_.title.en -match 'rings' }).Count -eq 0) 'Rings: pilot channel present -> no ring finding'
    $devs['r1'].avPlatformVersion = '4.18.24110.1'; $devs['r2'].avPlatformVersion = '4.18.25010.1'; $devs['r3'].avPlatformVersion = '4.18.25050.1'
    $u = @(Get-GapsioUpdateFindings -Devices $devs -SettingValues @())
    & $A (@($u | Where-Object { $_.title.en -match 'supported window' -and $_.severity -eq 'High' -and $_.deviceName -eq 'RING-1' }).Count -eq 1) 'Platform: 10 months behind -> High'
    & $A (@($u | Where-Object { $_.title.en -match 'sprawl' }).Count -eq 1) 'Platform: 4 releases across 12 devices -> sprawl'
} ${function:Assert}

Write-Host '== Inventory hygiene (unit)' -ForegroundColor Cyan
& $mod {
    param($A)
    $devs = @{}
    $mk = { param($id, $name, $os, $grp, $aad, $mb) $d = New-GapsioDevice -Id $id -Name $name -Os $os; $d.deviceGroup = $grp; $d.aadDeviceId = $aad; $d.managedBy = $mb; $devs[$id] = $d }
    & $mk 'a' 'PC-1' 'Windows11' 'Clients' 'aad-1' 'Intune'
    & $mk 'a-old' 'PC-1' 'Windows11' 'Clients' 'aad-1' 'Intune'
    & $mk 'b' 'pc-2.contoso.local' 'Windows11' 'Clients' $null 'MicrosoftDefenderForEndpoint'
    & $mk 'b2' 'PC-2' 'Windows11' 'Clients' $null 'ConfigMgr'
    & $mk 'c' 'KIOSK-1' 'Windows11' 'UnassignedGroup' $null 'Unknown'
    & $mk 'd' 'MAC-1' 'macOS' '' $null 'Unknown'
    $sv = @([pscustomobject]@{ definitionId = 'x'; value = 'x_1'; assignments = @('All'); policyId = 'p'; policyName = 'P' })
    $i = @(Get-GapsioInventoryFindings -Devices $devs -SettingValues $sv -Asr $null)
    & $A (@($i | Where-Object { $_.title.en -eq '2 onboarded device(s) not in any device group' -and $_.detail.en -match 'KIOSK-1' -and $_.detail.en -match 'MAC-1' }).Count -eq 1) 'Inventory: ungrouped (empty + UnassignedGroup)'
    & $A (@($i | Where-Object { $_.title.en -eq 'Duplicate device records: PC-1' }).Count -eq 1) 'Inventory: duplicate by Entra device ID'
    & $A (@($i | Where-Object { $_.title.en -match 'Duplicate device records: pc-2' }).Count -eq 1) 'Inventory: duplicate by short name, case/FQDN-insensitive'
    & $A (@($i | Where-Object { $_.title.en -match 'without a management channel' -and $_.detail.en -match 'KIOSK-1' -and $_.detail.en -notmatch 'MAC-1' }).Count -eq 1) 'Inventory: unmanaged Windows only'
    $devs.Remove('c'); $devs.Remove('d'); $devs.Remove('a-old'); $devs.Remove('b2')
    $i = @(Get-GapsioInventoryFindings -Devices $devs -SettingValues $sv -Asr $null)
    & $A ($i.Count -eq 0) 'Inventory: clean fleet -> nothing'
    $devs['a'].deviceGroup = ''; $devs['b'].deviceGroup = ''
    $i = @(Get-GapsioInventoryFindings -Devices $devs -SettingValues $sv -Asr $null)
    & $A (@($i | Where-Object { $_.title.en -match 'device group' }).Count -eq 0) 'Inventory: no groups used at all -> no ungrouped finding'
} ${function:Assert}

Write-Host '== Response readiness (unit)' -ForegroundColor Cyan
& $mod {
    param($A, $T)
    $act = { param($type, $status, $dev, $daysAgo, $who, $cmds) [pscustomobject]@{ id = [guid]::NewGuid().ToString(); type = $type; status = $status; requestor = $who; deviceId = $dev; deviceName = $dev; at = (& $T $daysAgo); updated = (& $T $daysAgo); commands = @($cmds) } }
    $al = { param($sev, $status, $inv, $dev, $daysAgo) [pscustomobject]@{ id = [guid]::NewGuid().ToString(); title = "Alert on $dev"; severity = $sev; status = $status; investigationState = $inv; deviceId = $dev; deviceName = $dev; at = (& $T $daysAgo); assignedTo = $null } }
    $facts = [pscustomobject]@{
        actions = @(
            (& $act 'Isolate' 'Succeeded' 'PC-ISO' 20 'ir@contoso.com' @()),
            (& $act 'Isolate' 'Succeeded' 'PC-FREED' 20 'ir@contoso.com' @()), (& $act 'Unisolate' 'Succeeded' 'PC-FREED' 15 'ir@contoso.com' @()),
            (& $act 'Isolate' 'Succeeded' 'PC-FRESH' 2 'ir@contoso.com' @()),
            (& $act 'LiveResponse' 'Succeeded' 'PC-LR' 5 'alice@contoso.com' @('GetFile', 'RunScript')),
            (& $act 'RunAntiVirusScan' 'Failed' 'PC-A' 3 'x' @()), (& $act 'RunAntiVirusScan' 'TimeOut' 'PC-B' 3 'x' @()), (& $act 'CollectInvestigationPackage' 'Pending' 'PC-C' 4 'x' @())
        )
        alerts  = @(
            (& $al 'High' 'InProgress' 'PendingApproval' 'PC-WAIT' 3),
            (& $al 'Medium' 'InProgress' 'PendingApproval' 'PC-NEWWAIT' 0),
            (& $al 'High' 'New' 'Benign' 'PC-OLD' 10), (& $al 'Low' 'New' 'Benign' 'PC-LOW' 10), (& $al 'High' 'New' 'Benign' 'PC-RECENT' 2),
            (& $al 'High' 'Resolved' 'Remediated' 'PC-DONE' 10)
        )
    }
    $r = @(Get-GapsioResponseFindings -Facts $facts -WindowsDevices 50)
    & $A (@($r | Where-Object { $_.category -ne 'Response' }).Count -eq 0) 'Response: all findings in category Response'
    & $A (@($r | Where-Object { $_.title.en -eq '1 automated investigation(s) waiting for approval' -and $_.severity -eq 'High' -and $_.detail.en -match 'PC-WAIT' -and $_.detail.en -notmatch 'PC-NEWWAIT' }).Count -eq 1) 'Response: pending approval older than a day only'
    & $A (@($r | Where-Object { $_.title.en -eq '1 alert(s) untouched for 7+ days' -and $_.detail.en -match 'PC-OLD' }).Count -eq 1) 'Response: stale New alerts (Medium+, 7+ days), Low and recent ignored'
    & $A (@($r | Where-Object { $_.title.en -eq 'Device isolated for more than 7 days' }).Count -eq 1 -and @($r | Where-Object { $_.deviceName -eq 'PC-ISO' }).Count -eq 1) 'Response: forgotten isolation only (released and fresh ones ignored)'
    & $A (@($r | Where-Object { $_.title.en -eq '3 response action(s) failed or stuck' }).Count -eq 1) 'Response: failed/timeout/pending counted'
    & $A (@($r | Where-Object { $_.title.en -match 'live response session\(s\) ran or uploaded scripts' -and $_.detail.en -match 'alice@contoso.com' }).Count -eq 1) 'Response: live response with RunScript'
    & $A (@($r | Where-Object { $_.title.en -eq 'Response capabilities never used in 90 days' }).Count -eq 0) 'Response: capabilities were exercised -> no readiness finding'
    $r2 = @(Get-GapsioResponseFindings -Facts ([pscustomobject]@{ actions = @(); alerts = @() }) -WindowsDevices 50)
    & $A ($r2.Count -eq 1 -and $r2[0].title.en -eq 'Response capabilities never used in 90 days') 'Response: nothing in 90 days on 50 devices -> readiness finding'
    & $A (@(Get-GapsioResponseFindings -Facts ([pscustomobject]@{ actions = @(); alerts = @() }) -WindowsDevices 10).Count -eq 0) 'Response: small fleet -> no readiness finding'
    & $A (@(Get-GapsioResponseFindings -Facts $null -WindowsDevices 50).Count -eq 0) 'Response: feature off -> nothing'
} ${function:Assert} ${function:T}

Write-Host '== Permission usage and coverage (unit)' -ForegroundColor Cyan
& $mod {
    param($A, $T)
    $r = Resolve-GapsioXdrPermission -Action 'microsoft.xdr/secops/securitydata/liveresponse-advanced/manage'
    & $A ($r.id -eq 'lr-advanced' -and $r.highImpact) 'Permission catalog: advanced live response, high impact'
    & $A ((Resolve-GapsioXdrPermission -Action 'microsoft.xdr/secops/securitydata/alerts/manage').id -eq 'alerts' -and -not (Resolve-GapsioXdrPermission -Action 'microsoft.xdr/secops/securitydata/alerts/manage').highImpact) 'Permission catalog: alerts (manage), not high impact'
    & $A ((Resolve-GapsioXdrPermission -Action 'microsoft.xdr/configuration/security/read').id -eq 'read') 'Permission catalog: read action'
    & $A ((Resolve-GapsioXdrPermission -Action 'microsoft.xdr/securityposture/posturemanagement/exceptionhandling/manage').id -eq 'posture') 'Permission catalog: posture management'
    $o = Resolve-GapsioXdrPermission -Action 'microsoft.xdr/secops/newthing/manage'
    & $A ($o.id -eq 'other:secops/newthing/manage' -and @($o.requires).Count -eq 0) 'Permission catalog: unknown action gets its own entry without a source'

    $saved = $env:GAPSIO_FEATURES
    try {
        $env:GAPSIO_FEATURES = 'hunting'   # response off -> no MDE calls
        $recs = @(
            [pscustomobject]@{ operation = 'SetAdvancedFeatures'; userPrincipalName = 'carol@contoso.com'; createdDateTime = (& $T 3) },
            [pscustomobject]@{ operation = 'AddIndicator'; userPrincipalName = 'carol@contoso.com'; createdDateTime = (& $T 4) },
            [pscustomobject]@{ operation = 'EditRole'; userPrincipalName = 'carol@contoso.com'; createdDateTime = (& $T 40) }
        )
        $u = Get-GapsioPermissionUsage -AuditRecords $recs -AuditState 'ok' -Days 30
        & $A ($u.sources.actions -eq 'off' -and $u.sources.alerts -eq 'off' -and $u.sources.audit -eq 'ok') 'Permission usage: response off, audit ok'
        & $A (@($u.rows | Where-Object permissionId -eq 'coresettings').Count -eq 1 -and @($u.rows | Where-Object permissionId -eq 'detectiontuning').Count -eq 1 -and @($u.rows | Where-Object permissionId -eq 'authorization').Count -eq 0) 'Permission usage: settings and indicators mapped, 40-day-old record ignored'
        $u2 = Get-GapsioPermissionUsage -AuditRecords $recs -AuditState 'running' -Days 30
        & $A (@($u2.rows).Count -eq 0 -and $u2.sources.audit -eq 'running') 'Permission usage: audit records ignored until the query finished'

        $roles = @([pscustomobject]@{ id = 'r1'; actions = @('microsoft.xdr/configuration/security/manage', 'microsoft.xdr/configuration/authorization/manage', 'microsoft.xdr/secops/securitydata/response/manage', 'microsoft.xdr/secops/securitydata/filecollection/manage') })
        $ent = [pscustomobject]@{ principalId = 'p1'; principalType = 'user'; upn = 'Carol@contoso.com'; displayName = 'Carol'; roleId = 'r1'; role = 'R1'; state = 'Active'; privileged = $true; usage = 'Used'; lastUsed = (& $T 1) }
        $c = @(Get-GapsioPermissionCoverage -Entitlements @($ent) -Roles $roles -Usage $u.rows -Sources $u.sources)
        $by = @{}; foreach ($x in $c) { $by[$x.permissionId] = $x }
        & $A ($c.Count -eq 4 -and $by['coresettings'].status -eq 'Used' -and $by['coresettings'].reason -eq 'activity') 'Coverage: settings change = used (UPN case-insensitive)'
        & $A ($by['authorization'].status -eq 'Unused' -and $by['authorization'].reason -eq 'checked') 'Coverage: audit read, no role change in 30 days = unused'
        & $A ($by['response'].status -eq 'NotMeasurable' -and $by['response'].reason -eq 'off.actions') 'Coverage: response feature off = not measurable, not unused'
        & $A ($by['filecollection'].status -eq 'NotMeasurable' -and $by['filecollection'].reason -eq 'noSource') 'Coverage: no API for file collection = not measurable'
        $c3 = @(Get-GapsioPermissionCoverage -Entitlements @($ent) -Roles $roles -Usage @() -Sources ([pscustomobject]@{ actions = 'ok'; alerts = 'ok'; audit = 'started' }))
        & $A (@($c3 | Where-Object { $_.permissionId -eq 'authorization' -and $_.status -eq 'NotMeasurable' -and $_.reason -eq 'started.audit' }).Count -eq 1) 'Coverage: audit query only started = not measurable yet'
        $c4 = @(Get-GapsioPermissionCoverage -Entitlements @($ent) -Roles $roles -Usage @() -Sources ([pscustomobject]@{ actions = 'failed'; alerts = 'ok'; audit = 'ok' }))
        & $A (@($c4 | Where-Object { $_.permissionId -eq 'response' -and $_.reason -eq 'failed.actions' }).Count -eq 1) 'Coverage: failed source = not measurable'
        $f = @(Get-GapsioPermissionUsageFindings -Coverage $c -Entitlements @($ent))
        & $A ($f.Count -eq 1 -and $f[0].severity -eq 'Medium' -and $f[0].detail.en -match 'Authorization \(manage\)' -and $f[0].detail.en -notmatch 'File collection|Response|Core security') 'Finding lists only provably unused permissions'
        $entR = [pscustomobject]@{ principalId = 'p2'; principalType = 'user'; upn = 'x@contoso.com'; displayName = 'X'; roleId = 'r1'; role = 'R1'; state = 'Eligible'; privileged = $true; usage = 'Used' }
        & $A (@(Get-GapsioPermissionUsageFindings -Coverage @(Get-GapsioPermissionCoverage -Entitlements @($entR) -Roles $roles -Usage @() -Sources $u.sources) -Entitlements @($entR)).Count -eq 0) 'No finding for eligible-only permissions'
    }
    finally { $env:GAPSIO_FEATURES = $saved }

    # Paging: nextLink is followed on Microsoft hosts only (the bearer token must not leave Microsoft)
    $orig = ${function:script:Invoke-GapsioRest}
    try {
        $script:calls = 0
        ${function:script:Invoke-GapsioRest} = { param([string]$Uri, [string]$Resource) $script:calls++; [pscustomobject]@{ value = @([pscustomobject]@{ id = $script:calls }); '@odata.nextLink' = 'https://evil.example.net/api/alerts?$skip=1' } }
        $m = Get-GapsioMdeItems -Path 'alerts' -Context 'Test paging'
        & $A ($m.ok -eq $false -and @($m.items).Count -eq 1 -and $script:calls -eq 1) 'Paging: link to a foreign host is not followed and marks the source failed'
        $script:calls = 0
        ${function:script:Invoke-GapsioRest} = { param([string]$Uri, [string]$Resource) $script:calls++; if ($script:calls -eq 1) { [pscustomobject]@{ value = @(1); '@odata.nextLink' = 'https://api.securitycenter.microsoft.com/api/alerts?$skip=1' } } else { [pscustomobject]@{ value = @(2) } } }
        $m = Get-GapsioMdeItems -Path 'alerts' -Context 'Test paging'
        & $A ($m.ok -and @($m.items).Count -eq 2) 'Paging: Microsoft nextLink followed'
    }
    finally { ${function:script:Invoke-GapsioRest} = $orig }
} ${function:Assert} ${function:T}

Write-Host '== Posture checks (unit)' -ForegroundColor Cyan
& $mod {
    param($A)
    $sv = { param($pol, $def, $val, $assign, $kind = 'choice', $plat = 'Windows') [pscustomobject]@{ policyId = $pol; policyName = "Policy $pol"; platform = $plat; definitionId = $def; value = $val; display = $null; kind = $kind; group = ''; assignments = @($assign) } }
    $asr = 'device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts'
    # No device data: overlap judged by the assignment texts
    $c = @(Get-GapsioPolicyConflicts -SettingValues @((& $sv 'a' $asr "${asr}_block" 'All devices'), (& $sv 'b' $asr "${asr}_audit" 'Group: Pilot')) -Devices @{} -Targets @{})
    & $A ($c.Count -eq 1 -and $c[0].isAsrRule -and $c[0].setting -like 'ASR:*' -and $null -eq $c[0].devices -and $c[0].overlap -eq 'Assignment' -and (@($c[0].values | ForEach-Object value) -join ',') -eq 'audit,block') 'Conflict without device data: ASR rule, "All devices" overlaps every group'
    $cf = @(Get-GapsioPolicyConflictFindings -Conflicts $c)
    & $A ($cf.Count -eq 1 -and $cf[0].detail.en -match 'left out of the merged rule set') 'Conflict finding explains the ASR merge behaviour'
    & $A (@(Get-GapsioPolicyConflicts -SettingValues @((& $sv 'a' $asr "${asr}_block" 'Group: Ring 1'), (& $sv 'b' $asr "${asr}_audit" 'Group: Ring 2')) -Devices @{} -Targets @{}).Count -eq 0) 'Different groups (rings): no conflict'
    & $A (@(Get-GapsioPolicyConflicts -SettingValues @((& $sv 'a' $asr "${asr}_block" 'All devices'), (& $sv 'b' $asr "${asr}_audit" 'Excluded: Servers')) -Devices @{} -Targets @{}).Count -eq 0) 'A policy with only an exclusion group is not assigned: no conflict'
    & $A (@(Get-GapsioPolicyConflicts -SettingValues @((& $sv 'a' 'x_excl' 'C:\a' 'All devices' 'simple'), (& $sv 'b' 'x_excl' 'C:\b' 'All devices' 'simple')) -Devices @{} -Targets @{}).Count -eq 0) 'Text values (lists such as exclusions) are not compared'
    & $A (@(Get-GapsioPolicyConflicts -SettingValues @((& $sv 'a' 'x_n' '1' 'All devices' 'simple'), (& $sv 'a' 'x_n' '2' 'All devices' 'simple'), (& $sv 'b' 'x_n' '3' 'All devices' 'simple')) -Devices @{} -Targets @{}).Count -eq 0) 'A setting repeated inside one policy is a list entry and ignored'
    & $A (@(Get-GapsioPolicyConflicts -SettingValues @((& $sv 'a' 'x_n' '1' 'All devices' 'simple' 'Windows'), (& $sv 'b' 'x_n' '2' 'All devices' 'simple' 'macOS')) -Devices @{} -Targets @{}).Count -eq 0) 'Different platforms never conflict'
    # With devices: the policies must reach the same device
    $devs = @{ d1 = @{ deviceId = 'd1'; deviceName = 'PC-1'; os = 'Windows11'; aadDeviceId = $null; lastUser = $null; clientVersion = '10.8470.1.1' }; d2 = @{ deviceId = 'd2'; deviceName = 'MAC-1'; os = 'macOS'; aadDeviceId = $null; lastUser = $null; clientVersion = '101.25' } }
    $all = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } })
    $c2 = @(Get-GapsioPolicyConflicts -SettingValues @((& $sv 'a' 'x_n' '1' 'All devices' 'simple'), (& $sv 'b' 'x_n' '2' 'All devices' 'simple')) -Devices $devs -Targets @{ a = $all; b = $all })
    & $A ($c2.Count -eq 1 -and $c2[0].devices -eq 1 -and $c2[0].deviceNames[0] -eq 'PC-1') 'Conflict with device data counts Windows devices only for a Windows policy'

    # Attack disruption: version comparison and "not measurable"
    $saved = $env:GAPSIO_FEATURES
    try {
        $env:GAPSIO_FEATURES = 'indicators'
        $r = Get-GapsioDisruptionReadiness -Devices $devs -Coverage @()
        & $A (@($r.checks | Where-Object { $_.status -eq 'NotMeasurable' }).Count -eq 6 -and $r.eventsStatus -eq 'off' -and @(Get-GapsioDisruptionFindings -Readiness $r).Count -eq 0) 'Disruption without Hunting: nothing is claimed'
        & $A ($null -eq (Get-GapsioDetectionRules)) 'Detection rules: feature off returns nothing'
        $dc = Get-GapsioDeviceControl -SettingValues @() -Devices $devs -Targets @{}
        & $A ($dc.usage -eq 'off' -and @(Get-GapsioDeviceControlFindings -DeviceControl $dc).Count -eq 0) 'Device control without Hunting: no usage data, no finding'
    }
    finally { $env:GAPSIO_FEATURES = $saved }
    $script:Hunt.MdiMissing = $true
    try {
        $r = Get-GapsioDisruptionReadiness -Devices $devs -Coverage @()
        & $A (@($r.checks | Where-Object id -eq 'sense')[0].status -eq 'OK' -and @($r.checks | Where-Object id -eq 'sense')[0].total -eq 1) 'Sense 10.8470.x meets the minimum; macOS agent versions are not compared'
        & $A (@($r.checks | Where-Object id -eq 'mdi')[0].status -eq 'Review' -and @(Get-GapsioWarnings | Where-Object { $_ -match 'IdentityDirectoryEvents' }).Count -eq 0) 'Missing Defender for Identity table: "review", not a run warning'
    }
    finally { $script:Hunt.MdiMissing = $false }
    # A device that only the configuration assessment still lists (no DeviceInfo in the lookback) is "not reporting"
    $savedTvm = $script:Hunt.Tvm
    $script:Hunt.Tvm = @($savedTvm) + [pscustomobject]@{ DeviceId = 'd-old1'; DeviceName = 'OLD-01'; OSPlatform = 'Windows11'; ConfigurationId = 'scid-91'; IsApplicable = $true; IsCompliant = $false }
    try {
        $ds = Get-GapsioDeviceStates
        & $A ($ds['d-old1'].reporting -eq $false -and $ds['d-win1'].reporting -eq $true -and -not $ds['d-old1'].lastSeen) 'Device listed by the configuration assessment only is not reporting; devices with DeviceInfo are'
        $cv = @(Get-GapsioCoverage -Devices $ds)
        & $A (@($cv | Where-Object { $_.deviceId -eq 'd-old1' -and $_.status -eq 'SensorInactive' }).Count -eq 1 -and $ds['d-old1'].lastSeen) 'Not reporting device is a coverage gap (once) and gets its last report time from the 30-day view'
        $fs = @((New-GapsioFinding -Severity 'High' -Category 'Device' -Title (New-GapsioText 'x' 'x') -Detail (New-GapsioText 'x' 'x') -Recommendation (New-GapsioText 'x' 'x') -Subject 'bm' -DeviceId 'd-old1' -DeviceName 'OLD-01'),
            (New-GapsioFinding -Severity 'High' -Category 'Device' -Title (New-GapsioText 'x' 'x') -Detail (New-GapsioText 'x' 'x') -Recommendation (New-GapsioText 'x' 'x') -Subject 'bm' -DeviceId 'd-win1' -DeviceName 'WIN-01'),
            (New-GapsioFinding -Severity 'High' -Category 'Baseline' -Title (New-GapsioText 'x' 'x') -Detail (New-GapsioText 'x' 'x') -Recommendation (New-GapsioText 'x' 'x') -Subject 'b'))
        Set-GapsioStaleFindings -Findings $fs -Devices $ds
        & $A ($fs[0].stale -eq $true -and -not $fs[1].PSObject.Properties['stale'] -and -not $fs[2].PSObject.Properties['stale'] -and $fs[0].severity -eq 'High') 'Findings of a not reporting device are marked as last known state, severity unchanged'
        $only = @{ 'd-old1' = $ds['d-old1'] }
        $r = Get-GapsioDisruptionReadiness -Devices $only -Coverage @()
        & $A (@($r.checks | Where-Object id -eq 'sense')[0].status -eq 'NotMeasurable' -and @($r.checks | Where-Object id -eq 'sense')[0].detail.en -match 'None of the 1 Windows device\(s\) reported in the last 7 days' -and @($r.checks | Where-Object id -eq 'sense')[0].detail.de -match 'Keines der 1 Windows') 'Sense check says why it cannot be measured'
        $script:Hunt.DeviceInfoFail = $true
        $before = @(Get-GapsioWarnings).Count
        $ds2 = Get-GapsioDeviceStates 3>$null
        & $A (@($ds2.Values | Where-Object { $null -ne $_.reporting }).Count -eq 0 -and $ds2.ContainsKey('d-old1') -and @(Get-GapsioWarnings).Count -gt $before) 'DeviceInfo did not answer: no device is called not reporting'
        & $A (@(Get-GapsioCoverage -Devices $ds2 | Where-Object { $_.deviceId -eq 'd-old1' }).Count -eq 0) 'DeviceInfo did not answer: no coverage gap is claimed for listed devices'
    }
    finally { $script:Hunt.Tvm = $savedTvm; $script:Hunt.DeviceInfoFail = $false }
    # Device control is not supported on servers: USB use there is listed but not a finding
    $dcs = [pscustomobject]@{ usage = 'ok'; summary = @{ assignedPolicies = 0 }; devices = @([pscustomobject]@{ deviceName = 'SRV-1'; mounts = 4; hasPolicy = $false; supported = $false }) }
    & $A (@(Get-GapsioDeviceControlFindings -DeviceControl $dcs).Count -eq 0) 'USB on a server: no device control finding'
    $dcc = [pscustomobject]@{ usage = 'ok'; summary = @{ assignedPolicies = 0 }; devices = @([pscustomobject]@{ deviceName = 'PC-1'; mounts = 4; hasPolicy = $false; supported = $true }) }
    & $A (@(Get-GapsioDeviceControlFindings -DeviceControl $dcc)[0].detail.en -match 'No such policy is assigned in Intune at all') 'No device control policy at all is called out'
    & $A (@(Get-GapsioDetectionRuleFindings -Detections ([pscustomobject]@{ status = 'failed'; rules = @() })).Count -eq 0) 'Detection rules could not be read: no findings'
} ${function:Assert}

Write-Host '== macOS/Linux platform (unit)' -ForegroundColor Cyan
& $mod {
    param($A)
    $devs = @{}
    $mk = { param($id, $os, $ver, $mb, $checks) $d = New-GapsioDevice -Id $id -Name $id -Os $os; $d.agentVersion = $ver; $d.managedBy = $mb; foreach ($k in $checks.Keys) { $d.checks[$k] = $checks[$k] }; $devs[$id] = $d }
    & $mk 'MAC-A' 'macOS' '101.2510.0001' 'Intune' @{ FullDiskAccess = 'GOOD'; SystemExtensions = 'GOOD' }
    & $mk 'MAC-B' 'macOS' '101.2503.0002' 'Jamf' @{ FullDiskAccess = 'BAD'; SystemExtensions = 'GOOD' }
    & $mk 'MAC-C' 'macOS' '101.2509.0001' 'Jamf' @{ FullDiskAccess = 'GOOD'; SystemExtensions = 'BAD' }
    & $mk 'LNX-A' 'Linux' '101.2509.0000' $null @{}
    & $mk 'LNX-B' 'Linux' '101.2406.0000' $null @{}
    & $mk 'WIN-A' 'Windows11' $null 'Intune' @{}
    $pols = @([pscustomobject]@{ id = 'p1'; name = 'Mac AV'; platforms = 'macOS' })
    $r = @(Get-GapsioPlatformFindings -Devices $devs -Policies $pols)
    & $A (@($r | Where-Object { $_.category -ne 'Platform' }).Count -eq 0) 'Platform: all findings in category Platform'
    & $A (@($r | Where-Object { $_.title.en -eq 'Defender on macOS without Full Disk Access' -and $_.deviceName -eq 'MAC-B' -and $_.severity -eq 'High' }).Count -eq 1) 'Platform: Full Disk Access missing on MAC-B only'
    & $A (@($r | Where-Object { $_.title.en -match 'system extensions not approved' -and $_.deviceName -eq 'MAC-C' }).Count -eq 1) 'Platform: system extensions on MAC-C only'
    & $A (@($r | Where-Object { $_.title.en -eq '1 macOS device(s) with a Defender agent 6+ months behind' -and $_.detail.en -match 'MAC-B \(101.2503.0002\)' -and $_.detail.en -match '101.2510.0001' }).Count -eq 1) 'Platform: macOS agent 7 months behind newest'
    & $A (@($r | Where-Object { $_.title.en -eq '1 Linux device(s) with a Defender agent 6+ months behind' -and $_.detail.en -match 'auditd' }).Count -eq 1) 'Platform: Linux agent old, auditd note for < 101.2408'
    & $A (@($r | Where-Object { $_.title.en -eq '2 Linux device(s) without an Intune Defender policy' -and $_.severity -eq 'Medium' -and $_.detail.en -match 'mdatp_managed.json' }).Count -eq 1) 'Platform: Linux without policy'
    & $A (@($r | Where-Object { $_.title.en -match 'macOS device\(s\) without an Intune Defender policy' }).Count -eq 0) 'Platform: macOS has a policy -> no finding'
    $r2 = @(Get-GapsioPlatformFindings -Devices $devs -Policies @())
    $m = @($r2 | Where-Object { $_.title.en -eq '3 macOS device(s) without an Intune Defender policy' })
    & $A ($m.Count -eq 1 -and $m[0].severity -eq 'Medium' -and $m[0].detail.en -match '2 of them are managed outside Intune \(Jamf\)') 'Platform: macOS without policy, mixed management -> Medium with Jamf note'
    $devs['MAC-A'].managedBy = 'Jamf'
    $r3 = @(Get-GapsioPlatformFindings -Devices $devs -Policies @())
    & $A (@($r3 | Where-Object { $_.title.en -eq '3 macOS device(s) without an Intune Defender policy' -and $_.severity -eq 'Low' }).Count -eq 1) 'Platform: all Macs on Jamf -> Low'
    & $A (@(Get-GapsioPlatformFindings -Devices @{ w = $devs['WIN-A'] } -Policies @()).Count -eq 0) 'Platform: Windows-only fleet -> nothing'
} ${function:Assert}

Write-Host '== Versions and update check' -ForegroundColor Cyan
& $mod {
    param($A)
    & $A ((Get-GapsioVersion) -eq (Get-Module Gapsio).Version.ToString()) 'Get-GapsioVersion = ModuleVersion of Gapsio.psd1'
    & $A ((Compare-GapsioVersion 'v0.10.0' '0.9.3') -eq 1 -and (Compare-GapsioVersion '0.4.0' 'v0.4.0') -eq 0 -and (Compare-GapsioVersion '0.4.0-rc.1' '0.4.1') -eq -1) 'Compare-GapsioVersion handles v prefix, numeric order and pre-release suffix'
    $env:GAPSIO_UPDATE_CHECK = $null; $env:GAPSIO_UPDATE_REPOSITORY = 'OWNER/gapsio'
    & $A ($null -eq (Update-GapsioReleaseInfo -Force)) 'Update check skipped while the repository is a placeholder'
    $env:GAPSIO_UPDATE_REPOSITORY = 'contoso/gapsio'; $env:GAPSIO_UPDATE_CHECK = 'false'
    & $A ($null -eq (Update-GapsioReleaseInfo -Force)) 'GAPSIO_UPDATE_CHECK=false disables the update check'
    $env:GAPSIO_UPDATE_CHECK = $null
    $script:ghCalls = 0
    function Invoke-RestMethod { param($Uri, $Headers, $TimeoutSec) $script:ghCalls++; [pscustomobject]@{ tag_name = 'v9.9.9'; html_url = 'https://github.com/contoso/gapsio/releases/tag/v9.9.9'; published_at = '2026-11-01T00:00:00Z'; uri = $Uri } }
    $u = Update-GapsioReleaseInfo -Force
    & $A ($u.available -and $u.latest -eq '9.9.9' -and $u.current -eq (Get-GapsioVersion)) "Newer release detected ($($u.latest))"
    $u2 = Update-GapsioReleaseInfo
    & $A ($script:ghCalls -eq 1 -and $u2.latest -eq '9.9.9') 'Release info is cached for a day (no second GitHub call)'
    Remove-Item function:Invoke-RestMethod
    $env:GAPSIO_UPDATE_REPOSITORY = $null; $env:GAPSIO_UPDATE_CHECK = 'false'
} ${function:Assert}
$r = Call 'me' -Principal $adminP; $me = $r.Body | ConvertFrom-Json
Assert ($me.version -and $me.update.available -and $me.update.latest -eq '9.9.9') 'api/me returns version and update info for admins'
$r = Call 'me' -Principal $userP; $me = $r.Body | ConvertFrom-Json
Assert ($null -eq $me.update) 'api/me hides update info from non-admins'
$tmpZip = Join-Path ([IO.Path]::GetTempPath()) "gapsio-pkg-$([guid]::NewGuid().ToString('n')).zip"
& (Join-Path $root 'build/New-GapsioPackage.ps1') -OutFile $tmpZip 6>$null | Out-Null
Assert ((Get-GapsioPackageVersion -Path $tmpZip) -eq (Import-PowerShellDataFile (Join-Path $root 'src/functionapp/Modules/Gapsio/Gapsio.psd1')).ModuleVersion) 'Get-GapsioPackageVersion reads the version from the function package'
Remove-Item $tmpZip -Force
$exp = [DateTime]::UtcNow.AddDays(14).ToString('yyyy-MM-dd')
$r = Call 'acceptances' -Method 'POST' -Principal $adminP -Body (@{ key = 'abcd1234'; kind = 'exclusion'; module = 'endpoint'; title = 'powershell.exe'; justification = 'Required by the build agent until Q3'; owner = 'Build team'; expires = $exp } | ConvertTo-Json)
Assert ([int]$r.StatusCode -eq 400) 'POST acceptances without X-Gapsio is rejected'
$r = Call 'acceptances' -Method 'POST' -Principal $userP -Headers @{ 'X-Gapsio' = '1' } -Body '{}'
Assert ([int]$r.StatusCode -eq 403) 'Non-admin cannot accept risks'
$r = Call 'acceptances' -Method 'POST' -Principal $adminP -Headers @{ 'X-Gapsio' = '1' } -Body (@{ key = 'abcd1234'; kind = 'exclusion'; module = 'endpoint'; title = 'powershell.exe'; justification = 'Required by the build agent until Q3'; owner = 'Build team'; expires = $exp } | ConvertTo-Json)
Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json).acceptance.acceptedBy -eq 'u-alice@contoso.com') "POST acceptances stores the acceptance ($($r.StatusCode))"
$r = Call 'acceptances' -Method 'POST' -Principal $adminP -Headers @{ 'X-Gapsio' = '1' } -Body '{"key":"abcd1234","justification":"x","owner":"y","expires":"2099-01-01"}'
Assert ([int]$r.StatusCode -eq 400) 'Invalid acceptance -> 400'
$r = Call 'acceptances' -Principal $adminP; $acc = ($r.Body | ConvertFrom-Json).acceptances
Assert (@($acc | Where-Object { $_.key -eq 'abcd1234' -and $_.active }).Count -eq 1) 'GET acceptances with active flag'
$r = Call 'acceptances/revoke' -Method 'POST' -Principal $adminP -Headers @{ 'X-Gapsio' = '1' } -Body '{"key":"abcd1234"}'
$r = Call 'acceptances' -Principal $adminP; $acc = ($r.Body | ConvertFrom-Json).acceptances
Assert (@($acc | Where-Object { $_.key -eq 'abcd1234' -and -not $_.active -and $_.revokedBy }).Count -eq 1) 'Revoke via API'
$r = Call 'acceptances' -Method 'POST' -Principal $adminP -Headers @{ 'X-Gapsio' = '1' } -Body (@{ key = 'abcd1234'; kind = 'exclusion'; module = 'endpoint'; title = 'powershell.exe'; justification = 'Permanent: signed build tooling'; owner = 'Build team'; expires = $null } | ConvertTo-Json)
Assert ([int]$r.StatusCode -eq 200 -and $null -eq ($r.Body | ConvertFrom-Json).acceptance.expires) 'POST acceptances: unlimited exception (expires null)'
$r = Call 'acceptances' -Principal $adminP; $acc = ($r.Body | ConvertFrom-Json).acceptances
Assert (@($acc | Where-Object { $_.key -eq 'abcd1234' -and $_.active -and $null -eq $_.expires }).Count -eq 1) 'GET acceptances: unlimited exception is active'
$r = Call 'directory/search' -Principal $userP -Query @{ q = 'Ali' }; Assert ([int]$r.StatusCode -eq 403) 'directory/search: admins only'
$r = Call 'directory/search' -Principal $adminP -Query @{ q = 'Ali' }; $ds = $r.Body | ConvertFrom-Json
Assert ([int]$r.StatusCode -eq 200 -and @($ds.results).Count -eq 1 -and $ds.results[0].type -eq 'user' -and $ds.results[0].mail -eq 'alice@contoso.com') "directory/search finds Alice ($($r.Body))"
$r = Call 'directory/search' -Principal $adminP -Query @{ q = 'Helpdesk' }; $ds = $r.Body | ConvertFrom-Json
Assert (@($ds.results).Count -eq 2 -and @($ds.results | Where-Object { $_.type -eq 'group' }).Count -eq 2) 'directory/search finds groups'
$r = Call 'assignments' -Method 'POST' -Principal $adminP -Body '{"key":"abcd1234","assignee":{"type":"email","mail":"ops@contoso.com"}}'
Assert ([int]$r.StatusCode -eq 400) 'POST assignments without X-Gapsio is rejected'
$r = Call 'assignments' -Method 'POST' -Principal $userP -Headers @{ 'X-Gapsio' = '1' } -Body '{}'; Assert ([int]$r.StatusCode -eq 403) 'Non-admin cannot assign'
$r = Call 'assignments' -Method 'POST' -Principal $adminP -Headers @{ 'X-Gapsio' = '1' } -Body (@{ key = 'abcd1234'; kind = 'exclusion'; module = 'endpoint'; title = 'powershell.exe'; assignee = @{ type = 'group'; id = 'g1'; displayName = 'Helpdesk-Team' }; note = 'Review' } | ConvertTo-Json)
Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json).assignment.assignee.type -eq 'group' -and ($r.Body | ConvertFrom-Json).assignment.assignedBy -eq 'u-alice@contoso.com') "POST assignments stores the assignment ($($r.Body))"
$r = Call 'assignments' -Method 'POST' -Principal $adminP -Headers @{ 'X-Gapsio' = '1' } -Body '{"key":"abcd1234","assignee":{"type":"email","mail":"nope"}}'; Assert ([int]$r.StatusCode -eq 400) 'Invalid assignee -> 400'
$r = Call 'assignments' -Principal $adminP; Assert (@(($r.Body | ConvertFrom-Json).assignments | Where-Object { $_.key -eq 'abcd1234' }).Count -eq 1) 'GET assignments'
$r = Call 'assignments/clear' -Method 'POST' -Principal $adminP -Headers @{ 'X-Gapsio' = '1' } -Body '{"key":"abcd1234"}'
$r = Call 'assignments' -Principal $adminP; Assert ([int]$r.StatusCode -eq 200 -and @(($r.Body | ConvertFrom-Json).assignments | Where-Object { $_.key -eq 'abcd1234' }).Count -eq 0) 'Clear assignment via API'
$r = Call 'acceptances/log' -Principal $adminP; $lg = $r.Body | ConvertFrom-Json
Assert ($lg[0].action -eq 'unassign' -and $lg[1].action -eq 'assign' -and $lg[1].assignee.displayName -eq 'Helpdesk-Team') 'Audit log via API includes assign/unassign'
$env:GAPSIO_MODULES = $null
$r = Call 'access' -Principal $adminP; Assert ([int]$r.StatusCode -eq 404) 'Default: access module off -> 404'
$r = Call 'access/me' -Principal $userP; Assert ([int]$r.StatusCode -eq 404) 'Default: my access off -> 404'
$r = Call 'me' -Principal $adminP; $me = $r.Body | ConvertFrom-Json; Assert ((@($me.modules) -join ',') -eq 'endpoint,agents') "Default modules endpoint,agents, is $(@($me.modules) -join ',')"
$queue.Clear(); $r = Call 'run' -Method 'POST' -Principal $adminP -Query @{ module = 'access' } -Headers @{ 'X-Gapsio' = '1' }; $qm = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(([xml]$queue[0]).QueueMessage.MessageText)) | ConvertFrom-Json; Assert ($qm.module -eq 'all') 'Disabled module becomes all'
$histBefore = @($blobs['state/endpoint-changes.json'] | ConvertFrom-Json -Depth 64).Count
$res = Invoke-GapsioCollection -Module 'all' 6>$null 3>$null; Assert ((@($res | ForEach-Object module) -join ',') -eq 'endpoint,agents') "all = enabled modules only, is $(@($res | ForEach-Object module) -join ',')"
$histAfter = @($blobs['state/endpoint-changes.json'] | ConvertFrom-Json -Depth 64).Count
Assert ($histBefore -ge 2 -and $histAfter -ge $histBefore) "Change history survives further runs regardless of culture ($histBefore -> $histAfter, culture $([Globalization.CultureInfo]::CurrentCulture.Name))"
& $mod {
    param($A)
    $saved = [Globalization.CultureInfo]::CurrentCulture
    [Globalization.CultureInfo]::CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('de-DE')
    try {
        $dt = ('{"at":"2026-10-30T22:47:14.0000000Z"}' | ConvertFrom-Json).at
        & $A ($dt -is [datetime] -and (ConvertTo-GapsioUtc $dt).Hour -eq 22) 'ConvertTo-GapsioUtc: deserialized DateTime kept as UTC under de-DE'
        & $A ((ConvertTo-GapsioUtc '2026-10-30').Day -eq 30 -and (Test-GapsioAcceptanceActive ([pscustomobject]@{ expires = '2099-10-30' }))) 'ConvertTo-GapsioUtc / acceptance expiry: ISO date culture-independent'
    }
    finally { [Globalization.CultureInfo]::CurrentCulture = $saved }
} ${function:Assert}
# Findings rollup: the same per-device finding on more devices than the threshold becomes one finding
& $mod {
    param($A)
    $many = @(1..250 | ForEach-Object { New-GapsioFinding -Severity 'High' -Category 'Device' -Title (New-GapsioText "Tamper Protection off on PC-$_" "Tamper Protection aus auf PC-$_") -Detail (New-GapsioText "PC-$_ reports BAD." "PC-$_ meldet BAD.") -Recommendation (New-GapsioText 'Fix' 'Beheben') -Subject 'tamper-off' -DeviceId "d$_" -DeviceName "PC-$_" })
    $few = @(1..3 | ForEach-Object { New-GapsioFinding -Severity 'Medium' -Category 'Device' -Title (New-GapsioText "Local exclusion on PC-$_" "Lokale Exclusion auf PC-$_") -Detail (New-GapsioText 'x' 'x') -DeviceId "d$_" -DeviceName "PC-$_" })
    $global = New-GapsioFinding -Severity 'Critical' -Category 'Policy' -Title (New-GapsioText 'Cloud protection off' 'Cloud-Schutz aus') -Detail (New-GapsioText 'x' 'x')
    $m = @(Merge-GapsioDeviceFindings -Findings ($many + $few + @($global)) -Threshold 200)
    $roll = @($m | Where-Object { $_.deviceCount })
    & $A ($m.Count -eq 5 -and $roll.Count -eq 1 -and $roll[0].deviceCount -eq 250 -and @($roll[0].deviceSample).Count -eq 25) "Rollup: 250 + 3 + 1 findings -> 5 (rolled $($roll.Count), count $($roll[0].deviceCount))"
    & $A ($roll[0].title.en -eq 'Tamper Protection off on 250 devices' -and $roll[0].title.de -eq 'Tamper Protection aus auf 250 Geräten' -and $roll[0].severity -eq 'High' -and -not $roll[0].deviceId) "Rollup: title with device count ($($roll[0].title.en))"
    & $A ($roll[0].detail.en -match '250 devices are affected' -and $roll[0].detail.en -match 'and 225 more') 'Rollup: detail with sample and remainder'
    $m2 = @(Merge-GapsioDeviceFindings -Findings ($many + $few + @($global)) -Threshold 300)
    & $A ($m2.Count -eq 254 -and $m2[0].severity -eq 'Critical') 'Rollup: below the threshold findings stay per device (sorted by severity)'
    $k1 = $roll[0].key; $m3 = @(Merge-GapsioDeviceFindings -Findings ($many | Select-Object -First 220) -Threshold 200); & $A ($m3[0].key -eq $k1 -and $m3[0].fp -ne $roll[0].fp) 'Rollup: stable key, fingerprint follows the count'
} ${function:Assert}
# Paged collections: pages of GAPSIO_PAGE_SIZE, index, fingerprints, stale pages removed
& $mod {
    param($A)
    $env:GAPSIO_PAGE_SIZE = '2000'
    $items = @(1..4500 | ForEach-Object { [pscustomobject]@{ deviceId = "x$_"; deviceName = "PC-$('{0:D5}' -f $_)"; key = "k$_"; fp = "f$_"; checks = [ordered]@{ A = 'GOOD'; B = 'BAD' }; lastSeen = [datetime]::new(2026, 1, 2, 3, 4, 5, [DateTimeKind]::Utc) } })
    $m = Write-GapsioPagedCollection -Module 'unit' -Name 'devices' -Items $items -IndexColumns @('deviceId', 'deviceName', 'checks', 'lastSeen') -At 't1'
    & $A ($m.pages -eq 3 -and $m.count -eq 4500 -and $script:Blobs.ContainsKey('state/unit-devices/0002.json') -and @($script:Blobs['state/unit-devices/0002.json'] | ConvertFrom-Json).Count -eq 500) "Paged: 4500 items -> 3 pages (pages=$($m.pages))"
    $idx = @(Get-GapsioPagedIndex -Module 'unit' -Name 'devices')
    & $A ($idx.Count -eq 4500 -and $idx[2100].page -eq '1' -and $idx[0].checks -eq 'A=GOOD;B=BAD' -and $idx[0].lastSeen -eq '2026-01-02T03:04:05.0000000Z') "Paged: index rows with page and flattened values ($($idx.Count), page=$($idx[2100].page))"
    $one = Get-GapsioPagedItem -Module 'unit' -Name 'devices' -Property 'deviceId' -Value 'x4321'
    & $A ($one.deviceName -eq 'PC-04321') 'Paged: item lookup via index'
    & $A (@($script:Blobs['state/unit-devices-fp.json'] | ConvertFrom-Json).Count -eq 4500) 'Paged: fingerprint list'
    $m2 = Write-GapsioPagedCollection -Module 'unit' -Name 'devices' -Items @($items | Select-Object -First 10) -IndexColumns @('deviceId') -At 't2'
    & $A ($m2.pages -eq 1 -and -not $script:Blobs.ContainsKey('state/unit-devices/0001.json') -and -not $script:Blobs.ContainsKey('state/unit-devices/0002.json')) 'Paged: stale pages of the previous run removed'
    & $A (@(Get-GapsioPagedIndex -Module 'unit' -Name 'devices').Count -eq 10) 'Paged: index cache refreshed by snapshot time'
    $m3 = Write-GapsioPagedCollection -Module 'unit' -Name 'empty' -Items @() -At 't3'
    & $A ($m3.pages -eq 0 -and $m3.count -eq 0 -and @(Get-GapsioPagedCollection -Module 'unit' -Name 'empty').Count -eq 0) 'Paged: empty collection'
    $env:GAPSIO_PAGE_SIZE = $null
} ${function:Assert}
# Advanced Hunting sharding: result sets at the 100k-row limit are counted and re-run in hash shards
& $mod {
    param($A)
    $calls = [System.Collections.Generic.List[string]]::new()
    $script:GapsioHuntingRowLimit = 1000
    $orig = ${function:Invoke-GapsioHunting}
    ${function:Invoke-GapsioHunting} = {
        param([string]$Query, [string]$Timespan = 'P30D')
        $calls.Add($Query)
        if ($Query -match '\| summarize Rows = count\(\)$') { return @([pscustomobject]@{ Rows = 2500 }) }
        if ($Query -match '\| where hash\(DeviceId, (\d+)\) == (\d+)$') { $n = [int]$Matches[1]; $i = [int]$Matches[2]; return @(0..($n * 100) | Where-Object { ($_ % $n) -eq $i } | ForEach-Object { [pscustomobject]@{ DeviceId = "d$_" } }) }
        if ($Query -match '\| take 10$') { return @(1..10 | ForEach-Object { [pscustomobject]@{ DeviceId = "d$_" } }) }
        @(1..1000 | ForEach-Object { [pscustomobject]@{ DeviceId = "d$_" } })
    }
    try {
        Reset-GapsioWarnings
        $rows = Invoke-GapsioHuntingSharded -Query "DeviceInfo`n| project DeviceId" -Context 'test' 6>$null
        & $A ($calls.Count -eq 1 + 1 + 4) "Sharding: 1 probe + 1 count + 4 shards for 2500 rows, got $($calls.Count) calls"
        & $A ($calls[1] -like "*`n| summarize Rows = count()") 'Sharding: count query appended'
        & $A ($calls[2] -like "DeviceInfo`n| project DeviceId`n| where hash(DeviceId, 4) == 0") 'Sharding: shard predicate appended to the original query'
        & $A (@($rows).Count -eq 401 -and @($rows | Select-Object -ExpandProperty DeviceId -Unique).Count -eq 401) "Sharding: shards concatenated without duplicates ($(@($rows).Count))"
        & $A (@(Get-GapsioWarnings).Count -eq 0) 'Sharding: no warning when shards are complete'
        $small = Invoke-GapsioHuntingSharded -Query "DeviceInfo | take 10" -Context 'test'; & $A ($calls.Count -eq 7) 'Sharding: queries below the limit run once'
        $script:GapsioHuntingRowLimit = 101; $calls.Clear(); Reset-GapsioWarnings
        ${function:Invoke-GapsioHunting} = { param([string]$Query, [string]$Timespan) $calls.Add($Query); if ($Query -match 'summarize Rows') { return @([pscustomobject]@{ Rows = 150 }) }; @(1..101 | ForEach-Object { [pscustomobject]@{ DeviceId = "d$_" } }) }
        $null = Invoke-GapsioHuntingSharded -Query 'DeviceInfo' -Context 'probe' 6>$null 3>$null
        & $A (@(Get-GapsioWarnings | Where-Object { $_ -like 'probe: shard * still hit the 101-row limit*' }).Count -eq 2) 'Sharding: warning when a shard is still truncated'
    }
    finally { ${function:Invoke-GapsioHunting} = $orig; $script:GapsioHuntingRowLimit = 100000 }
    $t0 = [DateTime]::UtcNow; $script:GapsioHuntingCalls.Clear(); 1..5 | ForEach-Object { Wait-GapsioHuntingBudget }
    & $A ($script:GapsioHuntingCalls.Count -eq 5 -and ([DateTime]::UtcNow - $t0).TotalSeconds -lt 2) 'Hunting budget: no pause below the per-minute limit'
    $script:GapsioHuntingCalls.Clear()
} ${function:Assert}
$env:GAPSIO_MODULES = 'endpoint,agents,access'
$env:WEBSITE_AUTH_ENABLED = $null
$r = Call 'me' -Principal $adminP; Assert ([int]$r.StatusCode -eq 503) 'Without enabled authentication: 503 (header is not trusted)'

# ---- Office preview: anti-phish drift (settings history + outcome correlation) ----
Write-Host 'Anti-phish drift'
$apParams = ConvertFrom-GapsioAntiPhishParams -Json (@(@{Name = 'Identity'; Value = 'P' }, @{Name = 'PhishThresholdLevel'; Value = '3' }, @{Name = 'ExcludedDomains'; Value = @('a.com', 'b.com') }) | ConvertTo-Json -Compress)
Assert ($apParams.Count -eq 2 -and $apParams['PhishThresholdLevel'] -eq '3' -and $apParams['ExcludedDomains'] -eq 'a.com;b.com') 'Anti-phish: audit parameters parsed, noise dropped, arrays flattened'
Assert ((Get-GapsioAntiPhishChangeDirection -Name 'PhishThresholdLevel' -Before '3' -After '1') -eq 'weaker') 'Anti-phish: threshold 3→1 is weaker'
Assert ((Get-GapsioAntiPhishChangeDirection -Name 'PhishThresholdLevel' -Before '2' -After '4') -eq 'stronger') 'Anti-phish: threshold 2→4 is stronger'
Assert ((Get-GapsioAntiPhishChangeDirection -Name 'TargetedUserProtectionAction' -Before 'Quarantine' -After 'MoveToJmf') -eq 'weaker') 'Anti-phish: Quarantine→MoveToJmf is weaker'
Assert ((Get-GapsioAntiPhishChangeDirection -Name 'EnableSpoofIntelligence' -Before 'True' -After 'False') -eq 'weaker') 'Anti-phish: disabling spoof intelligence is weaker'
Assert ((Get-GapsioAntiPhishChangeDirection -Name 'ExcludedDomains' -Before 'a.com' -After 'a.com;b.com') -eq 'weaker') 'Anti-phish: more exclusions is weaker'
Assert ((Test-GapsioAntiPhishPolicyMatch -AuditName 'Office365 AntiPhish Default' -EventPolicy 'Office365 AntiPhish Default (Default)') -and -not (Test-GapsioAntiPhishPolicyMatch -AuditName 'Strict' -EventPolicy 'Standard Preset')) 'Anti-phish: policy name matching tolerates suffixes'
& (Get-Module Gapsio) {
    param($A)
    $origHunt = ${function:Invoke-GapsioOfficeHunting}; $origGet = ${function:Get-GapsioBlob}; $origSet = ${function:Set-GapsioBlob}
    try {
        $script:apBlobs = @{}
        ${function:Get-GapsioBlob} = { param($Container, $Name) $script:apBlobs[$Name] }
        ${function:Set-GapsioBlob} = { param($Container, $Name, $Object, $Depth = 32, $ContentType) $script:apBlobs[$Name] = ($Object | ConvertTo-Json -Depth 16 | ConvertFrom-Json -Depth 16) }
        $script:apBase = [datetime]::UtcNow.Date
        ${function:Invoke-GapsioOfficeHunting} = {
            param($Query, $Context, $Timespan)
            if ($Context -like '*changes*') {
                return @(
                    [pscustomobject]@{ Timestamp = $script:apBase.AddDays(-20); ActionType = 'New-AntiPhishPolicy'; Policy = 'Strict Phish'; Actor = 'admin@x'; Result = 'True'; Params = (@(@{Name = 'Name'; Value = 'Strict Phish' }, @{Name = 'PhishThresholdLevel'; Value = '3' }, @{Name = 'TargetedUserProtectionAction'; Value = 'Quarantine' }) | ConvertTo-Json -Compress) },
                    [pscustomobject]@{ Timestamp = $script:apBase.AddDays(-10); ActionType = 'Set-AntiPhishPolicy'; Policy = 'Strict Phish'; Actor = 'admin@x'; Result = 'True'; Params = (@(@{Name = 'Identity'; Value = 'Strict Phish' }, @{Name = 'PhishThresholdLevel'; Value = '1' }) | ConvertTo-Json -Compress) })
            }
            $rows = @()
            for ($i = 29; $i -ge 0; $i--) {
                $d = $script:apBase.AddDays(-$i); $del = if ($i -le 10) { 8 } else { 2 }
                $rows += [pscustomobject]@{ day = $d; Policy = 'Strict Phish'; Method = 'Filter'; Outcome = 'Delivered'; Confidence = 'Normal'; events = $del }
                $rows += [pscustomobject]@{ day = $d; Policy = 'Strict Phish'; Method = 'Impersonation'; Outcome = 'Quarantine'; Confidence = 'High'; events = 5 }
            }
            $rows
        }
        $r1 = Update-GapsioOfficeAntiPhishHistory
        & $A (@($r1.rows).Count -eq 2 -and @($r1.rows | Where-Object status -eq 'ok').Count -eq 2) 'Anti-phish: two probe rows ok'
        & $A (@($r1.findings | Where-Object id -eq 'office.antiphish_weakened').Count -eq 1) 'Anti-phish: weakened finding when threshold is lowered'
        & $A (@($r1.findings | Where-Object id -eq 'office.antiphish_delivery_up').Count -eq 1) 'Anti-phish: delivered-up finding when delivered share rises ≥10 pp after the change'
        $eff = @($r1.antiphish.effects | Where-Object cmdlet -eq 'Set-AntiPhishPolicy')[0]
        & $A ($eff.scope -eq 'policy' -and $eff.before.deliveredPct -lt $eff.after.deliveredPct -and $eff.deliveredDelta -gt 10) "Anti-phish: before/after window computed per policy ($($eff.before.deliveredPct) → $($eff.after.deliveredPct))"
        $cur = @($r1.antiphish.periods | Where-Object current)[0]
        & $A ($cur.threshold -eq '1' -and @($r1.antiphish.periods).Count -eq 3) "Anti-phish: setting periods split at changes, current threshold 1 ($(@($r1.antiphish.periods).Count) periods)"
        & $A ($r1.antiphish.policies[0].settings.PhishThresholdLevel.value -eq '1' -and $r1.antiphish.policies[0].settings.TargetedUserProtectionAction.value -eq 'Quarantine') 'Anti-phish: last known settings carry over unchanged values'
        & $A (@($r1.antiphish.matrix).Count -eq 2) 'Anti-phish: policy × method matrix'
        $h1 = $script:apBlobs['office-antiphish-history.json']
        $r2 = Update-GapsioOfficeAntiPhishHistory
        $h2 = $script:apBlobs['office-antiphish-history.json']
        & $A (@($h1.changes).Count -eq 2 -and @($h2.changes).Count -eq 2 -and @($h2.daily).Count -eq @($h1.daily).Count) 'Anti-phish: re-run merges history without duplicates'
        & $A ($r2.rows[0].result[0].newChanges -eq 0 -and $h2.since -eq $h1.since) 'Anti-phish: second run adds no new changes and keeps history start'
    }
    finally { ${function:Invoke-GapsioOfficeHunting} = $origHunt; ${function:Get-GapsioBlob} = $origGet; ${function:Set-GapsioBlob} = $origSet }
} ${function:Assert}

if ($OutDir) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    foreach ($k in 'state/agents-latest.json', 'state/access-latest.json', 'state/licensing-latest.json', 'state/officepreview-latest.json', 'state/endpoint-changes.json', 'state/runs.json', 'state/acceptances.json', 'state/acceptances-log.json') { $blobs[$k] | Set-Content -Path (Join-Path $OutDir (Split-Path $k -Leaf)) -Encoding utf8 }
    # The demo is static: the paged device collections are written inline again
    (Get-EpSnapshot) | ConvertTo-Json -Depth 64 -Compress | Set-Content -Path (Join-Path $OutDir 'endpoint-latest.json') -Encoding utf8
    (Call 'access/me' -Principal $userP) | Out-Null
}

Write-Host ''
Write-Host "Result: $script:passed passed, $script:failed failed" -ForegroundColor ($(if ($script:failed) { 'Red' } else { 'Green' }))
if ($script:failed) { exit 1 }
