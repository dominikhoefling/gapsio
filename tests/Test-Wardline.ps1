#Requires -Version 7.2
<#
.SYNOPSIS
    Logic and end-to-end tests for Wardline without Azure: Graph, Advanced Hunting, the Defender API and
    storage are replaced with sample data in the module scope.
    Usage: pwsh ./tests/Test-Wardline.ps1 [-OutDir <folder for generated snapshots>]
#>
param([string]$OutDir)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'src/functionapp/Modules/Wardline/Wardline.psd1') -Force
$mod = Get-Module Wardline

$script:failed = 0; $script:passed = 0
function Assert { param([bool]$Condition, [string]$Message) if ($Condition) { $script:passed++ } else { $script:failed++; Write-Host "  FAILED: $Message" -ForegroundColor Red } }

Write-Host '== Unit tests' -ForegroundColor Cyan
& $mod {
    param($A)
    # Risk rating
    $r = Get-WlExclusionRisk -Type 'Process' -Value 'powershell.exe'
    & $A ($r.level -eq 'Critical') "powershell.exe as process exclusion should be Critical, is $($r.level)"
    $r = Get-WlExclusionRisk -Type 'Path' -Value 'C:\'
    & $A ($r.level -eq 'Critical') "Drive C:\ should be Critical, is $($r.level)"
    $r = Get-WlExclusionRisk -Type 'Path' -Value 'C:\Program Files\App\app.exe\:{PathType:file,ScanTrigger:OnAccess}'
    & $A ($r.level -eq 'Low') "Contextual file exclusion should be Low, is $($r.level)"
    $r = Get-WlExclusionRisk -Type 'Extension' -Value '.ps1'
    & $A ($r.level -eq 'Critical') ".ps1 extension should be Critical, is $($r.level)"
    $r = Get-WlExclusionRisk -Type 'Path' -Value '/tmp/tools' -Origin 'Local'
    & $A ($r.level -in 'High', 'Critical') "Local /tmp exclusion should be High, is $($r.level)"

    # Baseline comparison
    & $A (Test-WlBaselineValue -Value 'device_vendor_msft_policy_config_defender_cloudblocklevel_4' -Expect ([pscustomobject]@{ op = 'gte'; value = 2 })) 'cloudblocklevel_4 >= 2'
    & $A (-not (Test-WlBaselineValue -Value 'device_vendor_msft_policy_config_defender_cloudblocklevel_0' -Expect ([pscustomobject]@{ op = 'gte'; value = 2 }))) 'cloudblocklevel_0 < 2'
    & $A (Test-WlBaselineValue -Value '50' -Expect ([pscustomobject]@{ op = 'gte'; value = 50 })) 'timeout 50'
    & $A (Test-WlBaselineValue -Value 'x_submitsamplesconsent_3' -Expect ([pscustomobject]@{ op = 'in'; values = @(1, 3) })) 'samples in (1,3)'
    & $A (Test-WlBaselineValue -Value 'com.apple.managedclient.preferences_exclusionsmergepolicy_admin_only' -Expect ([pscustomobject]@{ op = 'match'; pattern = 'admin_?only$' })) 'mac admin_only'

    # mdatp commands
    $m = ConvertFrom-WlMdatpCommand 'mdatp exclusion folder add --path "/Users/Shared/my tools" --scope global'
    & $A ($m.Type -eq 'Path' -and $m.Value -eq '/Users/Shared/my tools' -and $m.Scope -eq 'Global' -and $m.Action -eq 'add') 'mdatp folder add with spaces and global scope'
    $m = ConvertFrom-WlMdatpCommand 'sudo mdatp exclusion process remove --name java'
    & $A ($m.Type -eq 'Process' -and $m.Action -eq 'remove' -and $m.Value -eq 'java') 'mdatp process remove'
    $m = ConvertFrom-WlMdatpCommand 'mdatp threat allowed add --name EICAR-Test-File'
    & $A ($m.Type -eq 'AllowedThreat') 'mdatp threat allowed'
    & $A ($null -eq (ConvertFrom-WlMdatpCommand 'mdatp health')) 'mdatp health ignored'

    # Settings Catalog parsing
    $inst = [pscustomobject]@{
        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance'; settingDefinitionId = 'linux_mdatp_managed_exclusions'
        groupSettingCollectionValue = @([pscustomobject]@{ children = @(
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'; settingDefinitionId = 'linux_mdatp_managed_exclusions_path'; simpleSettingValue = [pscustomobject]@{ value = '/opt/agent' } },
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'; settingDefinitionId = 'linux_mdatp_managed_exclusions_scope'; choiceSettingValue = [pscustomobject]@{ value = 'linux_mdatp_managed_exclusions_scope_global'; children = @() } }
                ) })
    }
    $v = Get-WlSettingValues -Instance $inst
    & $A ($v.Count -eq 2 -and ($v | Where-Object kind -eq 'simple').value -eq '/opt/agent' -and $v[0].group -eq $v[1].group) 'Group settings are split with a shared group'

    $bl = [pscustomobject]@{ checks = @([pscustomobject]@{ id = 'x'; platform = 'Windows'; title = 'X'; severity = 'High'; definitionId = 'def_x'; expect = [pscustomobject]@{ op = 'eq'; value = 1 } }) }
    $r = Test-WlBaseline -Baseline $bl -SettingValues @([pscustomobject]@{ policyId = 'p'; policyName = 'P'; platform = 'Windows'; definitionId = 'def_x'; value = 'def_x_1'; kind = 'choice'; group = ''; assignments = @() }) -Devices @{}
    & $A ($r[0].status -eq 'NotAssigned') "Baseline without assignment -> 'NotAssigned', is $($r[0].status)"
    $r = Test-WlBaseline -Baseline $bl -SettingValues @([pscustomobject]@{ policyId = 'p'; policyName = 'P'; platform = 'Windows'; definitionId = 'def_x'; value = 'def_x_1'; kind = 'choice'; group = ''; assignments = @('Group: A') }) -Devices @{}
    & $A ($r[0].status -eq 'OK') "Baseline with assignment -> OK, is $($r[0].status)"
} ${function:Assert}

Write-Host '== Settings Catalog builder (test data script)' -ForegroundColor Cyan
. (Join-Path $PSScriptRoot 'tenant/SettingsCatalog.ps1')
$defs = @{
    'x_cloudblocklevel' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition'; options = @([pscustomobject]@{ itemId = 'x_cloudblocklevel_0'; displayName = 'Default' }, [pscustomobject]@{ itemId = 'x_cloudblocklevel_2'; displayName = 'High' }) }
    'x_timeout'         = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingDefinition'; valueDefinition = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationIntegerSettingValueDefinition' } }
    'x_paths'           = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionDefinition'; valueDefinition = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValueDefinition' } }
    'x_asr'             = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSettingGroupCollectionDefinition'; childIds = @('x_asr_rulea', 'x_asr_ruleb') }
    'x_asr_rulea'       = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition'; options = @([pscustomobject]@{ itemId = 'x_asr_rulea_block' }, [pscustomobject]@{ itemId = 'x_asr_rulea_audit' }) }
    'mac_excl'          = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSettingGroupCollectionDefinition'; childIds = @('mac_excl_item_$type', 'mac_excl_item_path') }
    'mac_excl_item_$type' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition'; options = @([pscustomobject]@{ itemId = 'mac_excl_item_$type_excluded_path'; displayName = 'Path'; dependedOnBy = @([pscustomobject]@{ dependedOnBy = 'mac_excl_item_path'; required = $true }) }) }
    'mac_excl_item_path' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingDefinition'; valueDefinition = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValueDefinition' } }
}
$fetchFake = { param($id) if ($defs.ContainsKey($id)) { $defs[$id] } else { throw 'nf' } }.GetNewClosure()
$log = [System.Collections.Generic.List[string]]::new()
$set = New-WlSettingsList -Fetch $fetchFake -Log $log -Spec ([ordered]@{
        'x_cloudblocklevel' = '2'; 'x_timeout' = 50; 'x_paths' = @('C:\a', 'D:\b'); 'x_missing|x_cloudblocklevel' = '0'
        'x_asr' = @([ordered]@{ rulea = 'audit'; rulez = 'block' })
        'mac_excl' = @([ordered]@{ '$type' = '0|path'; path = '/tmp/x' })
        'gibtsnicht' = '1'
    })
Assert ($set.Count -eq 6) "6 settings expected, $($set.Count): $($log -join ' / ')"
Assert ($set[0].settingInstance.choiceSettingValue.value -eq 'x_cloudblocklevel_2') 'Choice by suffix'
Assert ($set[1].settingInstance.simpleSettingValue.'@odata.type' -match 'Integer' -and $set[1].settingInstance.simpleSettingValue.value -eq 50) 'Integer value'
Assert ($set[2].settingInstance.simpleSettingCollectionValue.Count -eq 2) 'String list'
Assert ($set[3].settingInstance.choiceSettingValue.value -eq 'x_cloudblocklevel_0') 'Candidate ID fallback'
Assert ($set[4].settingInstance.groupSettingCollectionValue[0].children.Count -eq 1 -and $set[4].settingInstance.groupSettingCollectionValue[0].children[0].choiceSettingValue.value -eq 'x_asr_rulea_audit') 'Group with unknown child'
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
        [pscustomobject]@{ id = 'pol-asr'; name = 'ASR Clients'; platforms = 'windows10'; technologies = 'mdm,microsoftSense'; lastModifiedDateTime = '2026-09-10T10:00:00Z'; templateReference = [pscustomobject]@{ templateDisplayName = 'Attack Surface Reduction Rules' } },
        [pscustomobject]@{ id = 'pol-asr2'; name = 'ASR Pilot'; platforms = 'windows10'; technologies = 'mdm,microsoftSense'; lastModifiedDateTime = '2026-09-11T10:00:00Z'; templateReference = [pscustomobject]@{ templateDisplayName = 'Attack Surface Reduction Rules' } },
        [pscustomobject]@{ id = 'pol-lnx2'; name = 'Linux AV'; platforms = 'linux'; technologies = 'mdm,microsoftSense'; lastModifiedDateTime = '2026-09-12T10:00:00Z'; templateReference = [pscustomobject]@{ templateDisplayName = 'Microsoft Defender Antivirus' } }
    )
    definitions = @{
        'linux_mdatp_managed_antivirusengine_enforcementlevel' = [pscustomobject]@{ id = 'linux_mdatp_managed_antivirusengine_enforcementlevel'; options = @(
                [pscustomobject]@{ itemId = 'linux_mdatp_managed_antivirusengine_enforcementlevel_0'; displayName = 'Real time'; optionValue = [pscustomobject]@{ value = 'real_time' } },
                [pscustomobject]@{ itemId = 'linux_mdatp_managed_antivirusengine_enforcementlevel_1'; displayName = 'On demand'; optionValue = [pscustomobject]@{ value = 'on_demand' } },
                [pscustomobject]@{ itemId = 'linux_mdatp_managed_antivirusengine_enforcementlevel_2'; displayName = 'Passive'; optionValue = [pscustomobject]@{ value = 'passive' } }) }
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
            (FxC 'linux_mdatp_managed_antivirusengine_enforcementlevel' 'linux_mdatp_managed_antivirusengine_enforcementlevel_2'),
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
    assignmentsByPolicy = @{ 'pol-lnx' = @() }
    healthScripts = @([pscustomobject]@{ id = 'hs1'; displayName = 'Wardline – local Defender exclusions (read-only)' }, [pscustomobject]@{ id = 'hs2'; displayName = 'Other script' })
    runStates = @(
        [pscustomobject]@{ lastStateUpdateDateTime = [DateTime]::UtcNow.AddMinutes(-30).ToString('o'); managedDevice = [pscustomobject]@{ deviceName = 'WIN-01'; azureADDeviceId = 'aad-win1' }
            preRemediationDetectionScriptOutput = '{"v":1,"m":1,"tp":0,"rm":"Normal","n":2,"tr":0,"x":[["P","L","C:\\Users\\Public\\x"],["P","L","C:\\Legacy\\Tool"]]}' },
        [pscustomobject]@{ lastStateUpdateDateTime = [DateTime]::UtcNow.AddMinutes(-30).ToString('o'); managedDevice = [pscustomobject]@{ deviceName = 'win-02'; azureADDeviceId = '' }
            preRemediationDetectionScriptOutput = '{"v":1,"m":0,"tp":1,"rm":"Passive Mode","n":2,"tr":0,"x":[["P","L","C:\\Users\\Public\\WardlineTest"],["E","G",".bak"]]}' },
        [pscustomobject]@{ lastStateUpdateDateTime = [DateTime]::UtcNow.ToString('o'); managedDevice = [pscustomobject]@{ deviceName = 'UNKNOWN-99'; azureADDeviceId = 'x' }; preRemediationDetectionScriptOutput = 'not json' }
    )
    assignments = @(
        [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-clients' } },
        [pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = 'g-servers' } }
    )
    groups = @{ 'g-clients' = 'All clients'; 'g-servers' = 'Server'; 'g1' = 'Helpdesk-Team'; 'g2' = 'PIM-SecOps'; 'g4' = 'Service desk candidates' }
    deviceConfigurations = @(
        [pscustomobject]@{ id = 'dc-1'; displayName = 'Legacy Endpoint Protection'; '@odata.type' = '#microsoft.graph.windows10EndpointProtectionConfiguration'; lastModifiedDateTime = '2024-01-01T00:00:00Z'; defenderProcessesToExclude = @('cmd.exe') }
    )
    indicators = @(
        [pscustomobject]@{ indicatorValue = 'ab12cd'; indicatorType = 'CertificateThumbprint'; action = 'Allowed'; title = 'Vendor-Zertifikat'; createdBy = 'admin@contoso.com'; creationTimeDateTimeUtc = '2025-01-01T00:00:00Z'; expirationTime = $null; rbacGroupNames = @() },
        [pscustomobject]@{ indicatorValue = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; indicatorType = 'FileSha256'; action = 'Allowed'; title = 'Tool'; createdBy = 'admin@contoso.com'; creationTimeDateTimeUtc = '2025-01-01T00:00:00Z'; expirationTime = '2027-01-01T00:00:00Z'; rbacGroupNames = @('IT') },
        [pscustomobject]@{ indicatorValue = 'bad.example'; indicatorType = 'DomainName'; action = 'Block'; title = 'Block'; createdBy = 'x' }
    )
}

$now = [DateTime]::UtcNow
function T { param([int]$DaysAgo) $now.AddDays(-$DaysAgo).ToString('o') }
$hunting = @{
    DeviceInfo = @(
        [pscustomobject]@{ DeviceId = 'd-win1'; DeviceName = 'WIN-01'; OSPlatform = 'Windows11'; OSVersion = '10.0.26100'; MachineGroup = 'Clients'; DeviceType = 'Workstation'; AadDeviceId = 'AAD-WIN1'; LastSeen = (T 0) },
        [pscustomobject]@{ DeviceId = 'd-win2'; DeviceName = 'WIN-02'; OSPlatform = 'Windows11'; OSVersion = '10.0.26100'; MachineGroup = 'Clients'; DeviceType = 'Workstation'; LastSeen = (T 0) },
        [pscustomobject]@{ DeviceId = 'd-mac1'; DeviceName = 'MAC-01'; OSPlatform = 'macOS'; OSVersion = '15.6'; MachineGroup = 'Mac'; DeviceType = 'Workstation'; LastSeen = (T 0) },
        [pscustomobject]@{ DeviceId = 'd-win3'; DeviceName = 'SRV-01'; OSPlatform = 'WindowsServer2022'; OSVersion = '10.0.20348'; MachineGroup = 'Server'; DeviceType = 'Server'; LastSeen = (T 0) },
        [pscustomobject]@{ DeviceId = 'd-lnx1'; DeviceName = 'LNX-01'; OSPlatform = 'Linux'; OSVersion = 'Ubuntu 24.04'; MachineGroup = 'Server'; DeviceType = 'Server'; LastSeen = (T 0) }
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
        [pscustomobject]@{ DeviceId = 'd-mac1'; DeviceName = 'MAC-01'; OSPlatform = 'macOS'; ConfigurationId = 'scid-5002'; ConfigurationName = 'Enable real-time protection'; IsApplicable = $true; IsCompliant = $true }
    )
    Info = @(
        [pscustomobject]@{ DeviceId = 'd-win1'; AvMode = '0'; AvSig = 'true'; AvPlat = 'true'; AvEng = 'true' },
        [pscustomobject]@{ DeviceId = 'd-win2'; AvMode = '1'; AvSig = 'true'; AvPlat = 'true'; AvEng = 'true' },
        [pscustomobject]@{ DeviceId = 'd-mac1'; AvMode = '0'; AvSig = 'true'; AvPlat = 'true'; AvEng = 'true' }
    )
    Alerts = @([pscustomobject]@{ DeviceId = 'd-win1'; Alerts = 1; LastAlert = (T 2) })
    Ps = @(
        [pscustomobject]@{ Timestamp = (T 3).Replace('Z',''); DeviceId = 'd-win2'; FileName = 'powershell.exe'; ProcessCommandLine = 'powershell.exe -c Add-MpPreference -ExclusionPath "C:\Users\Public\WardlineTest"'; AccountName = 'system' }
    )
    Registry = @(
        [pscustomobject]@{ Timestamp = (T 3); DeviceId = 'd-win2'; DeviceName = 'WIN-02'; ActionType = 'RegistryValueSet'; RegistryKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'; RegistryValueName = 'C:\Users\Public\WardlineTest'; InitiatingProcessFileName = 'MsMpEng.exe'; InitiatingProcessCommandLine = 'MsMpEng.exe'; InitiatingProcessAccountName = 'system' },
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
    'u-alice' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-alice'; userPrincipalName = 'alice@contoso.com'; displayName = 'Alice'; userType = 'Member' }
    'u-bob'   = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-bob'; userPrincipalName = 'bob@contoso.com'; displayName = 'Bob'; userType = 'Member' }
    'u-carol' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-carol'; userPrincipalName = 'carol@contoso.com'; displayName = 'Carol'; userType = 'Member' }
    'u-dave'  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-dave'; userPrincipalName = 'dave@contoso.com'; displayName = 'Dave'; userType = 'Member' }
    'u-erin'  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-erin'; userPrincipalName = 'erin@contoso.com'; displayName = 'Erin'; userType = 'Member' }
    'u-frank' = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-frank'; userPrincipalName = 'frank@contoso.com'; displayName = 'Frank'; userType = 'Member' }
    'u-gina'  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-gina'; userPrincipalName = 'gina@contoso.com'; displayName = 'Gina'; userType = 'Member' }
    'u-hank'  = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u-hank'; userPrincipalName = 'hank@contoso.com'; displayName = 'Hank'; userType = 'Member' }
}
$grp = { param($id, $name) [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = $id; displayName = $name } }
$GA = '62e90394-69f5-4237-9190-012177145e10'; $HD = '729827e3-9c14-49f7-bb1b-9608f156bbb8'; $SR = '5d6b6bb7-de71-4623-b4af-96380a352509'
$access = @{
    roleDefs = @(
        [pscustomobject]@{ id = $GA; templateId = $GA; displayName = 'Global Administrator'; isBuiltIn = $true; isPrivileged = $true; rolePermissions = @([pscustomobject]@{ allowedResourceActions = @('microsoft.directory/allEntities/allProperties/allTasks') }) },
        [pscustomobject]@{ id = $HD; templateId = $HD; displayName = 'Helpdesk Administrator'; isBuiltIn = $true; isPrivileged = $true; rolePermissions = @([pscustomobject]@{ allowedResourceActions = @('microsoft.directory/users/password/update', 'microsoft.directory/users/invalidateAllRefreshTokens') }) },
        [pscustomobject]@{ id = $SR; templateId = $SR; displayName = 'Security Reader'; isBuiltIn = $true; isPrivileged = $false; rolePermissions = @([pscustomobject]@{ allowedResourceActions = @('microsoft.directory/policies/standard/read') }) }
    )
    active = @(
        [pscustomobject]@{ principalId = 'u-alice'; roleDefinitionId = $GA; directoryScopeId = '/'; assignmentType = 'Assigned'; memberType = 'Direct'; principal = $users['u-alice'] },
        [pscustomobject]@{ principalId = 'g1'; roleDefinitionId = $HD; directoryScopeId = '/'; assignmentType = 'Assigned'; memberType = 'Direct'; principal = (& $grp 'g1' 'Helpdesk-Team') },
        [pscustomobject]@{ principalId = 'u-dave'; roleDefinitionId = $HD; directoryScopeId = '/'; assignmentType = 'Assigned'; memberType = 'Group'; principal = $users['u-dave'] },
        [pscustomobject]@{ principalId = 'u-bob'; roleDefinitionId = $SR; directoryScopeId = '/'; assignmentType = 'Activated'; memberType = 'Direct'; endDateTime = (T -1); principal = $users['u-bob'] }
    )
    eligible = @(
        [pscustomobject]@{ principalId = 'u-carol'; roleDefinitionId = $GA; directoryScopeId = '/'; memberType = 'Direct'; endDateTime = (T -180); principal = $users['u-carol'] },
        [pscustomobject]@{ principalId = 'g2'; roleDefinitionId = $SR; directoryScopeId = '/administrativeUnits/au-1'; memberType = 'Direct'; principal = (& $grp 'g2' 'PIM-SecOps') }
    )
    members = @{ 'g1' = @($users['u-dave'], $users['u-erin']); 'g2' = @($users['u-frank']); 'g4' = @($users['u-hank']) }
    pimGroups = @{ 'g1' = @([pscustomobject]@{ groupId = 'g1'; principalId = 'u-gina'; accessId = 'member'; endDateTime = (T -30) }) }
    intuneDefs = @([pscustomobject]@{ id = 'ir1'; displayName = 'Intune Endpoint Security Manager'; description = ''; isBuiltIn = $true })
    intuneAssign = @{ 'ir1' = @([pscustomobject]@{ id = 'ra1'; displayName = 'ESM Helpdesk' }) }
    intuneDetail = @{ 'ra1' = [pscustomobject]@{ id = 'ra1'; members = @('g1'); scopeMembers = @(); scopeType = 'allDevicesAndLicensedUsers' } }
    aps = @(
        [pscustomobject]@{ id = 'ap1'; displayName = 'Helpdesk access'; assignmentPolicies = @([pscustomobject]@{ id = 'pol1'; displayName = 'Candidates'; allowedTargetScope = 'specificDirectoryUsers'; requestorSettings = [pscustomobject]@{ enableTargetsToSelfAddAccess = $true }; specificAllowedTargets = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupMembers'; groupId = 'g4' }) }) },
        [pscustomobject]@{ id = 'ap2'; displayName = 'Security Reader for everyone'; assignmentPolicies = @([pscustomobject]@{ id = 'pol2'; displayName = 'All employees'; allowedTargetScope = 'allMemberUsers'; requestorSettings = [pscustomobject]@{ enableTargetsToSelfAddAccess = $true }; specificAllowedTargets = @() }) }
    )
    apDetail = @{
        'ap1' = [pscustomobject]@{ resourceRoleScopes = @([pscustomobject]@{ role = [pscustomobject]@{ originSystem = 'AadGroup'; originId = 'Member_g1'; resource = [pscustomobject]@{ originId = 'g1' } }; scope = [pscustomobject]@{ originId = 'g1' } }) }
        'ap2' = [pscustomobject]@{ resourceRoleScopes = @([pscustomobject]@{ role = [pscustomobject]@{ originSystem = 'DirectoryRole'; originId = 'Eligible'; resource = [pscustomobject]@{ originId = $SR } }; scope = [pscustomobject]@{ originId = '/' } }) }
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
        [pscustomobject]@{ id = 'ca-3'; displayName = 'Alle Benutzer: MFA'; state = 'enabled'; conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All') }; applications = [pscustomobject]@{ includeApplications = @('All') } }; grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('mfa') } },
        [pscustomobject]@{ id = 'ca-4'; displayName = 'Agents: Risiko hoch (aus)'; state = 'disabled'; conditions = [pscustomobject]@{ clientApplications = [pscustomobject]@{ includeAgentIdServicePrincipals = @('All') }; agentIdRiskLevels = @('high') }; grantControls = [pscustomobject]@{ builtInControls = @('block') } }
    )
}
$hunting.AgentsInfo = @(
    [pscustomobject]@{ AgentId = 'mde-1'; Name = 'Report Agent'; Platform = 'Microsoft Foundry'; EntraAgentID = 'ai-2'; EntraBlueprintID = 'bp-app-1'; PublishedStatus = 'Published'; LifecycleStatus = 'Active' },
    [pscustomobject]@{ AgentId = 'mde-2'; Name = 'Local Agent'; Platform = 'LocalAgents'; EntraAgentID = ''; EntraBlueprintID = ''; PublishedStatus = ''; LifecycleStatus = ''; IsLocal = $true
        Vendor = 'OpenAI'; LocalDeviceId = 'd-win1'; LocalDeviceName = 'WIN-01'; LocalOs = 'Windows11'; LocalUser = 'alice@contoso.com'; AutoApprove = 'true'; TrustedProcess = 'true'; Process = 'codex.exe'
        LocalMcps = '[{"name":"filesystem","commandName":"npx","commandArgs":["-y","@modelcontextprotocol/server-filesystem"]},{"name":"pinned","commandName":"npx","commandArgs":["tool@1.2.3"]}]'; McpServers = '[]' }
)
$fixtures.agents = $agentFx

Write-Host '== HTTP layer (real local server)' -ForegroundColor Cyan
# Checks Invoke-WlRest with the real cmdlets (Invoke-WebRequest/-RestMethod) – parameter errors only show up this way.
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
        function Get-WlToken { param($Resource) 'test-token' }
        $base = "http://127.0.0.1:$Port"
        $raw = Invoke-WlRest -Uri "$base/blob" -Resource 'https://storage.azure.com' -Raw -MaxRetries 0
        & $A ($raw -is [string] -and $raw -match '"ok":true') "Invoke-WlRest -Raw returns text ($raw)"
        $obj = Invoke-WlRest -Uri "$base/obj" -Resource 'https://graph.microsoft.com' -MaxRetries 0
        & $A ($obj.ok -eq $true -and $obj.text -eq 'äö') 'Invoke-WlRest returns an object with UTF-8'
        $st = $null; try { Invoke-WlRest -Uri "$base/missing" -Resource 'https://storage.azure.com' -Raw -MaxRetries 0 | Out-Null } catch { $st = $_.Exception.Data['Status'] ; if (-not $st) { $st = [string]$_ } }
        & $A ([string]$st -match '404') "Invoke-WlRest -Raw reports 404 ($st)"
        $st = $null; try { Invoke-WlRest -Uri "$base/missing" -Resource 'https://graph.microsoft.com' -MaxRetries 0 | Out-Null } catch { $st = $_.Exception.Data['Status'] ; if (-not $st) { $st = [string]$_ } }
        & $A ([string]$st -match '404') "Invoke-WlRest reports 404 ($st)"
    } ${function:Assert} $port
}
finally { $listener.Stop(); $ps.Dispose() }

Write-Host '== Least privilege: features and federated data app' -ForegroundColor Cyan
& $mod {
    param($A)
    $saved = @{}; foreach ($n in 'WL_FEATURES', 'WL_DEVICE_INVENTORY', 'WL_DATA_APP_ID', 'WL_TENANT_ID', 'IDENTITY_ENDPOINT', 'IDENTITY_HEADER', 'WL_CLIENT_ID') { $saved[$n] = [Environment]::GetEnvironmentVariable($n) }
    try {
        $env:WL_FEATURES = $null; $env:WL_DEVICE_INVENTORY = $null
        & $A ((Test-WlFeature 'hunting') -and (Test-WlFeature 'indicators') -and -not (Test-WlFeature 'inventory')) 'Default features: hunting + indicators, no inventory'
        $env:WL_FEATURES = 'indicators'
        & $A (-not (Test-WlFeature 'Hunting') -and (Test-WlFeature 'INDICATORS')) 'WL_FEATURES limits features (case-insensitive)'
        & $A ($null -eq (Invoke-WlHuntingSafe -Query 'DeviceInfo' -Context 'x')) 'Hunting off -> no Advanced Hunting call'
        $env:WL_DEVICE_INVENTORY = 'true'
        & $A (Test-WlFeature 'inventory') 'Legacy WL_DEVICE_INVENTORY still enables inventory'

        $calls = [System.Collections.Generic.List[object]]::new()
        function Invoke-RestMethod { param($Method, $Uri, $ContentType, $Body, $Headers)
            $calls.Add([pscustomobject]@{ Uri = [string]$Uri; Body = $Body })
            if ($Uri -like '*oauth2/v2.0/token') { return [pscustomobject]@{ access_token = "app-token-$($Body.scope)"; expires_in = 3600 } }
            [pscustomobject]@{ access_token = 'mi-assertion'; expires_on = [DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds() }
        }
        $env:IDENTITY_ENDPOINT = 'http://mi.local/msi/token'; $env:IDENTITY_HEADER = 'h'; $env:WL_CLIENT_ID = 'mi-client'
        $env:WL_DATA_APP_ID = 'data-app-1'; $env:WL_TENANT_ID = 'tenant-1'
        $script:WlTokens.Clear()
        $t = Get-WlToken -Resource 'https://graph.microsoft.com'
        $ex = @($calls | Where-Object { $_.Uri -like '*oauth2*' })[0]
        & $A ($t -eq 'app-token-https://graph.microsoft.com/.default') "Graph token comes from the data app ($t)"
        & $A ($ex.Uri -eq 'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token' -and $ex.Body.client_id -eq 'data-app-1' -and $ex.Body.client_assertion -eq 'mi-assertion' -and $ex.Body.client_assertion_type -like '*jwt-bearer') 'Token exchange: client assertion from the managed identity'
        & $A (@($calls | Where-Object { $_.Uri -like '*AzureADTokenExchange*' -and $_.Uri -like '*client_id=mi-client*' }).Count -eq 1) 'Assertion requested for api://AzureADTokenExchange'
        $n = $calls.Count
        $s = Get-WlToken -Resource 'https://storage.azure.com'
        & $A ($s -eq 'mi-assertion' -and @($calls | Select-Object -Skip $n | Where-Object { $_.Uri -like '*oauth2*' }).Count -eq 0) 'Storage keeps using the managed identity directly'
        $n = $calls.Count; $null = Get-WlToken -Resource 'https://graph.microsoft.com'
        & $A ($calls.Count -eq $n) 'Data app token is cached'
        $env:WL_DATA_APP_ID = $null; $script:WlTokens.Clear()
        & $A ((Get-WlToken -Resource 'https://graph.microsoft.com') -eq 'mi-assertion') 'Without WL_DATA_APP_ID: managed identity token'
    }
    finally {
        foreach ($n in $saved.Keys) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
        $script:WlTokens.Clear()
        Remove-Item function:Invoke-RestMethod -ErrorAction SilentlyContinue
    }
} ${function:Assert}

Write-Host '== Setup: permission model' -ForegroundColor Cyan
. (Join-Path $root 'setup/WardlineSetup.ps1')
Assert ((Resolve-WardlineFeatures -Features 'hunting', 'Hunting') -join ',' -eq 'Core,Hunting') 'Resolve-WardlineFeatures: Core always, names normalised, no duplicates'
$threw = $false; try { Resolve-WardlineFeatures -Features 'Everything' | Out-Null } catch { $threw = $true }
Assert $threw 'Unknown feature is rejected'
$ps = @(Get-WardlinePermissionSet -Features 'Core', 'Hunting' | ForEach-Object Value)
Assert (($ps -contains 'ThreatHunting.Read.All') -and ($ps -contains 'DeviceManagementConfiguration.Read.All') -and -not ($ps -contains 'Policy.Read.All') -and -not ($ps -contains 'Ti.Read.All')) "Core + Hunting grants only their permissions ($($ps -join ', '))"
$permModel = Get-Content -Raw (Join-Path $root 'setup/permissions.json') | ConvertFrom-Json
$allPerms = @($permModel.features | ForEach-Object { $_.permissions } | ForEach-Object value)
Assert (@($allPerms | Where-Object { $_ -notmatch '\.Read(Basic)?\.' }).Count -eq 0) "All Wardline permissions are read-only ($(@($allPerms | Where-Object { $_ -notmatch '\.Read(Basic)?\.' }) -join ', '))"
Assert (@($permModel.features | Where-Object required).id -join ',' -eq 'Core') 'Only Core is required'
Assert (@($permModel.features | ForEach-Object { $_.permissions } | Where-Object { -not $permModel.resources.($_.resource) }).Count -eq 0) 'Every permission references a known resource'

$blobs = @{}
$queue = [System.Collections.Generic.List[string]]::new()
& $mod {
    param($Fx, $Hunt, $Acc, $Users, $Blobs, $Queue)
    $script:Fx = $Fx; $script:Hunt = $Hunt; $script:Acc = $Acc; $script:Users = $Users; $script:Blobs = $Blobs; $script:Queue = $Queue
    $env:WL_STORAGE_ACCOUNT = 'teststorage'; $env:WL_TENANT_ID = '00000000-0000-0000-0000-000000000001'

    function script:V { param($Items) [pscustomobject]@{ value = @($Items) } }

    function script:Invoke-WlRest {
        param([string]$Uri, [string]$Method = 'GET', $Body, [string]$Resource, [hashtable]$Headers = @{}, [string]$ContentType, [switch]$Raw, [int]$MaxRetries)
        if ($Uri -match '\.blob\.core\.windows\.net/(.+)$') {
            $k = $Matches[1]
            if ($Method -eq 'PUT') { $script:Blobs[$k] = [string]$Body; return '' }
            if (-not $script:Blobs.ContainsKey($k)) { throw (New-WlHttpException -Status 404 -Message "404 $k") }
            if ($Raw) { return $script:Blobs[$k] } else { return ($script:Blobs[$k] | ConvertFrom-Json) }
        }
        if ($Uri -match '\.queue\.core\.windows\.net/') { $script:Queue.Add([string]$Body); return '' }
        if ($Uri -match 'runHuntingQuery') {
            $q = [string]$Body.Query
            $rows = if ($q -match '^AgentsInfo') { $script:Hunt.AgentsInfo }
            elseif ($q -match 'AsrConfigurationStates') { $script:Hunt.AsrInfo }
            elseif ($q -match 'Attack Surface Reduction') { $script:Hunt.AsrTvm }
            elseif ($q -match 'DeviceFileEvents') { $script:Hunt.FileEvents }
            elseif ($q -match '"--value"') { $script:Hunt.MdatpConfig }
            elseif ($q -match 'DeviceRegistryEvents') { $script:Hunt.Registry }
            elseif ($q -match 'MpPreference') { $script:Hunt.Ps }
            elseif ($q -match 'DeviceProcessEvents') { $script:Hunt.Process }
            elseif ($q -match 'DeviceTvmSecureConfigurationAssessmentKB') { $script:Hunt.TvmMac }
            elseif ($q -match 'DeviceTvmSecureConfigurationAssessment') { $script:Hunt.Tvm }
            elseif ($q -match 'DeviceTvmInfoGathering') { $script:Hunt.Info }
            elseif ($q -match 'AlertInfo') { $script:Hunt.Alerts }
            elseif ($q -match 'DeviceInfo') { $script:Hunt.DeviceInfo }
            else { throw "Unbekannte Hunting-Abfrage" }
            return [pscustomobject]@{ schema = @(); results = @($rows) }
        }
        if ($Uri -match 'api.securitycenter.microsoft.com/api/indicators') { return (V $script:Fx.indicators) }

        $path = ($Uri -replace '^https://graph.microsoft.com/(v1.0|beta)/', '')
        switch -Regex ($path) {
            '^deviceManagement/configurationPolicies\?' { return (V $script:Fx.policies) }
            '^applications/microsoft.graph.agentIdentityBlueprint' { return (V $script:Fx.agents.blueprints) }
            '^servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal' { return (V $script:Fx.agents.principals) }
            '^servicePrincipals/microsoft.graph.agentIdentity\?' { return (V $script:Fx.agents.identities) }
            '^users/microsoft.graph.agentUser' { return (V $script:Fx.agents.users) }
            '^agentRegistry/agentInstances' { return (V $script:Fx.agents.registry) }
            '^identity/conditionalAccess/policies' { return (V $script:Fx.agents.policies) }
            '^policies/identitySecurityDefaultsEnforcementPolicy' { return [pscustomobject]@{ isEnabled = $false } }
            "^deviceManagement/configurationSettings\('([^']+)'\)" { if ($script:Fx.definitions.ContainsKey($Matches[1])) { return $script:Fx.definitions[$Matches[1]] }; throw (New-WlHttpException -Status 404 -Message 'nf') }
            "^deviceManagement/configurationPolicies\('([^']+)'\)/settings" { return (V $script:Fx.settings[$Matches[1]]) }
            "^deviceManagement/configurationPolicies\('([^']+)'\)/assignments" { if ($script:Fx.assignmentsByPolicy -and $script:Fx.assignmentsByPolicy.ContainsKey($Matches[1])) { return (V $script:Fx.assignmentsByPolicy[$Matches[1]]) }; return (V $script:Fx.assignments) }
            '^deviceManagement/intents\?' { return (V @()) }
            '^deviceManagement/deviceHealthScripts\?' { return (V $script:Fx.healthScripts) }
            '^deviceManagement/deviceHealthScripts/([^/]+)/deviceRunStates' { return (V $script:Fx.runStates) }
            '^deviceManagement/deviceConfigurations$' { return (V $script:Fx.deviceConfigurations) }
            '^deviceManagement/deviceConfigurations/[^/]+/assignments' { return (V @($script:Fx.assignments[0])) }
            '^groups/([^/?]+)\?\$select=id,displayName' { $id = $Matches[1]; return [pscustomobject]@{ id = $id; displayName = $script:Fx.groups[$id] } }
            '^groups/([^/]+)/transitiveMembers' { return (V $script:Acc.members[$Matches[1]]) }
            '^roleManagement/directory/roleDefinitions' { return (V $script:Acc.roleDefs) }
            '^roleManagement/directory/roleAssignmentScheduleInstances' { return (V $script:Acc.active) }
            '^roleManagement/directory/roleEligibilityScheduleInstances' { return (V $script:Acc.eligible) }
            "^identityGovernance/privilegedAccess/group/eligibilityScheduleInstances\?\`$filter=groupId eq '([^']+)'" { return (V $script:Acc.pimGroups[$Matches[1]]) }
            '^deviceManagement/roleDefinitions\?' { return (V $script:Acc.intuneDefs) }
            '^deviceManagement/roleDefinitions/([^/]+)/roleAssignments' { return (V $script:Acc.intuneAssign[$Matches[1]]) }
            '^deviceManagement/roleAssignments/([^/?]+)$' { return $script:Acc.intuneDetail[$Matches[1]] }
            '^identityGovernance/entitlementManagement/accessPackages\?' { return (V $script:Acc.aps) }
            '^identityGovernance/entitlementManagement/accessPackages/([^?]+)\?' { return $script:Acc.apDetail[$Matches[1]] }
            '^identityGovernance/entitlementManagement/assignments' { return (V $script:Acc.apAssignments) }
            '^directoryObjects/(.+)$' { $id = $Matches[1]; if ($script:Users.ContainsKey($id)) { return $script:Users[$id] } ; throw (New-WlHttpException -Status 404 -Message 'nf') }
            '^users/([^?]+)\?' { return $script:Users[$Matches[1]] }
            default { throw "Nicht simulierter Aufruf: $Method $Uri" }
        }
    }
} $fixtures $hunting $access $users $blobs $queue

# ---------------------------------------------------------------- End-to-end
Write-Host '== End-to-end: endpoint' -ForegroundColor Cyan
$r1 = Invoke-WlEndpointCollection 6>$null
$ep = $blobs['state/endpoint-latest.json'] | ConvertFrom-Json -Depth 64
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
Assert (@($ep.indicators).Count -eq 2) 'Allow indicators only'
$f = @($ep.findings)
Assert (@($f | Where-Object { $_.title.en -eq 'Tamper Protection off and local exclusions present' -and $_.deviceName -eq 'WIN-01' }).Count -eq 1) 'Combined finding TP + local for WIN-01'
Assert (@($f | Where-Object { $_.title.en -match 'passive mode' -and $_.deviceName -eq 'WIN-02' }).Count -eq 1) 'Passive mode WIN-02'
Assert (@($f | Where-Object { $_.title.en -match 'Tamper' -and $_.deviceName -eq 'MAC-01' }).Count -eq 1) 'macOS tamper finding'
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
Assert ($b['linux-enforcement-level'].status -eq 'Deviation' -and $b['linux-enforcement-level'].configured[0].value -match 'passive') "Linux enforcementLevel passive -> Deviation (display name), is $($b['linux-enforcement-level'].status) / $($b['linux-enforcement-level'].configured[0].value)"
Assert ($b['linux-exclusions-merge-policy'].status -eq 'OK') "Linux mergePolicy admin_only -> OK, is $($b['linux-exclusions-merge-policy'].status)"
Assert ($b['linux-tamper-protection'].status -eq 'NotConfigured') "Linux tamper not configured, is $($b['linux-tamper-protection'].status)"
Assert ($b['mac-cloud-block-level'].status -eq 'NotConfigured') "macOS cloud block level not configured, is $($b['mac-cloud-block-level'].status)"
Assert (@($ep.seenDefenderSettings | Where-Object { $_ -match 'smartscreen' }).Count -eq 0) 'Edge SmartScreen (mac) ignored'
Assert (@($ep.seenDefenderSettings | Where-Object { $_ -match 'edge' }).Count -eq 0) 'Edge settings ignored'
Assert ($ep.isFirstRun -eq $true) 'First run flagged'
$viaPs = @($le | Where-Object { $_.value -eq 'C:\Users\Public\WardlineTest' })
Assert ($viaPs.Count -eq 1 -and $viaPs[0].addedBy.process -eq 'powershell.exe' -and $viaPs[0].addedBy.commandLine -match 'Add-MpPreference') "Caller of Add-MpPreference detected instead of MsMpEng.exe (is: $($viaPs[0].addedBy.process))"
Assert (@($pe | Where-Object { $_.platform -eq 'Linux' -and $_.assigned -eq $false }).Count -eq 1) 'Unassigned Linux policy detected'
Assert (@($pe | Where-Object { $_.platform -eq 'Windows' -and $_.assigned -eq $true }).Count -ge 1) 'Windows policy detected as assigned'

Write-Host '== End-to-end: drift' -ForegroundColor Cyan
$fixtures.settings['pol-win'][9] = (FxL "${p}excludedextensions" @('.log'))   # .ps1 removed
$r2 = Invoke-WlEndpointCollection 6>$null
$changes = $blobs['state/endpoint-changes.json'] | ConvertFrom-Json -Depth 64
Assert (@($changes | Where-Object { $_.change -eq 'Removed' -and $_.label.en -match "\.ps1" }).Count -ge 1) 'Removed .ps1 exclusion detected as a change'
Assert ($r2.changes -ge 1) 'Second run reports changes'
Assert (@($blobs.Keys | Where-Object { $_ -like 'snapshots/endpoint/*' }).Count -eq 2) 'Two dated snapshots'

Write-Host '== End-to-end: device inventory (optional)' -ForegroundColor Cyan
Assert ($ep.localDetection -eq 'AdvancedHunting') 'Default: Advanced Hunting only'
$env:WL_DEVICE_INVENTORY = 'true'
$r3 = Invoke-WlEndpointCollection 6>$null
$env:WL_DEVICE_INVENTORY = $null
$ep3 = $blobs['state/endpoint-latest.json'] | ConvertFrom-Json -Depth 64
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
$rg = Invoke-WlAgentsCollection 6>$null
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
Assert ($a2.platform -eq 'Microsoft Foundry' -and @($a2.sources) -contains 'DefenderAgentsInfo') 'AgentsInfo match via EntraAgentID'
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
$cov = & $mod { param($p) Get-WlAgentCaCoverage -Policies @($p) -Kind Identity -Ids @('x') -DirectId 'x' -SecurityDefaults $false } $fxp
Assert ($cov.status -eq 'Unclear') "Attribute filter -> Unclear, is $($cov.status)"
$cov = & $mod { param($p) Get-WlAgentCaCoverage -Policies @($p) -Kind Identity -Ids @('x') -DirectId 'x' -SecurityDefaults $true } $fxp
Assert ($cov.status -eq 'SecurityDefaults') 'Security defaults override CA'
$bp2 = [pscustomobject]@{ id = 'ca-b'; displayName = 'Blueprint'; state = 'enabled'; conditions = [pscustomobject]@{ clientApplications = [pscustomobject]@{ includeAgentIdServicePrincipals = @('BP-OBJ-1') } } }
$cov = & $mod { param($p) Get-WlAgentCaCoverage -Policies @($p) -Kind Identity -Ids @('ai-9', 'bp-obj-1') -DirectId 'ai-9' -SecurityDefaults $false } $bp2
Assert ($cov.status -eq 'Protected' -and $cov.policies[0].via -eq 'Blueprint') 'Blueprint target covers the agent (case-insensitive)'

Write-Host '== End-to-end: access' -ForegroundColor Cyan
$env:WL_MODULES = 'endpoint,agents,access'
$ra = Invoke-WlAccessCollection 6>$null
$ac = $blobs['state/access-latest.json'] | ConvertFrom-Json -Depth 64
Assert ($ac.warnings.Count -eq 0) "Warnings in the access run: $($ac.warnings -join ' | ')"
$e = @($ac.entitlements)
function Has { param($upn, $role, $state, $via) @($e | Where-Object { $_.upn -eq $upn -and $_.role -eq $role -and $_.state -eq $state -and $_.via -like $via }).Count -ge 1 }
Assert (Has 'alice@contoso.com' 'Global Administrator' 'Active' 'direct') 'Alice GA active direct'
Assert (Has 'bob@contoso.com' 'Security Reader' 'Activated' 'direct') 'Bob SR activated'
Assert (Has 'carol@contoso.com' 'Global Administrator' 'Eligible' 'direct') 'Carol GA eligible'
Assert (Has 'dave@contoso.com' 'Helpdesk Administrator' 'Active' 'Group: Helpdesk-Team') 'Dave HD via group'
Assert (-not (Has 'dave@contoso.com' 'Helpdesk Administrator' 'Active' 'direct')) 'Dave not listed twice as direct (memberType Group)'
Assert (Has 'frank@contoso.com' 'Security Reader' 'Eligible' 'Group: PIM-SecOps') 'Frank SR eligible via group'
Assert (Has 'gina@contoso.com' 'Helpdesk Administrator' 'Eligible' 'PIM for groups: Helpdesk-Team') 'Gina HD eligible via PIM for groups'
Assert (Has 'gina@contoso.com' 'Intune Endpoint Security Manager' 'Eligible' 'PIM for groups: Helpdesk-Team') 'Gina Intune role eligible via PIM for groups'
Assert (Has 'erin@contoso.com' 'Intune Endpoint Security Manager' 'Active' 'Group: Helpdesk-Team') 'Erin Intune role via group'
Assert (Has 'hank@contoso.com' 'Helpdesk Administrator' 'Requestable' 'Access package: Helpdesk access*') 'Hank HD requestable'
Assert (Has 'erin@contoso.com' 'Helpdesk Administrator' 'Active' 'Access package: Helpdesk access (assigned*') 'Erin assigned via package'
Assert (@($ac.audiences | Where-Object { $_.audience -eq 'allMemberUsers' -and $_.grants[0].role -eq 'Security Reader' }).Count -eq 1) 'Open package for all members'
Assert (@($e | Where-Object { $_.scope -like 'Administrative Unit*' }).Count -ge 1) 'AU scope detected'

Write-Host '== API' -ForegroundColor Cyan
Add-Type -TypeDefinition 'public class HttpResponseContext { public object StatusCode; public object Body; public string ContentType; public System.Collections.Hashtable Headers; }' -ErrorAction SilentlyContinue
$script:resp = $null
function global:Push-OutputBinding { param($Name, $Value) $global:WlTestResp = $Value }
$env:WEBSITE_AUTH_ENABLED = 'True'
function New-Principal { param([string[]]$Roles, [string]$Oid)
    $claims = @(@{ typ = 'http://schemas.microsoft.com/identity/claims/objectidentifier'; val = $Oid }, @{ typ = 'preferred_username'; val = "$Oid@contoso.com" }, @{ typ = 'name'; val = $Oid })
    $claims += @($Roles | ForEach-Object { @{ typ = 'roles'; val = $_ } })
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{ auth_typ = 'aad'; claims = $claims; role_typ = 'roles' } | ConvertTo-Json -Depth 5)))
}
$api = Join-Path $root 'src/functionapp/Api/run.ps1'
$env:PSModulePath = (Join-Path $root 'src/functionapp/Modules') + [IO.Path]::PathSeparator + $env:PSModulePath
function Call { param($Seg, $Method = 'GET', $Principal, $Query = @{}, $Headers = @{})
    $h = @{ 'x-ms-client-principal' = $Principal }; foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
    & $api -Request ([pscustomobject]@{ Params = @{ segments = $Seg }; Method = $Method; Query = $Query; Headers = $h }) -TriggerMetadata $null
    $global:WlTestResp
}
$adminP = New-Principal -Roles 'Wardline.Admin' -Oid 'u-alice'
$userP = New-Principal -Roles @() -Oid 'u-hank'
$r = Call 'me' -Principal $adminP; Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json).isAdmin) 'api/me Admin'
$r = Call 'endpoint' -Principal $userP; Assert ([int]$r.StatusCode -eq 403) 'Non-admin gets 403 on endpoint'
$r = Call 'endpoint' -Principal $adminP; Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json).module -eq 'endpoint') 'Admin gets endpoint'
$r = Call 'access/me' -Principal $userP; $m = $r.Body | ConvertFrom-Json
Assert ([int]$r.StatusCode -eq 200 -and @($m.entitlements | Where-Object { $_.state -eq 'Requestable' }).Count -ge 1 -and @($m.audiences).Count -eq 1) 'My access for Hank (requestable + open package)'
$r = Call 'agents' -Principal $adminP; Assert ([int]$r.StatusCode -eq 200 -and ($r.Body | ConvertFrom-Json).module -eq 'agents') 'Admin gets agents'
$r = Call 'changes' -Principal $adminP -Query @{ module = 'agents' }; Assert ([int]$r.StatusCode -eq 200) 'changes?module=agents'
$r = Call 'run' -Method 'POST' -Principal $adminP -Query @{ module = 'endpoint' }; Assert ([int]$r.StatusCode -eq 400) 'POST without X-Wardline is rejected'
$r = Call 'run' -Method 'POST' -Principal $adminP -Query @{ module = 'endpoint' } -Headers @{ 'X-Wardline' = '1' }; Assert ([int]$r.StatusCode -eq 202 -and $queue.Count -eq 1) 'POST run creates a queue message'

Write-Host '== Versions and update check' -ForegroundColor Cyan
& $mod {
    param($A)
    & $A ((Get-WlVersion) -eq (Get-Module Wardline).Version.ToString()) 'Get-WlVersion = ModuleVersion of Wardline.psd1'
    & $A ((Compare-WlVersion 'v0.10.0' '0.9.3') -eq 1 -and (Compare-WlVersion '0.4.0' 'v0.4.0') -eq 0 -and (Compare-WlVersion '0.4.0-rc.1' '0.4.1') -eq -1) 'Compare-WlVersion handles v prefix, numeric order and pre-release suffix'
    $env:WL_UPDATE_REPOSITORY = $null
    & $A ($null -eq (Update-WlReleaseInfo -Force)) 'Update check skipped while the repository is a placeholder'
    $env:WL_UPDATE_REPOSITORY = 'contoso/wardline'; $env:WL_UPDATE_CHECK = 'false'
    & $A ($null -eq (Update-WlReleaseInfo -Force)) 'WL_UPDATE_CHECK=false disables the update check'
    $env:WL_UPDATE_CHECK = $null
    $script:ghCalls = 0
    function Invoke-RestMethod { param($Uri, $Headers, $TimeoutSec) $script:ghCalls++; [pscustomobject]@{ tag_name = 'v9.9.9'; html_url = 'https://github.com/contoso/wardline/releases/tag/v9.9.9'; published_at = '2026-11-01T00:00:00Z'; uri = $Uri } }
    $u = Update-WlReleaseInfo -Force
    & $A ($u.available -and $u.latest -eq '9.9.9' -and $u.current -eq (Get-WlVersion)) "Newer release detected ($($u.latest))"
    $u2 = Update-WlReleaseInfo
    & $A ($script:ghCalls -eq 1 -and $u2.latest -eq '9.9.9') 'Release info is cached for a day (no second GitHub call)'
    Remove-Item function:Invoke-RestMethod
    $env:WL_UPDATE_REPOSITORY = $null
} ${function:Assert}
$r = Call 'me' -Principal $adminP; $me = $r.Body | ConvertFrom-Json
Assert ($me.version -and $me.update.available -and $me.update.latest -eq '9.9.9') 'api/me returns version and update info for admins'
$r = Call 'me' -Principal $userP; $me = $r.Body | ConvertFrom-Json
Assert ($null -eq $me.update) 'api/me hides update info from non-admins'
$tmpZip = Join-Path ([IO.Path]::GetTempPath()) "wl-pkg-$([guid]::NewGuid().ToString('n')).zip"
& (Join-Path $root 'build/New-WardlinePackage.ps1') -OutFile $tmpZip 6>$null | Out-Null
Assert ((Get-WardlinePackageVersion -Path $tmpZip) -eq (Import-PowerShellDataFile (Join-Path $root 'src/functionapp/Modules/Wardline/Wardline.psd1')).ModuleVersion) 'Get-WardlinePackageVersion reads the version from the function package'
Remove-Item $tmpZip -Force
$env:WL_MODULES = $null
$r = Call 'access' -Principal $adminP; Assert ([int]$r.StatusCode -eq 404) 'Default: access module off -> 404'
$r = Call 'access/me' -Principal $userP; Assert ([int]$r.StatusCode -eq 404) 'Default: my access off -> 404'
$r = Call 'me' -Principal $adminP; $me = $r.Body | ConvertFrom-Json; Assert ((@($me.modules) -join ',') -eq 'endpoint,agents') "Default modules endpoint,agents, is $(@($me.modules) -join ',')"
$queue.Clear(); $r = Call 'run' -Method 'POST' -Principal $adminP -Query @{ module = 'access' } -Headers @{ 'X-Wardline' = '1' }; $qm = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(([xml]$queue[0]).QueueMessage.MessageText)) | ConvertFrom-Json; Assert ($qm.module -eq 'all') 'Disabled module becomes all'
$res = Invoke-WlCollection -Module 'all' 6>$null 3>$null; Assert ((@($res | ForEach-Object module) -join ',') -eq 'endpoint,agents') "all = enabled modules only, is $(@($res | ForEach-Object module) -join ',')"
$env:WL_MODULES = 'endpoint,agents,access'
$env:WEBSITE_AUTH_ENABLED = $null
$r = Call 'me' -Principal $adminP; Assert ([int]$r.StatusCode -eq 503) 'Without enabled authentication: 503 (header is not trusted)'

if ($OutDir) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    foreach ($k in 'state/endpoint-latest.json', 'state/agents-latest.json', 'state/access-latest.json', 'state/endpoint-changes.json', 'state/runs.json') { $blobs[$k] | Set-Content -Path (Join-Path $OutDir (Split-Path $k -Leaf)) -Encoding utf8 }
    (Call 'access/me' -Principal $userP) | Out-Null
}

Write-Host ''
Write-Host "Result: $script:passed passed, $script:failed failed" -ForegroundColor ($(if ($script:failed) { 'Red' } else { 'Green' }))
if ($script:failed) { exit 1 }
