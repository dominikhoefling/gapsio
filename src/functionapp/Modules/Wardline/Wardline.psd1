@{
    RootModule        = 'Wardline.psm1'
    ModuleVersion     = '0.5.0'
    GUID              = '6b0f7c52-2a0e-4d6f-9a51-3c1d8e0b7a41'
    Author            = 'Wardline'
    CompanyName       = 'Wardline'
    Copyright         = '(c) Wardline. All rights reserved.'
    Description       = 'Wardline core: data collection and analysis for Microsoft Defender, AI agents (Entra Agent ID, local agents) and Entra/Intune RBAC.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @(
        'Get-WlSetting', 'Reset-WlWarnings', 'Add-WlWarning', 'Get-WlWarnings',
        'Get-WlToken', 'Invoke-WlRest', 'Invoke-WlGraph', 'Invoke-WlGraphSafe', 'Invoke-WlGraphV1First', 'Invoke-WlHunting',
        'Get-WlBlob', 'Get-WlBlobText', 'Set-WlBlob', 'Remove-WlBlob', 'Add-WlQueueMessage', 'Get-WlPage', 'Get-WlPagedMeta', 'Get-WlPagedCollection', 'Get-WlPagedIndex', 'Get-WlPagedIndexRaw', 'Search-WlDevices', 'Get-WlDevice',
        'Get-WlHash', 'Get-WlSettingValues', 'Get-WlExclusionRisk', 'Get-WlIndicatorRisk',
        'Compare-WlCollection', 'Save-WlSnapshot', 'Get-WlPrincipal', 'Get-WlBaseline', 'Test-WlBaselineValue',
        'Invoke-WlEndpointCollection', 'Invoke-WlAccessCollection', 'Invoke-WlAgentsCollection', 'Invoke-WlLicensingCollection', 'Get-WlLicensingModel', 'Get-WlSkuDisplayName', 'Invoke-WlCollection',
        'Get-WlModules', 'Test-WlModuleEnabled', 'Test-WlFeature', 'Get-WlVersion', 'Compare-WlVersion', 'Update-WlReleaseInfo', 'Get-WlAcceptances', 'Test-WlAcceptanceActive', 'Set-WlAcceptance', 'Get-WlAssignments', 'Set-WlAssignment', 'Search-WlDirectory', 'Send-WlNotification', 'Test-WlLicenseKey', 'Get-WlLicense', 'Set-WlLicense', 'Get-WlLicenseTier', 'Get-WlCommunityRows', 'Get-WlPageSize', 'Protect-WlCommunity', 'Protect-WlCommunityList', 'Hide-WlItem',
        'Update-WlLocalExclusionState', 'Get-WlEndpointFindings', 'Test-WlBaseline',
        'Test-WlAssistant', 'Get-WlAssistantContext', 'Invoke-WlAssistant',
        'Update-WlOfficeAntiPhishHistory', 'ConvertFrom-WlAntiPhishParams', 'Get-WlAntiPhishChangeDirection', 'Test-WlAntiPhishPolicyMatch'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
