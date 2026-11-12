@{
    RootModule        = 'Gapsio.psm1'
    ModuleVersion     = '0.8.5'
    GUID              = '6b0f7c52-2a0e-4d6f-9a51-3c1d8e0b7a41'
    Author            = 'Gapsio'
    CompanyName       = 'Gapsio'
    Copyright         = '(c) Gapsio. All rights reserved.'
    Description       = 'Gapsio core: data collection and analysis for Microsoft Defender, AI agents (Entra Agent ID, local agents) and Entra/Intune RBAC.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @(
        'Get-GapsioSetting', 'Reset-GapsioWarnings', 'Add-GapsioWarning', 'Get-GapsioWarnings',
        'Get-GapsioToken', 'Invoke-GapsioRest', 'Invoke-GapsioGraph', 'Invoke-GapsioGraphSafe', 'Invoke-GapsioGraphV1First', 'Invoke-GapsioHunting',
        'Get-GapsioBlob', 'Get-GapsioBlobText', 'Set-GapsioBlob', 'Remove-GapsioBlob', 'Add-GapsioQueueMessage', 'Get-GapsioPage', 'Get-GapsioPagedMeta', 'Get-GapsioPagedCollection', 'Get-GapsioPagedIndex', 'Get-GapsioPagedIndexRaw', 'Search-GapsioDevices', 'Get-GapsioDevice',
        'Get-GapsioHash', 'ConvertTo-GapsioUtc', 'Get-GapsioSettingValues', 'Get-GapsioExclusionRisk', 'Get-GapsioIndicatorRisk',
        'Compare-GapsioCollection', 'Save-GapsioSnapshot', 'Get-GapsioPrincipal', 'Get-GapsioBaseline', 'Get-GapsioControlMapping', 'Test-GapsioBaselineValue',
        'Invoke-GapsioEndpointCollection', 'Invoke-GapsioAccessCollection', 'Invoke-GapsioAgentsCollection', 'Invoke-GapsioLicensingCollection', 'Invoke-GapsioOfficePreviewCollection', 'Invoke-GapsioPurviewPreviewCollection', 'Get-GapsioLicensingModel', 'Get-GapsioSkuDisplayName', 'Invoke-GapsioCollection',
        'Get-GapsioModules', 'Test-GapsioModuleEnabled', 'Test-GapsioFeature', 'Get-GapsioVersion', 'Compare-GapsioVersion', 'Update-GapsioReleaseInfo', 'Get-GapsioAcceptances', 'Test-GapsioAcceptanceActive', 'Set-GapsioAcceptance', 'Get-GapsioAssignments', 'Set-GapsioAssignment', 'Search-GapsioDirectory', 'Send-GapsioNotification', 'Test-GapsioLicenseKey', 'Get-GapsioLicense', 'Set-GapsioLicense', 'Get-GapsioLicenseTier', 'Get-GapsioCommunityRows', 'Get-GapsioPageSize', 'Protect-GapsioCommunity', 'Protect-GapsioCommunityList', 'Hide-GapsioItem',
        'Update-GapsioLocalExclusionState', 'Get-GapsioEndpointFindings', 'Test-GapsioBaseline',
        'Test-GapsioAssistant', 'Get-GapsioAssistantContext', 'Invoke-GapsioAssistant',
        'Update-GapsioOfficeAntiPhishHistory', 'ConvertFrom-GapsioAntiPhishParams', 'Get-GapsioAntiPhishChangeDirection', 'Test-GapsioAntiPhishPolicyMatch'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
