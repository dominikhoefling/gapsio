// Wardline – infrastructure in the customer's Azure subscription (self-hosted).
// Everything runs with a user-assigned managed identity: no secrets, no storage keys.
targetScope = 'resourceGroup'

@description('Azure region. Flex Consumption must be available in the region (e.g. westeurope, northeurope, swedencentral, germanywestcentral).')
param location string = resourceGroup().location

@description('Short name for all resources (3–10 lowercase letters/digits).')
@minLength(3)
@maxLength(10)
param namePrefix string = 'wardline'

@description('Optional custom Function App name (instead of <namePrefix>-<suffix>).')
param customFunctionAppName string = ''

@description('Optional custom storage account name (3–24 lowercase letters/digits, globally unique).')
param customStorageAccountName string = ''

@description('Optional custom name of the runner managed identity.')
param customRunnerIdentityName string = ''

@description('Optional custom name of the deploy managed identity (Deploy to Azure path).')
param customDeployIdentityName string = ''

@description('Optional custom App Service plan name.')
param customPlanName string = ''

@description('Optional custom Log Analytics workspace name.')
param customLogWorkspaceName string = ''

@description('Optional custom Application Insights name.')
param customAppInsightsName string = ''

@description('Client ID of the portal app registration (set by setup/Install-Wardline.ps1). Empty = the portal stays locked.')
param ssoClientId string = ''

@description('Retention of snapshots and change history in days.')
@minValue(30)
@maxValue(3650)
param retentionDays int = 365

@description('Store snapshots immutably (WORM, time-based retention). The policy is not locked initially.')
param enableImmutability bool = false

@description('Optional: public URL of the function package (zip). If set, the code is deployed as well (Deploy to Azure button).')
param packageUri string = ''

@description('Optional device inventory: Wardline also reads the results of the detection script from Intune Remediations (created by Install-Wardline.ps1 -DeviceInventory). Off = Advanced Hunting only.')
param deviceInventory bool = false

@description('Module "Agents": inventory of AI agents (Entra Agent ID, Agent 365, local agents) and Conditional Access coverage.')
param enableAgents bool = true

@description('Endpoint features (comma-separated): hunting (Advanced Hunting), indicators (Defender for Endpoint indicators), inventory (Intune Remediations). Only selected features are queried – matching the permissions granted.')
param features string = 'hunting,indicators'

@description('Optional: app ID of a pre-created data-access app registration. The managed identity signs in to it via workload identity federation (no secret). Empty = the managed identity itself holds the permissions.')
param dataAppId string = ''

@description('Module "Access" (PIM, roles, access packages). Optional, off by default.')
param enableAccess bool = false

@description('Daily check for a newer Wardline release (anonymous GET to the GitHub releases API, no tenant data). Wardline never updates itself.')
param updateCheck bool = true

@description('Optional webhook for notifications about new findings (Teams workflow, Power Automate or any HTTPS endpoint accepting JSON).')
@secure()
param notifyWebhook string = ''

@description('Minimum severity of new findings that trigger a notification.')
@allowed(['Critical', 'High', 'Medium', 'Low'])
param notifyMinSeverity string = 'High'

@description('Schedule of the agents module (NCRONTAB, UTC).')
param scheduleAgents string = '0 32 2 * * *'

@description('Schedule of the endpoint module (NCRONTAB, UTC).')
param scheduleEndpoint string = '0 17 2 * * *'

@description('Schedule of the access module (NCRONTAB, UTC).')
param scheduleAccess string = '0 47 2 * * *'

@description('Redundancy of the storage account.')
@allowed([ 'Standard_LRS', 'Standard_ZRS', 'Standard_GRS' ])
param storageSku string = 'Standard_LRS'

param tags object = {
  product: 'Wardline'
}

var suffix = uniqueString(resourceGroup().id, namePrefix)
var cleanPrefix = toLower(replace(namePrefix, '-', ''))
var storageName = empty(customStorageAccountName) ? take('${cleanPrefix}${suffix}', 24) : toLower(customStorageAccountName)
var functionAppName = empty(customFunctionAppName) ? '${namePrefix}-${suffix}' : customFunctionAppName
var runnerIdentityName = empty(customRunnerIdentityName) ? 'id-${namePrefix}-runner' : customRunnerIdentityName
var deployIdentityName = empty(customDeployIdentityName) ? 'id-${namePrefix}-deploy' : customDeployIdentityName
var planName = empty(customPlanName) ? 'plan-${namePrefix}-${suffix}' : customPlanName
var logWorkspaceName = empty(customLogWorkspaceName) ? 'log-${namePrefix}-${suffix}' : customLogWorkspaceName
var appInsightsName = empty(customAppInsightsName) ? 'appi-${namePrefix}-${suffix}' : customAppInsightsName
var modules = 'endpoint${enableAgents ? ',agents' : ''}${enableAccess ? ',access' : ''}'

var roles = {
  storageBlobDataOwner: 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
  storageQueueDataContributor: '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
  storageTableDataContributor: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
  monitoringMetricsPublisher: '3913510d-42f4-4e42-8a64-420c390055eb'
  websiteContributor: 'de139f84-1756-47ae-9be6-808fbbe84772'
}

// ---------- Identity ----------
resource runner 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: runnerIdentityName
  location: location
  tags: union(tags, { 'wardline-component': 'runner' })
}

// ---------- Storage (Entra authentication only) ----------
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: union(tags, { 'wardline-component': 'storage' })
  kind: 'StorageV2'
  sku: {
    name: storageSku
  }
  properties: {
    accessTier: 'Hot'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    allowCrossTenantReplication: false
    publicNetworkAccess: 'Enabled'
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 14
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 14
    }
  }
}

resource containers 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = [for c in [ 'deploymentpackage', 'snapshots', 'state', 'config' ]: {
  parent: blobService
  name: c
  properties: {
    publicAccess: 'None'
  }
}]

resource snapshotImmutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = if (enableImmutability) {
  name: '${storage.name}/default/snapshots/default'
  properties: {
    immutabilityPeriodSinceCreationInDays: retentionDays
    allowProtectedAppendWrites: false
  }
  dependsOn: [
    containers
  ]
}

resource queueService 'Microsoft.Storage/storageAccounts/queueServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource runQueue 'Microsoft.Storage/storageAccounts/queueServices/queues@2023-05-01' = {
  parent: queueService
  name: 'wl-run'
}

resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'snapshots-lifecycle'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: [ 'blockBlob' ]
              prefixMatch: [ 'snapshots/' ]
            }
            actions: {
              baseBlob: {
                tierToCool: {
                  daysAfterModificationGreaterThan: 30
                }
                delete: {
                  daysAfterModificationGreaterThan: retentionDays
                }
              }
            }
          }
        }
      ]
    }
  }
}

// ---------- Monitoring ----------
resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logWorkspaceName
  location: location
  tags: union(tags, { 'wardline-component': 'logs' })
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: union(tags, { 'wardline-component': 'appinsights' })
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logs.id
    DisableLocalAuth: true
  }
}

// ---------- Permissions of the managed identity ----------
resource raBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: storage
  name: guid(storage.id, runner.id, roles.storageBlobDataOwner)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.storageBlobDataOwner)
    principalId: runner.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource raQueue 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: storage
  name: guid(storage.id, runner.id, roles.storageQueueDataContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.storageQueueDataContributor)
    principalId: runner.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource raTable 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: storage
  name: guid(storage.id, runner.id, roles.storageTableDataContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.storageTableDataContributor)
    principalId: runner.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource raMetrics 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: appInsights
  name: guid(appInsights.id, runner.id, roles.monitoringMetricsPublisher)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.monitoringMetricsPublisher)
    principalId: runner.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------- Function App (Flex Consumption, PowerShell 7.4) ----------
resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: planName
  location: location
  tags: union(tags, { 'wardline-component': 'plan' })
  kind: 'functionapp'
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: functionAppName
  location: location
  tags: union(tags, { 'wardline-component': 'functionapp' })
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${runner.id}': {}
    }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
      // Browsers send an Origin header with POST requests (e.g. "Collect now") – also to the own site.
      // Without the own address in the list the platform rejects these requests with 403.
      cors: {
        allowedOrigins: [
          'https://${functionAppName}.azurewebsites.net'
        ]
        supportCredentials: true
      }
      appSettings: [
        { name: 'AzureWebJobsStorage__accountName', value: storage.name }
        { name: 'AzureWebJobsStorage__credential', value: 'managedidentity' }
        { name: 'AzureWebJobsStorage__clientId', value: runner.properties.clientId }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
        { name: 'APPLICATIONINSIGHTS_AUTHENTICATION_STRING', value: 'ClientId=${runner.properties.clientId};Authorization=AAD' }
        { name: 'PSWorkerInProcConcurrencyUpperBound', value: '4' }
        { name: 'WL_CLIENT_ID', value: runner.properties.clientId }
        { name: 'WL_TENANT_ID', value: tenant().tenantId }
        { name: 'WL_STORAGE_ACCOUNT', value: storage.name }
        { name: 'WL_STORAGE_SUFFIX', value: environment().suffixes.storage }
        { name: 'WL_SCHEDULE_ENDPOINT', value: scheduleEndpoint }
        { name: 'WL_SCHEDULE_ACCESS', value: scheduleAccess }
        { name: 'WL_CHANGE_RETENTION_DAYS', value: string(retentionDays) }
        { name: 'WL_DEVICE_INVENTORY', value: deviceInventory ? 'true' : 'false' }
        { name: 'WL_MODULES', value: modules }
        { name: 'WL_FEATURES', value: features }
        { name: 'WL_DATA_APP_ID', value: dataAppId }
        { name: 'WL_UPDATE_CHECK', value: string(updateCheck) }
        { name: 'WL_NOTIFY_WEBHOOK', value: notifyWebhook }
        { name: 'WL_NOTIFY_MIN_SEVERITY', value: notifyMinSeverity }
        { name: 'WL_SCHEDULE_AGENTS', value: scheduleAgents }
      ]
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}deploymentpackage'
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: runner.id
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: 40
        instanceMemoryMB: 2048
      }
      runtime: {
        name: 'powershell'
        version: '7.4'
      }
    }
  }
  dependsOn: [
    raBlob
    raQueue
    raTable
    containers
  ]
}

// Sign-in to the portal: App Service Authentication with the portal app registration (no client secret).
resource auth 'Microsoft.Web/sites/config@2024-04-01' = if (!empty(ssoClientId)) {
  parent: functionApp
  name: 'authsettingsV2'
  properties: {
    platform: {
      enabled: true
    }
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'RedirectToLoginPage'
      redirectToProvider: 'azureactivedirectory'
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          openIdIssuer: '${environment().authentication.loginEndpoint}${tenant().tenantId}/v2.0'
          clientId: ssoClientId
        }
        validation: {
          allowedAudiences: [
            ssoClientId
            'api://${ssoClientId}'
          ]
        }
      }
    }
    login: {
      tokenStore: {
        enabled: false
      }
    }
    httpSettings: {
      requireHttps: true
    }
  }
}

// ---------- Optional: code deployment for the Deploy to Azure button ----------
resource deployer 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (!empty(packageUri)) {
  name: deployIdentityName
  location: location
  tags: union(tags, { 'wardline-component': 'deployer' })
}

resource raDeploy 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(packageUri)) {
  scope: functionApp
  name: guid(functionApp.id, deployIdentityName, roles.websiteContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.websiteContributor)
    principalId: deployer!.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource deployCode 'Microsoft.Resources/deploymentScripts@2023-08-01' = if (!empty(packageUri)) {
  name: 'deploy-${namePrefix}-code'
  location: location
  tags: tags
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${deployer!.id}': {}
    }
  }
  properties: {
    azCliVersion: '2.63.0'
    retentionInterval: 'PT1H'
    cleanupPreference: 'OnSuccess'
    timeout: 'PT30M'
    environmentVariables: [
      { name: 'PACKAGE_URI', value: packageUri }
      { name: 'RG', value: resourceGroup().name }
      { name: 'APP', value: functionApp.name }
    ]
    scriptContent: '''
set -e
curl -fsSL -o /tmp/wardline.zip "$PACKAGE_URI"
# Role assignments take a while to take effect – hence several attempts.
for i in 1 2 3 4 5 6 7 8 9 10; do
  if az functionapp deployment source config-zip -g "$RG" -n "$APP" --src /tmp/wardline.zip; then exit 0; fi
  echo "Attempt $i failed, waiting 30 s ..."; sleep 30
done
exit 1
'''
  }
  dependsOn: [
    raDeploy
  ]
}

output functionAppName string = functionApp.name
output defaultHostName string = functionApp.properties.defaultHostName
output portalUrl string = 'https://${functionApp.properties.defaultHostName}'
output runnerPrincipalId string = runner.properties.principalId
output runnerClientId string = runner.properties.clientId
output modules string = modules
output storageAccountName string = storage.name
