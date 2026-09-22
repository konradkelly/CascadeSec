param location string = 'eastus'

resource stg 'Microsoft.Storage/storageAccounts@2021-09-01' = {
  name: 'stgevalinsecure'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: false
    minimumTlsVersion: 'TLS1_0'
  }
}
