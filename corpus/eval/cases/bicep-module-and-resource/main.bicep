param location string = 'eastus'

resource stg 'Microsoft.Storage/storageAccounts@2021-09-01' = {
  name: 'stgevalmodule'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: false
  }
}

module networking 'net.bicep' = {
  name: 'networking'
  params: {
    location: location
  }
}
