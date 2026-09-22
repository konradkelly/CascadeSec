param location string = 'eastus'

resource kv 'Microsoft.KeyVault/vaults@2021-10-01' = {
  name: 'kv-eval-nopurge'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    accessPolicies: []
    enableSoftDelete: false
    enablePurgeProtection: false
  }
}
