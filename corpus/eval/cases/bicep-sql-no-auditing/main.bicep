param location string = 'eastus'

@secure()
param adminPassword string

resource sql 'Microsoft.Sql/servers@2021-11-01' = {
  name: 'sql-eval-noaudit'
  location: location
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: adminPassword
    publicNetworkAccess: 'Enabled'
  }
}
