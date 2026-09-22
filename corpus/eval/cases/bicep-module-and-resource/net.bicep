param location string

resource vnet 'Microsoft.Network/virtualNetworks@2021-05-01' = {
  name: 'vnet-eval'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
  }
}
