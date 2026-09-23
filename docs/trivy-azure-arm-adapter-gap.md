# Trivy's `azure-arm` adapter does not populate every field its own checks read

**Status: drafted, not filed.** This is written as a Trivy issue so it can be
submitted as-is. It is kept here because `lambda/iac-scanner/handler.py`
(`ARM_UNSATISFIABLE_TRIVY_RULES`) drops four rule ids on ARM targets on the
strength of it, and that exception should not outlive the bug that justifies
it.

Measured 2026-09-23 against **Trivy 0.74.0**, the current release at the time
of writing, as packaged in this project's scanner image.

---

## Summary

Several Azure storage and Key Vault checks can never pass when the input is
an ARM template, because the ARM adapter leaves the fields those checks read
at their zero values regardless of what the template declares. The checks
themselves are correct — the identical configuration expressed in Terraform
passes all of them.

Affected in this measurement:

| rule | what it reads | ARM adapter supplies |
|---|---|---|
| `AZU-0058` | storage account replication type | `accountreplicationtype` = `""` |
| `AZU-0057` | queue/blob/table logging | `queueproperties.enablelogging` = `false` |
| `AZU-0056` | blob soft delete retention | `blobproperties.deleteretentionpolicy` with no scalar |
| `AZU-0013` | Key Vault network ACLs | network rule block not populated |

## Reproduction

`azuredeploy.json` — a storage account that satisfies all of the above:

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type": "Microsoft.Storage/storageAccounts",
    "apiVersion": "2021-09-01",
    "name": "s",
    "location": "eastus",
    "sku": { "name": "Standard_GRS" },
    "kind": "StorageV2",
    "properties": {
      "supportsHttpsTrafficOnly": true,
      "minimumTlsVersion": "TLS1_2",
      "allowBlobPublicAccess": false,
      "encryption": {
        "requireInfrastructureEncryption": true,
        "services": { "blob": { "enabled": true } },
        "keySource": "Microsoft.Storage"
      },
      "networkAcls": { "defaultAction": "Deny", "bypass": "AzureServices" }
    },
    "resources": [{
      "type": "blobServices",
      "apiVersion": "2021-09-01",
      "name": "default",
      "properties": { "deleteRetentionPolicy": { "enabled": true, "days": 30 } }
    }]
  }]
}
```

```
trivy config . --misconfig-scanners azure-arm --include-non-failures
```

**Expected:** all storage checks PASS.

**Actual:** nine PASS, three FAIL.

```
AZU-0008  PASS   secure transfer
AZU-0011  PASS   minimum TLS version
AZU-0012  PASS   default network action
AZU-0061  PASS   infrastructure encryption
AZU-0056  FAIL   blob soft delete            <-- deleteRetentionPolicy is set
AZU-0057  FAIL   storage logging             <-- configured below
AZU-0058  FAIL   geo-redundant replication   <-- sku is Standard_GRS
```

The split is the diagnosis: **every check that reads a field under
`properties` passes, and every check that reads something else fails.**
`sku` is a sibling of `properties`, and blob/queue settings live in child
resources. Neither is reached.

Adding a `queueServices` child with a full `logging` block does not change
`AZU-0057`. Raising `deleteRetentionPolicy.days` to 365 does not change
`AZU-0056`. Moving the `blobServices` child to a top-level
`Microsoft.Storage/storageAccounts/blobServices` resource does not change it
either.

## The adapted state, directly

A custom Rego check on `schema["cloud"]` (selector `type: cloud`, provider
`azure`, service `storage`) run against the template above reports:

```
replication=""  enablelogging=false  mintls="TLS1_2"  enforcehttps=true
```

`minimumtlsversion` and `enforcehttps` arrive correctly. `accountreplicationtype`
is empty on a template that declares `Standard_GRS`.

## The same configuration in Terraform

```hcl
resource "azurerm_storage_account" "hardened" {
  name                       = "stghardened"
  resource_group_name        = "rg"
  location                   = "eastus"
  account_tier               = "Standard"
  account_replication_type   = "GRS"
  https_traffic_only_enabled = true
  min_tls_version            = "TLS1_2"
  queue_properties { logging { delete = true, read = true, write = true, version = "1.0", retention_policy_days = 30 } }
  blob_properties { delete_retention_policy { days = 30 } }
  network_rules { default_action = "Deny", bypass = ["AzureServices"] }
}
```

`AZU-0056`, `AZU-0057` and `AZU-0058` all pass. So the checks are right and
the ARM adapter is where the gap is.

## Scale

Over 175 real ARM templates from `Azure/azure-quickstart-templates`
(`17d3abd`, the storage/keyvault/sql/network quickstarts), with
`--include-non-failures`:

| rule | PASS | FAIL |
|---|---|---|
| `AZU-0057` | 0 | 25 |
| `AZU-0058` | 0 | 25 |
| `AZU-0013` | 0 | 13 |
| `AZU-0056` | 7 | 24 |

`AZU-0056`'s seven passes are all storage accounts that declare nothing about
blobs at all — the vacuous case. Every template that actually configures
`deleteRetentionPolicy` fails, so the pass is the say-nothing default rather
than a state a correction can reach.

Together these are 87 of the 264 `azure-arm` findings on that corpus, a third
of the output, none of it actionable.

## Not part of this report

Trivy reports `Detected config files num=92` for the 175 templates, which
looks like a second gap and is not one. The other 84 declare resource types
Trivy has no Azure checks for — 44 `virtualNetworks`, 32 `publicIPAddresses`,
15 `applicationGateways` and so on. `--debug` shows `[rego] Scanning inputs
count=1` for them, so they are parsed and scanned and simply match nothing.
Only one of the 84 declares anything checkable, and that is a
`Microsoft.KeyVault/vaults/accessPolicies` child rather than a vault.

## What this project did meanwhile

Dropped the four ids for ARM targets only, in the scanner's normalisation
step, pinned to Trivy 0.74.0 and covered by a test that fails if they are
still mapped to a control. They remain enabled for Terraform. If the adapter
is fixed, that list should be deleted and the eval re-run.
