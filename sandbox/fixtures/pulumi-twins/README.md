# Pulumi scanner twins

`index.ts` declares nine AWS resources. `twin.tf.template` independently declares
the same resources in Terraform. A `hardened` config switch tightens access,
versioning, KMS rotation/encryption, IMDS and volume encryption, ingress and
CloudTrail. Both scanners still find residual issues in the hardened case;
the test requires exact parity, not an artificially clean result.

Install fixture dependencies, then run from the repository root:

```powershell
npm ci --prefix sandbox/fixtures/pulumi-twins --ignore-scripts --no-audit --no-fund
.venv/Scripts/python scripts/validate_pulumi_adapter.py
```

The validator uses the existing pinned scanner Docker image offline. It captures
both Pulumi variants, converts them on the trusted side, renders each Terraform
twin from the template, and compares `(rule, resource)` pairs. It also requires
hardening to clear findings in both tools. It runs no provider plugins or AWS calls.

Measured with Trivy 0.74.0 and Checkov 3.3.16:

| Variant | Trivy, both twins | Checkov, both twins |
|---|---:|---:|
| Vulnerable | 15 | 25 |
| Hardened | 2 | 11 |

For an AWS run, pass configuration such as
`{"pulumi-adapter-twins:hardened":"true"}` through `sandbox.py pulumi --config`.

Verified through AWS Step Functions/Fargate and the deployed scanner on
2026-10-12: the hardened program captured ten registrations (root stack plus
nine AWS resources), emitted a synthetic plan, and produced exactly 2 Trivy
and 11 Checkov findings with zero parse errors. All 13 findings had distinct
IDs, target type `pulumi`, and creation sites in `index.ts`. The sandbox passed
containment and timeout cleanup, then was switched off.
