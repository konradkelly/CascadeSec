# cdk-app

The CDK app the multi-iac probes used (docs/multi-iac-spec.md §7.2 a), kept
so the sandbox's cdk-synth kind has a known app to run:

    python scripts/sandbox.py synth sandbox/fixtures/cdk-app

Three deliberate defects, each made on a line a finding should come back to:

| Defect | Construct | Expected source line |
|---|---|---|
| A bucket on defaults: no encryption settings, versioning or logging | `Data` | `lib/storage.ts:6` |
| SSH open to `0.0.0.0/0` | `Net/Ssh` | `lib/network.ts:8`, and `:9` for the ingress rule |
| A `*:*` managed policy | `AdminPolicy` | `lib/stack.ts:12` |

The VPC's own resources (subnets, routes) trace to `lib/network.ts:7`, the
`new ec2.Vpc` line. Measured 2026-10-10 against the scanner image: 41
findings across Trivy, checkov and KICS, every one placed on one of these
lines, and the one template-wide finding (KICS's Access Analyzer check) on
the stack's own line, `bin/app.ts:4`.
