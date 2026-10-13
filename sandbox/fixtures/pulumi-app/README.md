# Pulumi sandbox fixture

Two deliberately permissive AWS resources for exercising the existing sandbox
with `pulumi-mock`. Nothing is deployed by this command:

```powershell
.venv/Scripts/python scripts/sandbox.py pulumi sandbox/fixtures/pulumi-app --output pulumi-resources.json --log
```

The fixture has a committed npm lockfile. The fetch task installs dependencies
with lifecycle scripts disabled. The execute task runs its TypeScript under
Pulumi's SDK mocks, without a CLI, state backend, provider plugins or AWS credentials.
The resulting JSON includes the root stack and two custom AWS resources.

Projects must have `Pulumi.yaml` with `runtime: nodejs`, `package.json`,
`package-lock.json` and `@pulumi/pulumi`. CommonJS TypeScript also needs `ts-node`
and `typescript`. JavaScript can use CommonJS or ESM. TypeScript ESM, npm
workspaces and asynchronous resource transforms are currently unsupported.
The entrypoint comes from Pulumi's `main`, then the directory's package `main`,
then an index file. Runtime command hooks are not run.

Supply configuration explicitly using `--config config.json`, containing
fully qualified keys and string values, for example:

```json
{"sandbox-pulumi-fixture:environment": "test"}
```

Stack YAML, ESC environments and encrypted secrets are not loaded. Use only
test configuration: Step Functions records its input, and a program can print
anything it receives. Pulumi-marked secret inputs are redacted in resources.json.

Lookups require `--mock-calls calls.json`. Each token maps to a list of exact
input/output fixtures; key order is ignored:

```json
{
  "aws:ec2/getVpc:getVpc": [
    {"inputs": {"id": "vpc-test"}, "outputs": {"id": "vpc-test", "cidrBlock": "10.0.0.0/16"}}
  ]
}
```

Unmatched lookups fail visibly. IDs are mock values; provider defaults and real
cloud state are unavailable. This is mock evaluation rather than a deployment
test. The trusted adapter now generates Terraform plan JSON and `--scan` sends
it to Trivy and Checkov:

```powershell
.venv/Scripts/python scripts/sandbox.py pulumi sandbox/fixtures/pulumi-app --scan --log
```

The command saves resources, a `.pulumi.plan.json` plan and `.findings.json`
results beside `--output`. Findings identify the Pulumi source line when known.
Scanning does not persist findings or draft fixes. Pulumi remediation and
automatic GitHub project detection are not implemented.

The adapter currently supports **@pulumi/aws 7.48.0** and 13 Terraform-backed
resource types: S3 bucket, public access block, versioning, encryption and
logging; KMS key; EC2 instance, security group, VPC and subnet; CloudTrail;
IAM role and policy. Its versioned metadata lives in
`lambda/sandbox-dispatch/aws-bridge.json`, with the upstream URL and SHA-256.
Other versions/types/providers reject the whole conversion. Legacy resource
captures must be rerun to capture SDK dependency URNs. No links are inferred
from matching string values. Mock output IDs become unknown plan values with
references; nested blocks retain Terraform's list shape and expression tree.
Redacted secret values and dependencies in whole blocks or nested collections
that cannot be represented precisely are reported unsupported rather than
scanned as an empty/partial plan.
Component resources, including `awsx` remote components, are currently
unsupported: mocks cannot guarantee that their underlying infrastructure was
expanded. The root stack and provider registrations are skipped normally.

See `sandbox/fixtures/pulumi-twins/README.md` for the independent scanner twins.

Build and deploy using the existing `sandbox/image/build-image.sh`, then
`scripts/sandbox.py up --yes`. Every changed image must pass
`scripts/sandbox.py leak-test` before use. Shut down with
`scripts/sandbox.py down --yes` when finished.

Local verification:

```powershell
cd sandbox/fixtures/pulumi-app
npm ci --ignore-scripts --no-audit --no-fund
cd ../../..
node --test sandbox/image/pulumi-mock.test.mjs
```

Run the harness tests with Node 22 or newer, matching the sandbox image.

Verified on AWS on 2026-10-12: the updated image passed both containment phases
and timeout cleanup. This fixture installed 240 packages with scripts disabled
in 13 seconds, then executed successfully through `sandbox-run`. The captured
output held the root stack and both AWS resources, with creation sites at
`index.ts:5` and `index.ts:8`. The sandbox was switched off after validation.
