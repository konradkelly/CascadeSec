# External-repository scans for `iac-scanner`

The labelled corpus in `../eval` measures recall. Every case in it was
written by someone who already knew what the scanner looks for, so it
cannot say how the scanner behaves on Terraform nobody here wrote. This
directory points the same **deployed** function at third-party repositories
and records what a label cannot: parse errors on real module trees, wall
time against the function's timeout, mapping coverage on the real long tail
of rules, and the finding load on a repository that is meant to be clean.

```
python run_external.py                    # every repo in repos.json
python run_external.py terragoat          # one, by name or unique substring
python run_external.py --report out.json  # keep every finding, per repo
python run_external.py --baseline         # accept this run's counts as the new baseline
```

Needs `git`, `boto3`, AWS credentials for the dev account, and the
`terraform` CLI on `PATH` (only to read the bucket name; `--bucket` skips
it). Repositories are cloned into `.repos/` (gitignored) at the commit
`repos.json` pins, and nothing from them is committed here.

No recall number comes out, because there are no labels. Each repository
instead carries a **baseline** -- file count, raw findings, distinct
finding ids, distinct rules, scan errors -- and a later run reports any
difference as drift. The commit is pinned and the tools are pinned in the
image, so the scan is deterministic (verified: two runs of terragoat on
2026-09-18 matched exactly) and drift means the scanner changed.

## Result, 2026-09-18

Trivy 0.74.0 + Checkov 3.3.16 + `IACP-0001`, scan stage only. Arrows are
before → after the two changes the run motivated, made the same day:
the scanner's memory raised to 3008 MB, and 16 rules added to
`rule_mappings.json`. Findings were identical across all four scans.

| repository | files | time | findings (distinct ids) | rules | mapped | scan errors |
|---|---|---|---|---|---|---|
| `bridgecrewio/terragoat` `terraform/aws` | 14 | 26s → 10s | 333 (329) | 144 | 35/144 — 24% → 50/144 — 35% | 0 |
| `terraform-aws-modules/terraform-aws-vpc` | 77 | **265s** → 139s | 58 (21) | 10 | 4/10 — 40% → 50% | 0 |
| `gruntwork-io/terragrunt-infrastructure-live-example` | 0 | — | not scanned | | | |

### Parse robustness held

Zero scan errors on both repositories, including terraform-aws-vpc's 1,500-line
root module (`for_each`, `dynamic`, provider aliases, ~100 variables) and its
thirteen `examples/` roots that instantiate it.

### terraform-aws-vpc ran to 265s of a 300s timeout

Not the file count. Reproduced in the scanner image locally: Trivy takes 5s
on this repo and Checkov 55s, and Checkov's time is the module expansion --
the root `*.tf` alone is 5–7s, and every `examples/*` directory that says
`source = "../../"` adds ~3s to rebuild the root module's graph again.
Thirteen examples make thirty such instantiations. Lambda at 1024 MB gets
roughly 0.6 of a vCPU, so 55s of CPU becomes 264s of wall time; peak memory
was 844 MB of 1024.

A larger module repository with an `examples/` tree (terraform-aws-eks,
eks-blueprints) would not have finished. The lever is `memory_size` in
`terraform/lambda_iac_scanner.tf`: Lambda's CPU share scales with memory,
so 3008 MB is ~1.7 vCPU. Applied the same day: vpc 265s → 139s and
terragoat 26s → 10s, peak memory unchanged at 837 MB (so the extra memory
buys CPU, nothing else), identical findings. Less than the 3× the CPU ratio
predicts -- Checkov is not perfectly single-threaded-CPU-bound -- but the
scan now finishes with half the timeout to spare rather than a tenth.

### Finding counts overstate what a reviewer sees

Trivy and Checkov report a module's resource once per instantiation, so
terraform-aws-vpc's `aws_vpc` at `main.tf:28-53` came back 14 times from
Trivy (`AWS-0178`) and 12 from Checkov (`CKV2_AWS_12`). `_write_findings`
keys on `finding_id`, which hashes the location, so DynamoDB holds 21 and
that is what mapping-agent and the dashboard see. Only the scan's
`finding_count` and the `FindingsPerScan` metric carry the 58. terragoat,
with no modules, is 333 → 329.

### Mapping coverage on real Terraform is lower than the corpus suggested

`../eval` reports 39% of distinct rules fired having a candidate control.
On terragoat it is 24%, and 256 of its 333 findings would reach a reviewer
as "raw". The unmapped tail is dominated by RDS (`CKV_AWS_96`, `_324`,
`_325`, `_326`, `_327`, `_162`, `_139`, `CKV2_AWS_8`, `AWS-0079`,
`AWS-0343`, nine each -- terragoat has nine database resources) and S3
(`AWS-0091`/`0093`/`0094` public-access-block settings, `CKV_AWS_144`
replication, six each). The three
frameworks loaded have no control for most of these; the full tail is in
`--report` output.

Sixteen rules were added the same day, each next to an existing precedent
rather than a new judgement: the Aurora-cluster forms of the RDS encryption
checks (CIS 2.3.1), the remaining S3 Block Public Access settings (2.1.5),
instance and launch-configuration EBS encryption (2.2.1), NACLs open to
SSH/RDP (5.1, the twin of 5.2 where `AWS-0107` sits), IMDSv1 (CNAS-1, like
the public-IP defaults), internet-facing load balancers and Elasticsearch
outside a VPC (CNAS-6, like RDS/Redshift public access), secrets in Lambda
environment variables (CNAS-5 + CICD-SEC-6, like `CKV_SECRET_*`), and
mutable ECR tags (CNAS-4 + CICD-SEC-9, like `CKV_TF_1`). That moved
terragoat to 35% of rules and 127 of 333 findings mappable, vpc to 50%.

What stays unmapped is deliberate and is most of the remaining tail:
deletion protection, backups and backtracking, audit and slow-query
logging, IAM database authentication, CMK-rather-than-any encryption,
log retention, copy-tags-to-snapshot, EKS control-plane logging, and
descriptions on security groups. None of the three frameworks loaded has a
control those violate, and the corpus README's rule is that a finding with
no confident control stays raw rather than being forced onto one. Loading
a framework that does have them (CIS AWS 3.0's RDS section, or AWS FSBP)
is the way to move the number further, not stretching CNAS-1.

### What a clean repository raises

terraform-aws-vpc is well maintained and raised 21 distinct findings, none
wrong but almost all hygiene the examples deliberately omit: VPC flow logs
not enabled (`AWS-0178`, `CKV2_AWS_11`), default security group
unrestricted (`CKV2_AWS_12`), log retention under a year (`CKV_AWS_338`),
and `CKV_TF_1` on registry modules pinned by `version`, which cannot carry
a commit hash. These are what a reviewer's queue looks like on a real PR
when there is nothing seriously wrong, and the argument for severity-aware
ordering in the dashboard.

### Remediation on code nobody here wrote

`ec2.tf`, `eks.tf`, `ecr.tf` and `providers.tf` from terragoat (plus
`consts.tf` for the variables), 73 findings, through the full pipeline
with `scripts/scan.py --yes`. Three things came out, two of them fixed the
same day.

**mapping-agent could not finish a real PR.** One model call per finding
in sequence, ~3s each; 47 findings had candidates and the function's
timeout was 120s. It was killed mid-loop with 38 mapped, and the
execution failed with it -- nothing reached remediation. It now yields
before its clock runs out, the way remediation-agent already did, and the
state machine loops `MapToControls` while `remaining` > 0; the timeout is
300s so most PRs still take one pass. A pass that maps nothing does not
ask for another (the failed findings would be first in line again). The
re-run mapped all 47 in 152s.

**Every fix to `eks.tf` was rejected for a finding it did not introduce.**
11 of 11 came back `needs-human-only` with `trivy:AWS-0038` (EKS
control-plane logging) among the "new" findings -- a rule that was on the
cluster in the original scan. Trivy reports it once per missing log type,
five times at one line range. `_write_findings` keeps one record per id,
and an id hashes the location, so the table held 1; the self-check counted
the rescan raw and saw 5, and the difference was "four new findings" on
every fix. remediation-agent now counts rescans by finding id, as the
table does. Re-run on `eks.tf` + `consts.tf` alone after the fix: 1
`fix-proposed`, 6 `needs-human-only`, 4 superseded, and `AWS-0038` no longer
appears as a new finding on any of them. The six held are held for real
reasons -- five state an assumption, one (`CKV2_AWS_11`, flow logs) added
an IAM role whose policy raised three genuinely new findings, one did not
clear.

**On real code, almost every fix is held for a human -- and correctly.**
Of 33 findings remediation reached, 1 was `fix-proposed`, 21
`needs-human-only`, 11 superseded by an earlier fix in the file. The 21
were held because the scanner accepted the fix but the model stated an
assumption, and the assumptions are the right ones: enabling encryption
on an attached volume forces its replacement; IMDSv2 breaks software that
only speaks v1; a Marketplace AMI can refuse an encrypted root; tightening
egress to 80/443 drops NTP. The fixture cases never had consequences like
these, so `fix-proposed` was the common outcome there. On infrastructure
someone runs, `needs-human-only` with a stated assumption is the normal
outcome and the reviewer's job is to answer the assumption -- the
dashboard should present it that way rather than as a lesser result.

**What a run costs, measured.** The three agents now log every model
call's `usage` as an EMF metric (`InputTokens`, `OutputTokens`, cache
counters; dimensions `Agent`, `Environment`), so a run's spend is a
CloudWatch sum. The `eks.tf` re-run, at Opus 5 first-party rates
($5/M in, $25/M out):

| agent | calls | input | output | cost |
|---|---|---|---|---|
| mapping-agent | 11 | 6.3k | 1.8k | $0.08 |
| remediation-agent | 13 | 72.3k | 63.9k | $1.96 |
| context-agent | 17 | 46.4k | 4.3k | $0.34 |
| **total** | 41 | 125k | 70k | **$2.37** |

Remediation's output is the bill: ~4.9k output tokens per call, because
the schema asks for the whole rewritten file, and output is five times the
price of input. Returning a diff or the replaced block instead is the lever
that matters; prompt caching the file across a chain's calls is the next
one (input is 70% of tokens but 30% of cost). The full five-file slice
above was roughly three times this run.

The last 14 findings on `ec2.tf` errored: the Anthropic account's credit
ran out mid-run (`400 credit balance is too low`). They are still
`mapped`; `scan.py --stages remediate` on the same PR id retries them.
Each failed in ~4s and the file's pass ended cleanly with the count, which
is the behaviour wanted from a persistent fault.

### Terragrunt is not scanned at all

The repository holds `terragrunt.hcl` files and no `.tf`, so nothing
matches `SNAPSHOT_SUFFIXES` and the runner reports that without uploading.
Left in the manifest as the record of a repository shape v1 does not
handle.

## Adding a repository

Add an entry to `repos.json` with `sha: null`, then run
`python run_external.py <name> --pin --baseline` to resolve the default
branch's tip, scan it, and record both. Prefer a `subdir` when the
repository holds several independent roots (terragoat has one per cloud)
so the baseline describes one thing.
