# Control corpus

Reference text `mapping-agent` cites when it maps a raw finding to a control
(spec §4.4 step 4, §6). Lives in S3 under `corpus/` on the artifacts bucket;
`upload.sh` syncs this directory there.

## Structure

- `frameworks/*.json` — one file per framework. Each control has a
  `control_id`, `title`, and short `text` description.
- `rule_mappings.json` — maps a scanner finding's `(source, rule_id)` to
  candidate controls. `mapping-agent` looks a finding up here first and only
  asks the LLM to pick/cite/explain among those candidates, rather than
  letting it freely guess a control_id from scratch — this is what keeps
  citations grounded instead of hallucinated.

## On the control text

The `text` field in each framework file is an **original summary I wrote**,
not a verbatim quote from the official CIS or OWASP documents — CIS Benchmark
text in particular isn't freely redistributable. Control IDs, titles, and
framework versions were verified against the sources listed in each file's
`source` field; the summaries are accurate to the control's actual meaning
but are our own wording, not a copy of the official text.

## Coverage

Only 9 CIS-AWS-1.4 controls, 4 OWASP-CloudNative items, and 2
OWASP-CICD-Top10 items are included — enough to cover the finding types
`terraform-scanner`'s test fixture actually produces (S3 public access,
encryption, logging; open security-group ingress), plus IaC-relevant items
(secrets storage, module pinning) not yet exercised by the fixture. This is
deliberately partial, not the full benchmarks: `rule_mappings.json` only maps
rule_ids we've actually observed rather than guessing ahead of evidence, and
a scanner rule with no confident mapping (e.g. pure hygiene checks like
"add a description to this security group rule") is left unmapped rather
than forced onto a control it doesn't really violate. Extend both files as
new rule_ids turn up in real scans.

## Coverage

51 rules mapped, against 16 CIS controls and the two OWASP lists. Measured
against `eval/`, whose 45 cases were all observed in a real scan:
**47 of 64 labelled `(source, rule_id)` pairs have a candidate control (73%)**,
from 9 rules before 2026-09-12. (Re-keyed from tfsec to Trivy ids the same
day, which also retired one mapped rule: Trivy deprecated
`aws-iam-no-policy-wildcards` and nothing replaces it.)

| category | mapped |
|---|---|
| missing-encryption | 10/21 |
| network-exposure | 17/18 |
| logging-monitoring | 8/10 |
| iam-over-permissioning | 5/8 |
| hardcoded-secrets | 5/5 |
| unpinned-modules | 2/2 |

The 17 unmapped pairs are unmapped on purpose, and they cluster:

- **Encryption at rest for resources CIS AWS 1.4 does not cover** — SNS, SQS,
  DynamoDB, EFS, Lambda environment variables, CloudWatch log groups. The
  benchmark has controls for S3, EBS, RDS and CloudTrail and stops there.
  Mapping these to a general "insecure configuration" control would be
  force-mapping.
- **Cloudsplaining IAM findings** (`CKV_AWS_286`, `CKV_AWS_287`) — privilege
  escalation and credentials exposure. CIS 1.16 is specifically about
  `"*:*"` admin policies, which is narrower than what these match.
- **Log retention** (`CKV_AWS_66`, `CKV_AWS_338`) — a real control gap rather
  than a missing mapping.

Closing those needs new framework content, not new mappings, which is a
different judgement call: the `text` of a control is what `mapping-agent`
cites verbatim, so adding one means writing text that will be quoted as
ground truth.

## Not the corpus: `eval/`

`eval/` is the detection-recall harness for `terraform-scanner` (spec §7.1),
not control text. `upload.sh` does not sync it, and nothing at runtime reads
it. See `eval/README.md`.
