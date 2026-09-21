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
`iac-scanner`'s test fixture actually produces (S3 public access,
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

### Kubernetes (added 2026-09-19)

`cis-kubernetes-2.0.json` is section 5 of the CIS Kubernetes Benchmark
v2.0.0 -- the Policies section, the one a manifest can satisfy or violate;
sections 1-4 audit the control plane and nodes. 18 controls. Ids and titles
were verified against kube-bench's `cfg/cis-2.0/policies.yaml`, which
carries the benchmark's own numbering (the benchmark PDF needs a CIS
WorkBench login and is not redistributable, so the summaries are ours as
above). Section 5 is numbered identically from v1.10 through v2.0; v1.9 and
earlier are *not* the same numbering, so a citation here should not be read
against them.

The 23 new mappings are grounded the same way as the AWS ones: every rule
was raised by the pinned Trivy 0.74.0 and checkov 3.3.16 on PugetScope's
`k8s/` (14 manifests; 239 Trivy findings across 19 rules, 250 checkov across
20). Measured against that scan, **296 of 489 findings (23 of 39 rules) now
have a candidate control.** `:latest` tags and images not pinned by digest
map to the same CNAS-4 / CICD-SEC-9 pair the Terraform module-pinning rules
do, since it is the same problem.

Extended 2026-09-20 with the rules the Kubernetes eval cases raise: 23
more mappings (90 -> 113) and one more control, **5.1.8** (bind, impersonate
and escalate), which `CKV_K8S_157`/`158` need and the first pass did not
carry. These cover the 5.2 family end to end -- privileged, hostPID, hostIPC,
hostNetwork, added capabilities, hostPath, hostPort -- plus wildcard RBAC
(5.1.3). Across those cases **44 of the 51 distinct rules raised now have a
candidate control**.

The 16 unmapped rules are unmapped on purpose, and again they cluster:

- **Resource requests and limits** (`KSV-0011/0015/0016/0018`,
  `CKV_K8S_10-13`; 104 findings) -- not in the CIS Kubernetes Benchmark at
  all. A control gap, like log retention was for AWS, not a missing mapping.
- **Read-only root filesystem** (`KSV-0014`, `CKV_K8S_22`; 28 findings, the
  only unmapped rule Trivy rates HIGH) -- the benchmark reaches it only by
  reference, 5.6.3 pointing at the Docker benchmark's list of security
  contexts. Mapping it to 5.6.3 would be force-mapping: a container with a
  securityContext and a writable root does not violate "apply a
  SecurityContext".
- **High UID/GID** (`KSV-0020/0021`, `CKV_K8S_40`; 42 findings) -- stricter
  than 5.2.7, which asks for not-root, not for UID > 10000.
- **Hygiene** -- liveness probes (`CKV_K8S_8`), `imagePullPolicy: Always`
  (`CKV_K8S_15`), privileged ports (`KSV-0117`).

What the number means for the pipeline: multi-iac-spec §5 warned that the
only thing keeping 239 Kubernetes findings out of remediation was the
*absence* of this corpus. It is no longer absent. 296 findings on one
repository would each be drafted at full price, so the deliberate volume
filter in that section is now due, not deferred.

## Not the corpus: `eval/`

`eval/` is the detection-recall harness for `iac-scanner` (spec §7.1),
not control text. `upload.sh` does not sync it, and nothing at runtime reads
it. See `eval/README.md`.
