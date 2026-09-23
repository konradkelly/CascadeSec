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

  A candidate may carry an optional **`target_type`**, which offers it only
  to findings from that target:

  ```json
  "checkov:CKV_SECRET_6": [
    { "framework": "OWASP-CloudNative",   "control_id": "CNAS-5" },
    { "framework": "CIS-Kubernetes-2.0",  "control_id": "5.4.2",
      "target_type": "kubernetes" }
  ]
  ```

  A candidate without the field applies to every target, which is most of
  them — the field is only needed for a rule that fires on more than one
  language. Added 2026-09-20; see below.

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

Extended again 2026-09-20 with `5.4.2` (consider external secret storage)
and a mapping for `IACP-0002`, this project's own check for a literal
credential in a container `env` (see `eval/README.md`). `IACP-0002` maps to
`5.4.1` plus the `CNAS-5`/`CICD-SEC-6` pair the other hardcoded-secret rules
use.

**`5.4.2` is cited through a scoped candidate, which is why that field
exists.** The finding that wants it is a Secret committed with a plaintext
`stringData`, which raises `CKV_SECRET_6` -- and that rule fires on
Terraform too, so before scoping the control could only be added to both
languages or neither. Adding it to both would have offered a Kubernetes
control as a candidate for a `.tf` finding, which is force-mapping by a
different route. `CKV_SECRET_6` now carries `CNAS-5` and `CICD-SEC-6` for
every target and `5.4.2` for Kubernetes alone.

Two things follow, and both are tested. A `target_type` that does not exist
is the worst typo this file can hold -- the candidate is silently never
offered, the finding stays `raw`, and nothing reports an error, so it looks
exactly like a rule nobody mapped; `test_a_scoped_candidate_names_a_target_type_that_can_exist`
catches it. And a finding written before the `target_type` split carries
none, so it is offered universal candidates only: withholding a control is
the safe direction when the language is unknown.

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

### Azure: ARM and Bicep (added 2026-09-22)

`cis-azure-3.0.json` is the part of the CIS Microsoft Azure Foundations
Benchmark v3.0.0 that a deployment template can satisfy or violate: 3.3 (Key
Vault), 4 (Storage), 5.1 and 5.3 (SQL and MySQL), 7 (Networking), 8 (Virtual
Machines) and 9 (App Service). 29 controls. Sections 1-2 audit Entra and the
directory, and 3.1 audits the subscription's Defender plans; no template rule
could ever cite either, so they are absent for the same reason sections 1-4 of
CIS Kubernetes are. Ids and titles were verified against Prowler's
`compliance/azure/cis_3.0_azure.json`, which carries the benchmark's own
numbering and plays the role kube-bench's config plays for Kubernetes.

**The edition is part of the citation here, which it was not for Kubernetes.**
CIS Kubernetes section 5 is numbered identically from v1.10 to v2.0, so that
file could take the current edition and the choice did not change a citation.
Azure is not like that. v4.0.0 is current, and we deliberately did not take it:
it renumbers every storage control -- 4.1 "Secure transfer required" becomes
10.3.4 -- and it drops the SQL auditing controls outright. 5.1.1 and 5.1.6 have
no v4.0 equivalent; its only SQL entries are Defender plans and Activity Log
Alerts, both subscription-level and invisible to a template. Auditing is among
the highest-volume families the pinned scanners raise on Azure templates, so
citing v4.0 would have meant leaving it unmapped in exchange for nothing. A
citation in this file should not be read against v4.0.

The 50 new candidates are grounded the same way as the AWS and Kubernetes ones:
every rule was observed firing from the pinned Trivy 0.74.0 and checkov 3.3.16,
run from the deployed scanner image over `Azure/azure-quickstart-templates`
(sha `17d3abd`, the storage, keyvault, sql and network quickstarts -- 175 ARM
templates and 107 Bicep files). That scan raised **1270 findings across 98
distinct rules**: Trivy 264 across 30, checkov 1006 across 68 (640 `arm`, 366
`bicep`). Measured against it, **809 of 1270 findings (46 of 98 rules) now have
a candidate control.**

Two measurements from that run worth keeping.

**Trivy produced a result for 92 of the 175 ARM templates.** Checked
2026-09-23 rather than left as a worry: the other 84 declare resource types
Trivy has no Azure checks for -- 44 virtual networks, 32 public IPs, 15
application gateways -- and `--debug` reports `[rego] Scanning inputs count=1`
for them, so they are parsed and scanned and match nothing. Exactly one of the
84 declares something checkable, and it is a `vaults/accessPolicies` child
rather than a vault. So this is ordinary coverage, not a silent skip.

What does still hold is why the scanner parses ARM itself rather than widening
a stderr regex: Trivy emits no parse error for ARM at all (multi-iac-spec §4).
checkov reported 8 real `parsing_errors` on the same tree, 4 ARM and 4 Bicep,
which is that path working as intended.

**checkov reports no severity on Azure either.** All 1006 checkov findings carry
`severity: None`, as all 250 Kubernetes ones did. The §5.1 conclusion that a
severity floor is Trivy-only in practice holds unchanged for a second cloud.

#### Four Trivy rules that an ARM template cannot satisfy

Found while building the eval cases, and the reason three of them are
deliberately *not* mapped even though they fire constantly.

`AZU-0056` (blob soft delete), `AZU-0057` (storage logging), `AZU-0058`
(geo-redundant replication) and `AZU-0013` (Key Vault network ACLs) cannot be
cleared by configuring the thing they name.

Measured two ways on 2026-09-23. **Trivy's own `--include-non-failures` over
all 175 templates: `AZU-0057` is 0 PASS / 25 FAIL, `AZU-0058` 0 PASS / 25
FAIL, `AZU-0013` 0 PASS / 13 FAIL.** Not one real template satisfies any of
them. `AZU-0056` does show 7 passes, but every one is a storage account that
declares *nothing* about blobs -- the vacuous case -- and every template that
actually configures `deleteRetentionPolicy` alongside a realistic
`properties` block fails it, including with 365-day retention. So its pass is
not reachable from a failing state by any benign edit, which is the same
practical outcome.

**Why**, from dumping the adapted state a Rego check actually receives: the
ARM adapter populates the fields it reads out of `properties` --
`minimumtlsversion` comes back `TLS1_2`, `enforcehttps` `true` -- and leaves
the rest empty. On a fully hardened template `accountreplicationtype` is
`""` despite `"sku": {"name": "Standard_GRS"}`, and `queueproperties.
enablelogging` is `false` despite a `queueServices` child configuring it.
The adapter does not read `sku` (a sibling of `properties`) or the child
resources. The same intent in Terraform clears all of them, so the checks are
correct and the adapter is not.

*A second earlier claim, also withdrawn: that Trivy "claimed only 92 of the
175 templates" was offered as corroboration. It is not evidence of anything.
The other 84 declare resource types Trivy has no Azure checks for -- 44
virtual networks, 32 public IPs, 15 application gateways -- and `--debug`
confirms they are parsed and scanned. They match nothing because there is
nothing to match.*

*An earlier version of this section said a template using `Standard_LRS`
"escapes" `AZU-0058`. That was read off the failure list, where a check that
was never evaluated looks the same as one that passed. The pass/fail census
above is the right instrument and shows no passes at all.*

`AZU-0058` was never mapped (geo-redundancy is availability, not a CIS
control). The other three were, and were **unmapped again on 2026-09-22**.
The reason is remediation, not tidiness: a mapped finding is drafted, and a
finding that cannot be cleared by any edit to the file would be drafted,
self-checked, failed and redrafted on every run -- spending model calls and
reviewer attention on a fix that cannot exist. Unmapped, they still appear in
the findings list at status `raw`, which is the honest outcome: the scanner
reported something, we are not hiding it, and we are not pretending we can
fix it. §8.1 is untouched.

Revisit on the next Trivy bump. If the adapter starts reading these
properties, the mappings are four lines.

#### What is not mapped, and why

52 rules, 461 findings. Clustered, they are:

- **No CIS control exists for it.** The largest group. `CKV_AZURE_178`/`1`/`149`
  and `AZU-0039` (123 findings) all want SSH keys rather than password
  authentication on a VM -- v3.0 section 8 has no such control, which is a gap
  in the benchmark rather than a missing mapping. Same for
  `CKV_AZURE_43` (storage account naming, 53) and `CKV_AZURE_216` (Azure
  Firewall DenyIntelMode, 25).
- **Availability, not security.** `CKV_AZURE_206` and `AZU-0058` (74 findings)
  want geo-redundant replication, and `CKV_AZURE_229`/`225` want zone
  redundancy. Real advice, no CIS control, and mapping them to one would be
  force-mapping.
- **A control exists but for a different resource.** `CKV_AZURE_52` (MSSQL TLS,
  16) and `AZU-0026` (generic database minimum TLS, 13) have no MSSQL
  equivalent of 5.3.2, which is MySQL-specific by its own wording. Mapping
  either to 5.3.2 would cite a control about a different service. The two rules
  that *are* explicitly MySQL, `CKV_AZURE_28` and `CKV_AZURE_54`, are mapped to
  5.3.1 and 5.3.2 and were the reason those two controls were vendored.
- **Threat-detection and alerting** (`CKV_AZURE_25`/`26`/`27`, `AZU-0018`/`0023`;
  24 findings) are Defender and notification settings. v3.0 has them in 3.1,
  which is deliberately not vendored: those controls audit the subscription,
  and these rules audit a template's `securityAlertPolicies`. Adjacent, not the
  same claim.
- **AKS, App Gateway, Front Door, ACR and API Management** (~40 findings across
  20 rules) -- services v3.0 does not cover at all.
- **Hygiene** -- Key Vault secret content types (`AZU-0015`, `CKV_AZURE_114`),
  HSM-backed keys (`CKV_AZURE_112`), health checks, DNS endpoint counts.

Closing the first three needs new framework content rather than new mappings,
and that is the judgement call the top of this file describes: a control's
`text` is quoted as ground truth, so writing one is not a mechanical step.

## Not the corpus: `eval/`

`eval/` is the detection-recall harness for `iac-scanner` (spec §7.1),
not control text. `upload.sh` does not sync it, and nothing at runtime reads
it. See `eval/README.md`.
