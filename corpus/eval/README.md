# Detection-recall eval for `iac-scanner`

Spec §7.1, §8.2 item 1. Labelled cases with known injected
vulnerabilities -- Terraform, OpenTofu and (since 2026-09-20) Kubernetes --
one command that scans them against the **deployed** scanner and reports what
fraction of the expected findings fired.

```
python run_eval.py                          # bucket from `terraform output`
python run_eval.py --report results.json    # keep the full per-case result
python run_eval.py --keep                   # leave the S3 prefix for inspection
```

Needs `boto3`, AWS credentials for the dev account, and the `terraform` CLI on
`PATH` (only to read the bucket name; pass `--bucket` to skip it).

## Result

**98.9% — 178 of 180 expected findings, across 84 positive cases and 6 clean
controls.** Run 2026-09-23 against the **deployed** scanner (image
`6d19e30`): checkov 3.3.16, Trivy 0.74.0 and KICS 2.1.20 plus the project's
own check `IACP-0001`, as packaged in the `iac-scanner` image.

By source: **Trivy 63/63, KICS 22/22, checkov 93/95.** All six clean
controls raised nothing. Both misses are the long-standing labelled tool
gaps below (`CKV_AWS_60` on a bare `"*"` principal, `CKV_SECRET_6` on a
password containing `!`), so this is the ceiling for these tools on these
cases. The CloudFormation cases fold in here: all 23 of their labelled
pairs fired on the deployed scanner, matching the local labelling exactly.
The run before this one was 98.7% (155/157), the same day, before them.

**What this number does not check is `target_type`, and that let a bug
through.** Recall compares `(source, rule_id)` pairs, so a finding that
fires under the wrong target type counts as a hit. A targeted scan after
this run found KICS findings on a YAML CloudFormation template coming back
`unknown` -- all ten on one file -- which remediation-agent refuses outright.
Detection was right and the language was unremediable. Fixed in iac-scanner
(KICS's per-query platform is now its reported type); the JSON syntax was
already correct.

This is now one number over the whole corpus rather than the AWS-and-OpenTofu
subset. The previous headline was 97.3% (73/75) on 2026-09-16, before the
Kubernetes cases (2026-09-20) and the Azure ones (2026-09-22); each reported
its own locally measured figure in its section until this run folded them in.
Both misses are labelled tool gaps (`CKV_AWS_60` on a bare `"*"` principal;
`CKV_SECRET_6` on a password with a `!` in it), so this is the ceiling for
these tools on these cases.

| category | recall |
|---|---|
| network-exposure | 22/22 |
| missing-encryption | 24/24 |
| logging-monitoring | 10/10 |
| unpinned-modules | 2/2 |
| iam-over-permissioning | 8/9 |
| hardcoded-secrets | 7/8 |
| **by source** | checkov 43/45 · trivy 30/30 |

Both clean controls raised nothing.

Previous: 97.0% (65/67) on 2026-09-10 with tfsec v1.28.14, before the
`.tfvars`/secrets surface (§8.2 item 4) and the Trivy swap (item 6).

## The Kubernetes cases (added 2026-09-20)

21 positive cases and one clean control, covering the CIS Kubernetes 5.1 and
5.2 families, seccomp, image provenance, secrets-as-env and the service
account token. **51 of 51 labelled pairs fire, and the clean control raises
nothing** -- measured locally against the same pinned Trivy 0.74.0 and
checkov 3.3.16 the scanner image carries, because the deployed scanner had
not yet been rebuilt when they were written. *Re-run `run_eval.py` after the
next deploy and replace this paragraph with the deployed number*, the way
every other number in this file was produced.

| | |
|---|---|
| labelled pairs | 52, all firing |
| by source | checkov 25/25 · trivy 27/27 |
| labelled pairs with a candidate control | **41/43 (95%)** |
| all distinct rules these cases raise | **46/53 (87%)** mapped |

The labelled-pair coverage is far above Terraform's 72% for one reason worth
naming: these cases were written *after* the CIS Kubernetes corpus, against
the controls it holds, where the Terraform cases predate their corpus by
months. The second number is the honest one for a real repository, and the
gap between them is smaller here for the same reason.

**Every case isolates its own rule.** The base manifest is hardened in every
other respect -- pod and container `securityContext`, dropped capabilities,
`RuntimeDefault` seccomp, read-only root, non-root high UID and GID, resource
requests and limits, both probes, no service account token, a digest-pinned
image, and a NetworkPolicy -- so a case's label is the one thing it breaks.
That took four measured iterations to reach; the first pass had five rules
firing on all twenty cases and a clean control that raised five findings.

Three things the iterations taught, all of them recorded in the case notes:

- **`KSV-0125` (trusted registries) trusts only a bare image name.**
  `docker.io/...`, `registry.k8s.io/...` and `ghcr.io/...` all fire it. On a
  real repository it therefore fires on essentially every image, which is
  why `k8s-untrusted-registry` owns it and every other case uses a bare name.
- **Either seccomp profile satisfies both tools.** The pod-level and the
  container-level `seccompProfile` are interchangeable for detection, so
  `k8s-no-seccomp-profile` has to drop both -- and a fix may legitimately add
  either.
- **Trivy splits "runs as root" in two.** `KSV-0105` is an explicit
  `runAsUser: 0`; `KSV-0012` is the *absent* securityContext. The two cases
  are labelled accordingly.

`k8s-no-security-context` is the exception to the one-rule-per-case rule, on
purpose: it is the PugetScope shape, one missing block raising eleven
labelled pairs across both tools, and it is what keeps the per-file collapse
in multi-iac-spec §5.1 measurable.

### The third miss, and the check that closed it

Added 2026-09-20 after the cases above, from a question about what
`k8s-secret-in-env` actually proves. **A hardcoded password in a container's
`env:` was detected by neither tool, and the direction was backwards: the
*correct* form raised a finding and the dangerous one did not.**

| manifest | fires |
|---|---|
| `valueFrom.secretKeyRef` (correct, but env) | `CKV_K8S_35` |
| `value: "<literal password>"` (dangerous) | **nothing** |
| the same literal under `password:` in a Secret's `stringData` | `CKV_SECRET_6` |

Isolated by a pair of cases, `k8s-literal-secret-in-env` and
`k8s-literal-secret-in-secret-object`, which differ only in where the value
sits. The cause is structural: checkov's `EntropyKeywordCombinator` needs a
keyword next to a high-entropy value, and Kubernetes' env list puts the
keyword under `name:` and the secret under `value:` -- two separate YAML
keys, never paired. The value is base64-charset only in both, so this does
not confound with the punctuation gap `rds-literal-password` isolates, and
the sibling firing is what makes the empty label evidence rather than an
absence.

It is *not* that env values go unscanned: an `AKIA...` key in the same
position fires `CKV_SECRET_2`, because `AWSKeyDetector` matches a shape and
needs no keyword. The blind spot is confined to credentials that are only
recognisable from the name beside them.

It was the third labelled miss in the eval and the first that was not a
Terraform one. **`IACP-0002` closes it** (`lambda/iac-scanner/checks/`), the
way `IACP-0001` closed the port-range gap, so `k8s-literal-secret-in-env` is
now a labelled hit rather than a labelled miss.

The check pairs the keyword with the value structurally rather than by
entropy: an `env` entry whose name contains a credential keyword and whose
value is a literal. **Entropy is deliberately not scored** -- a weak password
is still a hardcoded credential, and `changeme` in a manifest is a finding,
not a false positive. It walks Pod, Deployment, ReplicaSet, StatefulSet,
DaemonSet, ReplicationController, Job and CronJob, and `initContainers` as
well as `containers`, since a schema-migration init container is a normal
place for a password to sit.

What it excludes is only what is not a credential by construction: an empty
value, a `$(VAR)` reference to another variable (Kubernetes expands those at
runtime, and PugetScope's `DATABASE_URL` is built that way), and names that
point *at* a secret rather than hold one -- `..._NAME`, `..._FILE`,
`..._PATH`. Verified against eight fixtures covering each branch, and
against PugetScope's twelve real manifests, where it raises **zero**: that
repository uses `secretKeyRef` and `$(VAR)` throughout, which is exactly the
code the check must stay quiet on.

Like `IACP-0001` it admits cases a human may judge acceptable -- a throwaway
value in a local-development overlay looks exactly like this finding. Whether
that matters is a reviewer's call recorded in the dashboard, not something
the scanner decides (spec §8.1).

## The Azure cases (added 2026-09-22; relabelled 2026-09-23)

**Relabelled when KICS replaced Trivy on ARM and Bicep** (`multi-iac-spec`
§6.2). Every `trivy:AZU-*` label on an ARM case is gone, because Trivy no
longer scans the language; the KICS query covering the same control takes its
place. Re-measured through the scanner afterwards: **155 of 157 labelled
pairs fire across the whole 83-case corpus**, the two misses being the
long-standing `CKV_AWS_60` and `CKV_SECRET_6` tool gaps documented below. By
source: KICS 13/13, Trivy 57/57, checkov 85/87.

Two things the relabelling turned up.

**`arm-storage-no-infrastructure-encryption` detects nothing any more**, and
is kept as a labelled coverage gap rather than deleted. CIS Azure 4.2 was
raised on ARM only by Trivy's `AZU-0061`, and neither remaining tool has an
infrastructure-encryption query for ARM. The template genuinely lacks the
setting and no tool now says so. Deleting the case would have deleted the
only record of that.

**Both tools gate the trusted-services check the same way.** KICS's
`Trusted Microsoft Services Not Enabled` was labelled on the two
`default-allow` cases and does not fire there -- for exactly the reason
checkov's `CKV_AZURE_36` does not, which was the correction logged in the
first run. Measured across all four combinations 2026-09-23, both tools
behaving identically:

| `networkAcls` | fires? |
|---|---|
| absent entirely | yes |
| `defaultAction: Allow` | **no** |
| `defaultAction: Deny`, `bypass: None` | yes |
| `defaultAction: Deny`, `bypass: AzureServices` | no |

So the precondition is not "Deny is required before the bypass list is
checked" -- an absent block fires too, and absent means Allow in Azure. It is
that an *explicit* `Allow` switches the check off. Defensible either way:
`bypass` is a carve-out from a block, and with everything allowed there is no
block to carve out of. Two independent tools agreeing makes it the rule
rather than a quirk of one.

## The Azure cases: what they cover

14 cases: six ARM, six Bicep, and a clean control for each. They were labelled
a priori from what each rule is for, then confirmed by running the pinned
Trivy 0.74.0 and checkov 3.3.16 from the built scanner image over each case
directory on its own. **26 of 26 labelled pairs fire.** Three labels were
corrected by that run and one case was rebuilt; both are below, because the
corrections are the part worth reading.

The ARM cases are `azuredeploy.json`, the Bicep ones `main.bicep`. They cover
the same ground from both sides on purpose -- insecure transfer, a network
rule defaulting to Allow, an open management port, a Key Vault without purge
protection, a SQL server with no auditing -- so the two languages can be
compared directly rather than each being tested on whatever was convenient.
`bicep-module-and-resource` is the exception: it exists for the structural
guard rather than for detection, since a Bicep `module` deploys a whole
sub-template and deleting one has to be caught.

### Bicep is covered, and had one source for a day

*Rewritten 2026-09-23.* What follows described Bicep as checkov-only, which
was true of the two scanners this project had at the time and stopped being
true when KICS arrived: it parses `.bicep` natively, so every Bicep case now
has two sources and the self-check compares two tools. The original reasoning
is kept below because OpenTofu still needs it.

The clearest sign of the change is `bicep-storage-network-default-allow`,
which used to expect one rule where its ARM twin expected three: CIS Azure
4.8 was reachable only through Trivy, and Trivy has no Bicep scanner. KICS
covers 4.8 on both languages, so the asymmetry is gone.

### The single-source caveat, which is now OpenTofu's alone

The mirror of OpenTofu above, with the tools reversed: Trivy has no Bicep
scanner at all (`multi-iac-spec` §2), so every Bicep case is labelled with
checkov expectations only, and a Bicep finding's self-check compares one
source rather than two. That is weaker, not broken -- the comparison is per
`(source, rule_id)`, so it degrades to checkov alone.

Unlike OpenTofu, this is now **said in the UI rather than left in this file**:
a finding, a row in the findings table and a fix group on a single-source
target all carry a "checkov only" badge beside the verdict
(`dashboard/src/review/coverage.ts`). OpenTofu gained the same badge in the
same change, since its caveat had been recorded only here since September.

The cost is visible in one case. `bicep-storage-network-default-allow` expects
one rule where its ARM twin expects three: CIS Azure 4.8 (trusted services) is
reached only through Trivy's `AZU-0010`, so on Bicep that control is simply
not reachable. That is the single-source cost made concrete, not a gap in the
case.

### The corrections the confirming run produced

**`CKV_AZURE_36` does not fire when `defaultAction` is `Allow`.** Both
`default-allow` cases expected it for the trusted-services half of the
finding. checkov only asks about the bypass list once the default action is
Deny, which is right: with Allow there is nothing to bypass. The ARM case is
labelled with Trivy's `AZU-0010` instead; the Bicep case loses the
expectation entirely, per the paragraph above.

**`clean-arm-hardened` was a hardened storage account, and could not be
one.** `AZU-0056` (blob soft delete), `AZU-0057` (logging) and `AZU-0058`
(geo-redundancy) cannot be cleared on an ARM storage account by configuring
what they name. The template that exposed it declared `Standard_GRS` and
still raised `AZU-0058`; Trivy's own pass/fail census over 175 real templates
then showed `AZU-0058` and `AZU-0057` never pass on any of them. The adapted
state a check receives has `accountreplicationtype` empty, because the
adapter reads `properties` and not its sibling `sku`. The same intent in
Terraform clears all three, so the checks are fine and the adapter is not. A clean control that cannot be clean is not a control, so it
was rebuilt from a hardened NSG and VNet, which both tools read correctly.
Both clean controls now return zero findings from both tools.

Three of those rules were **unmapped in the corpus** as a result, so they are
reported but never drafted; `corpus/README.md` has the reasoning.

## Mapping coverage

The same run also reports what fraction of findings have a candidate control
in `rule_mappings.json` — spec §7.1's second half. Read from the file rather
than from a `mapping-agent` run: it is a property of the corpus, costs
nothing, and is deterministic.

| | coverage |
|---|---|
| labelled pairs that fired | **44/61 — 72%** |
| all distinct rules fired | **48/123 — 39%** |

Two numbers because they answer different questions. The first is comparable
with detection recall above. The second is the honest one for a real PR: the
labels are a deliberate *minimum*, so 40 cases written to catch 67 specific
pairs actually raise 123 distinct rules, and a reviewer's queue reflects the
123. Most of the long tail is rules no case was written for —
`aws-rds-enable-performance-insights`, `aws-eks-enable-control-plane-logging`,
RDS backup retention — which are real findings with no control in the three
frameworks loaded.

It measures whether a finding *can* be mapped, not whether the agent picks
well among the candidates. That would need a labelled expected control per
case and a live run, and is not measured.

### The two misses are real, and each names a specific gap

**`CKV_AWS_60` on `iam-role-assumable-by-anyone`.** The check
(`IAMRoleAllowsPublicAssume.py`) only ever inspects `statement['Principal']['AWS']`.
A trust policy with the bare `Principal = "*"` — the fully anonymous form,
the more dangerous of the two — is never examined. The sibling case
`iam-role-assumable-by-any-aws-principal` uses `Principal = { AWS = "*" }` and
hits, which is what isolates the blind spot to the bare form.

**`CKV_SECRET_6` on `rds-literal-password`.** `CKV_SECRET_*` belongs to
checkov's `secrets` framework, and the scanner runs `--framework terraform`
only. This is the §2 goal "hardcoded secrets" measured rather than assumed:
a literal master password in an `aws_db_instance` is not detected. Kept as a
positive on purpose — §8.2 item 4 is where it gets fixed, and this is the
number that should move when it does.

### A Trivy coverage gap that is labelled, not counted

Trivy's `AWS-0009` (tfsec's `aws-ec2-no-public-ip`; same engine) fires on
`aws_launch_configuration` and on nothing else. `aws_instance` with
`associate_public_ip_address = true` and `aws_launch_template` with the same
in `network_interfaces` are both blind spots. The three `*-public-ip` cases
pin this down; checkov's `CKV_AWS_88` covers all three resource types, so
the pipeline as a whole still catches it. The two modern-form cases are
labelled for checkov only, with the gap recorded in their `note`.

### OpenTofu is covered, and is Trivy-only

`.tofu` and `.tofu.json` joined the snapshot on 2026-09-16
(`docs/multi-iac-spec.md` §6 step 1). OpenTofu is Terraform's HCL, so the
rules already written apply unchanged: `opentofu-unencrypted-bucket` is
`s3-no-encryption` in a `.tofu` file and fires the same `AWS-0132`, and
`opentofu-encryption-block` puts OpenTofu's own `terraform { encryption
{ … } }` — which Terraform itself rejects — in front of the parser and still
gets its queue finding, with no `scan_errors`. If a Trivy bump ever stopped
tolerating that unknown block, the second case goes red.

**Measured the same day, and worth knowing: checkov does not open `.tofu`.**
Zero checkov findings on either case, where the identical `.tf`
(`s3-no-encryption`) raises `CKV_AWS_145` and six more. So OpenTofu files
have Trivy-only coverage — described here as the mirror of Bicep being
checkov-only until KICS gave Bicep a second source on 2026-09-23, leaving
OpenTofu the only single-source target — which
also means a single-source self-check for them. Labelled in both cases
rather than counted as a miss.

### Public ingress on non-admin ports: a gap the Trivy swap opened, and the check that closed it

tfsec's `aws-ec2-no-public-ingress-sgr` fired on any ingress rule open to
`0.0.0.0/0`, whatever the port. Trivy's `AWS-0107` is the same check
narrowed upstream to SSH and RDP (`net.is_ssh_or_rdp_port` in
trivy-checks). Found on 2026-09-13, when the two PugetScope findings that
motivated `context-agent` — port 80 and the NodePort range 30000-32767 open
to the world — were simply not admitted after the swap.

Closed the same day by the project's first custom check, **`IACP-0001`**
(`lambda/iac-scanner/checks/aws_ec2_no_public_ingress_any_port.rego`,
shipped in the scanner image and loaded with `--config-check` and
`--check-namespaces user` — without the second flag a check from disk loads
and silently never fires). It reports an ingress rule open to every IP on
any TCP/UDP port range that `AWS-0107` does not already cover, so the two
never report one rule twice: 80, 443 and the NodePort range fire under
`IACP-0001`; 22, 3389 and "all ports" stay with `AWS-0107`. Deterministic
and versioned with the image, so it satisfies §8.1 like any built-in rule.

Two cases pin it down. `sg-http-from-anywhere` expects checkov's
`CKV_AWS_260` (per-port rules exist for 80, 20/21, 23 and a few others) and
`IACP-0001`; `sg-port-range-from-anywhere` expects `IACP-0001` alone, since
checkov has nothing for an arbitrary range. Both rules, and `CKV_AWS_260`,
map to OWASP CNAS-6 (default-deny network access controls), the same control
as the egress twin `AWS-0104`. A public web tier looks exactly like this
finding, on purpose: whether port 80 open to the world is intended is the
reviewer's call, not the scanner's.

### tfsec → Trivy, 2026-09-12

The scanner swapped tfsec for Trivy (§8.2 item 6). Trivy's report carries
only its own id (`AWS-0107`), never the tfsec long id, so every tfsec label
was re-keyed by reading `long_id → id` out of trivy-checks' check metadata
at the exact commit Trivy 0.74.0 embeds. Three checks had been renamed
upstream and were matched by hand (`aws-cloudtrail-enable-at-rest-encryption`
→ `AWS-0015`, `aws-rds-no-public-db-access` → `AWS-0180`,
`aws-s3-enable-bucket-logging` → `AWS-0089`). Two are deprecated in Trivy
and off by default, so they can never fire; see the corrections log. The
translated labels were then run through the same Trivy binary locally
before deploy: 26/26 fired, and the deployed run matched.

## How the labels were produced, and what happened to them

This section exists so the number above is not circular.

**checkov labels were verified a priori** against the vendored source
(`layers/checkov/python/checkov/` at the time; the same pinned version is now
installed in the scanner image) — every `CKV_*` id in every `expected.json`
appears as a check id in the exact version deployed. (Rule ids live in
`.py`, `.yaml` **and** `.json` graph checks; an index that skips the JSON
files misses the S3 rules entirely.)

**Trivy labels were verified against source** — every `AWS-*` id in every
`expected.json` is the `id` of a check in trivy-checks at the commit Trivy
0.74.0 embeds, and each was observed firing on its case with that binary
run locally. (The tfsec labels they replaced could not be: no binary ran
here, and only the short-name component of each id had been confirmed
embedded in the deployed binary.)

**Corrections log.** The first run scored 92.3%. Each miss was then classified
as either a label error (mine — corrected, listed here) or a scanner gap
(kept, reported above). Nothing was relabelled to match output without a
source-level reason.

| run | case | was | now | why |
|---|---|---|---|---|
| 1→2 | `iam-credentials-exposure` | `CKV_AWS_107` | `CKV_AWS_287` | 107 is the `aws_iam_policy_document` data-source variant; the resource check is 287, and it had fired |
| 1→2 | `iam-privilege-escalation` | `CKV_AWS_110` | `CKV_AWS_286` | same split; 286 had fired |
| 1→2 | `ec2-public-ip` | + `tfsec aws-ec2-no-public-ip` | checkov only | tfsec raised nothing on `aws_instance`; see the coverage gap above |
| 1→2 | `clean-sg-restricted` | orphaned SG | attached to an ENI | `CKV2_AWS_5` (SG attached to nothing) is a fair finding, so the control was not clean |
| 1→2 | *(added)* `iam-role-assumable-by-any-aws-principal` | — | `CKV_AWS_60` | isolates the bare-`"*"` blind spot to that form |
| 2→3 | *(added)* `launch-configuration-public-ip` | — | `tfsec aws-ec2-no-public-ip` | tests where the tfsec rule does apply; it fired |
| 3→4 | `launch-template-public-ip` | `tfsec aws-ec2-no-public-ip` | `CKV_AWS_88` | tfsec raised nothing on the launch template either; the rule is launch-configuration only |
| tfsec→Trivy | every `tfsec` label (27 cases) | `tfsec <long-id>` | `trivy AWS-nnnn` | Trivy emits its own id only; translated from trivy-checks metadata, see above |
| tfsec→Trivy | `s3-no-encryption`, `tf-json-unencrypted-bucket` | `aws-s3-enable-bucket-encryption` | `AWS-0132` | `AWS-0088` is deprecated in Trivy (AWS encrypts S3 by default since 2023) and off by default; `AWS-0132` (customer-managed key) is what fires on a bare bucket, and is the Trivy-side twin of the `CKV_AWS_145` the cases already expect |
| tfsec→Trivy | `iam-policy-full-admin`, `iam-policy-document-full-admin` | + `aws-iam-no-policy-wildcards` | checkov only | `AWS-0057` is deprecated in Trivy with no replacement; nothing on the Trivy side fires on a `"*":"*"` policy |
| 2026-09-13 | *(added)* `sg-http-from-anywhere` | — | `CKV_AWS_260` | Trivy's `AWS-0107` is SSH/RDP-only where tfsec's fired on any port; see the gap above |
| 2026-09-13 | *(added)* `sg-port-range-from-anywhere` | — | *(nothing)* | neither tool covers an arbitrary port range open to the world; labelled empty so the gap is recorded and counted nowhere |
| 2026-09-13 | `sg-http-from-anywhere`, `sg-port-range-from-anywhere` | as above | + `trivy IACP-0001` | the project's own check landed the same day and fired on both; the empty label lasted hours |
| 2026-09-16 | *(added)* `opentofu-unencrypted-bucket`, `opentofu-encryption-block` | — | `trivy` only | both labelled Trivy-only from the start on the theory that checkov globs `*.tf`; the run confirmed it — zero checkov findings on either |

## What recall means here, and what it does not

Recall is per expected `(source, rule_id)` pair: hit if that pair fired on
that case's file at least once. The labels are a **minimum** — a bare S3
bucket raises a dozen rules, and its case expects only the encryption pair.
Extra findings are reported but never counted against recall, because they
are correct.

The two clean controls are the only precision signal. Anything they raise
is reported as a false positive. Getting a truly zero-finding case is
harder than it sounds — an unattached security group is a finding — which is
its own small lesson about what "clean" means to these tools.

Not measured: mapping recall (§7.1's second half, needs labelled control
mappings), remediation safety (§7.2), fix acceptance (§7.3).

### Adding an ARM or Bicep case

`terraform fmt -check -recursive cases/` does not reach them -- it handles
`.tf` and `.tfvars` only -- so the validity check is the run itself. A case
whose sample does not parse shows up as a `scan_errors` entry rather than as
a quiet zero, for ARM because the scanner parses the JSON itself and for
Bicep because checkov reports `parsing_errors`. Both were confirmed on real
templates: checkov reported 8 genuine parse failures across
`azure-quickstart-templates`, 4 ARM and 4 Bicep. So "the case is valid"
means the run reported `scan_errors: 0`, and that is checked rather than
assumed.

An ARM case's sample must carry a top-level `$schema` naming a
`deploymentTemplate`, or nothing will upload it: `.json` is admitted by
content, not by name. A CloudFormation case in the JSON syntax has the same
requirement against the other marker -- `AWSTemplateFormatVersion`, or a
`Resources` mapping whose every entry carries an `AWS::`/`Alexa::`/`Custom::`
`Type`. This is also what keeps each case's own `expected.json` out of its
snapshot. A CloudFormation case in YAML needs no marker to be uploaded,
since `.yaml` is admitted by suffix for Kubernetes -- but it should carry one
anyway, because that is what the scanner's tools classify it by.

## The CloudFormation cases (added 2026-09-23)

Seven cases: five positive, one clean control, and one that exists for the
file format rather than a vulnerability. **Labelled locally against the same
pinned Trivy 0.74.0, checkov 3.3.16 and KICS 2.1.20 the scanner image
carries**, because the deployed scanner had not been rebuilt when they were
written — the Kubernetes and Azure cases were added the same way. *Re-run
`run_eval.py` after the deploy and fold these into the headline.*

| case | what it injects | sources that see it |
|---|---|---|
| `cfn-s3-unencrypted` | bucket with no encryption, versioning, logging or public-access block | trivy, kics |
| `cfn-sg-open-ingress` | SSH from `0.0.0.0/0`, unrestricted egress | trivy, checkov, kics |
| `cfn-iam-full-admin` | `Action: '*'` on `Resource: '*'` | checkov, kics |
| `cfn-rds-literal-password` | hardcoded `MasterUserPassword` | checkov, kics |
| `cfn-cloudtrail-no-validation` | log validation off, single-region, no CMK | trivy, checkov, kics |
| `cfn-json-syntax` | the bucket again, in the JSON syntax | trivy, kics |
| `clean-cfn-hardened` | nothing — the false-positive control | none, on all three |

**`cfn-json-syntax` is the odd one and is deliberate.** CloudFormation is the
first language admitted in two syntaxes under one `target_type`, so "both
syntaxes are the same target" is a claim the eval holds rather than a comment
in the scanner. It also exercises the JSON admission path, which is where
CloudFormation collides with ARM: both are content-sniffed off a bare
`.json`, and this file has to come back `target_type` `cloudformation`
rather than `arm`.

### Two per-tool gaps, labelled rather than papered over

**checkov raises no S3 encryption check on a template.** On
`cfn-s3-unencrypted` it reports `CKV_AWS_18`, `21` and `53`–`56` — logging,
versioning and the four public-access-block checks — and nothing about
encryption, where Trivy has `AWS-0132` and KICS has `b2e8752c`. So the
project's opening example, the unencrypted bucket, is two-source in
CloudFormation where it is three-source in Terraform.

**Trivy reports nothing at all on a full-admin IAM policy** — and this one is
*not* a CloudFormation gap, which is why the case says so. Trivy deprecated
`aws-iam-no-policy-wildcards` (`AWS-0057`), it is off by default and nothing
replaced it, so the Terraform case `iam-policy-full-admin` is checkov-only
for exactly the same reason. The difference is that KICS covers it here,
which the Terraform case cannot say: KICS is scoped to ARM, Bicep and
CloudFormation.

### What the clean control had to do to be clean

Two KICS queries fire on essentially any CloudFormation template, and both
are tool behaviour rather than security judgement:

- `0104165b` (*DB Security Group Open To Large Scope*) wants an ingress CIDR
  of fewer than 256 hosts, so the control uses a `/25` — a `/24` is exactly
  256 and one host too many.
- `8d29754a` (*IAM Access Analyzer Not Enabled*) fires on any template that
  does not declare an `AWS::AccessAnalyzer::Analyzer`, which is an
  account-level control expressed as a per-template check.

Both are *satisfiable*, unlike the four Trivy ARM rules in
`docs/trivy-azure-arm-adapter-gap.md`, so they are satisfied here rather than
dropped from the corpus. Worth knowing anyway: they will fire on nearly every
real template a user scans.

### Corpus cost was low, as §6 step 4 predicted

**11 of the 21 labelled rules were already mapped**, through the Terraform
work — Trivy and checkov report the same `AWS-*` and `CKV_AWS_*` ids on a
template as on HCL, and only one candidate in the whole table is
`target_type`-scoped (Kubernetes'). The ten added are seven KICS AWS query
ids — KICS had only Azure keys until now — and checkov's three IAM
constraint checks, each landing on the control its Trivy or checkov
counterpart already carried.

## Adding a case

```
cases/<name>/main.tf          # one clear injected vulnerability, self-contained
                              # (manifest.yaml, azuredeploy.json, main.bicep,
                              #  template.yaml/.json per language)
cases/<name>/expected.json    # {description, category, expected: [{source, rule_id}], note?}
```

Keep `main.tf` minimal and valid — `terraform fmt -check -recursive cases/`
must pass, which also proves every case parses. Verify a checkov id against
the checkov source at the version `lambda/iac-scanner/Dockerfile` pins
before labelling it, and a Trivy id against the check metadata in
trivy-checks at the commit the pinned Trivy embeds (the Dockerfile names the
version; Trivy's `go.mod` names the commit).
Trivy ids are the bare `AWS-nnnn` form the report emits, not `AVD-AWS-nnnn`
and not the tfsec long id. If an id is a guess, say so in `note` and let the
run decide.

Runs cost one scanner invocation regardless of case count: everything is
uploaded under one prefix and Trivy/checkov treat each subdirectory as its own
module. The prefix is deleted afterwards unless `--keep` is passed.
