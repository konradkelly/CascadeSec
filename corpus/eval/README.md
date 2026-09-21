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

**97.3% — 73 of 75 expected findings, across 45 positive cases and 2 clean
controls.** Run 2026-09-16 against checkov 3.3.16 and Trivy 0.74.0 plus the
project's own check `IACP-0001`, as packaged in the `iac-scanner` image.
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
| labelled pairs | 51, all firing |
| by source | checkov 25/25 · trivy 26/26 |
| labelled pairs with a candidate control | **40/42 (95%)** |
| all distinct rules these cases raise | **45/52 (87%)** mapped |

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

### The third miss: a literal password in an env var

Added 2026-09-20 after the cases above, from a question about what
`k8s-secret-in-env` actually proves. **A hardcoded password in a container's
`env:` is detected by neither tool, and the direction is backwards: the
*correct* form raises a finding and the dangerous one does not.**

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

This is the third labelled miss in the eval and the first that is not a
Terraform one. Closing it means a custom check, the way `IACP-0001` closed
the port-range gap -- and this is the number that should move when it does.

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
have Trivy-only coverage — the mirror of Bicep being checkov-only — which
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

## Adding a case

```
cases/<name>/main.tf          # one clear injected vulnerability, self-contained
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
