# Beyond Terraform — spec (draft)

Covering more IaC languages: OpenTofu, Kubernetes/Helm, CloudFormation,
Bicep/ARM, and what to do about Pulumi.

Written before building. Every claim about tool support below was tested
against the pinned Trivy 0.74.0 and checkov 3.3.16 in the deployed scanner
image on 2026-09-16; the commands are in §2 so they can be re-run when either
is bumped.

## 1. Why this is not one feature

"Support more IaC tools" reads as one item and is at least three, separated
by how the tools see the input:

- **Same parser, different file extension.** OpenTofu is Terraform's HCL. The
  scanner already handles it; nothing is missing but the suffix.
- **Different parser, same scanner.** Kubernetes, Helm, CloudFormation,
  ARM and Bicep are declarative files that Trivy or checkov already parse.
  The scanner needs a flag; the *project* needs a corpus and an eval.
- **No parser exists, because there is no file to parse.** Pulumi and CDK
  are programs. Getting a resource graph out of them means running the user's
  code, which is a different trust model — see §7.

Sorting the work this way is the whole point of the document. The scanner is
the cheap part everywhere; what costs is §5.

## 2. What the pinned tools actually do

`trivy config --help` reports its misconfiguration scanners as
`azure-arm, cloudformation, dockerfile, helm, kubernetes, terraform,
terraformplan-json, terraformplan-snapshot, ansible`. checkov's runners
include `terraform, terraform_plan, terraform_json, cloudformation,
kubernetes, helm, kustomize, arm, bicep, dockerfile, serverless, ansible,
github_actions, secrets` and several SAST engines.

Measured, not inferred:

| Target | Trivy | checkov | Evidence |
|---|---|---|---|
| **OpenTofu** (`.tofu`) | ✅ scanned as `terraform` | ✅ same HCL | 8 rules fired on a bare S3 bucket in `main.tofu`, the same 8 as `.tf` |
| **Kubernetes** | ✅ `KSV-*` ids | ✅ `CKV_K8S_*` | PugetScope's `k8s/`: **239 findings, 19 distinct rules, 14 files** |
| **Helm** | ✅ renders charts natively | ✅ | not yet measured |
| **CloudFormation** | ✅ 8 rules on a bare bucket | ✅ 6 failed checks | same template, both tools |
| **ARM** | ✅ `azure-arm` | ✅ `arm` | not yet measured |
| **Bicep** | ❌ not a Trivy scanner | ✅ `bicep` | 4 Azure findings (`CKV_AZURE_3/35/44/206`) on a storage account with `supportsHttpsTrafficOnly: false` |
| **Pulumi** | ❌ | ❌ | no runner in either; see §7 |
| **CDK** | ❌ | ~ `cdk` runner, but SAST over TypeScript/Python, not a resource graph | out of scope with Pulumi |

Two results worth pulling out.

**OpenTofu is free, including its divergent syntax.** A `.tofu` file
containing OpenTofu's `terraform { encryption { ... } }` state-encryption
block — which Terraform itself rejects — parsed without error and still
raised all 8 bucket findings. Trivy's HCL parser tolerates unknown blocks
rather than failing the file, which is the behaviour this depends on. Worth
re-testing on each Trivy bump, because it is incidental rather than promised.

**Bicep is checkov-only.** That is the first time the two scanners will not
be interchangeable for a language, and §4 has to say what a self-check means
when only one tool covers the file.

## 3. The architecture: one scanner, many `iac_type`s

Spec §4.3 split the scan stage into `terraform-scanner` and a future
`k8s-scanner`, and §4.4 has `webhook-receiver` fanning out between them. That
design existed for one reason, stated there: Checkov's dependency tree is
heavy, and each function had to fit under Lambda's 250MB layer ceiling.

**That reason is gone.** §4.3 was revised on 2026-09-13 to a container image,
and the one image already contains every parser in §2's table. A second
scanner Lambda would now be a second copy of the same image with a different
name.

So: **one scanner, `iac_type` selected per file rather than per function.**

- The scanner classifies each file in the snapshot by extension and, where
  extension is ambiguous (`.yaml` is Kubernetes, Helm, CloudFormation or
  none of them), by content — Trivy and checkov both already do this
  internally, so the honest implementation is to hand them the directory and
  read `Type` back off each Result rather than pre-classify.
- A finding's `iac_type` comes from what the tool reported, not from the
  invocation. `FindingRecord.iac_type` already exists (spec §5) and is
  hard-coded `"terraform"` today.
- `_run_trivy` passes `--misconfig-scanners` with the enabled set;
  `_run_checkov` passes `--framework`. Both are already single call sites.

**This obsoletes §4.4's v2 fan-out.** `webhook-receiver` does not route by
type; it uploads a snapshot. Pipeline, mapping-agent, remediation-agent,
review-api and the dashboard need no structural change.

*Naming.* `terraform-scanner` becomes a misnomer. Renaming a Lambda is a
destroy-and-create, taking its log group and alarm names with it, and every
`terraform_scanner_function_name` reference. Deferred, deliberately: the
rename is cosmetic and the cost is a deploy window. Recorded in §9.

## 4. What the self-check means per language

This is the part that cannot be copied from Terraform, and it is where a
careless port would quietly break the project's central guarantee.

`remediation-agent` proves a fix by re-scanning the patched file and
comparing `(source, rule_id)` counts (spec §6.1). Three of its guards are
Terraform-shaped:

| Guard | Today | Per language |
|---|---|---|
| `SUPPRESSION_MARKERS` | `tfsec:ignore`, `trivy:ignore`, `checkov:skip`, `nosec` — HCL comment syntax | Kubernetes suppresses by **annotation**, not comment; CloudFormation by `Metadata: cfn_nag`/`checkov`. A marker set that does not cover the language means the suppression gate **silently passes** — the failure §8.1 calls out by name |
| `_find_dropped_resources` | `RESOURCE_BLOCK_RE`, an HCL `resource "type" "name" {` regex | Matches nothing in YAML or JSON, so the deletion gate silently passes too: an agent could delete a whole Deployment and the rescan would call it clean |
| `scan_errors` | the scanner reports unparseable files | Unchanged, and the one guard that ports as-is |

**Rule: a language is not enabled until its suppression markers and its
structural guard are implemented and tested.** Two of the three gates failing
open is worse than not scanning the language at all, because the output
*looks* verified. This is the single most important sentence in this
document.

**And where only one tool covers the language** (Bicep), the self-check has
one source rather than two. That is weaker but not broken — the comparison is
per `(source, rule_id)`, so it degrades to checkov alone. It should be said
in the UI, not discovered.

## 5. The real cost: corpus and eval

The scanner flag is a day. These are not.

**The corpus is 100% AWS.** All 51 entries in `rule_mappings.json` are AWS
rules; `cis-aws-1.4.json` (16 controls) is the only framework with real
coverage. Nothing maps `CKV_AZURE_*`, `KSV-*`, or `CKV_K8S_*`. mapping-agent
leaves an unmapped finding at status `raw`, so **enabling Kubernetes today
would produce 239 findings on PugetScope alone, every one of them unmapped
and unremediated.** Breadth without corpus is a longer list, not more value.

Each language needs framework content before it is worth enabling:
Kubernetes → CIS Kubernetes Benchmark; Bicep/ARM → CIS Azure. That is
research and writing, not code, and it is the critical path.

**The eval corpus is 45 AWS Terraform cases.** §8 gates v2 on "eval numbers
are solid", and the number that makes this project credible is 71/73 *with
every gap labelled*. A language with no labelled cases has no recall number,
and shipping it asserts coverage nobody measured. Each language needs its own
cases, and its own honest gaps.

**Volume changes the cost model.** 239 Kubernetes findings against 68
Terraform ones for the same repository. At roughly $0.11 a drafted fix
(§ cost estimate, 2026-09-12), remediating one repo's manifests is ~$26
before anything is reviewed. Per-finding economics that were fine at 20
findings need re-examining at 240 — probably a severity floor, or
mapping-first as the filter it already effectively is.

## 6. Order, and why

By cost, and each step earns the next:

1. **OpenTofu.** Days. Add `.tofu`/`.tofu.json` to `SNAPSHOT_SUFFIXES` and
   `CONTEXT_SUFFIXES`, a handful of eval cases including one using
   OpenTofu-only syntax, and re-run the eval. The corpus already covers it —
   the rules are the same rules. **No new gates needed: it is HCL, so the
   suppression markers and the resource regex already apply.**
2. **The multi-type scanner** (§3), with Terraform and OpenTofu as the only
   enabled types. Structure first, on a language that cannot fail, so the
   refactor is provable against an unchanged 71/73.
3. **Kubernetes/Helm** — the planned v2. Trivy does it today, the YAML is
   already in the snapshot for context-agent. Gated on: CIS Kubernetes in the
   corpus, annotation-based suppression markers, a YAML structural guard,
   eval cases, and a decision on volume (§5).
4. **CloudFormation.** AWS, so much of the corpus carries over — the same CIS
   AWS controls, reached through different rule ids. Cheapest of the
   remaining.
5. **Bicep/ARM.** A whole new cloud: CIS Azure content, plus §4's
   single-source self-check caveat.
6. **Pulumi/CDK.** §7.

## 7. Pulumi, honestly

Neither scanner has a Pulumi runner, and that is not an oversight. A Pulumi
program is TypeScript, Python, Go or C#; there is no declarative file to
parse, because the resource graph does not exist until the program runs.

The only way to a graph is `pulumi preview --json`, which **executes the
user's program** — with their language runtime, their package tree (which it
may install), and frequently their cloud credentials, since providers read
live state.

That is a different project, for a reason that has nothing to do with
difficulty:

- Today the scanner **reads** files. It never executes input. Running
  `pulumi preview` is arbitrary code execution on untrusted input, inside a
  security tool, and dependency installation is itself a supply-chain
  surface.
- It is where Lambda stops being the right compute — not for duration
  (§4.3's Fargate discussion) but for isolation and egress control.
- §8.1's admission rule survives it, but only if the rules that match the
  preview output are deterministic, and none exist.

**The path that does not require executing anything: ingest the plan the
user already produces.** Trivy supports `terraformplan-json` for exactly this
shape. The analogue is asking the user to run `pulumi preview --json` in
their own CI and upload the artifact; code execution stays on their side of
the boundary, where it already happens and is already trusted.

What would then be missing is rules: nothing matches Pulumi's plan schema. It
would need an adapter mapping Pulumi resource types onto the cloud schema
Trivy's checks already consume (`input.aws.s3.buckets` and friends) — which,
if it worked, would light up the entire existing rule set at once. That is
the interesting version of this problem and it is a research project, not a
sprint. **Recommendation: do not commit to Pulumi support. Spec the
plan-artifact ingestion path, and prototype the adapter against one provider
to find out whether the schema mapping holds.**

## 8. What this does not change

- **§8.1's admission rule.** A deterministic scanner rule still originates
  every finding. More languages means more rules, not a softer bar.
- **The self-check decides `self_check_passed`**, computed from a rescan, per
  language. §4 is about keeping that true, not relaxing it.
- **context-agent** is language-agnostic already: it greps and reads text,
  and `CONTEXT_SUFFIXES` is a list. It gets better with a wider snapshot, not
  different.
- **The pipeline** — one execution per PR, `Map` over files — is unchanged.
  A file is a file.

## 9. Open decisions

- [ ] Whether to rename `terraform-scanner` (§3), and whether it is worth a
      destroy-and-create of the function, its log group and its alarms.
- [ ] The volume question (§5): a severity floor before remediation, or
      mapping coverage as the de facto filter it already is, or per-PR caps.
- [ ] Whether `iac_type` is per finding (from the tool's reported `Type`) or
      per file. Per finding is more honest and costs nothing; confirm both
      tools report it reliably before relying on it.
- [ ] Whether Helm is scanned as charts (Trivy renders them) or only as
      rendered output the user supplies. Rendering runs templates — far
      milder than §7, but not nothing.
- [ ] Whether a language with single-tool coverage (Bicep) is enabled at all,
      given the weaker self-check, or held until Trivy adds a Bicep scanner.
- [ ] Which CIS benchmark editions to vendor, and their licensing.
