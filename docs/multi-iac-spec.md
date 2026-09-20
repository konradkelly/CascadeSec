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

*Naming.* **Decided 2026-09-16: `terraform-scanner` becomes `iac-scanner`.**
It is a misnomer the moment a second language lands, and the alternative is a
function called `terraform-scanner` scanning Bicep, which is the kind of
thing nobody fixes later. The cost is a destroy-and-create: the function, its
log group, its ECR repository name, the error and near-timeout alarms, and
every `terraform_scanner_function_name` reference in Terraform, `scan.py`,
`run_eval.py`, remediation-agent's env and the Step Functions definition. No
data is at risk -- findings live in DynamoDB and snapshots in S3, neither
keyed by function name -- so the blast radius is one deploy window and a lost
log history. Do it as step 2 (§6), with the multi-type refactor, so there is
one rename rather than two.

### 3.1 `iac_type` becomes two fields

**Decided 2026-09-16, with the function rename and for the same reason:** a
name that is already a misnomer becomes permanent once a third value lands.
npm is what forces it — `docs/dependency-safety-spec.md` §6 raised the same
question from the other side.

The field's job today is routing the self-check: *what do I re-run to verify
a fix to this?* (spec §4.4 step 5). npm needs two independent answers, and
Trivy's own output already carries both axes — we parse them already:

```
Class=config      Type=terraform     main.tf
Class=lang-pkgs   Type=npm           package-lock.json
```

| Question | Field | Values |
|---|---|---|
| What do I re-run? | `target_type` | `terraform`, `opentofu`, `kubernetes`, `cloudformation`, `bicep`, `npm`, `dockerfile` |
| What kind of problem, and so which remediation path? | `finding_class` | `misconfiguration`, `vulnerability`, `secret` |

**They are not derivable from each other, and the live table already proves
it.** A checkov secrets finding on a `.tfvars` file is `target_type:
terraform` but is not a misconfiguration; today it rides as `iac_type:
terraform` and nothing records what it is.

`finding_class` is what branches the pipeline. A misconfiguration is drafted
and rescanned; an npm vulnerability is a version bump *judged* by gates and
never drafted at all (dependency-safety §1). Two paths through
remediation-agent, with nothing in the record to switch on until this exists.

*Rejected:* `source_type` (collides with `source`, which is `trivy`/
`checkov`); `ecosystem` (right for npm, meaningless for Terraform);
`language` (neither is one); `scan_type` (ambiguous between the two axes,
which is the bug); one field plus a lookup table (`npm` ⇒ vulnerability) —
workable, but that table *is* the missing field and it cannot express the
secrets case.

*Populated from what the tools already report:* Trivy's `Class` and `Type`
directly, checkov's `check_type` for the rest. Done in the same deploy
window as the function rename — one breaking change rather than two, and the
dev table is disposable demo data, so this is the cheapest it will ever be.

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

**Built for Kubernetes/Helm 2026-09-19**, ahead of the language, per the rule
above. Three things the build settled that the table did not predict:

- *The markers are one set, not one per language.* A marker is a substring
  of an added line, so the union costs nothing but a held-for-review on the
  odd `.tf` that gains a Kubernetes annotation -- and a per-language set is
  exactly the shape that fails open when a language is added to the scanner
  and not to it. `checkov.io/skip` is the only addition: Trivy's YAML
  suppression is the same `trivy:ignore` comment as HCL, and checkov reads
  `checkov:skip` comments in YAML too, so the annotation was the one form an
  HCL-shaped set missed.
- *The structural guard dispatches on `target_type` and refuses one it has
  no reader for.* `_find_dropped_resources` raises on an unknown type rather
  than returning `[]`, so the scanner's admission list is the only place a
  language can be enabled. A record from before the §3.1 split carries no
  `target_type` and defaults to `terraform`, which is what every such record
  was by construction.
- *The Kubernetes reader is line-based, not a YAML parser*, for two reasons
  that turned out to be the same one: PyYAML is in neither the runtime nor
  the layer, and a Helm template is not valid YAML until rendered -- the
  guard has to hold on the file the agent edited. It reads each `---`
  document's column-0 `kind:` and the `name:` at the first child indent of
  its column-0 `metadata:`, which is enough to tell a deleted Service from a
  tightened `securityContext`, and ignores the indented `kind:` under a
  RoleBinding's `subjects`/`roleRef` and a pod template's nested `metadata`.
  Anchors tolerate `\r`, because a snapshot from a Windows-committed repo
  folds every document into the first without it (tested). Reports
  `Kind/name` where Terraform reports `type.name`.

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

*Kubernetes corpus built 2026-09-19:* `cis-kubernetes-2.0.json`, section 5
of CIS Kubernetes v2.0.0 (18 controls), and 23 mappings for the rules the
pinned scanners raised on PugetScope's `k8s/` -- 296 of the 489 findings
(Trivy's 239 plus checkov's 250) now have a candidate; the 16 unmapped
rules and why are in `corpus/README.md`. Grounded the same way as the AWS
corpus, by re-running both tools from the deployed image against the
repository. So the paragraph above is no longer true, and the accidental
filter it describes is gone the moment Kubernetes is admitted: the volume
decision in this section is now the blocker for step 3, not a nice-to-have.

Each language needs framework content before it is worth enabling:
Kubernetes → CIS Kubernetes Benchmark; Bicep/ARM → CIS Azure. That is
research and writing, not code, and it is the critical path.

**The eval corpus is 45 AWS Terraform cases.** §8 gates v2 on "eval numbers
are solid", and the number that makes this project credible is 71/73 *with
every gap labelled*. A language with no labelled cases has no recall number,
and shipping it asserts coverage nobody measured. Each language needs its own
cases, and its own honest gaps.

**Volume changes the cost model, and not in the obvious way.** The 239
Kubernetes findings on PugetScope are **19 distinct rules across 14 files** —
each rule hits 11.8 files on average, and the top eight hit all fourteen.
It is one workload's problems, repeated: every Deployment and CronJob is
missing the same `securityContext`. Severity skews low — 136 LOW, 61 MEDIUM,
42 HIGH — and ~18 findings land on each file.

That shape interacts with the existing design in two opposite ways.

**Within a file, the pipeline already collapses it.** Findings on one file
are chained, and `cleared_by` marks every finding a previous fix took to zero
as `superseded` without spending a model call (§8.3). One `securityContext`
block plausibly clears eight of the nineteen rules at once, so a file's 18
findings may cost four or five drafts rather than eighteen. *Unmeasured* —
worth measuring on one file before assuming it, because the estimate below
swings by 4x on it.

**Across files, nothing collapses.** The chain is per file by construction
(§8.2 item 5), so the same `securityContext` fix is drafted independently
fourteen times, at full price, producing fourteen near-identical diffs and
fourteen review decisions. That is the genuinely new problem: Terraform's
findings cluster in a few files, Kubernetes' repeat across many. Estimating
5 drafts a file, 14 files is ~70 model calls and ~$8 a run — tolerable — but
it is *fourteen times the reviewer attention for one decision*, and reviewer
attention is the scarce resource this project is built around.

**The filter that exists today is accidental.** mapping-agent leaves an
unmapped finding at `raw`, and remediation only touches `mapped`, so with no
CIS Kubernetes content all 239 are filtered — by an absence. Grow the corpus
as §5 requires and the filter silently disappears. **So the decision is not
"how do we reduce volume" but "what is the deliberate filter, before the
accidental one goes away".** Candidates, none chosen:

- *A severity floor on remediation.* Scan and map everything — both cheap and
  deterministic — but draft fixes only above a threshold. §8.1 is untouched:
  the findings are still admitted and still shown, they just do not all cost
  a model call. On this data a HIGH-only floor is 42 findings, not 239.
- *Fix once, apply to many.* Draft one fix for a (rule, file-shape) class and
  offer it across the files it fits. This is the right answer for the
  cross-file repetition and the wrong shape for everything built so far: the
  self-check is per file, and `applies_after` chains per file. It would need
  its own spec.
- *A per-PR cap.* Crude, predictable, and it makes the thing it drops
  invisible, which is the failure mode §8.1 exists to prevent. Only with a
  clear "N not drafted" surfaced to the reviewer.

### 5.1 Measured, and decided (2026-09-19)

**The measurement the decision was blocked on.** PugetScope's
`api-deployment.yaml`, hardened one edit unit at a time and rescanned by the
pinned tools after each -- no model in the loop, so this is the ceiling the
supersede can reach, not what a draft will reach:

| edit | findings left | mapped left | cleared |
|---|---|---|---|
| (none) | 36 | 22 | -- |
| `securityContext`, pod and container | 15 | 6 | **21** -- every 5.2.6/5.2.7/5.2.8/5.2.9/5.6.2/5.6.3 finding from both tools |
| `resources` | 7 | 6 | 8, all unmapped |
| image by digest | 4 | 3 | 3 |
| `automountServiceAccountToken: false` | 3 | 2 | 1 |
| liveness probe | 2 | 2 | 1, unmapped |
| NetworkPolicy document | 2 | 2 | 0 (see below) |
| secrets as files | 1 | 1 | 1 |

22 mapped findings, **5 distinct edits**, one of which clears 16. So the
per-file supersede is real -- if the first `securityContext` draft is
complete. The prompt's "configure an added block completely" exception
exists for exactly that and is unmeasured on YAML; the worst case, one field
per draft, is ~16 calls for that family alone. Cross-file: 14 Deployments ×
5-6 = **70-84 drafts for ~6 distinct decisions**, which is the estimate above
confirmed. Two side findings: `CKV2_K8S_6` is a graph check across the whole
scan directory, so the self-check -- which scans one file in isolation --
only sees a NetworkPolicy added to the *same* file; and `KSV-0125` (trusted
registry) has no fix that does not need to know the registry, so it will be
held on an assumption every time.

**Three facts that settled it:**

1. **checkov reports no severity.** All 250 Kubernetes findings carry
   `severity: None` (Prisma Cloud assigns them), which the scanner records as
   `UNKNOWN`. A severity floor is Trivy-only in practice, and checkov is the
   sole source for `CKV_K8S_35/38/43` and `CKV2_K8S_6`. The floor is dead --
   and severity was the wrong axis anyway: the cost is repetition.
2. **Files are remediated in parallel** (`Map`, `remediation_concurrency`
   4). A cross-file "draft once" cannot live in remediation-agent without
   racing; it belongs in mapping-agent (sequential over the PR) or in the
   review layer.
3. The spec's own line: ~$8-11 a run is tolerable; **the scarce resource is
   reviewer attention**, and that is spent in the dashboard, not the
   pipeline.

**Decided: draft everything, collapse the repetition where it is reviewed,
and cap the pipeline per file as a backstop.**

- *The pipeline is unchanged.* Every mapped finding is drafted, every draft
  is self-checked on its own file. §8.1 is untouched: nothing is filtered
  from view.
- *`MAX_DRAFTS_PER_FILE`* (remediation-agent, Terraform
  `max_drafts_per_file`, default 8): the backstop between the measured 5-6
  and the one-field-at-a-time 16. Superseded findings are free and do not
  count. Past the budget a finding is written **`not-drafted`** with the
  reason -- its own status, not `mapped`, so "N not drafted" is a count on
  the PR page rather than an inference -- and the next run queries it back
  up: once the drafted fixes are accepted, most come back superseded at
  baseline 0 without a call, and the rest get a fresh budget. Per file
  because of fact 2. The budget spans a file's continuations, since the
  counters a continuation carries in are that file's.
- *The dashboard groups drafted fixes by `(target_type, framework,
  control_id)`* -- "By control" on the PR page -- one card per group, the
  files inside it, and a group approve for the fixes that are
  scanner-verified `fix-proposed` with no unmet prerequisite. Keyed on the
  control rather than the rule, because the same `securityContext` fix is
  reached by a Trivy rule and a checkov rule. A `needs-human-only` fix is
  listed in the group and never bulk-approved: it is held because it deletes
  something or rests on a claim, and that is a per-fix judgement by
  construction. Each approval is its own audit event, noted as one of the
  group, so the trail explains itself without the page.

*Rejected:* the severity floor (fact 1); a per-PR cap as the primary filter
(the first N drafts are still fourteen copies, so it bounds cost without
reducing decisions). *Deferred, not rejected:* fix-once-apply-many in the
pipeline -- the right shape for the drafting cost, and fact 2 says how:
mapping-agent defers later occurrences of a pattern behind the first, and
approval triggers drafting the rest with the approved diff as template. Its
own spec, if the drafting cost ever matters more than it does now.

## 6. Order, and why

By cost, and each step earns the next:

1. **OpenTofu.** ✅ **Built 2026-09-16.** `.tofu`/`.tofu.json` in
   `SNAPSHOT_SUFFIXES` and `CONTEXT_SUFFIXES`, two eval cases including one
   using OpenTofu-only syntax. The corpus covered it already — same rules.
   No new gates: it is HCL, so the suppression markers and the resource
   regex apply as they are. **One thing the run taught us that the plan did
   not predict: checkov does not open `.tofu`**, so OpenTofu is Trivy-only
   coverage and its self-check has one source. Labelled in both cases.
2. **The multi-type scanner** (§3). ✅ **Built 2026-09-16**, with Terraform
   and OpenTofu as the only enabled types, and the rename and field split
   in the same deploy. Eval held at 97.3% across the refactor (73/75, up
   from 71/73 only because the two OpenTofu cases were added).
3. **Kubernetes/Helm** — the planned v2. Trivy does it today, the YAML is
   already in the snapshot for context-agent. Gated on: CIS Kubernetes in the
   ~~corpus~~ (built 2026-09-19, §5), ~~annotation-based suppression
   markers, a YAML structural guard~~ (both built 2026-09-19, §4), eval
   cases, and ~~a decision on volume~~ (decided and built 2026-09-19,
   §5.1). What is left is the eval cases and the admission itself.
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

- [x] Rename `terraform-scanner` → `iac-scanner` (§3). Decided 2026-09-16;
      done with the multi-type refactor so the destroy-and-create happens
      once.
- [x] The deliberate filter on remediation volume (§5). Measured and
      decided 2026-09-19 (§5.1): draft everything, group by control at
      review, `MAX_DRAFTS_PER_FILE` as the backstop. The severity floor it
      was leaning toward is dead -- checkov reports no severity.
- [x] `iac_type` splits into `target_type` and `finding_class` (§3.1).
      Decided 2026-09-16, done with the function rename. Both are per
      finding, from the tool's reported `Type`/`Class`, which both tools
      emit on every Result.
- [ ] Whether Helm is scanned as charts (Trivy renders them) or only as
      rendered output the user supplies. Rendering runs templates — far
      milder than §7, but not nothing.
- [ ] Whether a language with single-tool coverage (Bicep) is enabled at all,
      given the weaker self-check, or held until Trivy adds a Bicep scanner.
- [x] Which CIS benchmark editions to vendor, and their licensing. Decided
      2026-09-19 for Kubernetes: v2.0.0, the current edition (Kubernetes
      1.34-1.35), section 5 only. Ids and titles are verified against
      kube-bench's public config rather than the benchmark PDF, and the
      control text is our own summary, as it is for CIS AWS. Section 5's
      numbering has been stable since v1.10, so the choice of edition
      within 1.10-2.0 does not change a citation; v1.9 and earlier differ.
      Azure is still open.
