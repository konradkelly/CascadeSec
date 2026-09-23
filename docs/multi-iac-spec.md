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
| **ARM** | ✅ `azure-arm`, ids `AZU-nnnn` | ✅ `arm` | Measured 2026-09-22 on `azure-quickstart-templates` (175 templates): Trivy **264 findings, 30 rules**; checkov **640**. Four Trivy rules cannot pass on ARM at all and are dropped for that target -- see `docs/trivy-azure-arm-adapter-gap.md` |
| **Bicep** | ❌ not a Trivy scanner | ✅ `bicep` | 4 Azure findings (`CKV_AZURE_3/35/44/206`) on a storage account with `supportsHttpsTrafficOnly: false`. At scale (107 files): **366 findings**. The runner loads in the stripped image -- `pycep-parser` survives the numpy strip, verified 2026-09-22 |
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
| What do I re-run? | `target_type` | `terraform`, `opentofu`, `kubernetes`, `cloudformation`, `arm`, `bicep`, `npm`, `dockerfile` |
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

*A consequence in the corpus, found 2026-09-20.* `rule_mappings.json` keys
candidates by `(source, rule_id)`, which is enough while a rule only ever
fires on one language — `CKV_AWS_145` is Terraform's by construction. It
stops being enough for the rules that cross languages. `CKV_SECRET_6`, a
plaintext secret, fires on a `.tf` file and on a Kubernetes manifest, and
the control that fits the manifest (CIS Kubernetes 5.4.2, external secret
storage) must not be offered as a candidate for the Terraform one. So a
candidate may now carry an optional `target_type` that scopes it, and
`mapping-agent` filters the candidate list per finding. The key did not
change and no existing entry moved — an unscoped candidate is universal,
which is nearly all of them. This is `target_type` earning its keep on the
corpus side, having been introduced for the self-check.

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
| `scan_errors` | the scanner reports unparseable files | ~~Unchanged, and the one guard that ports as-is~~ **Wrong, measured 2026-09-22.** It ports only where a tool reports the failure. Trivy's parse-error logging is Terraform-only, and checkov reports `parsing_errors` for `arm` and `bicep` but **not** for `kubernetes` — so a broken manifest was invisible to both and the guard had been failing open since Kubernetes was admitted. See below |

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

**Built for ARM and Bicep 2026-09-22**, ahead of the language, per the rule
above. Everything below was measured against the pinned tools in a locally
built scanner image, not inferred:

- *ARM needs one suppression marker; Bicep needs none.* Strict JSON has no
  comment syntax, so every marker in the set was unreachable in an ARM
  template by construction. checkov reads a resource-level `"metadata":
  {"checkov": {"skip": [{"id": ..., "comment": ...}]}}` — confirmed: the
  check moved from `failed_checks` to `skipped_checks`. Its added lines carry
  the quoted token `"checkov"` and *not* the substring `checkov:skip`, so
  that token is the entry an HCL- and YAML-shaped set misses. Bicep has `//`
  comments and reaches `checkov:skip` as HCL does; the one surprise is that
  checkov honours it only *inside* the resource body — above the declaration
  it is ignored, as are `# checkov:skip` and `// checkov:skip` with a space.
  That changes nothing here, because the marker is a substring of an added
  line either way. Trivy's only ARM suppression is `.trivyignore`, a separate
  file the agent cannot write: it returns one file's corrected content.
- *ARM's reader is a real parser, unlike Kubernetes'.* Both of that reader's
  reasons are absent — `json` is stdlib where PyYAML is in neither the
  runtime nor the layer, and there is no ARM analogue of an unrendered chart.
  It reads `resources` recursively so a child resource counts, and both the
  list form and languageVersion 2.0's symbolic-name object form, since a
  reader that knew only the list would see no resources at all in a 2.0
  template — and no resources means no deletions, which is the gate failing
  open. It *raises* rather than returning `[]` when the file does not parse,
  for the same reason.
- *Bicep's is a regex*, because `pycep-parser` lives in the scanner image and
  not in remediation-agent. It stops at the type's closing quote, so `= if
  (...)`, `= [for x in y: {` and a leading `existing` are all covered without
  being enumerated, and it counts `module` declarations under a synthetic
  type: a module deploys a whole sub-template, so dropping one is more of
  this gate's business than dropping a resource, not less.
- *Addresses join on `/` for both.* An ARM type already contains dots
  (`Microsoft.Storage/storageAccounts`), so a dot would read as part of the
  type rather than as the separator before the name.

**The third guard was not fine, and had not been since 2026-09-20.** The
table above said `scan_errors` was the one guard that ports as-is. Measured:
a Kubernetes manifest that is not valid YAML is invisible to *both* tools.
Trivy reports `Detected config files num=0` and logs nothing at all — its
parse-error line is Terraform-only, so no widening of the stderr regex
reaches it. checkov's `kubernetes` runner emits no report whatsoever, not
even a `parsing_errors` entry, where its `arm` and `bicep` runners both do
(a valid manifest in the same place gives 20 failed checks, so the runner
does run). Zero findings with an empty `scan_errors` is exactly what the
self-check reads as *the fix worked*, so a remediation that broke a
manifest's YAML earned a scanner-verified badge.

So the scanner now parses what it admitted, itself, and reports what it
cannot read — PyYAML read off `/opt/python`, where checkov already ships it,
imported only when the snapshot holds YAML and refusing the scan outright if
it is missing, because a parse check that quietly does not run is the same
fail-open again. A Go-template file is skipped rather than reported: a chart
template is not a file this scanner failed to read, it is one this scanner
does not handle, and §6 step 3 measured the cost of leaving Helm out as zero
noise. Reporting them would put a scan error on every repository carrying a
chart, and two of the external baselines carry one.

ARM and Bicep do not need this — checkov reports `parsing_errors` for both —
but ARM gets it anyway when it is admitted, since the `$schema` sniff has to
parse the file to classify it at all.

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
3. **Kubernetes.** ✅ **Built 2026-09-20**, every gate first: the CIS
   Kubernetes corpus and the two remediation gates (2026-09-19, §4 and §5),
   the volume decision (§5.1), then 19 eval cases and a clean control, then
   the admission — `.yaml`/`.yml` in `SNAPSHOT_SUFFIXES`, `kubernetes` in
   `--misconfig-scanners` and `--framework`. 50 of 50 labelled pairs fire
   locally against the pinned tools; the deployed number needs a rebuild and
   a `run_eval.py` run.

   **Helm is not in it.** Chart files are already in the snapshot — they are
   `.yaml` — and Trivy renders charts natively, so enabling it is one word.
   The word stays out because of the self-check, not because of the
   rendering: remediation scans *one corrected file in isolation*, and a
   template without its `Chart.yaml` and `values.yaml` renders nothing, so
   the rescan returns no findings and this pipeline reads no findings as
   "the fix worked". That is precisely the fail-open §4 exists to prevent.
   Enabling Helm means teaching the self-check to rescan a chart, not adding
   a scanner name. Measured alongside: with `helm` off, Trivy skips a chart
   template silently rather than reporting a parse error, so the cost of
   leaving it out is zero noise.

   **What admission actually cost, measured 2026-09-20.** A `.yaml` is the
   first suffix that does not say what the file is — manifest, Helm template,
   CloudFormation stack, CI workflow, or none. Nothing pre-classifies it:
   both tools were run over a directory holding all five, and each reported
   only the Kubernetes manifest, skipping the rest silently with no parse
   error and nothing on stderr. So the admission lists are the classifier,
   and a repository full of unrelated YAML costs a download.
4. **CloudFormation.** AWS, so much of the corpus carries over — the same CIS
   AWS controls, reached through different rule ids. Cheapest of the
   remaining.
5. **Bicep/ARM.** ✅ **Built 2026-09-22**, gates first as always: the ARM
   and Bicep structural guards and the ARM suppression marker, the CIS Azure
   3.0 corpus, the volume measurement and the single-source badge, 14 eval
   cases, then the admission -- `.bicep` in `SNAPSHOT_SUFFIXES`, `azure-arm`
   in `--misconfig-scanners`, `arm,bicep` in `--framework`. 26 of 26 labelled
   pairs fire locally against the pinned tools.

   **Three things the run taught us that the plan did not predict.**

   *ARM is the first language admitted by content rather than by name.* A
   `.json` is a deployment template, a lockfile, a tsconfig or none of them,
   and unlike `.yaml` the non-matches vastly outnumber the matches, so the
   Kubernetes precedent -- let the admission lists classify -- does not carry
   over: checkov's secrets runner is given `--enable-secret-scan-all-files`
   and reads the directory, so an unwanted `.json` has to be *removed*, not
   merely unlisted. Admission is a top-level `$schema` naming a
   `deploymentTemplate`. The measurement that settles the alternative: on
   `azure-quickstart-templates` the tree holds 519 `.json` files of which 175
   are templates, and 159 of the remainder are `azuredeploy.parameters.json`
   -- files a filename convention admits and this does not.

   *Trivy's `azure-arm` adapter is weaker than its scanner list suggests.*
   Four of its rules -- `AZU-0056`, `AZU-0057`, `AZU-0058`, `AZU-0013` --
   cannot be cleared by configuring what they name. Trivy's own pass/fail
   census over the 175 templates gives `AZU-0057` 0 PASS / 25 FAIL,
   `AZU-0058` 0 PASS / 25 FAIL and `AZU-0013` 0 PASS / 13 FAIL. Dumping the
   adapted state a check receives says why: `accountreplicationtype` is
   empty on a template declaring `Standard_GRS`, because the adapter reads
   `properties` and not its sibling `sku`. The same intent in Terraform
   clears all four, so it is the adapter and not the checks. Three were unmapped in the corpus as a result: a finding no
   edit can clear would be drafted, failed and redrafted forever.

   *The CIS edition is part of the citation here*, unlike CIS Kubernetes
   section 5. v4.0 renumbers every storage control and drops SQL auditing
   entirely, so v3.0 is vendored deliberately rather than by default. See
   `corpus/README.md`.
6. **Pulumi/CDK.** §7.

### 6.1 Azure volume, measured 2026-09-22

§5 asks what a new language does to remediation volume before it is enabled.
Measured on `Azure/azure-quickstart-templates` (175 ARM templates, 107 Bicep
files): **1270 findings, 98 distinct rules, 219 files with at least one
finding.** Findings per file: mean 5.8, median 5, max 26. Files per rule:
mean 11.3, **median 3**, max 57.

The mean is Kubernetes' number (11.8) and the median is not, which is the
whole story. Kubernetes' repetition came from one workload copied per
service, so the typical rule really did hit twelve near-identical
Deployments. Here the mean is dragged up by a handful of VM rules across 175
*unrelated sample projects* that happen to share a tree; the typical rule
hits three files. A repository of independent quickstarts is not the shape of
a pull request, and reading this as the Kubernetes problem would be reading
an artefact of the corpus target.

So: **nothing new is needed.** `MAX_DRAFTS_PER_FILE` (default 8) is already
the backstop, the per-file chain and the `cleared_by`/`resolved_by` supersede
already collapse the within-file case, and the dashboard's group-by-control
forms `arm` and `bicep` groups with no change, since it keys on
`(target_type, framework, control_id)` and those values simply appear. If a
real Azure pull request ever shows files-per-rule above ~5, reopen §5 then,
with that measurement rather than this one.

One finding that does carry over unchanged: **checkov reports no severity on
Azure either.** All 1006 of its findings here are `severity: None`, as all
250 Kubernetes ones were. §5.1's fact 1 -- that a severity floor would be
Trivy-only in practice -- now holds across three target types, which is
enough to stop treating it as a per-language question.

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
- [x] Whether Helm is scanned as charts (Trivy renders them) or only as
      rendered output the user supplies. **Decided 2026-09-20: neither, for
      now.** The question turned out not to be about rendering safety at all
      — the blocker is that the self-check rescans a single file, where a
      chart template renders to nothing and an empty rescan reads as a
      verified fix. Reopen it with a design for a chart-aware self-check
      (rescan the chart directory, not the file), which is also what
      `applies_after` would need to chain across a chart. See §6 step 3.
- [x] Whether a language with single-tool coverage (Bicep) is enabled at all,
      given the weaker self-check, or held until Trivy adds a Bicep scanner.
      **Decided 2026-09-22: enabled, and said in the UI.** The question
      answered itself the moment §6 step 1 shipped -- OpenTofu is Trivy-only
      because checkov will not open a `.tofu`, so a single-source self-check
      has been in production since 2026-09-16 and nobody proposed holding
      that. Bicep is the same situation with the tools reversed, and it is
      where most new Azure IaC is written, so holding it would forgo the bulk
      of the coverage this step exists for. What was actually wrong was not
      the weaker check but that it was invisible: OpenTofu's caveat lived
      only in `corpus/eval/README.md`, which no reviewer reads. Both now
      carry a "<tool> only" badge beside the verdict -- on the finding, in
      the findings table, and on the fix group, which is where a bulk
      approval is decided (`dashboard/src/review/coverage.ts`). The badge
      adds to the verdict and never softens it.
- [x] Which CIS benchmark editions to vendor, and their licensing. Decided
      2026-09-19 for Kubernetes: v2.0.0, the current edition (Kubernetes
      1.34-1.35), section 5 only. Ids and titles are verified against
      kube-bench's public config rather than the benchmark PDF, and the
      control text is our own summary, as it is for CIS AWS. Section 5's
      numbering has been stable since v1.10, so the choice of edition
      within 1.10-2.0 does not change a citation; v1.9 and earlier differ.
      Azure is still open.
