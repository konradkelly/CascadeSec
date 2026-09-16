# IaCPosture — Technical Spec

**GitHub repo description:** DevSecOps/AppSec tool: Terraform security scanning, OWASP/CIS control mapping, and AI-assisted remediation with self-verification, built on serverless AWS.

**Version:** 0.1 (draft)
**Author:** Konrad Le-De Kelly
**Status:** Pre-build / architecture phase

---

## 1. Summary

An agentic system that scans Terraform infrastructure-as-code for security misconfigurations, IAM policy violations, and OWASP/CIS-mapped vulnerabilities, then proposes minimal, self-verified remediation diffs for human review. The system runs as a CI check on pull requests and never auto-merges — every finding and every proposed fix is presented to a human reviewer with full citations back to the specific rule and framework control it addresses.

**Core design principle:** the agent proposes, it never disposes. Deterministic tools do the finding; the LLM explains and drafts; a human approves.

---

## 2. Goals / Non-Goals

**Goals**
- Detect security misconfigurations in Terraform (network exposure, IAM over-permissioning, missing encryption, hardcoded secrets, unpinned module sources)
- Detect security misconfigurations in Kubernetes manifests and Helm charts (privileged containers, missing `runAsNonRoot`, host network/PID access, missing resource limits, overly broad RBAC) — **v2 scope, see §8**
- Map each finding to a specific control (OWASP CI/CD Top 10, OWASP Cloud-Native/IaC security guidance, CIS AWS Foundations Benchmark; CIS Kubernetes Benchmark added in v2 alongside K8s/Helm scanning)
- Propose minimal remediation diffs, self-verified against the same scanner that found the issue
- Run as a GitHub Action / PR check with a reviewable dashboard
- Produce measurable eval numbers (detection recall, fix acceptance rate)

**Non-Goals (v1)**
- Auto-merging any change without human approval
- Covering cloud providers beyond AWS
- Kubernetes manifests and Helm charts as scan targets — deferred to v2 once the Terraform path is proven (see §8); CloudFormation/Pulumi remain further out
- Deploying this project's own infrastructure on Kubernetes — the pipeline itself stays serverless (see §4); EKS/Helm, once added, refers to the *scan target*, not the *host*
- Full legal/compliance certification (SOC 2 audit-readiness claims) — this is a developer aid, not an auditor

---

## 3. Architecture Overview

```
                    ┌─────────────────────────────────────────────┐
                    │              GitHub PR Trigger               │
                    │         (terraform plan / PR diff)            │
                    └───────────────────┬───────────────────────────┘
                                        │
                    ┌───────────────────▼───────────────────────────┐
                    │   Layer 1 — Deterministic Scan (no LLM)        │
                    │   terraform-scanner Lambda: Trivy + Checkov    │
                    │   (v1)                                          │
                    │   k8s-scanner Lambda: kubesec + Checkov +      │
                    │     helm template — v2 addition, same          │
                    │     fan-out pattern by iac_type                │
                    │   → raw findings                                │
                    └───────────────────┬───────────────────────────┘
                                        │
                    ┌───────────────────▼───────────────────────────┐
                    │   Layer 2 — Framework Mapping Agent (Lambda)   │
                    │   finding → OWASP/CIS control + citation       │
                    └───────────────────┬───────────────────────────┘
                                        │
                    ┌───────────────────▼───────────────────────────┐
                    │   Layer 3 — Remediation Agent (Lambda)         │
                    │   finding → proposed diff → self-check rescan  │
                    └───────────────────┬───────────────────────────┘
                                        │
                    ┌───────────────────▼───────────────────────────┐
                    │   Layer 4 — Review Dashboard (API GW + React)  │
                    │   human approve / edit / reject → audit log    │
                    └─────────────────────────────────────────────────┘
```

---

## 4. AWS Architecture (DVA-C02-aligned)

The system is built as a serverless pipeline so it doubles as hands-on practice for AWS Developer Associate domains (Lambda, API Gateway, IAM, DynamoDB/RDS, event-driven design, deployment/CI-CD, monitoring).

### 4.1 Core resources

| Resource | Purpose | DVA-C02 domain |
|---|---|---|
| **API Gateway (REST or HTTP API)** | Public-facing endpoints for the review dashboard (fetch findings, submit review decisions) and the GitHub webhook receiver | Deployment, Security |
| **Lambda — `webhook-receiver`** | Validates GitHub webhook signature, extracts PR diff/Terraform files, drops job onto SQS | Development with AWS Services |
| **Lambda — `terraform-scanner`** | Runs Trivy + Checkov against Terraform files. Packaged as a container image in ECR (layers until 2026-09-13; §4.3). **v1.** | Development, Deployment |
| **Lambda — `k8s-scanner`** | Runs `helm template` to render charts, then kubesec + Checkov against the rendered manifests. Packaged with the same shared Checkov layer + a kubesec/helm-binaries layer. **v2 — deferred until the Terraform path is proven; see §8.** | Development, Deployment |
| **Lambda — `mapping-agent`** | Calls Anthropic API with scanner findings, returns control-mapped findings (strict JSON schema) | Development, Security |
| **Lambda — `remediation-agent`** | Calls Anthropic API to draft a diff, then invokes `terraform-scanner` or `k8s-scanner` (by `iac_type`) to self-check the fix. A draft may return `questions` about the rest of the repository; `context-agent` answers them and the fix is redrafted (docs/context-agent-spec.md) | Development, Security |
| **Lambda — `context-agent`** | Answers a draft's questions by searching and reading the repository snapshot in S3, every `yes`/`no` cited to `file:line` and the citation verified in code. Own least-privilege role: reads `scans/*` and the API key, nothing else. Built 2026-09-12 | Development, Security |
| **Lambda — `review-api`** | CRUD behind API Gateway for the dashboard: list findings, get diff, post approve/reject | Development with AWS Services |
| **SQS queue** | Decouples webhook ingestion from scan execution — a PR with many changed files shouldn't block the webhook response (GitHub expects a fast ACK) | Development, Deployment |
| **DynamoDB** *or* **RDS (Postgres)** | Findings, controls corpus, review audit log. DynamoDB fits the access pattern better (fetch by PR/finding ID) and is more idiomatic serverless; Postgres is a better fit if you want relational queries across the controls corpus. See §4.2 for the tradeoff. | Development with AWS Services |
| **S3** | Stores raw Terraform snapshots per scan run, scanner output artifacts, and the versioned control corpus (CIS/OWASP text) | Development, Deployment |
| **EventBridge** | Fan-out trigger for scheduled re-scans (e.g. nightly re-check of `main` against an updated CIS benchmark version) | Development with AWS Services |
| **IAM roles (per Lambda, least-privilege)** | Each Lambda gets a narrowly scoped execution role — `terraform-scanner` and `k8s-scanner` each get only the tooling/permissions their scan type needs, and neither gets `remediation-agent`'s permissions. This is itself a live demo of the least-privilege principle the tool checks for. | Security, Deployment |
| **Secrets Manager** | Anthropic API key, GitHub App private key/webhook secret | Security |
| **CloudWatch (Logs, Metrics, Alarms)** | Structured logs per Lambda, custom metric for findings-per-scan and fix-acceptance-rate, alarm on scan failures | Troubleshooting and Monitoring |
| **X-Ray** | Trace a webhook event end-to-end through the SQS → Lambda chain — useful for debugging latency in the self-check loop | Troubleshooting and Monitoring |
| **CloudFront + S3 (static hosting)** | Hosts the review dashboard (React + Vite + TypeScript) | Deployment |
| **Cognito** | Auth for the review dashboard and its API. Pulled forward from the original v1.1 plan (see §8): the API exposes real vulnerability findings and a route that resolves them, and an unauthenticated write endpoint plus a self-asserted audit-trail actor were both live problems the moment the dashboard went internet-facing, not multi-tenant-only ones. | Security |

### 4.2 Data store decision

**Decided: DynamoDB.** Single-table design keyed on `PR#<id>` / `FINDING#<id>`, fits Lambda's stateless request pattern well, no VPC/connection-pooling concerns, cheaper at low volume. GSIs will be added per query pattern as they come up (e.g. a `control_id` GSI for "show me all findings mapped to CIS 1.16 across every scan this month"). If ad-hoc analytical queries across the controls corpus become a real need later, a small Postgres+pgvector instance can be added alongside for that piece specifically, rather than migrating the whole findings store.

**Recommendation for v1:** DynamoDB for findings/audit-log (matches the event-driven access pattern and avoids VPC complexity for the Lambda chain), S3 for the versioned control corpus text. If you later add embedding-based retrieval over the corpus, add a small Postgres+pgvector instance just for that piece rather than migrating everything — a hybrid is fine and is itself a defensible architecture decision to explain in an interview.

### 4.3 Scanner packaging decision

**Decided 2026-09-13: a container image for the scanner; zip + layer for everything else.** `lambda/terraform-scanner/Dockerfile`, built and pushed by `build-image.sh` to an ECR repository Terraform owns, and pinned by digest in `lambda_terraform_scanner.tf` so a push followed by an apply rolls the function and an apply alone changes nothing.

*Originally decided: Lambda layers* — a shared Checkov layer plus a per-scanner binary layer, for the DVA-C02 reps with layer versioning and size limits, and because each function fitted. It held from 2026-08-31 to 2026-09-12 and delivered those reps, including the one that ended it: the day Trivy replaced tfsec (§8.2 item 6) the function stood at 247MB of Lambda's 250MB unzipped ceiling, and the next bump of either tool was certain to fail the deploy. An image is allowed 10GB. Nothing else changed — same handler, same role, same Step Functions integration, same alarms; the image keeps the layers' on-disk layout (`/opt/bin/trivy`, `/opt/python`), so `handler.py` did not change. Measured after the swap: the eval is the same 68/70, and a cold invocation is 1.4s init plus ~50s for the checkov import and a 43-case scan, as before — the image pull is not visible in it.

Splitting the scan stage by `iac_type` (rather than one Lambda running every tool) still stands, for the least-privilege reason in §4.1 rather than the size one. `k8s-scanner` (v2) becomes a second image — or the same one, since Trivy scans Helm charts, Kubernetes manifests and Dockerfiles natively — instead of another layer-budget puzzle.

*What was considered and not done:* ECS/Fargate. It solves the size problem too, and would remove the 15-minute ceiling and the cold start — but only the cold start is a real cost today, and only a persistent worker fixes it, which brings a VPC, NAT for the agents' egress, a queue replacing the `Map` fan-out, and a cost floor above the whole current bill. The trigger to revisit is a context-agent loop that needs more than 15 minutes for one finding, or a v3 PR-check latency target a cold start cannot meet; neither exists yet. The cold start itself has Lambda-native fixes (the in-process checkov `Runner` import the handler's TODO names; provisioned concurrency) that do not need a platform change.

The other functions stay zip-packaged with the shared anthropic layer: they are small, and there is no size pressure on them.

### 4.4 Event flow (detail) — v1 (Terraform only)

1. GitHub PR opened/updated → webhook → **API Gateway** → **`webhook-receiver` Lambda**
2. `webhook-receiver` verifies HMAC signature, pulls changed `.tf` files via GitHub API, tags each with `iac_type: terraform`, writes raw files to **S3**, drops `{pr_id, s3_key, iac_type}` onto **SQS**
3. **`terraform-scanner` Lambda** runs Trivy + Checkov, writes raw findings to **DynamoDB** (`status: raw`)
4. **`mapping-agent` Lambda** — for each raw finding, calls Anthropic API with the finding + relevant control corpus excerpt (pulled from S3), writes back `status: mapped` with control citation. *Built as a Step Functions state (§8.2 item 5) rather than the DynamoDB stream originally sketched here: steps 3–5 are one Standard execution per PR, `terraform/step_functions.tf`.*
5. **`remediation-agent` Lambda** triggered per **file** with mapped findings — a `Map` state, bounded concurrency — drafts a diff via Anthropic API for each finding in the file in turn, then invokes `terraform-scanner` to self-check the fix against the patched file, sets `self_check_passed: true/false`, writes `status: fix-proposed` or `status: needs-human-only` if self-check fails. *Per file, not per finding, because fixes within a file are chained (each drafted on the last verified one); a file too large for one invocation continues across several, the handler returning where it stopped.*
6. Reviewer opens dashboard (**CloudFront** → React app → **API Gateway** → **`review-api` Lambda** → DynamoDB) — approves/edits/rejects
7. On approval, `review-api` Lambda calls GitHub API to push the diff as a suggested change / commit on the PR branch
8. Every step writes a `review_event` / `audit_log` entry — nothing is silently decided

**v2 change:** step 2 tags K8s/Helm files as `k8s-manifest`/`helm` too, `webhook-receiver` fans out to `k8s-scanner` alongside `terraform-scanner`, and step 5's self-check routes by `iac_type` to whichever scanner matches. `mapping-agent`, `remediation-agent`, `review-api`, and the dashboard require no changes — the fan-out is isolated entirely to the scan stage, which is the point of splitting it into two Lambdas now rather than later.

---

## 5. Data Model

Both item types below live in a **single DynamoDB table**, not two separate tables — this is the standard single-table design pattern for DynamoDB, where distinct entity types are distinguished by their key prefixes (`PR#`/`FINDING#` vs `PR#…#FINDING#`/`EVENT#`) rather than by separate tables. This keeps related data queryable together (e.g. everything under one `PR#<pr_id>` partition) and avoids the cross-table joins DynamoDB isn't designed for.

```
FindingRecord (DynamoDB)
├── pk: PR#<pr_id>
├── sk: FINDING#<finding_id>
├── iac_type: "terraform" | "k8s-manifest" | "helm"
├── source: "trivy" | "checkov" | "kubesec"      # "tfsec" in records written before 2026-09-12
├── rule_id: string
├── file, line_range
├── severity
├── control_mappings: [{ framework: "CIS-AWS" | "CIS-Kubernetes" | "OWASP-CICD" | "OWASP-CloudNative", control_id, control_text_ref (S3 key), citation_span }]
├── status: raw | mapped | fix-proposed | needs-human-only | superseded | resolved
├── superseded_by: finding_id, only with status superseded
├── proposed_fix: { diff, rationale, self_check_passed, cleared, self_check_new_findings: [], agent_diff?, applies_after: [], scan_errors: [] }
└── created_at, updated_at

ReviewEvent (DynamoDB)
├── pk: PR#<pr_id>#FINDING#<finding_id>
├── sk: EVENT#<timestamp>
├── actor: reviewer id (from the verified JWT, never the request body)
├── action: approved | edited | rejected | reopened
│     reopened is written by actor "system", never posted by a reviewer: an edit or
│     rejection upstream invalidated a fix that had already been decided
├── edited_diff: the reviewer's diff, on an "edited" action
└── notes
```

**Why `ReviewEvent.pk` carries `pr_id`.** An earlier draft keyed it on
`FINDING#<finding_id>` alone. That is unsound: `finding_id` is a content hash
of the finding, so the same rule on the same file yields the *same* id in
every PR that scans it — ids are unique within a PR, not across them. Keyed on
the id alone, a decision recorded against one PR appears in the audit trail of
every other PR containing that finding, attributing decisions nobody made
there. This was observed in practice, with one approval on `demo-1` showing up
against `manual-test-1`. For a log whose entire purpose is that nothing is
silently decided, misattribution is the one defect it cannot tolerate.

**On `superseded`:** set when another fix on the same file already cleared this
finding's rule, so no fix was drafted for it — with `superseded_by` naming the
finding whose fix did it. Rules overlap between and within the two scanners
(`CKV_AWS_145` wants KMS, `aws-s3-enable-bucket-encryption` wants any
encryption), so one fix routinely clears more than its own finding. Distinct
from `resolved`, which means a human accepted something; this is the scanner
reporting the rule no longer fires, and it holds only while the superseding fix
does.

**On `applies_after`:** the ordered finding ids whose fixes this one is
drafted on top of, empty for the first fix in a file. Fixes to one file are a
chain, not a set — every file in the live table carries 3-22 findings, and
drafting each from the pristine snapshot produced that many competing rewrites
of the same lines. A diff does not apply cleanly without its prerequisites, so
approving one without them lands a change whose context never existed. Survives
a reviewer's edit, unlike the self-check fields: editing a diff does not
re-root it.

**On `scan_errors`:** files the scanner could not parse when rescanning this
fix. Non-empty means the fix was never verified at all, which is distinct from
a fix that was verified and failed.

**On `proposed_fix`:** `cleared` records whether the rescan confirmed the
original finding gone, separately from `self_check_passed`, which also
requires that no new findings appeared — a fix can clear the original and
still fail, and the two failure modes need telling apart (§8.1). `agent_diff`
preserves the agent's original diff the first time a reviewer edits the fix,
so fix-acceptance (§7) stays measurable after an edit.

---

## 6. Agent Contracts (strict JSON schemas)

Both LLM-calling Lambdas constrain output to schema-validated JSON — no free text accepted downstream.

**Mapping agent output:**
```json
{
  "finding_id": "string",
  "control_id": "string",
  "framework": "CIS-AWS-1.4 | OWASP-CICD-Top10 | OWASP-CloudNative",
  "citation": "verbatim short excerpt, <15 words, from control text",
  "rationale": "1-2 sentences, must reference the finding's rule_id"
}
```

**Remediation agent output:**
```json
{
  "finding_id": "string",
  "diff": "unified diff format only",
  "rationale": "string",
  "self_check_passed": "boolean — set by code, not the LLM",
  "self_check_new_findings": ["array of any new rule_ids introduced by the fix"]
}
```

`self_check_passed` is **never** an LLM-asserted field — it's computed by re-running the deterministic scanner against the patched file and comparing findings before/after in code. This is the single most important integrity guarantee in the system.

**Suppression comments defeat that guarantee, and must be rejected in code.** The self-check asks "does the scanner still report this finding?", so a diff that merely silences the rule — `#tfsec:ignore:`, `#checkov:skip=`, `trivy:ignore`, `nosec` — clears the finding, introduces nothing new, and comes back `self_check_passed: true`. The agent earns a scanner-verified badge for changing no infrastructure at all.

This is not hypothetical. On the first run against real code (PugetScope, §7), asked to fix a CRITICAL `0.0.0.0/0` ingress rule, the agent left the CIDR untouched and added `#tfsec:ignore:aws-ec2-no-public-ingress-sgr` twice, with a fluent justification comment. It failed the self-check only by accident: that file held three instances of the rule, so the rescan still reported the pair. In a single-instance file it would have passed and been presented to a reviewer as verified.

Two consequences, both now implemented in `remediation-agent`:

- The prompt forbids suppressions **and** `_find_added_suppressions` enforces it on the diff's added lines, refusing the fix before the scanner ever runs. Prompt-only would be trusting the model's output, which is precisely what this project exists not to do. Pre-existing suppressions are the author's decision and are left alone.
- The before/after comparison counts **occurrences** per `(source, rule_id)` rather than testing presence, so "one of three instances was fixed" is distinguishable from "none were". Note this removes the accident above — which is exactly why the suppression check has to be a hard gate rather than advisory.

This also qualifies §8.1's admission rule. "The scanner's rule *is* the vulnerability" holds for what the rule *matches*, but every scanner ships an escape hatch that stops it matching without changing the infrastructure. Any scanner class admitted in future needs its suppression syntax added to `SUPPRESSION_MARKERS` before its fixes can be trusted.

### 6.1 The self-check proves security posture, not functional correctness

A clean rescan proves the finding is gone. It cannot prove the infrastructure still works, and nothing downstream should read it as though it does.

The sharpest illustration, again from the first real-code run: asked to fix an open port 80 ingress rule, the agent deleted the rule and stated in its rationale that certificate issuance used DNS-01. PugetScope's cert-manager `ClusterIssuer` uses ACME **HTTP-01**, which requires inbound port 80. The fix would have broken TLS renewal roughly 60 days later — long after anyone would connect the outage to a security fix. It passed the self-check cleanly, because deleting the rule genuinely removes the finding.

Two structural consequences, both enforced in `remediation-agent` rather than requested in the prompt:

- **Deletions are held for review.** `_find_dropped_resources` compares resource-block counts per *type* between the original and corrected file. A net decrease forces `needs-human-only` however clean the rescan. Comparison is per type, not per address, so a rename (a delete plus an add — as in a legitimate `nodeport_from_internet` → `nodeport_from_admin` rescope) is not mistaken for a deletion.
- **Unverifiable claims are declared, not buried.** `assumptions` is a required field on the agent's output schema, and a non-empty list forces `needs-human-only`. The agent sees exactly one file, so any claim about how the wider system behaves is a guess; the schema makes it a visible, checkable guess instead of confident prose.

**Calibrating `assumptions` mattered as much as adding it.** Defined as "every fact you could not verify," even a self-contained fix (adding an SSE block to a bucket) declared four — provider versions, style preferences, *"SSE-S3 is transparent to clients"* — so nothing ever passed and `fix-proposed` became an empty category. A gate that catches everything discriminates nothing, and a reviewer trained to skim four bullets of boilerplate is a reviewer who will skim the one that matters. The definition is therefore **consequence-based**: an assumption qualifies only if it is unverifiable from the file *and* its falsity would break the running system or leave the finding unfixed. Measured either side of that change:

| Case | "unverifiable" wording | consequence wording |
|---|---|---|
| S3 encryption (self-contained) | 4 assumptions, held | **0 assumptions, passes** |
| Port 80 (depends on unseen ACME config) | 4 assumptions, held | **2 assumptions, held** — and both are real |

The surviving port-80 assumption names ACME HTTP-01 explicitly, so the fix now arrives with its own falsification test attached.

**Measured again across every fix in the table on 2026-09-12**, after the gate had been live for four days: of 14 drafted fixes, 7 passed to `fix-proposed` and 6 were held — but only **2 of those 6 were held by `assumptions`**, both on PugetScope's security groups, and both name a real dependency (ACME HTTP-01, and `var.admin_cidrs` being populated). The other 4 were held by `self_check_new_findings`. On `demo-1`'s self-contained bucket fixes the gate fired **zero** times. So the consequence-based wording is holding: it is quiet on fixes that can be checked from the file and loud on the ones that cannot. The dominant reason a fix is held is not assumptions but a fix that introduces new findings — see §8.3.

**Where this leads.** An assumption is a question the agent could not ask.
`docs/context-agent-spec.md` (v5) is the component that asks them, under the
same retrieve-and-cite discipline `mapping-agent` already uses for controls —
and the resolution rate of the assumptions now in the table is its eval.

**On division of labour between prompt and code.** The prompt is what changed the agent's *behaviour* — it stopped suppressing, and started constraining rather than deleting. The code gates are what make that behaviour non-optional. As of this writing neither the suppression nor the deletion gate has fired in production, because the prompt has so far prevented the behaviour they guard against; they are proven by unit tests against the real captured diffs. That is the intended arrangement, not a redundancy: a prompt is a request, and the project's premise is that the model's output is checked by code rather than trusted.

---

## 7. Eval Plan

1. **Detection recall**: labeled set of ~30-50 Terraform snippets with known injected vulnerabilities (drawn from CIS benchmark examples + hand-crafted edge cases) — measure what fraction Layer 1 + Layer 2 correctly find and correctly map. *Built: `corpus/eval/`, 40 cases. Layer 1 detection recall **97.0%** (2026-09-10), with a corrections log that keeps the number non-circular. Layer 2 reports **mapping coverage** — whether a candidate control exists to cite — at **72%** of labelled pairs and **39%** of all distinct rules a scan raises (2026-09-12); the gap between the two is the point, since the labels are a minimum and a real queue looks like the 123. Whether the agent picks **well** among candidates is still unmeasured: that needs a labelled expected control per case.* In v2, extend with ~15-20 hand-crafted/AI-generated Kubernetes manifest/Helm chart snippets and report recall per `iac_type`.
2. **Remediation safety**: for every proposed fix in the labeled set, measure (a) does self-check confirm the original finding cleared, (b) does the fix introduce any new findings
3. **Fix acceptance rate**: once running against real PRs, track approved-unedited vs edited vs rejected per fix — the headline metric for the project writeup

---

## 8. Build Phases

| Phase | Scope |
|---|---|
| **v1 — Terraform only, read-only scan + suggest** | `terraform-scanner` + Layers 2-3 running on manual trigger (CLI or simple upload), findings + proposed diffs shown in dashboard, no GitHub write-back. Fastest path to a complete, demoable project — proves the whole pipeline (scan → map → remediate → self-check → review) on one IaC type before adding scope. Dashboard and review API ship behind Cognito from the start (see below) rather than as a later add-on. |
| **v2 — Beyond Terraform** | *Rescoped 2026-09-16 — [`docs/multi-iac-spec.md`](./multi-iac-spec.md).* No `k8s-scanner` Lambda: §4.3's split existed for the 250MB layer ceiling, which the container image removed, and the one image already parses Kubernetes, Helm, CloudFormation, ARM and Ansible (Trivy) plus Bicep (checkov). So one scanner selects `iac_type` per file instead, renamed `iac-scanner` (decided 2026-09-16). Order: OpenTofu (free — `.tofu` is HCL and scans identically), then the multi-type refactor, then Kubernetes/Helm, CloudFormation, Bicep/ARM. The cost is not the scanner but the corpus (all 51 mappings are AWS; Kubernetes alone raised 239 unmappable findings on PugetScope) and the eval (45 cases, all AWS Terraform). **No language ships until its suppression markers and structural guard are implemented** — both are HCL-shaped today and would fail open on YAML, which looks like a verified fix. Pulumi and CDK are out: no scanner parses them, and the only route runs the user's program. |
| **v3 — CI integration** | GitHub App/webhook, PR-triggered scans, diff suggestions posted as PR comments |
| **v4 — Write-back on approval** | Approved fixes committed to PR branch automatically |
| **v5 — `context-agent`** | A retrieval step that answers what `remediation-agent` currently has to declare it cannot: it reads the rest of the repository and cites `file:line`. Deferred deliberately, not for lack of motivation — the evidence is already in the table (see below). [`docs/context-agent-spec.md`](./context-agent-spec.md) |

**On v5's position.** `assumptions` is, read literally, a list of queries the
agent wanted to run and could not — and four of the six in the live table are
answerable from Terraform already in the snapshot. So the case for
`context-agent` is measured rather than speculative, and it is last anyway,
for two reasons that are dependencies rather than preferences: the snapshot
carries `**/*.tf` only, so two of those six questions have no files to read;
and a multi-call agent has no execution budget until remediation fans out
(§8.2 item 5). Corpus growth is **not** among its prerequisites — it reads the
repository, not `corpus/` — and coupling the two would make it wait on
something it does not need.

**Recommended sequencing given your Feb–June 2027 timeline:** ship v1 first as a complete, demoable artifact — Terraform-only already exercises every DVA-C02-relevant AWS resource in §4.1 except `k8s-scanner` itself. Add v2 (K8s/Helm) once v1's eval numbers (§7) are solid, then invest in v3's GitHub App plumbing last, since it's the most infra-heavy phase for the least new agent-architecture learning.

### 8.1 The admission rule

*Reconstructed from the two places §6 cites it (lines "the two failure modes need telling apart" and "§8.1's admission rule"); the section itself had never been written.*

**A finding enters the pipeline only if a deterministic scanner rule matched. The scanner's rule *is* the vulnerability.** No LLM originates a finding, and no LLM decides that a matched rule is not "really" a problem — that is a human's call, made in the dashboard, recorded in the audit log. This is what keeps detection provable: a finding can always be reproduced by re-running the same tool on the same file, which is not true of anything an LLM asserts.

Two consequences follow.

**The self-check inherits the definition.** "Fixed" means the rule that admitted the finding no longer matches — nothing more. So a fix has exactly two ways to fail the self-check, and they must be reported separately because they call for different responses:

| Failure | Meaning | Reviewer's likely next step |
|---|---|---|
| `cleared: false` | The admitting rule still matches | The fix missed; redraft |
| `cleared: true`, `self_check_new_findings` non-empty | The admitting rule stopped matching, but others started | Usually one edit from passing |

Collapsing both into "self-check failed" would tell a reviewer nothing about which one they are looking at.

**The rule can be made to stop matching without the vulnerability going away.** Every scanner ships an escape hatch — `#tfsec:ignore`, `#checkov:skip`, `trivy:ignore`, `nosec` — and a diff that adds one clears the finding by the definition above while changing no infrastructure. §6 records this happening on the first real run. So the admission rule needs a qualification: it holds for what a rule *matches*, and any scanner class admitted in future must have its suppression syntax added to `SUPPRESSION_MARKERS` before its fixes can be trusted. Likewise a rule stops matching when the file stops parsing, which is what `scan_errors` guards.

### 8.2 `terraform-scanner`: remaining v1 work

What the sections above specify for the scanner versus what exists, as of 2026-09-10, in the order it should be built. The ordering is the argument: the harness is first because nothing after it can be evaluated without it.

| # | Work | Spec | State | Why this position |
|---|---|---|---|---|
| 1 | **Eval harness** — labeled `.tf` cases with expected `(source, rule_id)` pairs, one command that scans them and reports detection recall | §7.1 | **Built** — `corpus/eval/`. 40 cases, **97.0%** (65/67) on 2026-09-10. The two misses are named, source-verified scanner gaps: checkov's `CKV_AWS_60` ignores a bare `Principal = "*"`, and `CKV_SECRET_*` is off because the scanner enables only the `terraform` framework | §8 gated v2 on "eval numbers are solid"; there is now a number. Item 4 is where the secrets miss gets fixed, and this is the number that should move when it does |
| 2 | **Manual trigger** — one command: upload a directory, scan, map, remediate | §8 v1 ("CLI or simple upload") | **Built** — `scripts/scan.py`. Synchronous, one invoke per stage, asks before remediation since that is the stage with a per-finding model call. Verified 2026-09-11 on a three-finding case: 3 scanned, 2 mapped, 1 fix drafted that superseded the other | v1 specifies it, and §7.2 (remediation safety) needs it to run the labelled cases through all three stages |
| 3 | **Observability** — `tracing_config` on every Lambda; custom metric findings-per-scan; alarm on scanner errors | §4.1 | **Built** — `terraform/observability.tf`. Active tracing on all four functions; `FindingsPerScan`, `ScanParseErrors` and `ReviewDecisions` (by action, so §7.3's acceptance rate is metric math) emitted as Embedded Metric Format — no `PutMetricData`, no extra IAM; error alarms on all four functions plus a near-timeout alarm on remediation-agent, to an SNS topic with an optional email subscriber | Cheap and DVA-C02 territory. Only became meaningful once `ScannerError` existed: before it, scanner failures were swallowed into empty results and an alarm would never have fired |
| 4 | **Scan surface** — `.tfvars` and `.tf.json` in the snapshot; a secret scanner; (`--download-external-modules` deliberately not, see below) | §2 goals: hardcoded secrets, unpinned module sources | **Built, pending deploy.** Snapshot is `.tf`, `.tf.json`, `.tfvars`, `.tfvars.json`; checkov runs `terraform,secrets`, whose `detect_secrets` dependency was already in the layer. Two eval cases added that only the wider surface can catch — a password in `terraform.tfvars`, and the bare-bucket case as `.tf.json`. Against the old scanner they miss, as predicted: 65/69. Expected after deploy: 68/69, the remaining miss being `CKV_AWS_60` | After 1, so the coverage gain is measured rather than claimed |
| 5 | **Orchestration** — one Step Functions execution per PR: scan → map → `Map` over files → remediate | §4.4 steps 3–5; `lambda_remediation_agent.tf`'s own timeout comment | **Built** — `terraform/step_functions.tf`; `scripts/scan.py` starts an execution and narrates it. Verified live 2026-09-12: two files remediated as parallel branches (`orch-demo-2`, 40s→59s and 40s→172s); and with the time reserve temporarily set to force a yield after every finding, a seven-finding file ran as three chained invocations whose later fixes recorded the earlier ones in `applies_after` (`orch-demo-3`). Two departures from the row as first written. **Per file, not per finding:** by the time this was built, fixes within a file were chained (each drafted on the previous verified one, `applies_after`), so the finding is not an independent unit of work and the file is. **Step Functions, not a stream:** a stream has no per-file ordering, no bounded concurrency, no "PR done", and would fire on every `review-api` status write. **A file that does not fit** in one 900s invocation is handled inside the iteration: the handler yields before its clock runs out, returns `remaining` and `resume_from`, and a `Choice` feeds that output back in as the next input, rooting the chain at the last verified fix rather than the snapshot. Failed executions alarm (`ExecutionsFailed`). **Left open:** a re-scan overwrites every finding on the PR back to `raw`, reviewed or not, so a redraft-only run (after a reviewer's edit reopens dependents) still invokes `remediation-agent` directly — `scan.py --stages remediate` — rather than through the pipeline. The fix for that is the scanner preserving status on re-scan, which is a different item | Bigger, and closer to v3's plumbing than v1's — but `context-agent` (docs/context-agent-spec.md §6) cannot fit its multi-call loop in the old envelope, so it was the next thing on the path anyway |
| 6 | **tfsec → Trivy** | §4.3 | **Built** — Trivy 0.74.0 (in the scanner image since 2026-09-13; a layer for the first day, see §4.3) with `--skip-check-update` so the embedded checks are the rule set and a scan is reproducible per §8.1. Upstream verified first: tfsec is not archived but its last release (v1.28.14, 2025-05-02) is a CVE bump and the README steers to Trivy. **Rule ids changed.** Trivy's report carries only its own id (`AWS-0086`); the tfsec long id is an alias for ignore comments and is *not* emitted (`DetectedMisconfiguration.Aliases` is `json:"-"`), so findings are `source: trivy, rule_id: AWS-0086` and `rule_mappings.json` plus every eval label were re-keyed from trivy-checks metadata. Two checks are deprecated in Trivy and off by default: `aws-s3-enable-bucket-encryption` (AWS encrypts by default now; `AWS-0132`, customer-managed key, is what fires and the two S3 cases expect it) and `aws-iam-no-policy-wildcards` (retired, nothing replaces it; the two admin-policy cases are checkov-only). Eval after deploy: **68/70 (97.1%)**, Trivy 26/26; the two misses are the labelled checkov gaps (`CKV_AWS_60`, `CKV_SECRET_6`). Trivy also skips an unparseable file and scans the rest where tfsec abandoned the run; the failure is read from stderr into `scan_errors`. Pipeline verified end to end on `trivy-demo-3`: `AWS-0107` mapped to CIS 5.2 and was superseded by the checkov twin's fix, i.e. the self-check compared the new pairs correctly. **Two deploy consequences.** Records written before the swap carry `source: tfsec`, and the self-check compares against the live scanner, so a PR from before it must be re-scanned before any further remediation. And `corpus/upload.sh` is part of this deploy: mapping-agent reads `rule_mappings.json` from S3 and caches it per container, so the first run after the swap mapped nothing on the Trivy side until the corpus was synced *and* the warm containers were recycled. **A detection regression, found 2026-09-13:** Trivy's `AWS-0107` is narrowed upstream to SSH/RDP ports, where tfsec's `aws-ec2-no-public-ingress-sgr` fired on any port. Port 80 open to the world is still caught by checkov's `CKV_AWS_260` (unmapped: no control fits); an arbitrary port range open to the world is caught by neither tool. Both are eval cases now (`sg-http-from-anywhere`, `sg-port-range-from-anywhere`); the second is labelled empty and counted nowhere. Closing it means a custom check. Brings K8s/Helm/Dockerfile scanning from one binary, which pre-solves part of v2's layer | Verified upstream status first, as the row asked |

**On external modules.** Item 4 originally included `--download-external-modules`. Not done, on purpose: `CKV_TF_1`/`CKV_TF_2` already detect an *unpinned* source from the `source` string alone (eval: 2/2), which is the §2 goal. Downloading modules is a different capability — scanning what the module *contains* — and it means registry and git fetches from inside the Lambda on every scan, into a 512MB `/tmp`, on a function with a 240s tool timeout. That is a design question about egress and cost, not a flag to flip, and it has no eval case yet to measure it against.

### 8.3 Why fixes are held: the two `new findings` patterns

`self_check_new_findings` is the most common reason a cleared fix is still held
(4 of 6 holds as of 2026-09-12). Two distinct causes, worth separating because
only one is a defect:

**Recursion.** A fix for "bucket has no access logging" creates a log
destination bucket, which inherits every rule the original violated —
observed introducing 7 new findings. Any fix whose remedy is another resource
of the same type does this and can never self-check clean. The honest options
are to scan only changed resources, or to accept that this class always lands
in human review.

**Partial fixes to a resource that gates several rules.** *(Prompt amended
and verified live 2026-09-12 — see below.)* On `demo-1`, the fix
for `aws-s3-block-public-acls` introduced `CKV_AWS_54`, `55` and `56`. The
bucket had no `aws_s3_bucket_public_access_block` at all, so checkov's
per-setting rules had nothing to evaluate; adding the resource with only the
one setting the finding asked for made the other three fire. **Minimality
itself created the findings.** When one resource gates several rules, the
minimal fix is to create it completely, not partially — which the prompt's
"minimal fix for this specific finding only" argues against. The model
sometimes gets this right anyway (`CKV2_AWS_6` on the same file set all four
and passed), so it is prompt calibration rather than a code gate.

The prompt now carries one stated exception to minimality: when a fix means
adding a resource or block that did not exist, configure it completely, on
the grounds that completing something you are already adding is the *smaller*
change than leaving attributes to fire as new findings. Deliberately narrow —
it does not license touching resources the fix does not need to add.

**Verified live on the file that produced the failure.** Scanning
`lambda/terraform-scanner/fixtures/vulnerable-sample` with only
`tfsec:aws-s3-block-public-acls` left mapped, the fix now writes an
`aws_s3_bucket_public_access_block` with all four attributes set and
`self_check_new_findings: []`, against `CKV_AWS_54/55/56` before. A prompt is
still a request, not a guarantee — nothing in code requires a complete
resource, and the self-check remains what catches it when the model does not
comply. What changed is how often it has to.

The fix is still held, on one assumption: that nothing serves objects from
the bucket anonymously. That is the assumptions gate working, not a
regression — it is unverifiable from the file and its falsity would break a
running system, which is exactly §6.1's test.

### 8.4 Before v2: three loose ends from v1

Each was found while building §8.2 items 5–6 and `context-agent`, and each
is small. In the order to do them, with the argument for the position.

| # | Work | Found by | State | Why this position |
|---|---|---|---|---|
| 1 | **Dashboard shows the `questions` record** — what a draft asked about the repository, the answer, and its `file:line` citations, beside the assumptions it already shows | `context-agent` (docs/context-agent-spec.md §12): `proposed_fix.questions` is written but `dashboard/src/types/finding.ts` does not know it exists | **Built** 2026-09-13 — `RepositoryQuestions` panel after the rationale, answers badged with citations as `file:start-end` plus the verified excerpt; a question that came back `unknown` is listed in the same alert under its own heading — asked, and the repository does not say — so "assumed" and "asked, unanswerable" no longer read the same, and a question is never shown as a fact | First because until it is on screen the component is invisible to the one person it is for. A reviewer sees "assumption: operators connect from 10.20.0.0/16" and nothing that says the agent *looked* and found `admin_cidrs` populated in `terraform.tfvars:1-2`. "Asked, not guessed" is the whole design and it has to be legible |
| 2 | **A custom check for public ingress on non-admin ports** — a Trivy Rego check shipped in the scanner image (`--config-check`), so a rule open to `0.0.0.0/0` on any port is admitted, not just SSH/RDP | §8.2 item 6's regression: Trivy's `AWS-0107` is tfsec's check narrowed to SSH/RDP; port 80 is checkov-only and unmapped, an arbitrary range is caught by neither. Eval cases `sg-http-from-anywhere` and `sg-port-range-from-anywhere` label it | **Built** 2026-09-13 — `IACP-0001`, `lambda/terraform-scanner/checks/`, in the image and loaded with `--config-check` plus `--check-namespaces user` (without the second a check from disk loads and silently never fires). Reports an ingress rule open to every IP on any TCP/UDP range `AWS-0107` does not cover, so no rule is reported twice; self-contained rather than importing `lib.net`. Mapped, with `CKV_AWS_260`, to OWASP CNAS-6 — the control the egress twin `AWS-0104` already used. Eval **71/73**, Trivy 28/28; the two cases go from labelled gap to expected | Deterministic, versioned with the image, so it satisfies §8.1 like any other rule. Closing it also un-blocks the eval `context-agent` was written for: the port-80 draft asking about ACME HTTP-01, with PugetScope's `ClusterIssuer` already in the snapshot. Needs a control to map to, which is a corpus question — the same one that left `CKV_AWS_260` unmapped — so the check and the mapping decision land together |
| 3 | **A re-scan preserves review state** — the scanner's write keeps `status`, `proposed_fix`, `control_mappings` and the review history for a finding id that already exists, and only resets one whose content changed | Flagged three times: the `--stages remediate` escape hatch in `scripts/scan.py` exists only because a re-scan resets reviewed findings to `raw`; every re-run re-pays the mapping bill for findings already mapped; a reviewer's edit reopening dependents needs a redraft-only run | **Built** 2026-09-15 — the scanner writes each finding with `update_item`, not `put_item`: `severity` and the timestamps are refreshed because the tool owns them, while `status`, `control_mappings`, `proposed_fix` and `created_at` are written under `if_not_exists` because a human or an agent owns them. A finding id hashes the location as well as the rule, so an id that fires again *is* the same finding in the same place and nothing else needs comparing. A finding that stops firing is marked `no_longer_detected` (once — a later scan cannot move the date) rather than deleted: a landed fix, a deleted file and a dropped rule read the same from here, and deleting would take the audit trail with it. The scan reports `preserved_count` and `no_longer_detected_count`; the dashboard shows a gone-from-the-code badge and says why it is kept. Two things the live test found: findings are deduplicated by id before the write, because the id hashes the location but not the resource address and one rule on four ECR repositories in one block collapses to one id (the old `batch_writer` silently took the last, so only the counts were wrong); and `scan.py` now mirrors the directory into the snapshot instead of only adding to it, since a file deleted locally used to stay in S3 and keep firing — which made the mark unreachable by the obvious route | Removes an escape hatch, cuts re-run cost, and makes the pipeline safe to run on a live PR on every push — which v3 needs before anything else in it can be built. Third because the other two are independent of it and smaller |

None of the three blocks v2 (§8); the order is by how much of what is already built each one makes usable.

---

## 9. Team Workflow

Two-person split: infra/deployment + `mapping-agent` (Konrad) vs. `remediation-agent` + scanner integration + frontend (partner). Ownership divide:

- **Konrad owns**: everything AWS-native — API Gateway, SQS, DynamoDB tables, IAM roles/policies, Lambda deployment and packaging (layers), CloudWatch/X-Ray, CI/CD, Secrets Manager, AWS account itself — plus `mapping-agent`'s prompt design and schema-validated JSON output
- **Partner owns**: `terraform-scanner`'s scanning logic (Trivy/Checkov invocation, parsing into `FindingRecord` shape), `remediation-agent`'s prompt design + diff generation + self-check integration, the review dashboard frontend (React + Vite + TypeScript), and the eval harness (§7)

**Workflow: independent development, merged via Git.** Partner builds against the schemas in §5 (`FindingRecord`) and §6 (agent JSON contracts) without needing AWS account access at all — no stub Lambdas to deploy, no IAM to grant, no sequencing dependency on Konrad's deploy schedule. Both people branch off the shared contracts, build independently, and merge. Merge conflicts in code are expected and fine to resolve as they come up.

**What Git merges catch, and what they don't:** a clean merge only guarantees the *code* combined without textual conflicts — it says nothing about whether partner's `remediation-agent` still matches the live `FindingRecord` shape or DynamoDB table structure if either changed since he last pulled. That's a runtime failure, not a merge-time one. Since this workflow trades away the "test against something real" benefit for speed and independence, the shared schemas in §5–§6 are the thing actually keeping both halves compatible between merges — treat any change to either as something to flag to the other person immediately, not just commit and move on.

**Recommended lightweight guardrails**, given no live integration testing until deploy:
- Version the schemas (§5, §6) in the repo itself (e.g. a `schemas/` folder with the JSON Schema definitions), so a schema change shows up as a reviewable diff, not a Slack message that's easy to miss
- Partner mocks `FindingRecord` inputs locally against the versioned schema for `remediation-agent` development — a small `fixtures/` folder of example findings works fine
- Konrad does a real integration pass (deploy partner's merged code, run it against actual DynamoDB data) before treating a milestone as "done," rather than assuming merge success equals working system

**Branching model.** Component ownership maps directly onto branches, which keeps conflicts scoped and predictable:

- `main` — always deployable; only merged into via PR, never pushed to directly
- `infra/*` (Konrad) — e.g. `infra/dynamo-schema`, `infra/api-gateway`, `infra/scanner-lambda-deploy`; touches Terraform/SAM/CDK for the AWS resources, plus `mapping-agent`'s Lambda code
- `agent/remediation` (partner) — `remediation-agent` prompt design, diff generation, self-check integration
- `scanner/terraform` (partner) — `terraform-scanner` scanning logic and `FindingRecord` parsing
- `frontend/dashboard` (partner) — React/Vite/TypeScript review dashboard

Because the two people's branches touch almost entirely different files (infra/deploy code vs. application logic vs. frontend), most merges into `main` should be conflict-free by construction. The place conflicts *will* happen is the shared schema files (`schemas/finding-record.json`, the agent contract schemas from §6) if both people are mid-change on them at once — treat those as a short-lived shared branch or just communicate before editing them, rather than letting them drift on two long-lived feature branches.

A couple of practical rules worth setting explicitly:
- PR into `main` requires the other person's review, even async — this is the actual substitute for the integration testing you're giving up by not deploying incrementally
- Rebase feature branches on `main` regularly rather than letting them diverge for weeks; the longer a branch lives, the more likely its assumptions about the schema have quietly gone stale
- Tag or note in the PR description which version of the schema a branch was built against, so a stale-schema conflict is easy to spot at review time instead of only surfacing at runtime

## 10. Open Decisions

- [x] DynamoDB vs Postgres for findings store — **Decided: DynamoDB** (see §4.2)
- [x] Container image Lambda vs Lambda layer for packaging scanner binaries — **Decided: Lambda layers** on 2026-08-31, **revised to a container image** for the scanner on 2026-09-13 when the layer ceiling was reached (see §4.3); the agents stay zip + layer
- [x] Whether `remediation-agent` and `mapping-agent` should be separate Lambdas or one Lambda with two code paths — **Decided: separate Lambdas**, each with its own least-privilege IAM role (distinct roles per agent is itself part of the project's security story)
- [x] Whether Kubernetes/Helm scanning ships in v1 alongside Terraform, or lands as a later addition — **Decided: v1 is Terraform-only**; K8s/Helm scanning is v2, added once the Terraform path's eval numbers are proven (see §8)
- [x] Where sample K8s manifests/Helm charts for the eval set come from — **Decided: hand-crafted/AI-generated**, not sourced from PugetScope's live cluster config (keeps the eval set's known-vulnerability labels clean and independent of production infra)

