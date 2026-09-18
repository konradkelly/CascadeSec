# CascadeSec

**DevSecOps/AppSec tool: Terraform security scanning, OWASP/CIS control mapping, and AI-assisted remediation with self-verification, built on serverless AWS.**

![CI](https://img.shields.io/github/actions/workflow/status/konradkelly/CascadeSec/ci.yml?branch=main&label=CI)
![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20Step%20Functions%20%7C%20DynamoDB-orange)

Formerly **IaCPosture**. The old name persists in the code — `var.project`, the
deployed AWS resource names, `iacposture-spec.md` — because renaming those means
recreating live infrastructure, and the name of a Lambda is not worth that.

---

## What it does

CascadeSec scans Terraform for security misconfigurations, maps every finding to the specific OWASP or CIS control it violates, and proposes a minimal fix — one it has already proven clears the issue before a human ever sees it.

**The core design principle: the agent proposes, it never decides.**

- A deterministic scanner (Trivy, Checkov, plus the project's own Rego checks) finds the issue — zero hallucination risk on detection
- An LLM agent maps the finding to the exact control it violates, with a citation, choosing only among candidates a curated rule-to-control table already allows
- A second LLM agent drafts a minimal diff — then re-runs the same scanner against its own proposed fix before surfacing it. If the fix doesn't clear the finding, introduces a new one, or suppresses the scanner instead of fixing anything, it never reaches a human as a suggestion
- When a fix needs to know something about the rest of the repository, the agent asks a context agent rather than assuming, and every answer is cited to `file:line`
- Every finding and every fix is reviewed and approved by a human — nothing is auto-merged

## Why

Most "AI security scanner" tools ask an LLM to both find and judge issues in one pass, with no way to verify the model's claims. CascadeSec splits detection (deterministic, provable) from remediation (LLM-drafted, but self-checked against the same scanner that found the problem) — so a proposed fix is never just an LLM's word that it worked.

## Architecture

```
scripts/scan.py  ──upload──▶  S3  ──▶  Step Functions (one execution per PR)
                                            │
                                            ▼
                                    iac-scanner (Lambda, container image)
                                    Trivy + Checkov + IACP-* checks → findings
                                            │
                                            ▼
                                  mapping-agent (Lambda)
                             finding → OWASP/CIS control + citation
                                            │
                                            ▼
                          Map state: remediation-agent, one per file
                        proposes diff → self-checks against iac-scanner
                           ↳ asks context-agent (Lambda) about the rest of
                             the repo; every answer cited to file:line
                                            │
                                            ▼
                                        DynamoDB
                                            │
                        API Gateway (Cognito JWT authorizer) → review-api (Lambda)
                                            │
                                            ▼
                         review dashboard (React + Vite + TS, CloudFront + S3)
                       human approves / edits / rejects → audit log
```

Built serverless on AWS — Lambda, Step Functions, API Gateway, DynamoDB, S3, ECR, Cognito, CloudFront, Secrets Manager, CloudWatch/X-Ray, SNS — provisioned end to end in Terraform. Doubles as hands-on AWS Developer Associate (DVA-C02) practice.

Full technical spec (data model, agent JSON contracts, eval plan, build phases): [`iacposture-spec.md`](./iacposture-spec.md). Per-feature specs are in [`docs/`](./docs/).

## Evaluation

Detection recall is measured, not assumed: a labelled corpus of Terraform cases with known injected vulnerabilities, scanned by the **deployed** scanner.

**97.3% — 71 of 73 expected findings across 43 positive cases and 2 clean controls** (2026-09-13, Trivy 0.74.0 + Checkov 3.3.16 + `IACP-0001`). Both misses are documented upstream tool gaps, not relabelled. The full method, the corrections log, and what the number does *not* measure are in [`corpus/eval/README.md`](./corpus/eval/README.md).

## Running it

Against the deployed dev stack, with AWS credentials and `terraform` on `PATH`:

```bash
python scripts/scan.py path/to/terraform          # upload, scan, map, then ask before remediating
python scripts/scan.py path/to/terraform --yes    # don't ask
python corpus/eval/run_eval.py                    # detection recall over the labelled cases
python corpus/external/run_external.py           # scan pinned third-party repos, compare to baseline
```

`scan.py` uploads the directory, starts one execution of the pipeline state
machine (scan → map → remediate, one remediation invocation per file in
parallel), narrates it stage by stage, and prints the dashboard URL when it
finishes. Remediation is the stage that costs model calls -- one per mapped
finding -- which is why it asks first (`--no-remediate` stops after mapping).

## Status

**v1 is deployed and running** against a dev AWS account: Terraform-only scanning, control mapping, self-verified remediation with per-file fix chains, and the human review dashboard. Triggered manually by `scripts/scan.py`; no GitHub write-back yet.

CI runs the Lambda test suites (pytest, 217 tests) and the dashboard lint + type-check on every push — deliberately with no AWS credentials, so a test run can never touch real infrastructure.

## Roadmap

- [x] v1 — Terraform scanning, mapping, remediation, review dashboard (manual trigger, no GitHub write-back)
- [ ] v2 — Kubernetes manifest + Helm chart scanning
- [ ] v3 — GitHub App / PR-triggered CI integration
- [ ] v4 — Approved-fix write-back to PR branch

## Tech stack

- **Infra:** AWS Lambda (zip and container-image), Step Functions, API Gateway, DynamoDB, S3, ECR, Cognito, CloudFront, Secrets Manager, CloudWatch (EMF metrics, alarms), X-Ray, SNS — all in Terraform
- **Scanning:** Trivy, Checkov, custom Trivy checks in Rego (Terraform); kubesec, Helm (v2)
- **Agents:** Anthropic API, strict JSON-schema-constrained outputs
- **Frontend:** React, Vite, TypeScript
- **CI:** GitHub Actions — pytest per Lambda, oxlint + `tsc` for the dashboard

## Disclaimer

This is an educational/portfolio project built to explore agentic AppSec/DevSecOps tooling patterns. It has not been security-audited and is not intended for production use scanning or remediating real infrastructure without independent review.

## License

MIT
