# IaCPosture

**DevSecOps/AppSec tool: Terraform security scanning, OWASP/CIS control mapping, and AI-assisted remediation with self-verification, built on serverless AWS.**

<!-- Badges — fill in once CI/license/etc. are set up -->
<!-- ![build](https://img.shields.io/github/actions/workflow/status/<you>/iacposture/ci.yml) -->
<!-- ![license](https://img.shields.io/github/license/<you>/iacposture) -->
<!-- ![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20API%20Gateway%20%7C%20DynamoDB-orange) -->

---

## What it does

IaCPosture scans Terraform for security misconfigurations, maps every finding to the specific OWASP or CIS control it violates, and proposes a minimal fix — one it has already proven clears the issue before a human ever sees it.

**The core design principle: the agent proposes, it never decides.**

- A deterministic scanner (Trivy, Checkov) finds the issue — zero hallucination risk on detection
- An LLM agent maps the finding to the exact control it violates, with a citation
- A second LLM agent drafts a minimal diff — then re-runs the same scanner against its own proposed fix before surfacing it. If the fix doesn't clear the finding, or introduces a new one, it never reaches a human as a suggestion.
- Every finding and every fix is reviewed and approved by a human — nothing is auto-merged

## Why

Most "AI security scanner" tools ask an LLM to both find and judge issues in one pass, with no way to verify the model's claims. IaCPosture splits detection (deterministic, provable) from remediation (LLM-drafted, but self-checked against the same scanner that found the problem) — so a proposed fix is never just an LLM's word that it worked.

## Architecture

```
GitHub PR → API Gateway → webhook-receiver (Lambda)
                                │
                                ▼
                     terraform-scanner (Lambda)
                        Trivy + Checkov → raw findings
                                │
                                ▼
                      mapping-agent (Lambda)
                 finding → OWASP/CIS control + citation
                                │
                                ▼
                    remediation-agent (Lambda)
              proposes diff → self-checks against terraform-scanner
                                │
                                ▼
                  review dashboard (React + Vite + TS)
               human approves / edits / rejects → audit log
```

Built serverless on AWS — API Gateway, Lambda, SQS, DynamoDB, S3, EventBridge, CloudWatch/X-Ray, CloudFront — doubling as hands-on AWS Developer Associate (DVA-C02) practice.

Full technical spec (data model, agent JSON contracts, eval plan, build phases): [`docs/spec.md`](./docs/spec.md)

## Running it

Against the deployed dev stack, with AWS credentials and `terraform` on `PATH`:

```bash
python scripts/scan.py path/to/terraform          # upload, scan, map, then ask before remediating
python scripts/scan.py path/to/terraform --yes    # don't ask
python corpus/eval/run_eval.py                    # detection recall over the labelled cases
```

`scan.py` uploads the directory, starts one execution of the pipeline state
machine (scan → map → remediate, one remediation invocation per file in
parallel), narrates it stage by stage, and prints the dashboard URL when it
finishes. Remediation is the stage that costs model calls -- one per mapped
finding -- which is why it asks first (`--no-remediate` stops after mapping).

## Status

🚧 Pre-build / architecture phase. v1 scope is Terraform-only (detect → map → propose fix → human review); Kubernetes/Helm scanning is planned for v2.

## Roadmap

- [ ] v1 — Terraform scanning, mapping, remediation, review dashboard (manual trigger, no GitHub write-back)
- [ ] v2 — Kubernetes manifest + Helm chart scanning
- [ ] v3 — GitHub App / PR-triggered CI integration
- [ ] v4 — Approved-fix write-back to PR branch

## Tech stack

- **Infra:** AWS Lambda, API Gateway, SQS, DynamoDB, S3, EventBridge, CloudWatch, X-Ray, CloudFront
- **Scanning:** Trivy, Checkov (Terraform); kubesec, Helm (v2)
- **Agents:** Anthropic API, strict JSON-schema-constrained outputs
- **Frontend:** React, Vite, TypeScript

## Disclaimer

This is an educational/portfolio project built to explore agentic AppSec/DevSecOps tooling patterns. It has not been security-audited and is not intended for production use scanning or remediating real infrastructure without independent review.

## License

MIT
