# context-agent — spec

Answers the questions `remediation-agent` would otherwise have to declare it
cannot answer, by reading the rest of the repository.

**Built 2026-09-12** — `lambda/context-agent/`, `terraform/lambda_context_agent.tf`,
and the questions step in `remediation-agent`. §9's prerequisites landed the
same day (§8.2 items 4 and 5). §12 records what was decided and what the
first live run showed; the sections before it are the design as written, and
still describe what was built.

## 1. Why: the assumptions are queries

`remediation-agent` sees exactly one file. Anything it needs to know about the
wider system it has to declare in `assumptions`, and a non-empty list forces
`needs-human-only` however clean the rescan (spec §6.1). That gate is
correctly calibrated — measured 2 holds in 14 fixes, zero on self-contained
ones — so the assumptions it produces are real.

What they are *not* is unknowable. Every assumption text in the live table:

| assumption | answerable by reading | in the snapshot today? |
|---|---|---|
| certificate issuance uses DNS-01, not ACME HTTP-01 | cert-manager `ClusterIssuer` | **no** — YAML, not uploaded |
| the root module can pass `public_http_cidrs` | the calling module | yes |
| `var.admin_cidrs` is a populated list | `variables.tf`, `*.tfvars` | partly — `.tfvars` not uploaded |
| no external LB needs ports 30000-32767 | the LB module | yes |
| public traffic arrives on 80/443, not a NodePort | ingress manifests | **no** |
| nothing serves this bucket anonymously | bucket policy, CloudFront origin | yes |

Four of six are answerable from Terraform already in the snapshot. Two need
files the snapshot does not carry.

So: **`assumptions` is a list of queries the agent wanted to run and could
not.** That reframing is the whole design, and it gives the component its
eval (§8) — the number to move is how many assumptions survive when the
answer was available.

## 2. What it is, and what it is not

**Is:** a retrieval step that answers specific, bounded questions about a
repository, and cites the file and line it answered from.

**Is not:** an autonomous agent that decides anything. It does not originate
findings (§8.1's admission rule is unchanged — only a deterministic scanner
rule admits a finding), it does not judge fixes, and it does not relax the
self-check. It informs a draft. That is the least safety-critical stage in the
pipeline and the one already understood to be the model's job.

The pattern is `mapping-agent`'s, applied to source instead of controls:
retrieve candidates deterministically, then ask the model to pick, cite, and
explain among them. `mapping-agent` does not let the LLM invent a
`control_id`; `context-agent` does not let it invent a fact about the repo.
**Every answer carries `file:line`.** Without that, "I checked and nothing
serves this bucket publicly" is just another unverifiable claim, and moving
the trust problem is not solving it.

## 3. Where it sits

```
remediation-agent
  ├── drafts a fix (as today)
  ├── the model returns `questions: [...]` instead of guessing     <- new
  ├── context-agent answers each, with citations                   <- new
  ├── the model redrafts, knowing the answers                      <- new
  └── self-check (unchanged, deterministic)
```

Questions come from the model because it is the thing that knows what it does
not know — that is exactly what `assumptions` already demonstrates it can
articulate. The schema change is `assumptions` splitting in two: questions
asked *before* drafting, and the residue that survived being asked.

## 4. Contract

Invoked per question, or per batch of questions for one finding:

```json
{
  "pr_id": "manual-1",
  "s3_prefix": "scans/manual-1/",
  "questions": [
    "Does anything in this repository serve objects from the S3 bucket
     `my-insecure-bucket` anonymously — a bucket policy, website
     configuration, or CloudFront origin?"
  ]
}
```

Returns, per question:

```json
{
  "question": "...",
  "answer": "no" | "yes" | "unknown",
  "explanation": "1-2 sentences",
  "citations": [{ "file": "modules/cdn/main.tf", "line_range": [12, 18],
                  "excerpt": "verbatim, <20 words" }]
}
```

Rules the schema enforces:

- `answer: "yes"` or `"no"` **requires** at least one citation. An uncited
  conclusion is not an answer.
- `"unknown"` requires none, and is the correct answer when the repository
  does not say. `unknown` flows back into `assumptions` unchanged — the
  reviewer still gets the question, now with "and we looked" attached.
- `excerpt` must appear verbatim in the cited file at the cited lines.
  **Verified in code, not trusted** — same rule the project applies to
  `self_check_passed`. A fabricated citation is the failure mode that would
  make this component worse than not having it.

## 5. Retrieval surface

Deterministic, before the model sees anything: ripgrep-style search over the
snapshot, plus whole-file reads of what matches. No embedding index — a
repository is small, exact search is precise, and an index is a second thing
to keep fresh.

**The snapshot has to widen first.** `scripts/scan.py` uploads `**/*.tf`.
Two of the six real assumptions above need YAML that is not there, and
`.tfvars` (a §8.2 item 4 gap independently) answers a third. Widening is a
prerequisite, not a nice-to-have — without it this component answers the
easy half of its own motivating examples.

Widening also brings secrets into the context window, which `.tfvars` is
precisely where they live. See §10.

## 6. Cost

A tool loop is several model calls per finding where there is now one.
`remediation-agent` already fits roughly two findings per 900s invocation on
a cold scanner. This component does not fit inside that envelope, which makes
**the Step Functions fan-out (§8.2 item 5) a hard prerequisite** rather than a
parallel nicety.

Cost control that does not need new infrastructure: only ask when the model
says it needs to. A fix with no questions costs exactly what it costs today.
On the measured distribution that is 12 of 14 fixes.

## 7. What this does not change

- **Detection** stays deterministic. §8.1's admission rule is untouched.
- **The self-check** stays deterministic, and stays the thing that decides
  `self_check_passed`.
- **The gates** — suppression, deletion, `scan_errors` — are unaffected.
- **`needs-human-only` on a surviving assumption** is still correct. The goal
  is fewer assumptions, not a lower bar for them.

## 8. Eval

The reframing gives a clean before/after on data that already exists:

1. **Assumption resolution rate** — re-run remediation over the same findings
   with and without context-agent; count assumptions that disappear because
   they were answered. The PugetScope port-80 case is the headline: the
   answer (`ClusterIssuer` uses HTTP-01) contradicts what the agent assumed,
   so the right outcome is not a passing fix but a *better* one that keeps
   port 80 open.
2. **Citation validity** — fraction of citations whose excerpt verifies
   against the file. Must be 100%; anything less is a correctness bug, not a
   quality metric.
3. **Fix-acceptance rate** (§7.3) — the number this is ultimately for.

(1) is measurable the day it ships, against findings already in the table.

## 9. Prerequisites

In order, and only the first two are genuine dependencies:

1. **Snapshot widening** (§5). Without it the component cannot answer the
   cross-stack questions that motivate it.
2. **Remediation fan-out**, §8.2 item 5. Without it there is no execution
   budget for a multi-call agent.
3. *Not* a prerequisite: **corpus growth.** `context-agent` reads the
   repository, not `corpus/`. Mapping coverage matters enormously for the
   pipeline's usefulness and not at all for this component — the two should
   not be coupled, or this waits on something it does not need.

## 10. Risks

**Fabricated citations.** The failure that would make this worse than
nothing: a confident, cited-looking answer whose excerpt is not in the file.
Mitigated by verifying excerpts in code (§4), which is cheap and
non-negotiable.

**Secrets in context.** Widening the snapshot to `.tfvars` and YAML puts
credentials in the model's context. Options, none yet chosen: redact on
upload, exclude `.tfvars` from retrieval while still scanning it, or accept
it on the grounds that `remediation-agent` already reads whatever file a
finding is on. Worth deciding before widening, not after.

**Unbounded context.** A question like "what depends on this?" can match
half a repository. Retrieval needs a hard cap on files and bytes returned,
and `unknown` is the correct answer when the cap is hit — a truncated search
that answers confidently is the fabrication risk wearing a different hat.

**Scope creep into judgement.** The temptation once the agent can read the
repo is to let it decide whether a finding matters. That is §8.1's line and
it does not move.

## 11. Open decisions

All four decided at build time; the reasoning is in §12.

- [x] Per-finding, not batched per file.
- [x] Recomputed per draft; the answers are stored on the record for the
      reviewer, never reused as an input.
- [x] Secrets: redacted at retrieval, `.tfvars` stays in.
- [x] `unknown` is surfaced as "asked, unanswerable": it lands in
      `assumptions` *and* in the `questions` record beside it.

## 12. As built

**Shape.** A separate Lambda with its own least-privilege role: read
`scans/*`, read the API key, nothing else — no DynamoDB, no writes. Invoked
synchronously by `remediation-agent` with `{pr_id, s3_prefix, questions}`.
Inside, a manual tool loop over the snapshot with two tools, `search`
(regex, case-insensitive, `file:line: text`) and `read_file` (numbered
lines, paged), and the answer schema of §4 enforced as structured output on
every turn. Caps: 8 tool calls, 40 matches per search, 300 lines per read,
200KB returned in total, 400 files downloaded. Each cap is announced to the
model when hit, with `unknown` named as the correct answer for anything it
cut off.

**Citations are verified in code.** For every citation the excerpt, with
whitespace squashed, must be a substring of the cited lines (with one line
of slack either side, since models are routinely one line off on a block
boundary). A failed citation is dropped and counted; a `yes`/`no` left
without one becomes `unknown` with the downgrade stated in its explanation.
`ContextCitationsRejected` is emitted as a metric so §8's citation-validity
number is a CloudWatch query.

**Questions come from the draft.** `remediation-agent`'s output schema gained
`questions`; the prompt tells the model to put an assumption there instead
when another file in the repository would settle it. A draft with none costs
one call, as before. A draft with some triggers one context-agent invocation
and one redraft whose prompt carries the answers with their citations. A
question answered `unknown` is put back into the redraft's `assumptions` by
code, not by trusting the model to carry it, so the human-review gate is
unchanged. If `CONTEXT_AGENT_FUNCTION_NAME` is unset the model is told not
to ask and any questions it raises anyway become assumptions — the two
functions deploy independently. A failed lookup raises, leaving the finding
`mapped` for a retry; drafting on an answer that was never given is worse
than not drafting.

**Per finding.** Batching per file would share retrieval, but the questions
are the draft's own and the audit trail — this fix asked this, was told
this — is the point. Recomputed per draft for the reason §11 gave: an answer
is about the snapshot, and the snapshot does not change, but the *question*
does with every redraft.

**Secrets.** `.tfvars` stays in the retrieval surface because it answers the
"is this variable populated" class of question. Values on lines whose key
looks like a credential (`password`, `secret`, `token`, `api_key`,
`access_key`, `private_key`) are replaced with `"<redacted>"` in every tool
result; a value that is a reference (`var.x`, `data.x`) is left alone so the
agent can follow it. A citation of a redacted line cannot verify — the
model saw text the file does not contain — which is the intended outcome:
no answer rests on a secret's value.

**Snapshot widening.** `scripts/scan.py` uploads `.yaml`/`.yml` alongside the
Terraform. The scanner's suffix set is unchanged, so it never sees them;
context-agent's `CONTEXT_SUFFIXES` does.

**Time budget.** `remediation-agent`'s per-finding reserve now counts the
scanner's timeout, context-agent's timeout (150s) and two model calls, set
from those functions' timeouts in Terraform so the numbers cannot drift.

**First live run** (`ctx-demo-1`: a security group with SSH and HTTP open to
the world, a `variables.tf` declaring `admin_cidrs`, a `terraform.tfvars`
populating it, a cert-manager `ClusterIssuer` using HTTP-01). All four
drafts asked questions. On `CKV_AWS_24` the draft asked whether any
`.tfvars` or caller specified the operator CIDR ranges for port 22;
context-agent answered **yes**, citing `terraform.tfvars:1-2` and the
variable's description in `variables.tf`, and the redraft replaced
`0.0.0.0/0` with `var.admin_cidrs` rather than inventing a new variable —
the PugetScope-shaped outcome §1 was written for. Every citation in the run
verified (`ContextCitationsRejected: 0`). The assumptions that survived are
about the running system — that operators actually connect from those
ranges — which is what should survive. The first attempt failed on a schema
detail (`minItems: 2` on `line_range` is rejected by structured outputs);
the failure path behaved as designed, four errors and four findings left
`mapped`, and the direct `--stages remediate` re-run picked them up.

**Not yet measured:** §8's assumption-resolution rate over the findings
already in the table. It needs a re-run of remediation over those PRs with
the widened snapshot re-uploaded, since their snapshots predate the YAML
upload.
