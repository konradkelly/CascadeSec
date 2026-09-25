# CI integration (v3) — spec (draft)

A GitHub App that scans a pull request when it is opened or pushed to, and
reports back on the PR itself: a check run with annotations, and — when the
reviewer asks for them — fixes posted as suggested changes.

Written before building, 2026-09-23. The pipeline claims below were checked
against the code on branch `v3-ci-integration`; the GitHub API claims are
from GitHub's documentation and are marked **(verify)** where one needs a real
App before anything is built on it.

## 1. What changed since the spec's v3 was written

`iacposture-spec.md` §4.4 describes v3 as `webhook-receiver` → S3 → **SQS** →
`iac-scanner`, with mapping on a DynamoDB stream. Three things have been built
since, and each one removes part of that design:

- **Step Functions owns orchestration** (§8.2 item 5). One Standard execution
  per PR runs scan → map → `Map` over files → remediate. Its input is
  `{pr_id, s3_prefix, remediate}`, the same thing `scripts/scan.py` sends. So
  v3 is not a new pipeline: it is a new way to **start** this execution and a
  new place to **report** what it found.
- **One scanner for every language** (multi-iac-spec §3). `webhook-receiver`
  no longer tags or routes by `iac_type`; it uploads a snapshot.
- **A re-scan preserves review state** (§8.2 item 3). Every push to a PR is a
  re-scan of the same `pr_id`, and that already keeps `status`,
  `proposed_fix` and the review history of a finding whose content did not
  change. v3 depends on this and adds nothing to it.

**SQS is dropped.** It was there so the webhook could return inside GitHub's
10-second window while a long scan ran. `StartExecution` returns in
milliseconds and a Standard execution is itself durable, so the queue would
add a hop and a consumer and remove no risk. The one thing a queue could
have done — serialise pushes to the same PR — it cannot do here, because its
consumer would return after starting an execution, not after the execution
finishes (§6.2). This drops a DVA-C02 rep that §4.1 listed; decided
2026-09-24 (D2). Cost played no part: at a few requests per push SQS sits
inside its permanent free tier either way.

## 2. Flow

Two directions of trust carry a PR through, and the first diagram is about
them. The **webhook secret** (symmetric, shared with GitHub) proves a
delivery came **from** GitHub; the **App key** (asymmetric, private half in
KMS) proves a call **to** GitHub comes from the App. The shaded part is not
built yet.

```mermaid
sequenceDiagram
    autonumber
    participant GH as GitHub
    participant GW as API Gateway
    participant R as webhook-receiver
    participant SM as Secrets Manager
    participant SF as Step Functions
    participant G as github-gateway
    participant K as KMS

    GH->>GW: POST /github/webhook, X-Hub-Signature-256
    GW->>R: invoke (no JWT authorizer, throttled)
    R->>SM: GetSecretValue (cached 5 min)
    R->>R: HMAC-SHA256 over the raw body, constant-time compare
    R->>SF: StartExecution, name = PR + head sha + trigger
    R-->>GH: 202 started (200 redelivery, 204 ignored, 401 forged)

    rect rgba(128, 128, 128, 0.15)
    SF->>G: fetch
    G->>K: Sign(JWT header and claims), RS256
    K-->>G: signature (the key never leaves KMS)
    G->>GH: POST access_tokens with the JWT
    GH-->>G: installation token, valid 1 hour
    G->>GH: tarball at head sha, PR changed files
    Note over SF: scan, map, remediate
    SF->>G: report
    G->>GH: check run, annotations, suggestions
    end
```

What one execution does between `fetch` and `report`. Solid arrows are the
state machine's order; dotted ones are data. Dashed boxes are not built yet.

```mermaid
flowchart TB
    start(["StartExecution from webhook-receiver"])
    fetch["fetch · github-gateway<br/>snapshot the PR head"]
    scan["scan · iac-scanner<br/>Trivy, Checkov, KICS"]
    map["map · mapping-agent<br/>findings to CIS controls"]
    rem["remediate · remediation-agent<br/>only after Draft fixes"]
    report["report · github-gateway<br/>results back to the PR"]

    s3[("S3<br/>scans/pr_id/")]
    ddb[("DynamoDB<br/>findings")]
    llm["Anthropic API"]

    start --> fetch --> scan --> map --> rem --> report

    fetch -.->|"write snapshot"| s3
    s3 -.->|"read snapshot"| scan
    scan -.->|"raw findings"| ddb
    map -.->|"model calls"| llm
    rem -.-> llm
    map -.->|"read and update"| ddb
    rem -.-> ddb
    ddb -.->|"findings and fixes"| report

    classDef planned stroke-dasharray: 6 4
    class fetch,report planned
```

The same, as the state machine sees it:

```
PR opened / synchronize / reopened
  → API Gateway  POST /github/webhook      (no JWT authorizer; the HMAC is the auth)
  → webhook-receiver                       verify signature, filter, StartExecution
  → state machine
       fetch     (github-gateway)   in-progress check run; tarball at head_sha → scans/<pr_id>/;
                                    PR's changed files + patch hunks → S3
       scan      (iac-scanner)      unchanged
       map       (mapping-agent)    unchanged
       remediate (remediation-agent) only if remediate=true — unchanged
       report    (github-gateway)   complete the check run; post suggestions
     Catch on every state → report   (the check run must never stay in_progress)
```

`scripts/scan.py` keeps working unchanged: `fetch` and `report` run only when
the input carries a `github` object, chosen by a `Choice` state, so a manual
run is the existing execution with two states skipped.

### 2.1 Two Lambdas, split by the credential each one can use

| Lambda | Holds | Can do |
|---|---|---|
| `webhook-receiver` | webhook secret only | `states:StartExecution` on the one state machine |
| `github-gateway` | `kms:Sign` on the App key — never the key itself | `s3:PutObject`/`DeleteObject` on `scans/*`, read of the finding table, GitHub API as the installation |

The receiver is the only internet-facing code that parses untrusted input
before authentication, so it gets nothing worth stealing: a forged request
that got past it could start an execution, and nothing else. The private key,
which can act on every repository the App is installed on, is not held by
any function: it lives in KMS, and the one role allowed to sign with it
belongs to a function API Gateway cannot reach (§4.1). Same least-privilege argument as
§4.1's per-Lambda roles, which is the point of the project.

`github-gateway` has two entry points (`fetch`, `report`) rather than being
two Lambdas, because both need the same signing grant and the same
installation-token code; splitting them would double the roles that can act
as the App and gain nothing.

## 3. `webhook-receiver`

1. Verify `X-Hub-Signature-256` — HMAC-SHA256 of the **raw** body, compared
   with `hmac.compare_digest`. The HTTP API delivers the body as a string,
   base64-encoded when `isBase64Encoded` is set; decode first, and never
   re-serialise parsed JSON to check it. Reject with 401 before parsing.
2. Accept `pull_request` with action `opened`, `synchronize`, `reopened`,
   `ready_for_review`, and `check_run` with action `requested_action` or
   `rerequested` (§5). Anything else: 204.
3. Skip draft PRs until `ready_for_review` (decision D4).
4. `StartExecution` with a **deterministic name** built from `pr_id`, the head
   SHA and the trigger (`push`, `fixes`, `rerun-<n>`). GitHub redelivers with
   the same payload; `ExecutionAlreadyExists` makes that idempotent for free,
   so a redelivery returns 200 and starts nothing. Names reuse `scan.py`'s
   `execution_name` sanitising, moved into a shared copy with a test
   asserting the copies agree — the pattern `CFN_MARKER_RE` already uses.
5. Return 202. Nothing in this function waits on GitHub or S3.

`pr_id` is `gh-<repository id>-<number>`. It must be stable across pushes
(state preservation keys on it) and distinct across repositories. *Changed
2026-09-24 from `gh-<owner>-<repo>-<number>`:* owner and repo names can both
contain hyphens, so `a-b/c` and `a/b-c` joined to the same string, and a
renamed repository would have orphaned its PRs' review history. The numeric
id is unique and never changes; the readable `owner/repo` travels in the
execution input. The installation id is kept out of `pr_id` for the same
reason: reinstalling the App changes it.

## 4. `github-gateway`

### 4.1 Authentication

JWT signed RS256 with the App's private key (`iss` = App id, `exp` ≤ 10
minutes) → `POST /app/installations/{id}/access_tokens` → a token valid for
an hour, scoped to the installation. Mint one per invocation; an execution is
shorter than an hour but a cached token is one more thing to expire at the
wrong moment.

**The private key is in KMS, not Secrets Manager** (decided 2026-09-24). The
JWT's header and claims are built with the standard library and the RS256
signature is `kms:Sign` with `RSASSA_PKCS1_V1_5_SHA_256`, so no function can
read the key, only use it, and every use is a CloudTrail event. A key in
Secrets Manager is readable by any role granted `GetSecretValue`, and readable
for good once copied out. It is imported rather than generated because GitHub
generates App keys and accepts no uploaded public key; so the guarantee holds
from the import onward, once the downloaded `.pem` and the interim Secrets
Manager copy are deleted. `scripts/import_github_app_key.py` creates the key
(`Origin=EXTERNAL`, alias `alias/iacposture-dev-github-app`), wraps and
imports the material locally, and proves it by verifying a KMS signature
against the local public key. Terraform looks the key up by alias: provider
5.x cannot create a key with imported material, and the material should not
pass through state anyway.

The webhook secret stays in Secrets Manager for now. It is symmetric, and
GitHub holds a readable copy regardless, so moving it gains less than moving
the App key did. A KMS HMAC key with imported material could still verify
deliveries without the receiver reading it (`VerifyMac`); whether KMS accepts
that import has not been checked. It has no placeholder value (`secrets.tf`
says why).

App permissions: Metadata read, Contents **read**, Pull requests write,
Checks write. Events: `pull_request`, `check_run`. Contents stays read-only
in v3; write is v4's scope and is requested when v4 needs it.

### 4.2 `fetch`

1. Create the check run on `head_sha`, status `in_progress`, and put its id in
   the execution state for `report`.
2. `GET /repos/{o}/{r}/tarball/{head_sha}` (a redirect to codeload). Stream it
   through `tarfile` in memory, and for each member:
   - skip anything that is not a regular file (symlinks, hardlinks, devices);
   - strip the top-level `<owner>-<repo>-<sha>/` directory, reject absolute
     paths and any `..` component — a key built from a tar path is a path
     traversal unless it is checked;
   - keep it if `is_snapshot_file` says the scanner would open it (a third
     copy of that rule, under the same agreement test).
3. Replace `scans/<pr_id>/` with the kept set (the same delete-then-put as
   `scan.py`'s `upload`, so a file deleted in the PR stops being scanned).
4. `GET /pulls/{n}/files` (paginated) and store each file's status and
   `patch` to `github/<pr_id>/<head_sha>/files.json`. `report` needs the
   hunks to know which lines a comment may attach to (§4.3).

**Limits.** A cap on tarball bytes and on kept-file count, set after
measuring one real repo. Over the cap, the check run completes as `neutral`
with "too large to scan", and **no partial scan runs**: a partial scan looks
exactly like a clean one for the files it skipped, which is the failure mode
this project exists to prevent.

The whole repository is snapshotted, not only the changed files. The scanner
resolves modules and variables across files, and `context-agent` answers a
fix's questions by reading the rest of the repo; a changed-files-only snapshot
would change what both of them see and make a PR's results disagree with a
manual scan of the same commit.

### 4.3 `report`

Reads the PR's findings from DynamoDB and the stored hunks, then:

- **Check run.** Completes with a summary: counts by severity and by
  `target_type`, the scan errors, and the dashboard link `/prs/<pr_id>`.
  **Annotations** only for findings whose `line_range` intersects a line the
  PR **added**. Annotations are sent at most 50 per API call **(verify)**,
  batched across updates.
- **What "introduced by this PR" means.** Without a scan of the base commit
  the project cannot know which findings are new. Intersecting with added
  lines is the cheap approximation, and it is stated as one in the summary:
  it misses a finding that a change *enables* on an untouched line (a
  variable default that flips a resource elsewhere), and the summary still
  counts every finding in the repo. A base-commit scan is deferred (§7).
- **Suggestions**, only when fixes exist (§5). One PR review, event
  `COMMENT`, with one comment per `fix-proposed` finding whose diff
  touches **only** lines inside the PR's right-side hunks, as a
  ```` ```suggestion ```` block spanning `start_line`..`line`. A fix that
  reaches outside the diff cannot be a suggestion — GitHub rejects the
  comment **(verify: whole review or one comment)** — so it is listed in the
  summary with a dashboard link instead. Fixes are chained (`applies_after`):
  post a chain's fixes only when every earlier link in it is also postable,
  or the second suggestion applies to text the first already changed.
  `needs-human-only` findings are never posted as suggestions.
- **Idempotency.** A re-run on the same SHA must not post the review twice.
  Before posting, list the App's own reviews on the PR and skip if one with
  the same execution marker exists (an HTML comment in the body).

**Conclusion** is `neutral` in v3 regardless of findings (decision D1). The
check is advisory until §7's fix-acceptance rate exists to say its
suggestions deserve to block a merge.

## 5. Remediation is a button, not a push

`scan.py` asks before remediating because it is the stage that costs model
calls, one or more per finding. A webhook cannot ask, and running it on every
push of every PR spends the most exactly where it is least wanted: on
work-in-progress commits that the next push replaces.

So a push runs scan and map only (`remediate: false`), and the completed
check run carries an action button, **Draft fixes**. Clicking it sends
`check_run.requested_action`; the receiver starts the same execution with
`remediate: true` on the same head SHA. The re-scan costs about a minute and
changes nothing, because review state is preserved.

This also gates cost on who can click: action buttons are shown only to users
with write access to the repository **(verify)**. That matters for §6.1 — an
outside contributor's PR is scanned and mapped, but no model call drafts a
fix for it until a maintainer asks.

## 6. Risks

### 6.1 Untrusted PRs

A PR from a fork is attacker-controlled input. What that allows:

- **Code execution:** none. Nothing is executed — the scanners parse files,
  which is why Pulumi and CDK are out (multi-iac-spec §7). That rule is what
  lets v3 accept fork PRs at all, and it should be restated wherever someone
  proposes adding a language that needs running.
- **Prompt injection into the agents.** File contents reach `mapping-agent`,
  `remediation-agent` and `context-agent`. The defences are the ones already
  there: strict JSON-schema outputs, the suppression and deletion gates, and
  the self-check that re-scans every fix. v3 adds one exposure — output now
  reaches a public PR thread — and one limit: `report` posts only fields
  code produced (diffs that passed self-check, rule ids, counts). It never
  posts free text from a model: not `explanation`, not `assumptions`.
- **Cost.** Covered by §5: scan and map only, until a maintainer clicks.
  Mapping is one model call per finding, so a fork PR that adds a thousand
  findings costs a thousand calls. Cap mapped findings per execution; over the
  cap, map the ones in changed files first.

### 6.2 Two pushes, one PR

Two quick pushes start two executions on the same `pr_id`. They share
`scans/<pr_id>/`, so the second `fetch` can replace the snapshot while the
first scan is reading it, and both write the same findings.

Proposed: the receiver records the running execution ARN on the PR item
(conditional write) and calls `StopExecution` on the previous one before
starting the next. That stops the state machine, **not** a Lambda that is
already running; a remediation invocation completes and writes anyway. The
window is small while remediation is off by default, and the check run is
attached to the older SHA, so a stale report lands on a stale commit, which is
harmless.

The full fix is a snapshot prefix per SHA (`scans/<pr_id>/<sha>/`). It is not
free: `remediation-agent` (`handler.py:742`, `:758`) and `review-api`
(`handler.py:391`) build `scans/{pr_id}/` themselves rather than reading
`s3_prefix`. Deferred until the race is observed, and noted here so the
hard-coded prefix is not copied into a new place in the meantime.

### 6.3 A check stuck `in_progress`

Every state gets a `Catch` that routes to `report` with the error. `report`
completes the run as `neutral` with the error and the execution link. If
`report` itself fails, the run stays `in_progress`; an EventBridge rule on
execution `FAILED`/`TIMED_OUT` can be the backstop, since it needs no state
from the execution beyond its input.

## 7. Not in v3

- **Write-back** of approved fixes to the branch — v4. Contents stays read.
- **A base-commit scan** to tell introduced findings from existing ones.
  It doubles scan cost per push; the added-lines approximation comes first,
  and its misses are what would justify this.
- **GitHub Enterprise Server and GitLab.**
- **Blocking merges.** See D1.

## 8. Decisions needed before building

| # | Decision | Recommendation |
|---|---|---|
| D1 | Check conclusion when findings exist | `neutral` always in v3 |
| D2 | Drop SQS (§1) — loses a DVA-C02 rep | **Decided 2026-09-24: dropped** |
| D3 | Remediation on push, or behind the button (§5) | Button |
| D4 | Scan draft PRs | No; start at `ready_for_review` |
| D5 | Which repo is the first installation | One the project owns, never a fork target, until §6.1's caps are in |
| D6 | Ownership | **Decided 2026-09-24: Konrad owns all of v3** |

## 9. Build order

1. **Register the App by hand** and settle every **(verify)** above against it:
   annotation batch size, how a review with one out-of-diff suggestion fails,
   who sees action buttons. Record answers here before code depends on them.
2. Secrets, `webhook-receiver`, the API route. Done when a real delivery
   starts an execution that `scan.py` would also have started, and a
   redelivery starts nothing.
3. `fetch`, with tests on hostile tarballs (symlink, `..`, absolute path,
   oversize) — the guards are code, so they get unit tests, not a prompt.
4. `report`: check run and annotations only.
5. The **Draft fixes** button and suggestions.
6. `Catch` routing and the stuck-check backstop.
7. Metrics: executions by trigger, suggestions posted vs. held back as
   out-of-diff. The second number says whether the added-lines rule is
   costing more fixes than it should.
