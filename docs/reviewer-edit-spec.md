# Reviewer edits as chain bases — spec

Follows `docs/fix-chain-review-spec.md`. That spec makes a reviewer's edit of
`f1` invalidate every fix drafted on top of it. This one makes the invalidated
fixes recoverable.

**Status, 2026-10-31.** Built and deployed 2026-09-11, all five steps of
§8. §6's open decision, re-running the self-check on a reviewer's edit,
was not built: an edited fix keeps `self_check_passed: false`. Its content
is scanned only when it roots a later chain, for that chain's counts, and
on the branch once it is committed (write-back-spec).

## 1. The dead end

After `f1` is edited, the cascade returns `f2`…`fN` to `needs-human-only` with
a `stale_reason` that says they need redrafting. Nothing redrafts them:

- remediation-agent picks up `status: mapped` only.
- No reviewer action moves `needs-human-only` back to `mapped` — approve and
  edit set `resolved`, reject leaves status alone.
- Approve and edit are blocked on them anyway (§3 of the fix-chain spec, the
  hash no longer matches).

So they can only be rejected. The reason text is a promise nothing keeps. The
same is true after a rejection of `f1`, which now also cascades.

Sending them to `mapped` is not enough on its own. remediation-agent starts
every chain from the pristine snapshot with the file's `mapped` findings, so
`f2` would be redrafted against a file that does not contain `f1`'s edited
fix — and would collide with it at application time, which is the original
problem this whole line of work exists to remove.

The root cause in one sentence: **an edit is a diff, a base is content, and
something has to turn one into the other.**

## 2. Design

Four changes that only work together.

### 2.1 The reviewer edits the file, not the diff

Today the edit textarea is prefilled with the agent's unified diff and the
reviewer hand-edits it. That diff is never validated — it may not apply to
anything. The spec already refuses to let the LLM author diffs for exactly
this reason ("a hand-authored diff risks not applying cleanly; a mechanically
computed one always will"). The same is true of reviewers.

The textarea is prefilled with the fix's **corrected file** instead. Every
scanner-verified fix already has one in S3: `_upload_scratch_file` writes it
to `fixes/<pr_id>/<finding_id>/<file>` for the self-check. The
reviewer submits `edited_content`; review-api computes the diff with
`difflib.unified_diff` against the fix's base, exactly as remediation-agent
does, and stores both. No diff application anywhere in the system.

`edited_diff` is removed from the review contract, not kept alongside. Keeping
it would mean keeping a path that produces unvalidated diffs.

### 2.2 Accepted content is durable and is the base

review-api writes `edited_content` to the fix's scratch key, replacing the
agent's version. From then on the fix's stored content *is* its edited
content, and anything rooted on the fix reads that.

`scans/` expires at 90 days, and content that later chains will be rooted
on cannot. The first draft of this spec said the lifecycle rule would stop
covering `scans/self-checks/`; S3 lifecycle rules cannot exempt a sub-prefix
from a prefix rule, so instead fix content moved out from under `scans/`
entirely, to `fixes/<pr_id>/<finding_id>/<file>`, which no expiry rule
touches. That is a key change in remediation-agent and review-api and an IAM
change in all three Lambda roles (the scanner reads it for self-checks).
Snapshots under `scans/<pr_id>/` still expire; a fix whose snapshot is gone
is orphaned but harmless.

### 2.3 remediation-agent roots a chain at the last accepted fix

Today: base = pristine snapshot; walk the file's `mapped` findings.

Now: base = the output of the **last accepted fix on that file**, read from
its scratch key; `applies_after` for new fixes starts as that fix's own
chain plus itself. If no fix on the file is accepted, base = pristine as
before. "Accepted" is defined in §2.4.

Reopened dependents go to `mapped` — chain dependents as well as superseded
ones, which PR #5 already does. On the next run they are redrafted against
the accepted state of the file, which is what `stale_reason` promised.

The rejected case falls out for free: a rejected `f1` is not accepted, so it
is not in the base, so `f2` is redrafted against the chain without it.

**A rule the accepted root already cleared supersedes by the root.** The
in-run `cleared_by` map only knows about fixes drafted in the current run.
When there is a root and a `mapped` finding's rule is already at zero in the
root's counts, the accepted chain cleared it, and the root — the fix whose
content was just rescanned to prove it — is recorded as `superseded_by`.
Found live: two findings an approved fix had cleared were drafted anyway,
the model returned the file unchanged saying the rule was already
satisfied, and the empty diff scored `cleared=False`.

### 2.4 Rejection retracts `resolved`

`status` is a lossy cache of the last resolving action and is never
retracted. This has now cost complexity in three places — the prerequisite
check, the cascade, and here, where remediation-agent has to decide which
fixes have landed. Reading the event log from a third Lambda is the wrong
answer.

A rejection sets status to `needs-human-only`. The finding is still real (the
comment on `RESOLVING_ACTIONS` is right about that), it is just no longer
resolved — and `needs-human-only` is exactly "a human has to decide". With
that, **accepted means `status == resolved`** and every consumer can trust it.
The prerequisite check keeps reading events, since it also needs to
distinguish `reopened` from `rejected`; it just stops being the *only* thing
that can tell.

Existing rejected-after-approved records keep `resolved` until touched again.
There are none in the live table today.

## 3. Data model

FindingRecord, no new fields. `proposed_fix.diff` is the reviewer's diff after
an edit; `agent_diff` preserves the original as it already does.

S3: `fixes/<pr_id>/<finding_id>/<file>` (previously `scans/self-checks/…`) becomes load-bearing —
the accepted content of a fix, agent-drafted or reviewer-edited.

## 4. API contract

`POST /prs/{pr_id}/findings/{finding_id}/review`

```
{ "action": "edited", "edited_content": "<full file>", "notes": "..." }
```

`edited_diff` is a 400. review-api:

1. Reads the fix's base: pristine `scans/<pr_id>/<file>` if `applies_after`
   is empty, else the scratch content of the last entry in `applies_after`.
2. Computes `diff = unified_diff(base, edited_content)`. An empty diff is a
   400 — an edit that changes nothing is not an edit.
3. Writes `edited_content` to the fix's scratch key.
4. Stores `diff`, resets the self-check fields (already does), cascades
   (already does).

New: `GET /prs/{pr_id}/findings/{finding_id}/content` returns the fix's
current corrected content, for the dashboard to prefill. Reading it from S3
on every detail-page load is fine; the alternative — storing the whole file
in DynamoDB — puts a 400KB item ceiling under a Terraform file.

IAM: review-api gains `s3:GetObject` on `scans/*` and `fixes/*` and
`s3:PutObject` on `fixes/*`. The read cannot be narrower — the pristine
snapshot is under `scans/<pr_id>/` and a prerequisite's content under
`fixes/` — and nothing wider is needed.

## 5. Dashboard

- The edit textarea prefills from `/content`, not `proposed_fix.diff`.
- Submits `edited_content`. `ReviewActions`' `currentDiff` prop becomes
  `currentContent`.
- The diff view stays as the review artifact; the file view is the edit
  artifact. A reviewer reads the diff and edits the file.
- `DiffViewer` is unchanged: review-api now produces the diff.

## 6. Decisions

- [x] **Reviewer submits content, not a diff.** Alternatives: apply the
  reviewer's diff in review-api at submit time (needs a unified-diff
  applier, ~60 lines, and the hash design was built to avoid exactly that
  class of code), or block edits on any fix with dependents (cheap,
  degrades the UX, and still leaves today's edits unvalidated).
- [x] **Rejection retracts `resolved`.** Deferred three times; each deferral
  added an event-log read somewhere. `needs-human-only` is the correct
  retracted state because the finding is still real.
- [x] **Content lives in S3, not DynamoDB.** The 400KB item limit is not
  hypothetical for a module's `main.tf`.
- [x] **Remove `edited_diff` rather than deprecate it.** A deprecated path is
  a path, and this one produces unvalidated input.
- [ ] Whether an edited fix should be re-self-checked automatically, now that
  its content is materialised. Today a reviewer's edit carries
  `self_check_passed: false` forever. Re-running the scanner on the edited
  content is one invoke and would give the reviewer's version the same
  standing as the agent's. Leaning yes, as a follow-on; it is a
  remediation-agent concern, not a review-api one.

## 7. Tests

review-api:
- edit with `edited_content` computes the diff against the pristine base when
  `applies_after` is empty
- … and against the last prerequisite's scratch content when it is not
- edit that changes nothing is a 400, nothing written
- `edited_diff` in the body is a 400
- edit writes the content to the fix's scratch key before writing the record
- `GET …/content` returns the scratch content; 404 when the fix has none
- reject sets status to `needs-human-only`; approve still sets `resolved`
- approved-then-rejected reads `needs-human-only`, so a status check now agrees
  with the event log

remediation-agent:
- a file with one `resolved` fix roots the chain at that fix's scratch content,
  and new fixes' `applies_after` begin with its chain plus itself
- a file with no `resolved` fix roots at the pristine snapshot, as before
- a `needs-human-only` (rejected) fix is not a root
- a reopened dependent returned to `mapped` is redrafted against the edited
  base, and its new diff is minimal against that base

dashboard: type check covers the contract change.

## 8. Order of work

*All five built in one pass on 2026-09-11; 113 tests across the three suites.
Two deviations from the plan above: §2.2's lifecycle exemption became a prefix
move (see there), and reopened chain dependents go to `mapped` rather than
`needs-human-only`, since there is nothing a human can do with one until it
is redrafted and `mapped` is what the redraft picks up.*

1. §2.4 first, on its own — it is one line in review-api and simplifies
   everything after it.
2. review-api: content endpoint, `edited_content`, S3 write, IAM.
3. remediation-agent: root at last accepted fix; cascade dependents to `mapped`.
4. Dashboard.
5. Lifecycle rule.

Each step is deployable alone; none is useful alone until 4.
