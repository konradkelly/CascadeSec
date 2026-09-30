# GitHub-first review — spec

A proposal to let a maintainer take CascadeSec's verified fixes from the
pull request to the branch without leaving GitHub. It amends write-back
(v4, [`write-back-spec.md`](./write-back-spec.md)), whose decision W3 put
every commit behind the dashboard, and adds nothing the dashboard loses.

Written 2026-09-30, before building. Nothing here is built. GitHub API
claims are from GitHub's documentation and are marked **(verify)** until a
deployed run has shown them. §9 is the build order and §8 the decisions.

## 1. The problem

A maintainer works in the pull request. Today a fix reaches the branch one
of two ways:

- **In GitHub**, a verified fix inside the PR's diff is posted as a
  suggestion, and **Commit suggestions** applies it (v3).
- **In the dashboard**, anything else: a fix outside the diff (GitHub cannot
  take it as a suggestion), a chain of fixes on one file whose hunks reach
  outside the diff, a held fix, an edit. A committer approves there, reviews
  the commit plan, and commits (v4).

So a PR whose fixes are all verified still sends its maintainer to a second
tool when any one of them sits outside the diff. On cascadesec-testbed #2
that was most of them. And the dashboard asks for a second login, Cognito,
for a decision the PR's own permissions could settle.

## 2. What stays in the dashboard, and why

Not everything can move, and the line is not arbitrary:

- **Held fixes.** A fix is held because a gate fired: it deletes a
  resource, rests on an assumption, or asked the repository something it
  could not answer. Weighing it means reading the model's rationale and
  assumptions. ci-integration-spec §4.3 posts no model prose to GitHub --
  a PR's comments are public on a public repository, and model prose there
  reads as a claim CascadeSec makes -- and that rule stands. So a held fix
  is reviewed where its reasons are shown.
- **Edits.** A reviewer edits a whole corrected file. A PR comment thread
  is the wrong surface for that.
- **Rejections, and the audit trail.** Both stay where the whole review
  history is readable.

What moves is the case that needs no judgement beyond "yes": **fixes that
passed their self-check**, whatever their position in the file.

## 3. The design: a Commit fixes button

After a Draft fixes run, the CascadeSec check run carries a second button,
**Commit fixes**, beside the summary of what it would commit. One click by
a maintainer with write access approves the listed fixes and commits them,
as one commit, through write-back's github-committer. Nothing else about
write-back changes: the same writer App, the same base check against the
branch, the same compare-and-swap ref update, the same records.

```mermaid
sequenceDiagram
    autonumber
    participant M as Maintainer
    participant GH as GitHub
    participant W as webhook-receiver
    participant P as pipeline (v3)
    participant S as commit state machine (new)
    participant C as github-committer
    participant DB as DynamoDB

    M->>GH: Draft fixes
    GH->>W: check_run.requested_action (draft_fixes)
    W->>P: StartExecution (unchanged)
    P->>DB: record the offer: per file, tip and content hash
    P->>GH: check run: summary with the plan's diffs, Commit fixes button
    M->>GH: Commit fixes
    GH->>W: check_run.requested_action (commit_fixes), sender
    W->>S: StartExecution {pr, check run, sender}
    S->>DB: put COMMIT# (source github, sender)
    S->>C: Invoke
    C->>GH: sender's permission on the repository
    C->>DB: "approved" events, actor github:<login>
    C->>GH: blobs, tree, commit, PATCH ref
    C->>GH: complete a check run: committed, with the commit link
```

### 3.1 What the button commits: the offer

The summary a maintainer reads is the thing they approve, so the click
commits exactly what the summary showed and nothing else -- the rule the
dashboard's `confirm` list enforces (write-back-spec §14).

When `report` finishes a Draft fixes run, it computes the **offer**: per
file, the longest chain made only of verified fixes -- `chain_tip`, which
already picks what v3 posts -- with the tip's content hash and the diff
from the PR head to the tip. The summary shows each file's diff, in and
out of the PR's diff alike, since a summary is not bound to diff lines the
way a suggestion is. The offer is stored under the check run's id, and the
button is added only if the offer has a file in it.

Check run summaries cap at 65,535 characters **(verify)**. An offer whose
diffs do not fit lists the files and links to the dashboard for the rest,
and the button is still offered: the stored offer, not the rendered text,
is what the click commits. The truncation says so in the summary.

### 3.2 Who may click it

A GitHub identity with **write** permission on the repository, checked by
the committer at the time of the click with
`GET /repos/{owner}/{repo}/collaborators/{username}/permission` under the
writer App's token **(verify)**. Not the Cognito group `committers`, which
remains the rule for dashboard commits.

GitHub shows a check run's action buttons to users with write access
**(verify)**, so the check is a second gate, not the only one. It is not
skipped for that: the webhook's `sender` is who clicked, and permission is
what the committer, not GitHub's UI, is accountable for. Read permission,
or a user GitHub no longer knows, ends the request as `held` with the
reason, and the check run says so.

This is weaker than the dashboard's gate in one way, on purpose: anyone who
can push to the branch can commit CascadeSec's verified fixes to it. They
could push the same change by hand, so the button grants nothing new. A
repository that wants a narrower rule can leave the writer App uninstalled,
which is write-back's opt-in already.

### 3.3 Identity in the audit log

A click writes, per fix in the offer, a ReviewEvent with action `approved`
and actor `github:<login>`, with the numeric GitHub user id alongside:
logins can be renamed and reused, ids cannot. Then the committer's
`committed` event, as today. The dashboard's audit trail shows both kinds
of actor, labelled.

This is what W3 declined: "a GitHub-side button would put a second identity
system in the audit log." It does. The log stays one log -- every decision
is still an event on the finding, attributed to a verified identity -- but
a reader has to know an actor can now be a Cognito email or a GitHub user.
What makes a GitHub identity trustworthy here is the webhook's HMAC
signature, which webhook-receiver already verifies: the sender is GitHub's
statement, not the request's.

### 3.4 Getting the click to the committer

webhook-receiver holds only the webhook secret and `states:StartExecution`
on one state machine, by design (ci-integration-spec §2.1). It stays that
way in kind: it gains StartExecution on a **second, small state machine**,
not a Lambda invoke and not a table write.

That state machine puts the COMMIT# request -- `source: github`, the
sender's login and id, the check run id whose offer is being accepted --
and invokes github-committer. Its execution name is (PR, check run,
`commit`), so a redelivered webhook or a double click starts nothing, as
Draft fixes' name already does.

The committer then works as write-back-spec §6 describes, with two
differences: the confirmed set is the stored offer rather than a list the
dashboard sent, and approval is the click, so it writes the `approved`
events itself, after the permission check and before any GitHub write.

### 3.5 Stale offers

An offer describes the PR head it was drafted on. A push after it makes it
stale, and the committer's base check holds every file whose head changed
-- that already exists. On top of it, the button is only honoured on the
check run for the PR's current head: a click on an older check run's
button ends the request as `held`, "this offer is for an older commit;
use the latest check". GitHub keeps older check runs' buttons clickable
**(verify)**, which is why this is checked rather than assumed.

### 3.6 Reporting the result

The committer completes a small check run of its own on the new head,
"CascadeSec: fixes committed", linking the commit, or on a held request
the reason per file. The new head's push also starts the ordinary scan,
whose check run is the verification (write-back-spec §7). The dashboard
shows the request like any other.

## 4. Suggestions, once there is a button

v3's suggestions remain. They let a maintainer take one file's fixes and
not another's, which the button's all-or-nothing offer does not, and they
cost nothing to keep. What changes is the summary text: it says the
suggestions cover the files GitHub can show inline, and the button covers
every verified file.

## 5. Data model

```
CommitRequest (write-back-spec §10) gains:
├── source: dashboard | github
├── requested_by            # an email for dashboard, "github:<login>" for github
├── github_user_id          # github only
└── check_run_id            # github only: the offer accepted

Offer (new, same table; written by the pipeline after Report)
├── pk: PR#<pr_id>
├── sk: OFFER#<check_run_id>
├── head_sha
└── files: [{ file, tip, chain: [finding_id], content_sha256 }]

ReviewEvent.actor           # may be "github:<login>"; github_user_id alongside
```

The offer is written by the state machine from `report`'s result, as
PullRequestMeta is (write-back-spec §12 step 2): github-gateway parses
tarballs and has no table write, and this spec does not give it one. The
result carries tips and hashes, not content, so it fits the 256KB state
limit.

## 6. Security

- **Forks** stay refused. GitHub sends a fork PR's check_run event with an
  empty `pull_requests` list, and webhook-receiver already drops it.
- **A forged click** needs the webhook secret, the same bar as a forged
  Draft fixes click today.
- **Least privilege holds.** webhook-receiver gains one StartExecution
  grant; the commit state machine gains PutItem on `PR#gh-*` and invoke on
  the committer; the committer gains nothing but a GitHub API read. Nothing
  that parses a tarball can reach the writer key.
- **Nothing a model wrote is posted.** The summary's diffs are fixes that
  passed their self-check, which v3 already posts as suggestions; the
  rationale, assumptions and questions stay in the dashboard.

## 7. Not in this spec

- **Approving or rejecting a single finding from GitHub**, by comment
  command or reaction. It would need a per-finding surface on the PR, and a
  rejection's reason is exactly the prose §2 keeps off GitHub. The button
  is all the verified fixes in the offer, or none.
- **Held fixes on GitHub.** §2.
- **Committing on Draft fixes, without a click.** A maintainer still asks,
  as W3 wanted: one click instead of a trip to another tool.
- **Other platforms.** GitLab's equivalent is integrations-spec's.

## 8. Decisions

| # | Decision | Outcome |
|---|---|---|
| G1 | The button commits verified fixes only; held fixes and edits stay in the dashboard (§2) | Proposed |
| G2 | Authorisation for a GitHub click is write permission on the repository, checked by the committer (§3.2) | **Open.** Proposed: write permission. Alternative: also require a `committers`-like list in the repository's config |
| G3 | The audit log accepts GitHub identities, `github:<login>` with the user id (§3.3) | **Open.** Reverses W3's identity reasoning; proposed |
| G4 | The click commits the stored offer, not what is planned at click time (§3.1) | Proposed |
| G5 | A second state machine carries the click; webhook-receiver gets no invoke or table grant (§3.4) | Proposed |
| G6 | Suggestions stay (§4) | Proposed |
| G7 | A click on a check run for an older head is held (§3.5) | Proposed |

## 9. Build order

Each step is a commit of its own.

1. **The offer.** `report` computes it after a Draft fixes run and returns
   it; a state after Report stores it. The summary shows each offered
   file's diff. No button yet: this alone shows maintainers the
   out-of-diff fixes on GitHub, which today live only in the dashboard.
2. **The commit state machine**, and webhook-receiver starting it for a
   `commit_fixes` click, named for idempotency.
3. **The committer's GitHub path**: the permission check, the offer as the
   confirmed set, `approved` events under a GitHub actor, the current-head
   rule, and the result check run. The dashboard path is unchanged.
4. **The button** on the check run when the offer has a file, and the
   summary text of §4.
5. **The dashboard** labels GitHub actors in the audit trail and shows a
   request's source.
6. **Verify on cascadesec-testbed**: a click by the owner; a click by a
   collaborator with read access (held); a click on an older check run
   (held); a double click (one commit); an offer with an out-of-diff file;
   a push between the offer and the click (base check holds the file). And
   each **(verify)** above.
7. **Docs**: write-back-spec W3 gains a pointer here, and ci-integration-
   spec §4.3 describes the offer.
