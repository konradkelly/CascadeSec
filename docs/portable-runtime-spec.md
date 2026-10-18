# Portable runtime — spec

CascadeSec runs its whole pipeline on AWS: S3, DynamoDB, Step Functions,
Lambda, Fargate, Secrets Manager, KMS and Cognito. That is a fine way to
host it and a poor requirement to use it. Someone on Azure or GCP, or with
no cloud account, cannot run the agents at all today. The only cloud-free
path planned so far (cli-spec §3) is detection: findings, with no citation
and no fix.

This spec makes the cloud an optional deployment target rather than a
prerequisite, in three runtimes:

| Runtime | Runs where | Who it is for |
|---|---|---|
| **Local** | one process and Docker, on a laptop or in any CI job | anyone; no account, no cloud |
| **AWS** | what exists today, unchanged | this deployment |
| **Portable hosted** | containers, Postgres and S3-compatible storage, on any cloud | a team that wants the GitHub App and a shared dashboard off AWS |

Written before building, 2026-10-18. Not started. Requested by Konrad on
2026-10-18, after S1 of the CLI's track S showed how thin the AWS layer is.

## 1. How much is actually AWS

Less than the architecture diagram suggests. Measured on `main` on
2026-10-18: the nine components hold about 9,700 lines of Python and about
100 AWS call sites. Everything that makes CascadeSec what it is does not
touch AWS:

- running and normalising three scanners (`scan_directory` since S1)
- mapping to controls among corpus candidates, with the model's answer
  checked against the candidate set
- drafting fixes, chaining them per file, the self-check, suppression and
  deletion gates, assumptions and repository questions
- review rules: prerequisites, reopening dependents, the commit plan

What AWS provides is storage, orchestration, secrets, signing, identity and
a sandbox:

| AWS service | What CascadeSec uses it for | Port (§3) |
|---|---|---|
| S3 | snapshots, corrected files, the corpus, CDK source maps | BlobStore |
| DynamoDB | findings, review events, commit requests, PR metadata | RecordStore |
| Step Functions, Lambda invoke | scan, map, remediate per file; the commit machine | Runner |
| Secrets Manager | the Anthropic key, the webhook secret | Secrets |
| KMS | signing the two GitHub Apps' JWTs | Signer |
| Fargate (ECS) | the CDK, Pulumi and Helm sandbox | SandboxRunner |
| Cognito, API Gateway authorizers | who is calling review-api | Identity |
| EventBridge, CloudWatch | the committer's failure backstop, alarms, metrics | (hosted only) |

The four Lambda-to-Lambda calls are part of the orchestration, not the
logic: remediation-agent calls iac-scanner for the self-check (twice) and
context-agent for repository questions, and review-api hands a commit
request to github-committer.

## 2. The rule

**One core, many adapters.** The logic above becomes a Python package,
`cascadesec_core`, that imports no cloud SDK. Each runtime is a thin layer
that gives the core its ports. The AWS Lambdas become those thin layers:
each handler parses its event, builds the AWS adapters, and calls the core.

That is the same move S1 made for the scanner, applied to the rest. It is
also what keeps three runtimes from becoming three products: a rule lives
in the core once, and the runtimes cannot disagree about it, in the same
way the CLI and the dashboard cannot (cli-spec §10).

What the rule forbids: an adapter that decides anything. A store stores,
a runner runs. If a runtime needs different behaviour, that is a parameter
the core takes, not a branch in an adapter.

## 3. Ports

Small and specific to what the code does now. None is a general framework.

**BlobStore.** `get(key)`, `get_range(key, max_bytes)`, `put(key, bytes)`,
`list(prefix)`, `delete(key)`. Keys keep their current layout (`scans/<pr>/`,
`fixes/<pr>/<finding>/<file>`, `corpus/`). Adapters: S3; a directory;
anything S3-compatible (GCS's interoperability API, Azure via a gateway,
MinIO, R2), which is one adapter, not one per cloud.

**RecordStore.** The item model stays exactly as it is: items keyed by `pk`
and `sk`, with the same attribute names and shapes, so the dashboard and
every reader are unchanged. The operations are the ones the code uses
today, made explicit instead of written as DynamoDB expression strings:

```
get(pk, sk) -> item | None
query(pk, sk_prefix) -> [item]              sorted by sk, exhausted (no pages)
put(item, unless_exists=False)              unless_exists -> Conflict
update(pk, sk, set={}, set_if_absent={}, remove=[], condition=None) -> item
    condition: StatusIs(...) | StatusIn(...) | Exists(attr) | Absent()
               | AbsentOr(StatusIn(...))      a failed condition -> Conflict
```

The 39 record call sites (`get_item`, `query`, `put_item`, `update_item`) move from boto3
expressions to this API, beside the 40 S3 call sites that move to BlobStore. The DynamoDB
adapter turns each call back into the expression it replaced, so the AWS
runtime's writes are the same writes. SQLite and Postgres hold one table,
`(pk TEXT, sk TEXT, item JSON, PRIMARY KEY (pk, sk))`, and do conditional
updates in a transaction: SQLite with `BEGIN IMMEDIATE`, Postgres with
`SELECT ... FOR UPDATE`.

**Runner.** Runs the pipeline for one scan: scan, then map, then remediate
each file. The AWS runner is the existing state machines, unchanged. The
in-process runner is a loop. Lambda's time budget, which is why mapping and
remediation yield and resume (`remaining`, `resume_from`), becomes a
parameter: unlimited in-process, so the loop never yields. The yield path
stays in the core and stays tested, because AWS still needs it.

**Secrets.** `get(name)`. Secrets Manager; an environment variable; the OS
keyring (as the CLI's session already uses, cli-spec §11.1).

**Signer.** Signs a GitHub App JWT. KMS today. A PEM file or an HSM-backed
key elsewhere. Only the hosted runtimes need it: local mode has no GitHub
App.

**SandboxRunner.** Runs a CDK, Pulumi or Helm job in its two phases (fetch
with network, execute without), as sandbox-spec defines them. Fargate
today; `docker run` locally, which is cli-spec §3.5's stage 2 and 3, so
that work is not done twice.

**Identity.** Who is calling the review API, and their groups. API
Gateway's authorizers today. The portable server verifies an OIDC JWT
itself, against any issuer (Cognito is one; so are Entra ID, Google,
Keycloak and Auth0). Local mode has one user and binds to localhost.

## 4. What must stay true in every store

DynamoDB's conditional writes carry guarantees the review process depends
on. Each one becomes a test in a **conformance suite** that every
RecordStore adapter must pass. An adapter that fails one is not an adapter.

| # | Guarantee | Where today |
|---|---|---|
| G1 | A rescan keeps review state: status, mappings, the fix and created_at are written only if absent | iac-scanner `_write_findings` (`if_not_exists`) |
| G2 | A finding is marked no-longer-detected once; a later scan cannot move the date | iac-scanner (`attribute_not_exists(no_longer_detected)`) |
| G3 | A fix is reopened only if its status is still what was read | remediation-agent `_conditional_reopen` (`status = :was`) |
| G4 | One commit request per id | review-api `_post_commit`, committer click path (`attribute_not_exists(sk)`) |
| G5 | The committer claims a request exactly once | committer `commit` (`requested` → `committing`) |
| G6 | A finished request is never overwritten by a late finisher or the failure backstop | committer `_finish`, backstop (`status = committing`, `IN (requested, committing)`) |
| G7 | A click's approval resolves only a fix that was proposed or resolved | committer click path (`status IN (...)`) |
| G8 | `committed` is recorded only on a record that has a fix | committer `record_commit` (`attribute_exists(proposed_fix)`) |
| G9 | A query returns every item under a key prefix, sorted by sk, however many | every `_query_all` |

G9 matters more than it looks: the latest review event, found by sorting on
`sk`, is what decides whether a prerequisite is satisfied
(review-api `_unmet_prerequisites`).

The suite runs in CI against SQLite and Postgres (a service container),
and against DynamoDB Local, so the AWS adapter is held to it too.

## 5. The local runtime

```
cascadesec run ./infra                    scan and map: findings with cited controls
cascadesec run ./infra --fix              ...and draft self-checked fixes
cascadesec serve                          the review API and dashboard on localhost
cascadesec findings / show / approve ...  the existing review commands, against it
cascadesec apply                          write approved fixes into the working tree
```

- **State** lives in the user's state directory, under one folder per
  project (`$XDG_STATE_HOME/cascadesec/<project>/`, `%LOCALAPPDATA%` on
  Windows): `records.sqlite` and `blobs/`. Never in the repository, which
  would put scan results in git. `--state-dir` overrides.
- **Scanning** is the published scanner image, as cli-spec §3.2 already
  defines it: pinned by digest, `--network none`.
- **Mapping and fixes** use the user's own model key (§6). The cost prompt
  is `scan.py`'s, and `--fix` without a terminal needs `--yes`, as in
  cli-spec §4.5.
- **The self-check** runs the scanner image again on the corrected file,
  exactly as remediation-agent calls iac-scanner today, but through the
  container instead of a Lambda invoke.
- **Review** goes through the same review API. `cascadesec serve` runs it
  over the local store, bound to 127.0.0.1, with no sign-in, and serves the
  dashboard's static build. The CLI's review commands already speak to
  "a deployment" (cli-spec §10); this is one more, so no review command is
  written twice.
- **Commit** has no GitHub App locally. `cascadesec apply` writes each
  file's approved chain tip into the working tree, only after confirming
  its root diff applies to the local file, as cli-spec §4.5's `--apply`
  defines, and the person commits.

**Network, said plainly.** Detection-only local mode (`cascadesec scan`,
cli-spec §3) sends nothing anywhere, and still runs under `--network none`.
`run` does not have that property: mapping and fixes send the finding, the
candidate controls, and the file being fixed to the model provider. The
help text and the first-run prompt say so, and say which provider.

## 6. The model

The Anthropic SDK reaches Claude directly or through a cloud's model
service, so the model follows the runtime rather than tying it to one
cloud: the Anthropic API by default, and Amazon Bedrock or Google Vertex AI
where a team must keep traffic inside its cloud account. That choice is
configuration, read by the core's one client factory. It is not a fork in
the agents.

The model id is configuration too, as `ANTHROPIC_MODEL` is in the Lambdas
today. Providers name models differently, so the setting is per provider.

## 7. Portable hosted

The AWS deployment, rebuilt from containers anyone can run:

- **One server image**: the review API, the GitHub App endpoints, and a
  worker running the in-process Runner off a job queue. A table in Postgres
  is enough for the queue at this scale (`SELECT ... FOR UPDATE SKIP
  LOCKED`); a broker is not needed.
- **Postgres** for records, **S3-compatible storage** for blobs, **OIDC**
  for identity, a **PEM or HSM** key for the Apps, and a **container
  runtime** for the sandbox.
- **One recipe proven** on one non-AWS platform, Cloud Run or Azure
  Container Apps, chosen when this phase starts. Other platforms follow
  from the same image.

**No native adapter per cloud** (Cosmos DB, Azure Blob's own API, Durable
Functions, Workflows) unless a user needs one. Each would add a second
implementation of something the portable stack already does on that cloud,
and every one of §4's guarantees would need proving again in each.

## 8. Packaging

The change most likely to cause trouble, so it goes first and alone.

Today each zip-packaged Lambda is one file: Terraform zips `handler.py`
(`archive_file` with `source_file`). A shared `cascadesec_core` cannot ship
that way. The options:

| Option | For | Against |
|---|---|---|
| A Lambda layer holding `cascadesec_core` | one artifact; handlers stay small | a layer version to keep in step with each handler |
| **Each zip built from a directory with the core vendored in** | each function's code is self-contained; a deploy is one artifact per function | the build copies the core into every zip |
| Container images for every function | same packaging as iac-scanner | slower cold starts; a registry push per change |

**Proposed: vendor the core into each zip** (`archive_file` with
`source_dir` over a build directory), because it keeps one artifact per
function and the deploy guard's code check (`scripts/deploy.py`) can still
compare what ships against `origin/main`. iac-scanner already ships as an
image and gets the core in its `COPY`.

This is also when mapping-agent's `_unmapped_reason` gets its shared home
(cli-spec §13, S1).

## 9. What changes elsewhere

- **cli-spec, track S.** S3 (`local_main.py`, GHCR) and S4 (local scan)
  stand as written: they are this runtime's scan stage, and detection-only
  stays the fully offline mode. S5 and S6 are unaffected. **S7 (`scan-api`,
  remote scans) and phase M drop in priority**, because a CI job can run
  the full pipeline itself with its own key. They are still wanted for teams
  that keep the key and the cost on a shared deployment.
- **sandbox-spec.** The two phases, network rules and output formats are
  the SandboxRunner contract, unchanged; this spec adds a Docker
  implementation beside Fargate.
- **The deploy guard.** Unchanged. It packages directories instead of
  files after §8, and its code check moves with them.

## 10. Risks

- **The refactor's size.** About 9,700 lines move behind ports. Mitigated
  by doing it one component at a time, with each component's existing tests
  unchanged and, where they exist, side-by-side runs of old against new (as
  S1 and S2 did over the 90 eval cases).
- **A guarantee lost in translation.** A store that skips a condition
  passes every happy-path test and corrupts review state under concurrency.
  That is what §4's conformance suite is for, including DynamoDB Local, so
  the AWS adapter is checked as hard as the new ones.
- **Drift between runtimes.** Kept out by §2: decisions live in the core.
  An adapter PR that adds an `if` about findings is the warning sign.
- **Local cost.** `--fix` spends the user's money on their key. The prompt
  states the estimate, as `scan.py` does.
- **Code leaving the machine.** `run` sends code to the model provider.
  §5's plain statement is a requirement, not a nicety.

## 11. Decisions

| # | Decision | Outcome |
|---|---|---|
| P1 | Local runtime before any other cloud | Proposed: it serves every user, with no hosting |
| P2 | One `cascadesec_core`, cloud SDKs only in adapters (§2) | Proposed |
| P3 | RecordStore keeps the pk/sk item model; explicit operations replace expression strings (§3) | Proposed: readers and the dashboard unchanged |
| P4 | §4's conformance suite gates every RecordStore adapter, DynamoDB's included | Proposed |
| P5 | Portable hosted on containers, Postgres and S3-compatible storage, not per-cloud native adapters (§7) | Proposed |
| P6 | Vendor the core into each Lambda zip (§8) | Proposed |
| P7 | Local review through `cascadesec serve` and the existing commands, not a second review path (§5) | Proposed |
| P8 | Model provider is configuration: Anthropic API, Bedrock or Vertex (§6) | Proposed |
| P9 | Lower S7 and phase M's priority (§9) | **Open**: depends on whether teams want CI to hold its own model key |

## 12. Build order

Each phase leaves the AWS runtime working and deployed.

1. **Packaging (§8).** Build zips from directories, with mapping-agent
   first (474 lines, the smallest agent). Its tests pass unchanged, and the
   deploy guard's plan shows only the code hash changing.
2. **Ports and the conformance suite.** BlobStore and RecordStore, their AWS
   adapters, and §4's suite passing on DynamoDB Local. Call sites move to
   the ports one component at a time, each behind its existing tests.
3. **The core.** Logic moves out of the handlers into `cascadesec_core`,
   component by component: mapping, then the scanner's write path, then
   remediation, then review. The handlers shrink to adapters.
4. **Local stores.** SQLite and directory adapters pass the same suite.
5. **`cascadesec run`.** In-process Runner, scan and map; then `--fix`, with
   the self-check through the scanner image.
6. **Local review.** `cascadesec serve`, then `cascadesec apply`.
7. **Portable hosted.** Server image, Postgres adapter, OIDC, one recipe on
   one platform.
8. **Native adapters**, only when someone needs one.

Phases 1 to 4 change no behaviour anywhere and can interleave with track
S. Phase 5 is the first thing a user can run.
