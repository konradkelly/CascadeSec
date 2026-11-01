# `cascadesec` CLI — spec

A command-line client that does two jobs. It **scans**, in two modes.
**Local** runs the scanner image on your machine: detection only, with no
account, no model, and no network. **Remote** sends a snapshot to the
pipeline for mapping and, when asked, fixes. That half is what every CI
platform, pre-commit, the MCP server and the VS Code extension run
underneath. It also **reviews** (§10). A signed-in person can list a PR's
findings, read a fix, approve, edit or reject it, and commit, all from the
terminal. That makes it a third interface next to the dashboard and the
GitHub App, and it works against the review API that already exists.

Written before building, 2026-09-25. Part of integrations-spec (phase A for
local mode and pre-commit, phase B for remote). Track R built (2026-10-18);
track S steps 1-6 built (2026-10-23).

**Status, 2026-10-31.** Track R and track S steps 1 to 6 are merged, with
SARIF output (sarif-spec) and the docker hook. The images local mode and
the docker hook pull are published to GHCR, and public since 2026-11-01.
Steps 7 to 9 are past 1.0 (§13).

Revised 2026-10-13. Added review from the terminal (§10), and changed the
authentication order (§11). Humans sign in with the existing Cognito pool
from day one. Machine auth comes only when CI needs the remote scan.
Local mode now covers the apps the sandbox synthesizes (§3.5), and the
NIST and raw-reason work (§3.3).

## 1. Why not `scripts/scan.py`

`scan.py` is an operator tool, and stays one. It needs AWS credentials for
the dev account, reads resource names from `terraform output`, and writes
S3 and Step Functions directly. It can also redraft one stage by invoking a
Lambda (`--stages`). None of that can be handed to a user, and none of it
should be. The CLI talks to the scanner image or to the scan API, and
nothing else.

## 2. Commands

```
cascadesec scan [PATH]                  local, detection only (default)
cascadesec scan [PATH] --remote         upload, scan, map; wait; print
cascadesec scan [PATH] --remote --fix   ...and draft self-checked fixes (costs model calls)
cascadesec wait <scan-id>               wait for a remote scan, then print its findings
cascadesec baseline [PATH]              write .cascadesec-baseline.json from a scan

cascadesec login | logout | whoami      browser sign-in for a human (§11.1)
cascadesec findings <pr-id>             a PR's findings, as the dashboard lists them (§10)
cascadesec show <pr-id> <finding-id>    citation, rationale, fix diff, self-check, history
cascadesec approve|reject <pr-id> <finding-id> [--notes TEXT]
cascadesec edit <pr-id> <finding-id>    correct the fix in $EDITOR, then record it as edited
cascadesec commit <pr-id>               show the commit plan, confirm, commit (committers only)

cascadesec mcp                          stdio MCP server (mcp-server-spec)
cascadesec version                      CLI version and scanner image digest
```

The review commands (the second block) need a signed-in person and nothing
else. They never run the scanner, and they're the same with or without
Docker.

Common flags:

| Flag | Default | Meaning |
|---|---|---|
| `--format` | `table` on a TTY, else `json` | `table`, `json`, `sarif` |
| `--output FILE` | stdout | where `--format` output goes; the table still prints |
| `--fail-on` | `high` | `critical`, `high`, `medium`, `low`, `any`, `none` (§5) |
| `--baseline FILE` | `.cascadesec-baseline.json` if present | findings to ignore (§6) |
| `--project`, `--ref` | from config, then git | form `pr_id = cli-<project>-<ref>` (integrations §3.1) |
| `--changed-only REV` | off | report only findings in files changed since `REV` |
| `--yes` | off | skip the `--fix` cost prompt; required for `--fix` without a TTY |

Configuration comes from `.cascadesec.toml` in the repository (project name,
API URL, fail-on, excluded paths), then environment variables
(`CASCADESEC_TOKEN`, `CASCADESEC_API`), then flags. A token is never read
from the repository file.

## 3. Local mode

### 3.1 Scanner refactor

`iac-scanner/handler.py`'s `handler()` does four things: it downloads a
snapshot, runs three tools, normalises their output, and writes DynamoDB.
Only the first and last are AWS. Split it:

```
scan_directory(work_dir, scan_id) -> {findings, scan_errors}
    _read_admitted_yaml, _run_trivy, _run_checkov, _run_kics,
    _normalize_*, _unparseable_admitted_files        (unchanged)

handler(event, context)                              (Lambda; behaviour unchanged)
    _download_snapshot → scan_directory → _write_findings → metrics

local_main.py  (new, in the image)
    copy admitted files from /src → scan_directory → JSON on stdout
```

`_download_snapshot` also classifies files and records unreadable ARM
templates. That logic moves into a `_admit(path, data)` helper that both
paths call, so "what is a snapshot file" stays one rule. It is already
duplicated three times under an agreement test (ci-integration-spec §4.2);
this does not add a fourth.

The module-level `boto3.client("s3")` and `boto3.resource("dynamodb")`
(handler.py:355) move behind a lazy accessor, so local mode imports the
module without AWS configuration. boto3 itself stays in the image, because
the base image ships it.

**Since 2026-10-10 the scan itself reads S3.** `_cdk_origins` takes
source maps that `_cdk_source_maps` fetches from the PR's scan prefix
during the scan, and `_pulumi_origins` reads the plans' `cascade_pulumi`
sources. So `scan_directory` takes the maps as an argument:
`scan_directory(work_dir, scan_id, cdk_source_maps={})`. The Lambda fetches
them from S3 and local mode builds them (§3.5), and the origin logic stays
in one place. "Lazy clients" alone is no longer enough for this split.

`local_main.py` copies admitted files into `/tmp/scan-<id>` rather than
scanning `/src` in place. This keeps local and Lambda runs on the same
inputs, because tools that walk a directory would otherwise see
`node_modules`, `.terraform/` and whatever else the Lambda never received.

### 3.2 Running it

```
docker run --rm --network none --read-only --tmpfs /tmp \
  -v "<abs PATH>:/src:ro" \
  --entrypoint python ghcr.io/konradkelly/cascadesec-scanner@sha256:<digest> \
  /var/task/local_main.py /src
```

- **`--network none`** is the guarantee that code and results never leave
  the machine. The tools already run offline (Trivy `--skip-check-update`,
  KICS `--disable-full-descriptions`, verified under `--network none` in the
  Dockerfile's KICS note). Local mode enforces this instead of trusting it.
- **Pinned by digest.** The CLI release pins the image digest the Lambda
  was deployed with. `cascadesec version` prints it. Local and pipeline
  results for the same files are the same tools at the same versions, which
  is the property the eval's numbers depend on (corpus/eval/README.md).
- **Published** by `build-image.sh` to GHCR as well as ECR, copied by digest
  (`crane copy`) so both registries hold one manifest **(verify: digest is
  preserved across a registry copy)**. `build-image.sh --ghcr` copies with
  `docker buildx imagetools create` from ECR by digest and fails unless GHCR
  then reports the same one; ECR's digest is already what the Lambda
  resolves (`ResolvedImageUri`).
  **Measured on the first publish, 2026-10-23:** the manifest digest is
  preserved, but `imagetools create` wraps it in a one-entry OCI index, so a
  GHCR *tag* resolves to a different digest than ECR's. The check is
  therefore that GHCR serves ECR's digest byte for byte, and the CLI pins
  that digest (`ghcr.io/konradkelly/cascadesec-scanner@sha256:6d0901b0...`,
  commit 58e0eff), never a tag. The image is public. It contains
  nothing that the Dockerfile and `checks/` don't already publish.
- **No Docker?** The CLI fails with a message that says so. There is no
  fallback to locally installed Trivy or Checkov: a different version fires
  different rules, and the result would silently disagree with the pipeline.

### 3.3 Candidate controls, with no model

Local output includes, per finding, the **candidate** controls from
`corpus/rule_mappings.json`, which ships in the image. These are the
curated candidates mapping-agent picks among, not its choice, and the CLI
labels them `candidates`, never `control`. That gives a local user the
OWASP/CIS context for free, and makes clear that the citation (which
control, and why) needs a remote scan.

The candidates include the NIST 800-53 tail, which is for rules CIS can't
place (2026-10-11). A rule with no candidate at all is labelled the way
the pipeline will label it: `raw`, with the `unmapped_reason` from
`rule_mappings.json`'s `unmapped` section, or `unreviewed` when the rule
isn't there. Local output then predicts which findings a remote scan
leaves raw, and why, using the same function as mapping-agent's
`_unmapped_reason`. That function moves into the shared module (§3.1) so
there's one copy. `cdk` and `pulumi` findings are labelled
**detection-only**, as mapping-agent treats them
(`DETECTION_ONLY_TARGET_TYPES`): a remote scan maps them but never drafts
fixes for them.

### 3.4 Cost of a local scan

Checkov's import is 50–100s cold in Lambda (handler.py's
`SCAN_TIMEOUT_SECONDS` comment), and a local container is cold on every
run. **Measure before promising pre-commit or on-save latency.** If it is
over about 20s on a laptop, the handler's own TODO (import checkov's
Terraform runner in-process) becomes a phase A prerequisite, not a nicety.
The IDE extension's long-lived daemon (ide-extension-spec §3) exists for
the same reason.

**Measured 2026-10-18**, the image run as §3.2 says (`--network none
--read-only --tmpfs /tmp`), cold each time, on Docker Desktop for Windows
with 16 CPUs and 9 GB for the VM:

| Target | Files | Findings | Wall time |
|---|---|---|---|
| one eval case (`s3-no-encryption`) | 1 | 15 | 10.9s |
| argocd-example-apps | 71 | 832 | 9.8s |
| kubernetes-goat | 29 | 591 | 10.6s |
| terragoat `terraform/aws` | 14 | 333 | 17.7s |
| microservices-demo | 112 | 618 | 20.0s |
| terraform-aws-vpc | 83 | 58 | 81.3s |

The 11-second floor is about half container start and mount, half
Checkov (4.5s on one file, mostly its own import; Trivy 0.7s; KICS does
not run without ARM or CloudFormation). terraform-aws-vpc is Checkov's
module expansion, as in Lambda (139-265s there). Importing Checkov's
runner in-process would not lower the floor: a fresh container imports it
on every run either way. So **pre-commit ships as `stages: [pre-push]`**
(D6), with pre-commit opt-in, and the daemon is the latency fix.

Every finding count matches the deployed pipeline's on the same pinned
commits (`corpus/external`, 2026-10-11), and argocd's one scan error is
the same file, so local and remote results agree as §3.2 requires.

### 3.5 Apps that must run before they can be scanned

CDK, Pulumi and Helm reach the scanner only as **output**. In the pipeline,
the sandbox makes that output (sandbox-spec): `cdk synth` for a cloud
assembly, a mocked Pulumi run that `pulumi_plan.py` turns into Terraform
plan JSON, and `helm template` for manifests. The scanner image can do none
of that. It has no Node, no Helm, and no network. And `_admit` drops
`cdk.out/`, as the gateway's `SKIP_DIRS` does, so a developer's own synth
output is skipped too.

**Locally, the threat model is different, and it matters.** The sandbox
exists because a pull request's code is untrusted. On a laptop it's the
developer's own code, and they run `cdk synth` on it all day. So local mode
doesn't need the full Fargate isolation. What it needs is the **same
output format**, so local and remote findings agree.

#### Stage 1: report, don't scan

`local_main.py` detects each app root and lists it as **not scanned
locally**. An app root is a `cdk.json`, a `Pulumi.yaml`, or a `Chart.yaml`
with `--helm` options in `.cascadesec.toml`. These count as `scan_errors`,
so the run exits 3 (§5). The message names the app and the command that
scans it (`--remote`, or a stage 2 flag once built). A CDK repository
can't come back "clean" just because its only IaC was TypeScript.

Exit 3 on every CDK repository would get the gate disabled. So
`.cascadesec.toml` can list apps under `skip_apps`, with a required
`reason`, and the run reports them as skipped by config. That's the same
"visible decision in a diff" as the baseline (§6).

#### Stage 2: Helm locally (`--helm`)

Helm renders offline: dependencies must already be vendored under
`charts/`, and lookups run in Helm's offline mode. That's the sandbox
contract too (sandbox-spec, "Helm rendering"). So local mode can run the
**sandbox image's** `helm template` under `--network none`, with the
values, release, namespace and kube version from `.cascadesec.toml`. It
writes the manifests into the scan copy under `<app>/helm.out/`, as
collect does. Findings point at rendered lines, as remote findings do, and
no fixes are drafted (also as remote). The sandbox image is pinned by
digest next to the scanner's, and both are published to GHCR (§3.2).

#### Stage 3: CDK and Pulumi locally (`--synth`)

This is the bigger job, and its main obstacle isn't trust:

- **The developer's `node_modules` won't run in the container.** Installed
  on Windows or macOS, they carry that platform's native binaries (esbuild,
  which CDK's `NodejsFunction` bundles with, is the common one). The
  sandbox's Linux execute step can't run them. So local synth repeats the
  sandbox's **two phases** as two `docker run`s:
  1. **fetch**: `npm ci --ignore-scripts` from the lockfile, with network
     access to the npm registry, into a Docker volume. No project code
     runs, as in sandbox-spec §4. The lockfile's integrity hashes pin the
     same packages the pipeline's CodeArtifact mirror serves.
  2. **execute**: the synth or mock run under `--network none`, with the
     source read-only.

  This is the one place local mode uses the network, so it's behind an
  explicit `--synth`, and the run prints that it fetched. The volume is
  keyed on the lockfile's hash and reused.
- **Context lookups.** `Vpc.fromLookup` and Pulumi `get*` calls need cloud
  credentials, which neither side has. A lookup that isn't cached in
  `cdk.context.json` fails the synth. A Pulumi lookup without a mock is
  "missing lookup mocks", the sandbox's own error. Either way it's reported,
  as in the pipeline, never guessed.
- **Same output format.** `cdk.py` (the template rewrite and source map)
  and `pulumi_plan.py` (the AWS bridge to plan JSON) are plain Python with
  no AWS calls. They move to the shared module (§3.1), so local mode
  produces byte-for-byte the files collect produces. That's what lets
  `_cdk_origins` turn a finding on `NetSsh9740AB70` into
  `lib/network.ts:8` locally too. Locally the hostile-input checks in
  those modules don't protect anything, but they run anyway: one code
  path, not two.

Stage 3 doesn't add `cdk-resynth`, the fix self-check. Local mode drafts no
fixes.

## 4. Remote mode and the scan API

### 4.1 Routes

New routes on the existing HTTP API, under `/v1`, behind the machine-auth
Lambda authorizer (machine-auth-spec §2). They are served by a new Lambda,
**`scan-api`**, not by review-api. The two roles differ: review-api has no
business presigning uploads or starting executions.

| Route | Permission | Does |
|---|---|---|
| `POST /v1/scans` | `scan` | `{project, ref, remediate}` → `{scan_id, pr_id, upload_url, expires_at}`. Presigned PUT for `uploads/<scan_id>.tar.gz`, content-type and max length fixed in the signature |
| `POST /v1/scans/{scan_id}/start` | `scan`, plus `remediate` when asked | starts the execution (§4.2) |
| `GET /v1/scans/{scan_id}` | `read` | execution status, stage, counts, `scan_errors` |
| `GET /v1/scans/{scan_id}/findings` | `read` | findings (§4.3) |
| `GET /v1/projects/{project}/baseline` | `read` | server-side baseline (§6) |

`scan_id` is a random id recorded as a `SCAN#<scan_id>` item under the
project, holding `pr_id`, the uploader's identity, the execution ARN and
`remediate`. The authorizer's project scope is checked against that item on
every route, so a token for one project cannot read another's scan by
guessing an id.

**Before machine auth exists** (§11.2), these routes sit behind the
existing Cognito JWT authorizer, and only signed-in people call them. There
are no projects yet, so there is no project check. That's the same exposure
the dashboard has today: every reviewer sees every PR. The routes still go
under `/v1` from the start. When machine auth arrives, the server swaps each
route's authorizer, and the paths and the client stay the same.

### 4.2 Starting the execution

The state machine's first `Choice` gains a third branch. `github` input
goes to `fetch`, `upload` input goes to a new **`unpack`** state, and
anything else goes straight to scan, as `scan.py` does today.

`unpack` is `scan-api`'s second entry point, like the gateway's
`fetch`/`report`. It reads the tarball and applies exactly the gateway's
member rules: regular files only, no absolute paths, no `..`, and
`is_snapshot_file`. It enforces the gateway's limits (3,000 files, 50MB
kept), replaces `scans/<pr_id>/`, and deletes the upload. The tar-safety
functions (`read_snapshot`, `repo_path`, `is_snapshot_file`) move from the
gateway into a small shared module, vendored into both zips by the build.
Duplicating path-traversal checks is how one copy gets fixed and the other
doesn't.

Over a limit, the scan fails with a reason. It never runs a partial scan
(ci-integration-spec §4.2, same argument).

Execution name: `cli-<scan_id>`. It's unique, so there's no redelivery to
dedupe. A second start of the same `scan_id` returns 409.

### 4.3 What remote findings contain

The reviewer view the dashboard gets, minus review actions: scanner fields,
`fingerprint`, `control_mappings` with citations, `status`, and for
`fix-proposed` findings the diff and self-check result. Model prose
(`rationale`, `assumptions`) is included **only for a human caller**
(machine-auth-spec §4 identity type `user`). For a CI token it is omitted,
because CI logs are often public (integrations §2.3).

### 4.4 Waiting

The CLI polls `GET /v1/scans/{id}` with backoff (2s, doubling, 15s cap) and
prints each stage as it's reached, like `scan.py`. `--timeout` defaults to
15 min without `--fix` and 60 min with it. On timeout it exits 4 and prints
the `scan_id`, because the execution keeps running and
`cascadesec wait <id>` picks it up. (`findings` takes a PR id, §10. A
remote scan's PR id is `cli-<project>-<ref>`, so its findings can also be
reviewed there.) Nothing on this path waits on a
synchronous Lambda invoke. A remediation run can take many minutes, and a
client-side synchronous invoke that long is the thing that fails, so the
execution runs asynchronously and the CLI only polls.

### 4.5 `--fix`

This requires the token's `remediate` permission. In phase H (§11.1),
there are no permissions yet, so any signed-in person may ask for fixes,
as with `scan.py` today. The cost prompt is the only guard. Interactively, it prompts
with an estimate: mapped findings × one to two model calls. That is the same
cost prompt as `scan.py`. Non-interactively it requires `--yes`. The output
lists verified fixes as diffs. `--apply` writes the **chain tip** of each
file (ci-integration-spec §4.3 step 1) into the working tree, and only after
confirming the root diff applies to the local file. It never commits.

## 5. Exit codes

| Code | Meaning |
|---|---|
| 0 | scan complete; nothing at or above `--fail-on` after baseline and `--changed-only` |
| 1 | scan complete; findings at or above `--fail-on` |
| 2 | usage or configuration error |
| 3 | **scan incomplete**: `scan_errors` non-empty (including an app local mode couldn't run, §3.5), or a limit was exceeded |
| 4 | service error, auth failure, or timeout |

Exit 3 takes precedence over 0 and 1. A clean result with an unparseable
file is not clean (integrations §2.2). `--allow-scan-errors` downgrades 3 to
the 0/1 result and prints the files. It's for repositories where a known
file will never parse, and it's opt-in per run.

**`--fail-on high` by default.** ci-integration-spec D1 keeps the GitHub
check neutral until fix suggestions have earned the right to block. That
argument is about suggestions. Detection is deterministic, and a gate on
it is what every scanner CLI offers. The baseline (§6) is what makes the
default usable on an existing repository.

## 6. Baseline

PugetScope carries 566 findings. A gate that fails on all of them will be
disabled on day one. So:

- `cascadesec baseline` scans and writes `.cascadesec-baseline.json`: the
  fingerprints (integrations §3.2), each with rule, file and severity for
  reading in review, and the scanner image digest.
- `scan` subtracts baselined fingerprints before applying `--fail-on`, and
  reports how many it suppressed. It never reports them silently.
- A baselined finding that stops firing is listed as "fixed; remove from
  baseline". `baseline --prune` removes those.
- If the baseline's image digest differs from the scanner's, the CLI warns.
  New rule versions can fire new findings that aren't regressions.

The file is committed and reviewed like code. Adding to it is a visible
decision in a diff, which suits a project where nothing is silently decided.
The server-side baseline (§4.1) serves the same content per project for
teams that don't want it in the repository. It's phase B, and optional.

`--changed-only REV` is the cheap complement. ~~It reports findings only in
files `git diff --name-only REV` lists.~~ **Revised 2026-10-25:** it reports
the findings a scan of REV's files does not have, matched by fingerprint,
in whichever file they land. Keeping the findings in changed files missed
a change that makes another file vulnerable: a variable's default turned
off in `variables.tf` opens the bucket in `main.tf`, and that push went
through. It also blocked an edit to a file with old findings. Parse errors
and unscanned apps still count only in changed files. REV's files are
exported from git and scanned side by side with the current ones. The
limit: a renamed file's findings read as new, because a fingerprint
includes the path.

## 7. Pre-commit hook

`.pre-commit-hooks.yaml` at the repository root:

```yaml
- id: cascadesec-docker
  name: CascadeSec IaC scan (Docker)
  language: docker_image
  entry: --network none -e PRE_COMMIT_FROM_REF -e PRE_COMMIT_TO_REF ghcr.io/konradkelly/cascadesec-hook@sha256:<digest>
  files: \.(tf|tf\.json|tfvars|tfvars\.json|tofu|tofu\.json|ya?ml|bicep|json|template)$
  pass_filenames: true
  require_serial: true
  stages: [pre-push]
```

- pre-commit passes the changed file names. The hook scans **each directory
  containing one**, not the files alone, because Terraform modules and
  tfvars resolve across a directory. ~~It reports only findings in the
  staged files, after the baseline.~~ **Revised 2026-10-25:** it also scans
  those directories **as they were before the change**, read from git, and
  blocks on the findings the change brought, after the baseline. Before is
  the push's merge base (`PRE_COMMIT_FROM_REF...PRE_COMMIT_TO_REF`, the
  range pre-commit took the files from), or HEAD for a commit. A finding in
  an untracked file is outside the change. With nothing to compare with (a
  first commit, `pre-commit run --all-files`, whose files are not a staged
  change, or git unreadable) it judges the changed files themselves, as it
  used to, and says why. On the system hook the two scans run side by side.
- The docker variant reads history inside the container, so the hook
  image carries git (a 64 MB layer; the scanner image, and so the Lambda,
  goes without it). Its entry passes the
  two refs with `-e`, because `docker run` passes no environment. A
  worktree's `.git` points outside the mount, so there it falls back to
  judging the files, and says so.
- ~~`--network none` cannot be set~~ **It can, measured 2026-10-23.**
  pre-commit appends a `docker_image` hook's `entry` tokens straight after
  its own `docker run --rm -v ...:/src --workdir /src`, so an entry of
  `--network none --entrypoint python <image> -m cascadesec hook` isolates
  the container. A probe hook trying to open a connection got `Network is
  unreachable` with it and connected without it. The docker hook therefore
  has the same guarantee as `cascadesec scan`, not just the tools' offline
  flags.
- ~~Tagged by version, not digest~~ **Pinned by manifest digest**.
  pre-commit's `rev` fixes the hook repository, but a tag inside it can
  still move. **Revised 2026-10-26:** the image is not the scanner's but a
  **hook image** (`cli/Dockerfile`): the scanner image, unchanged, with the
  CLI on top, built `FROM` the digest `scan.py`'s `SCANNER_IMAGE` pins. A
  test holds the Dockerfile's default to `SCANNER_IMAGE`, so both hooks scan
  with the tools the Lambda runs. Kept apart from the scanner image so that
  a change to the hook never rebuilds the image the Lambda runs, and the
  Lambda's ECR scan never reports what only the hook needs. The cost is a
  second package: `build-image.sh --ghcr` builds and pushes
  `cascadesec-hook` on each scanner publish, and it is made public once,
  like the scanner's.
- Latency is §3.4's measurement. If it's over budget, the hook ships as
  `stages: [pre-push]` by default.

A `language: system` variant, `cascadesec` (`entry: cascadesec hook`), is
for users who already have the CLI. It runs the scanner image through
Docker. The hook image's entrypoint is `cascadesec hook` itself, which sees
`CASCADESEC_IN_IMAGE` and scans in-process, so both hooks judge a file with
one copy of the scoping, baseline and verdict.

## 8. Distribution

`cli/` in this repository, with a `pyproject.toml` and the entry point
`cascadesec`, published to PyPI and installed with `pipx`. It has one
required runtime dependency, `keyring`, which keeps the refresh token in
the OS credential store (Windows Credential Manager, macOS Keychain, Secret
Service), never in a dotfile (§11.1). The `mcp` SDK is an optional extra
for `cascadesec mcp`. HTTP uses urllib, like the gateway. Windows is
supported and tested in CI: tarballs are built with forward-slash member
names, and Docker volume paths are passed absolute.

## 9. Risks

- **Tarball as an attack surface.** Handled by sharing the gateway's code
  (§4.2), not rewriting it. That shared module gets its own tests, including
  zip-slip and symlink members.
- **Presigned URL misuse.** The URL is scoped to one key, has a fixed
  content-type and length cap, and expires in 10 minutes. `unpack` rejects
  an upload over the limit even if a client got around the cap.
- **Cost from a leaked token.** `remediate` is a separate permission, off by
  default for new tokens (machine-auth-spec §4). A CI token that only needs
  detection and mapping can't spend on fixes.

## 10. Review from the terminal

The dashboard's review work, without a browser tab. Every command calls a
review-api route that already exists ([api_gateway.tf](../terraform/api_gateway.tf)),
behind the Cognito JWT authorizer that already guards them. **No new server
code**, except the `cli-interactive` client (§11.1). The CLI shows what the
API returns and decides nothing itself. Prerequisites, statuses and the
commit check stay in review-api, so the dashboard and the CLI can't
disagree about a rule.

| Command | Route(s) | Notes |
|---|---|---|
| `findings <pr>` | `GET /prs/{pr}/findings` | Table by default, `--format json`. Grouped like the dashboard: fixes to review, open, settled (resolved and superseded). Raw findings are listed apart and grouped by `unmapped_reason`, as on the dashboard since `deada0b`. Filters: `--status`, `--severity`, `--file` |
| `show <pr> <id>` | `GET .../{id}`, `.../events`; the PR's findings when the fix has prerequisites or the id is a prefix | Rule, file and line. Each control with its citation. The fix's diff, `proposed_fix.diff` as the dashboard shows it (colored on a TTY; `--agent-diff` for the agent's original after an edit). Not `.../content`: that route returns the corrected file but not the base it was drafted on, so it cannot make a diff. Self-check result, rationale and assumptions. Prerequisites, then the event history. The caller is always a person here, so model prose is shown (§4.3) |
| `approve <pr> <id>` | `POST .../review` `{action: approved, notes}` | |
| `reject <pr> <id>` | same, `rejected` | Never blocked, as in the API |
| `edit <pr> <id>` | `GET .../content`, then `POST .../review` `{action: edited, edited_content, notes}` | Below |
| `commit <pr>` | `GET /prs/{pr}/commit-plan`, then `POST /prs/{pr}/commits`, then poll `GET .../commits/{request_id}` | Below |

**`edit`.** It fetches the fix's current corrected file and writes it to a
temp file with the same extension, so the editor highlights it. It then
opens `$VISUAL` or `$EDITOR` (Notepad on Windows if neither is set). If you
save without changes, it stops. Otherwise it shows the diff against the
agent's version and asks for confirmation before sending the **full file**.
review-api accepts only `edited_content`, not a diff. `--file PATH` sends a
prepared file without an editor, for scripting your own reviews.

**Things the API reports, printed rather than swallowed:**

- A 409 on approve or edit lists the unmet prerequisites. The CLI prints
  them with the `show` command for each.
- `reopened_dependents` on an edit or reject is printed as "this reopened:
  …". The response names them so the reviewer who caused the cascade learns
  about it immediately, and the CLI keeps that.
- `commit` prints the plan the dashboard's commit panel shows: per file,
  the head-to-tip diff, the files held back and why, and any unverified
  links. It sends `confirm` built **from that printed plan**: file, tip,
  `content_sha256`. If the plan moved in between, review-api refuses, and
  the CLI says to look at the plan again. It never re-fetches and retries
  on its own, because that would commit something nobody looked at.
  `can_commit: false` is shown before any prompt, not after a 403. `--yes`
  skips the confirmation. Without a TTY, `commit` needs `--yes` **and**
  `--expect-sha FILE=SHA ...`, so a script can only confirm content it was
  told about.

**Exit codes** for these commands: 0 done, 1 refused by the API with a
reason (prerequisites, a moved plan, not a committer), 2 usage, 4 service
or auth error.

**Finding a PR id.** There is no route that lists PRs. The dashboard gets
the id from its URL. For `cli-` PRs, the CLI derives it like `scan` does
(`--project`, `--ref`, §2). `gh-` ids use the **numeric** repository id
(`gh-<repo_id>-<pr>`, webhook-receiver's `pr_id`), which nobody knows by
heart. So the CLI also accepts `owner/repo#123`, and resolves the id with
`GET /repos/{owner}/{repo}` on GitHub. That call is anonymous for a public
repository, and for a private one it uses `GITHUB_TOKEN` or `gh auth token`
when present. A
`GET /prs` listing (`cascadesec prs`) would be review-api's first route
that spans PRs, and it's D8.

## 11. Authentication, in two phases

Humans and machines authenticate differently (machine-auth-spec §3), and the
CLI needs the human half first. Review must be a person: machines never
review (machine-auth-spec §5). Phase H ships everything a person does,
using only the Cognito pool that already exists. Phase M adds the machine
callers when CI needs the remote scan.

### 11.1 Phase H: people, through Cognito

- **`cli-interactive` public client** in [cognito.tf](../terraform/cognito.tf):
  code flow, no secret (so PKCE is required), and loopback callbacks
  `http://localhost:<port>/callback` on three fixed ports. Cognito accepts
  plain `http` only for `http://localhost`, and callback URLs must be
  pre-registered absolute URIs. Measured against the deployed client on
  2026-10-14: registered ports reach the login page. An unregistered port
  (47899), `127.0.0.1` on a registered port, and a URL with no port each get
  Cognito's error page. So the port is matched exactly, with no wildcard,
  which RFC 8252 §7.3's "any port" rule would have avoided. The listener binds both `127.0.0.1` and `::1`, because
  `localhost` can resolve to either. If all three ports are busy, `login`
  falls back to `--no-browser`. Its id is added to the JWT authorizer's
  `audience` next to the dashboard and test `cli` clients. That's the whole
  server change.
- **`login`** opens the Hosted UI, receives the code on the loopback
  listener, and exchanges it with the PKCE verifier. On a machine with no
  browser (SSH), `--no-browser` prints the URL. You open it elsewhere, and
  then paste back the URL the browser was redirected to (it fails to load,
  but the code is in its query string). The verifier never leaves the CLI.
- **Tokens.** The refresh token goes in the keyring (§8), and so does the
  current ID token. Each command is a new process, so a token kept only in
  memory would mean one refresh per command. The ID token is refreshed
  within two minutes of expiry. The session is stored in chunks, because
  Windows Credential Manager refuses a secret over 1,280 characters and a
  Cognito refresh token is longer (measured 2026-10-13). The pool's settings apply
  unchanged: a 60-minute ID token and a **1-day refresh token**, so a
  person signs in about once a day. That's fine for a person. It's also why
  phase H doesn't serve CI.
- **The ID token is the credential, not the access token**, as with the
  dashboard. The JWT authorizer checks `aud`, and only the ID token carries
  it.
- **Committers.** `cognito:groups` is issued at sign-in. A person newly
  added to `committers` runs `login` again. `whoami` prints the email,
  groups and token expiry, so this is visible.

What phase H **does not** have, and accepts on purpose:

- **No tenancy.** Every signed-in person sees every PR, as on the dashboard
  today. That's acceptable while accounts are admin-created and few.
- **No CI.** Putting a person's password in a CI secret to drive
  `admin-initiate-auth` is the pattern this design exists to avoid. The CLI
  doesn't support it, and the test `cli` client stays test-only.
- **Revocation is coarse.** Disabling a user stops refreshes. An ID token
  already issued stays valid for up to 60 minutes.

Remote scan by a person (§4) also works in phase H, with the `/v1` routes
on the JWT authorizer (§4.1).

### 11.2 Phase M: machines, through the Lambda authorizer

machine-auth-spec, as written: projects and permissions, `csk_` tokens, CI
OIDC federation, and the `api-authorizer` Lambda, which also accepts the
same Cognito ID tokens. The CLI changes very little. It reads
`CASCADESEC_TOKEN` when set, sends it as the bearer, and drops model prose
for non-human callers (§4.3). `login` is untouched. On the server, the
`/v1` routes move to the Lambda authorizer. The review routes never do
(machine-auth-spec §5).

**What triggers phase M:** the first time a credential has to live
somewhere other than a person's keyring, meaning a CI job or a shared
runner. Until then, the authorizer is security-critical code with nothing
to protect yet.

## 12. Decisions

| # | Decision | Outcome |
|---|---|---|
| D1 | Local mode through the pinned image, no native-tool fallback (§3.2) | Proposed |
| D2 | New `scan-api` Lambda rather than routes on review-api (§4.1) | Proposed |
| D3 | Tarball upload and an `unpack` state, rather than per-file presigned URLs (§4.2) | Proposed: reuses the gateway's safety code, one request |
| D4 | `--fail-on high` default (§5) | Proposed |
| D5 | Baseline committed to the repository, with a server copy optional (§6) | Proposed |
| D6 | Pre-commit on commit or on push | Proposed 2026-10-18: on push by default, commit opt-in; §3.4 measured 10-20s typical, 81s worst |
| D7 | Phase H (Cognito, people only) before phase M (machine auth) (§11) | Proposed 2026-10-13: no auth code to write until there's a credential to protect |
| D8 | `GET /prs` listing route for `cascadesec prs` (§10) | **Open**: useful, but it's review-api's first cross-PR read, and with no tenancy it lists every PR to everyone |
| D9 | Review commands in the CLI at all (§10) | Proposed 2026-10-13: thin over existing routes; the API keeps every rule |
| D10 | CDK, Pulumi and Helm locally: report (stage 1), then Helm (stage 2), then synth (stage 3) (§3.5) | Proposed 2026-10-13: stage 1 ships with local mode. Stages 2 and 3 wait for demand |
| D11 | Local synth fetches from public npm behind an explicit `--synth`, rather than reusing the host's `node_modules` (§3.5) | Proposed: a host's native binaries don't run in a Linux container |

## 13. Build order

Two tracks that don't depend on each other. **R** (review) needs no scanner
work. **S** (scan) needs no auth until remote mode.

**For 1.0** (`docs/completion.md`), track R and steps 1 to 6 of track S are
complete. Steps 7 to 9 are past 1.0. What the CLI still gains before 1.0
comes from the portable runtime instead: `cascadesec run`, `--fix`,
`serve` and `apply` (portable-runtime-spec §5).

**Track R: review, phase H**

1. `cli/` skeleton: `pyproject.toml`, config, `--format`, exit codes.
2. `cli-interactive` client and authorizer audience (Terraform), then
   `login`, `logout` and `whoami` with the keyring.
3. `findings` and `show`. **Built 2026-10-17**, with `owner/repo#123` and PR
   URLs resolved to `gh-<repo_id>-<pr>`, and a finding id accepted by unique
   prefix.
4. `approve`, `reject` and `edit`. **Built 2026-10-18.** A 409 prints each
   unmet prerequisite in the server's terms, which are finer than the
   dashboard's (`undecided`, `rejected` and `reopened`, where the page can
   only say "not accepted yet"), and a 400 such as "nothing to record" exits
   1 like any refusal. `edit` sends bytes as saved, so line endings survive,
   and keeps the file on disk when anything after the editor fails.
5. `commit`, against the testbed PR, with a committer and a non-committer
   account. **Built 2026-10-18.** Every refusal the plan already implies --
   write-back not deployed, not a committer, a request in flight -- is
   reported after the plan is printed and before any prompt. A held request
   exits 1 with each file's reason, a failed one 4, and a wait that times out
   4 with the request id, since the request keeps running.

**Track S: scan**

1. Scanner refactor (§3.1): `scan_directory` with source maps passed in,
   `_admit`, lazy clients, and `_unmapped_reason` in the shared module.
   Existing iac-scanner and mapping-agent tests pass unchanged, and the
   eval's recall is identical. **Built 2026-10-18**, except `_unmapped_reason`,
   which moves in step 4 with its first caller: mapping-agent deploys as a
   single-file zip, so a shared module changes its packaging, and nothing
   needs it before local output does. Verified beyond recall: the old and
   new handler, run side by side in the scanner image under `--network
   none`, gave identical responses on all 90 eval cases (517 findings,
   compared field by field apart from wall-clock stamps).
2. Fingerprint on `_build_finding` (integrations §3.2). **Built 2026-10-18**,
   with two departures, both from measuring the tools' output. It is
   computed once, at the end of `scan_directory` rather than in
   `_build_finding`, because the CDK and Pulumi origins rewrite `resource`
   after the build, and it is anchored on that rewritten value. And a
   `resource` that is a position (Trivy names a CloudFormation resource
   `template.yaml:5-8`, 30 of its 38 eval findings) or a placeholder (KICS's
   `n/a`) falls back to the flagged line's text, since anchoring on either
   would move with the lines. On the 90 eval cases, with a line inserted at
   the top of every file: 514 of 517 `finding_id`s changed, and all 517
   fingerprints held. Four pairs share one, each the documented limit (one
   rule, one resource, two lines of it).
3. `local_main.py` with app detection (§3.5 stage 1), then GHCR
   publishing, then the §3.4 measurement. **Built 2026-10-18**, except the
   first GHCR publish, which needs `write:packages` and makes a public
   package. App roots are reported in their own `unscanned_apps` field
   rather than mixed into `scan_errors`, which lists files; the CLI exits 3
   for either.
4. CLI local mode: table, json, and exit codes, with candidates and raw
   reasons (§3.3). SARIF comes with sarif-spec. **Built 2026-10-18**, and
   SARIF on 2026-10-31 (`--format sarif`, uploaded to the testbed:
   sarif-spec §5). The
   corpus ships in the image through a named build context, so candidates
   come from the corpus version the image was built from. §3.3's "one copy"
   of `_unmapped_reason` became an agreement-tested copy instead: mapping-
   agent's is now a pure function, and `corpus/test_corpus.py` holds it,
   `_candidates_for` and the two constants identical to `local_main.py`'s
   until the core is shared (portable-runtime-spec §8). On terragoat: 251 of
   333 findings with candidates, 55 raw no-control and 27 hygiene, which
   matches the pipeline's own counts after the 2026-10-11 triage.
5. Baseline, `--changed-only` and `skip_apps`. **Built 2026-10-22.** Live on
   a copy of terragoat: with every line shifted down by one and a new public
   bucket added, all 333 baselined findings stayed suppressed and only the
   bucket's 17 were reported. Three choices the spec left open:
   `--changed-only` scopes parse errors and unscanned apps as well as
   findings, so a file nobody touched cannot make a change incomplete; the
   baseline's "fixed" list is taken from the full scan, because a finding
   left out by `--changed-only` has not been fixed; and `skip_apps` is read
   only from the repository's file, resolved against that file's directory,
   with a reason required.
6. Pre-commit hook. **Built 2026-10-23**, the `language: system` variant
   first: `cascadesec hook`, which runs the installed CLI and so the pinned
   image under `--network none`, on push by default (D6), `require_serial`
   so one scan covers every changed file. The `docker_image` variant needs
   the CLI's baseline and exit logic inside the image, so the two hooks
   cannot judge a file differently: the hook image (`cli/Dockerfile`, the
   scanner image with the CLI on top) carries it since 2026-10-26. Both
   images were first published on 2026-10-29, from b85206d, and the
   `cascadesec-docker` manifest entry came with them, pinned to the hook
   image's digest. Taken through the manifest as a user takes it (a
   `repo:` at a commit, the image pulled from GHCR by digest), it let a
   comment fixed in `s3.tf` through, blocked a variable turned off for the
   4 HIGH findings in `main.tf`, and skipped a Markdown push.
   Live through a
   real `git push` (pre-commit 4.7.0) to a scratch remote: a commit adding a
   public bucket to baselined terragoat was blocked in 14 seconds, judged
   on `s3.tf` alone (17 findings, 65 baselined, 268 elsewhere left out),
   and a push touching only a Markdown file went through with the hook
   skipped. **Revised 2026-10-25:** judged against the version before the
   change (§7). Through pre-commit 4.7.0 and `git push`, both variants, on
   terragoat plus a bucket that a variable guards: a comment fixed in
   `s3.tf` went through (blocked on 24 old HIGH findings before), a variable
   turned off was blocked for 4 HIGH findings in the untouched `main.tf`
   (let through before), a new public bucket was blocked, and the two
   variants agreed on all four pushes. The system hook took 7.3-8.1s and
   the docker hook, which scans in turn, 11.3-13.1s.
7. `scan-api` and `unpack` under `/v1` on the JWT authorizer (phase H).
   Then remote mode, `--fix` and `--apply` for a signed-in person.
   **Deferred 2026-10-31:** portable-runtime-spec P9 was accepted, so its
   phases come first, and a CI job runs the pipeline itself with its own
   key.
8. Phase M (machine-auth-spec build order), when CI needs step 7.
9. When asked for: `--helm` (§3.5 stage 2), once the sandbox image's Helm
   rendering is deployed. Then `--synth` (stage 3), with `cdk.py` and
   `pulumi_plan.py` moved to the shared module first, and sandbox-dispatch's
   tests passing unchanged.
