# Sandbox — spec (draft)

Somewhere to run code from a pull request: a CDK app, a Pulumi program, a
test suite. Until now CascadeSec has only ever *read* its input.

Written before building, on 2026-10-08. Three specs already need this and
each declined to specify it on its own: `docs/multi-iac-spec.md` §7.2 (CDK
and Pulumi), `docs/dependency-safety-spec.md` §5 (the test-suite gate), and
any future SAST remediation. That spec's open decision -- CodeBuild,
Fargate or a container Lambda -- is answered in §3. Nothing here has been
measured on AWS. Each claim that needs measuring says so, and §9 makes
measuring the containment the first thing built.

## 1. What it is for, and what it is not

| Consumer | Runs | Emits | Network after install |
|---|---|---|---|
| CDK | the app as `cdk synth` runs it, without the CLI, bundling off (§9 step 2) | templates and `<Stack>.metadata.json` | none (lookups come from a committed `cdk.context.json`) |
| Pulumi | the program under the SDK's mocks (multi-iac §7.2 b) | `resources.json`: inputs and creation sites | none |
| Dependency test gate | the suite, before and after the bump | pass/fail per test, and the logs | none; a suite that needs a database fails, and the gate reports that it could not be evaluated |

**Not for:**
- **Scanning.** The scanners stay in `iac-scanner`, where they read files.
  The sandbox produces files for them to read; it never scans and never
  decides (§7).
- **Helm.** Rendering a chart runs no user code. Its blocker is the
  single-file self-check, which needs no sandbox.
- **Anything that needs cloud credentials.** A CDK lookup without a cached
  context, or `pulumi preview` against real state, is reported as needing
  what is missing. Supplying credentials is not an option this spec offers.

## 2. Threat model

The input is hostile. A pull request can carry any code, and installing its
dependencies pulls in code from whoever published them. Inside the
sandbox, assume the code will:

- read everything in the container, including its environment and anything
  reachable on the network, such as metadata and credential endpoints;
- try to reach the internet, directly or over DNS;
- use all the CPU, memory, disk and time it is given;
- try to persist into the next run;
- write output designed to attack whatever reads it: oversized files,
  archive paths that climb out of their directory, malformed JSON.

What must hold however it behaves:

1. **No AWS credentials exist in the container.** Not scoped down, absent
   (§3).
2. **No route out.** Packages come only from a mirror (§5), and only in a
   phase that runs no user code (§4).
3. **Every run starts clean.** Nothing survives from one task to the next.
4. **Output is data.** It is read by code that expects it to be hostile
   (§6).

**One thing it cannot hold.** A program can tell it is in the sandbox and
emit something different there -- a clean template under synth, a green
suite under test. The isolation protects the account. It cannot make a
program honest about itself. This is a real difference from Terraform,
where the file is what gets deployed. The mistakes this project catches are
honest ones, and against those it makes no difference. Against a PR author
hiding a misconfiguration on purpose it is a hole, and §8's fork rule exists
partly because of it.

## 3. Platform: one-shot Fargate tasks with no task role

| | Credentials visible to the code | Fresh per run | Egress control | Step Functions |
|---|---|---|---|---|
| **Fargate** | **none** without a task role | yes, one task per run | security groups, VPC endpoints | `ecs:runTask.sync` |
| CodeBuild | the service role, through the container credentials endpoint | yes | VPC mode | `codebuild:startBuild.sync` |
| Container Lambda | the execution role, as environment variables | no; warm environments are reused | VPC mode | `lambda:invoke` |

The first column decides it. A CodeBuild build and a Lambda function both
always have a role, and the code they run can read its credentials. Scoping
the role down still leaves a credential in hostile hands. Writing to
another job's output prefix, for one, cannot be ruled out by IAM without
per-run session policies, which neither service has.

A Fargate task can run with no task role at all. Then no credentials
endpoint exists in the container and no AWS credentials exist anywhere in
it. The *execution* role, which pulls the image and ships logs, is used by
the Fargate agent and is never exposed to the task. Input and output move
over presigned S3 URLs (§6), so the code never needs to authenticate to
anything. Each task runs in its own isolation boundary and shares no kernel
with any other, and a task is never reused.

`iacposture-spec.md` §4.3 declined Fargate for the pipeline, on cold start
and the cost of a persistent worker. Neither carries over. This is one task
per run, not a worker. The cold start is real (§7) and is the price of a
clean environment.

## 4. Two tasks per run: fetch, then execute

A security group cannot change during a task, and Fargate tasks cannot
rewrite their own iptables. So "egress during install, none after" becomes
two tasks with two security groups:

1. **Fetch.** Installs dependencies from the lockfile, with egress only to
   the CodeArtifact endpoints (§5). It must run **no user code**, so:
   - npm installs with `--ignore-scripts`, which skips lifecycle scripts in
     the dependency tree *and* in the project itself.
   - Python installs **wheels only** (`--only-binary=:all:`). Building an
     sdist runs its `setup.py`, which is code execution in a task that has
     egress. A dependency with no wheel fails the fetch, and the reason is
     reported. This is the Python equivalent of `--ignore-scripts`, not a
     restriction peculiar to this project.
   - The output is a tarball of the installed tree, written to S3.
2. **Execute.** Unpacks the snapshot and the installed tree, then runs the
   job. Its security group allows only what the Fargate agent needs to
   start the task (§5), and the code has no credentials to use those
   endpoints with.

**Measure before building on it:** whether CDK and Pulumi apps install and
synthesize with `--ignore-scripts`. The multi-iac probes installed *with*
scripts. `esbuild` now ships its binary as an optional dependency rather
than through a postinstall step, so it should be fine, but nothing has
tested it. A project whose synth needs a postinstall step is reported as
unsupported. It is never given scripts.

## 5. The network: the project's first VPC

There is no VPC today; every function runs outside one. The sandbox's needs
are small:

- **One private subnet in one AZ.** No internet gateway, no NAT.
- **Endpoints.**
  - S3 gateway (free). Its endpoint policy admits only the sandbox bucket,
    so a presigned URL to any other bucket goes nowhere.
  - Interface endpoints for `ecr.api`, `ecr.dkr` and `logs`, which the
    Fargate agent needs to pull the image and ship logs. Image layers come
    over the S3 gateway.
  - Interface endpoints for CodeArtifact (`codeartifact.api`,
    `codeartifact.repositories`), which only the fetch group can reach.
- **DNS.** The VPC resolver resolves public names, and a lookup is an
  outbound channel even when nothing else is. Route 53 Resolver DNS
  Firewall with an allow-list of the endpoint names, and block everything
  else, closes it. Cheap at this volume, but its own decision (§10).
- **CodeArtifact** with external connections to npmjs and PyPI. It is the
  only registry the fetch task can reach. It also leaves a record of every
  package any run fetched, which the dependency gate can use.

**Cost.** Five interface endpoints in one AZ, at roughly $7 a month each,
is about $36 a month before data. That is a new fixed cost and, unlike
everything else in the account, it is charged while idle. Fargate itself is
billed per task-second and is small next to it. The endpoints are the
number to accept or decline (§10).

## 6. The contract

A small Lambda, `sandbox-dispatch`, prepares each run. Step Functions
cannot presign a URL.

**In:** `{pr_id, run_id, kind, workdir, snapshot_key}`, where `kind` is one
of `cdk-synth`, `pulumi-mock`, `test-suite`. Dispatch presigns a GET for the
snapshot tarball and the installed tree, and a PUT for exactly two
objects: `sandbox/<run_id>/output.tgz` and `sandbox/<run_id>/result.json`.
It returns them as container overrides for the task. Each URL expires with
the task's timeout.

*Amended 2026-10-09.* The URLs no longer go in the overrides. They go in a
per-phase **manifest** (`runs/<run_id>/<phase>/manifest.json`), and the
task's environment holds only the run id, the kind, and a presigned GET for
its manifest. There were two reasons. ECS caps container overrides at 8192
characters, and three URLs plus a CodeArtifact token measured 7363 on the
first deployed run, before the snapshot and dependency URLs this section
promises. And the overrides are shown in full in the execution's history
and the task's description, so every credential sat in plain view there.
Now only the manifest's URL does, and it expires with the rest.

**The job itself is chosen by the image, not by the input.** There is one
image per runtime (`node22`, `python312`), pinned by digest. Each image
carries the harnesses: the CDK runner, the Pulumi mock harness from the
probe, and a test runner. `kind` selects among them. The pull request
supplies files, never a command line -- with one exception found in
building CDK: `cdk.json`'s `app` is the PR's command, run inside the
execute task like the code it starts (§9 step 2).

**Inside:** a non-root user, a read-only root filesystem, and a writable
scratch volume. Resource limits come from the task size and from a
`TimeoutSeconds` on the state that starts the task.

**Out:** `result.json` (`{exit_code, duration_ms, kind, truncated: bool,
log_tail}`) and `output.tgz` (the job's files). Both are hostile:

- Read with hard caps on compressed size, uncompressed size and file count.
- Unpacked under the rules `github-gateway`'s `read_snapshot` and
  `repo_path` already apply to GitHub tarballs: stream, never extract to
  disk; skip links and devices; refuse any name that is absolute or has
  a `..` or `.` component, rather than normalising it. Those rules carry
  over, but not the function: it strips GitHub's top-level directory and
  keeps only scanner files.
- **Turned into findings outside the sandbox.** The Pulumi-to-plan
  converter and the CDK source mapping (multi-iac §7.2) run on the trusted
  side, over `resources.json` and the metadata, as parsers of untrusted
  data. They do not run inside the task, where the program could rewrite
  their output.

## 7. Orchestration: Step Functions waits, Lambda never does

Lambda never waits on a task. A run takes a cold start plus the job: tens
of seconds to start, by AWS's own figures, and unmeasured here. A Lambda
holding a synchronous call open for that is what the long-invoke rule
already forbids. Step Functions' `ecs:runTask.sync` waits without paying for
it.

- **Detection.** For a target that needs execution, a `Synthesize` branch
  before `Scan` runs Dispatch → Fetch → Execute. The output's templates or
  plan land in the scan prefix like any snapshot file.
- **Remediation.** The per-file loop already passes a continuation token
  between `RemediateFile` and itself. A self-check that needs the sandbox
  becomes a yield. The handler returns the token with a `sandbox` request
  (the patched snapshot key). A new `Choice` in the `Map`'s
  `ItemProcessor` routes it through Dispatch → Execute, and the next
  `RemediateFile` gets the output key and rescans. The fetch is reused: a
  fix to source does not change the lockfile. A fix that does change it is
  a dependency bump, and that gate fetches again.
- **Dependency tests.** Two Execute runs, before and after the bump, over
  two fetches.

**Latency is the cost to watch.** A CDK file with eight findings is eight
round trips, each paying a cold start. The first build runs one task per
self-check and measures. A warm worker per pull request -- one program, one
author, so reuse within it does not cross a trust boundary -- is the
optimisation if the measurement calls for it. It is not built first.

Whether stopping or timing out a `.sync` state also stops its task is
documented behaviour to verify, not assume. An orphaned task with no
credentials and no network is harmless but costs money, and the same
leak-test task (§9) checks this too.

## 8. Who may trigger execution

Today any pull request on an installed repository starts a scan, and a
scan only reads. Once some targets execute, that is no longer free to
allow. On a public repository anyone can open a pull request, and doing so
would run their code in this account -- contained, but still a cost and a
target.

**Rule:** execution runs for pull requests whose head is in the same
repository. A pull request **from a fork** is scanned as before, and its
executable targets are reported as *needs approval* until someone with
write access approves. This is the line GitHub Actions draws for fork
workflows, and it is the one maintainers already expect. The approval
mechanism is the same shape as **Commit fixes**: a check-run action
restricted to writers. That restriction already exists in
`github-committer` (`COMMIT_PERMISSIONS`, checked against the
collaborator-permission endpoint), and the approval reuses it.

This also bounds §2's hole. A program that lies to the sandbox comes from
someone the repository already trusts to push to it.

## 9. Order

1. **Containment, proven before anything uses it.** The VPC, endpoints,
   CodeArtifact, both task definitions, and a *leak test*: a job that tries
   every way out and must fail at each:
   - reach the internet by IP and by name, and resolve an external name;
   - read `169.254.170.2` and `169.254.169.254`;
   - find any `AWS_*` variable;
   - PUT to a presigned URL for another run's key, and to another bucket;
   - outlive its timeout.

   Its result is asserted, not read. It runs on every change to the sandbox
   Terraform or images, the way the eval runs on scanner changes. Nothing
   below starts until it passes.

   **Built 2026-10-09**: `terraform/sandbox/` (its own root and state),
   `sandbox/image/`, `lambda/sandbox-dispatch/`, and `scripts/sandbox.py`
   (`up`, `down`, `leak-test`). The leak test is graded on the trusted side
   by `lambda/sandbox-dispatch/leak.py`, not by the runner, which shares a
   container with what it tests. Each way out comes with a *control*,
   something that must still work, so a sandbox whose network is simply
   broken fails rather than passes. Building it corrected the spec in four
   places:

   - **The fetch task does hold one credential** (§3, §4): a CodeArtifact
     bearer token. Without credentials it could not read the mirror.
     Dispatch mints it for fifteen minutes, with the dispatch role's
     CodeArtifact rights, which are read-only on the two mirrors. No user
     code runs in that task, and the execute task never receives the
     token. "No AWS credentials in the container" still holds for both
     tasks; this is a narrower credential, said plainly rather than left
     to be found.
   - **The S3 endpoint policy admits two AWS-owned buckets** besides the
     sandbox's own (§5): ECR serves image layers from
     `prod-<region>-starport-layer-bucket`, and CodeArtifact serves package
     assets from its own per-region bucket. Both are read-only grants on
     AWS's buckets. Without the first, no task can start.
   - **A run's tasks are found by ECS task group, not `StartedBy`** (§7).
     Step Functions' ECS integration rejects `StartedBy`. The reap step
     lists the cluster's running tasks and stops those in the run's group.
   - **DNS Firewall stores names fully qualified.** `logs.<region>.amazonaws.com.`
     with the trailing dot. Written without it, every plan shows a diff.

   The first deployed run then found two more, before any task started.
   Step Functions takes every ECS parameter in PascalCase, including the
   `Name`/`Value` of environment entries that ECS's own API spells
   lowercase. And the overrides were close to ECS's size cap, which moved
   the URLs into a manifest (§6, amended).

   **First leak test, 2026-10-10: 40 of 42 checks passed, and the two
   failures were real.** Every credential, internet, S3, CodeArtifact and
   filesystem check passed in both tasks, with every control working:
   - the ECS credentials endpoint answered 400;
   - a valid presigned URL for the canary bucket got 403 from the endpoint
     policy;
   - unauthenticated ECR answered 401;
   - execute could not reach CodeArtifact, while fetch read metadata and
     downloaded a tarball through it.

   That last control proved the endpoint policy's CodeArtifact assets
   bucket. The sleep run settled §7's open question: **Step Functions
   stops a task when its `.sync` state times out**, and the reap step
   found nothing left. Reap stays anyway, since it costs one call.

   The failure was DNS. `example.com` resolved, in both tasks, because the
   firewall was not attached (§10). It also exposed a flaw in the test
   itself. The "never-seen name" was under `example.org`, which resolves
   nowhere, so it failed with or without a firewall and passed a check it
   could not fail. It is now a name that resolves publicly by construction
   (`<run>-<phase>.127.0.0.1.nip.io`, a wildcard DNS service), and
   `collect` resolves both names from outside the VPC. A DNS check passes
   only if its name resolves outside and fails inside. Otherwise it is
   inconclusive, and it fails.

   **Second leak test, same day: no task could start.** With the firewall
   attached, it refused names on its own allow-list. The reason is that
   DNS Firewall, by default, also judges every name a lookup is redirected
   to. Every allowed name redirects: an endpoint's private DNS name to
   `vpce-….vpce.amazonaws.com`, an S3 name to S3's internal names. So ECR
   auth and the image-layer bucket were both "no such host". The allow
   rule now trusts redirection (`TRUST_REDIRECTION_DOMAIN`). That is safe
   because every allowed name is AWS's, so only AWS decides where it
   points. The same run showed the timeout check could pass a task that
   never started, since one still pulling its image when the clock runs
   out times out just the same. It now also requires the task to have
   been running.

   **Third leak test, 2026-10-10: passed.** 42 of 42 checks, fetch and
   execute, and all three timeout checks. Both DNS names failed inside
   the sandbox and resolved outside it, so the firewall is what stopped
   them, and HTTPS by name now fails at DNS before it can try to
   connect. Every control held: the endpoints resolve, the run writes its
   own objects, fetch reads the mirror, and `/work` and `/tmp` are
   writable. **Step 1 is done; step 2 may start.** The test reruns on
   every change to `terraform/sandbox/` or `sandbox/image/`.
2. **CDK detection.** Synth in the sandbox, templates into the scan,
   findings mapped to source lines. CDK first because its output is already
   a target type (multi-iac §9).

   **Built 2026-10-10, measured locally; not yet run on AWS.** A pull
   request with a `cdk.json` now goes through the sandbox and comes back
   as findings on its TypeScript:

   - **github-gateway** finds every directory holding a `cdk.json` while
     the snapshot streams, and packs the repository into
     `projects/<pr_id>/<sha>.tgz` under the snapshot's own path rules
     (`SKIP_DIRS`, regular files, refused names). An app is run only if the
     deployment has `cdk_synthesis` on, the PR is not from a fork (§8), it
     has a `package.json` and a `package-lock.json`, and it is among the
     first five. Every other app is reported on the check run with the
     reason.
   - **The pipeline** gains `Synthesize` before `Scan`: a Map over the
     apps, each one a `sandbox-run` execution (`startExecution.sync:2`).
     Every outcome is a result, not a failed execution, so a broken app
     never stops the rest of the repository being scanned.
   - **The `cdk-synth` harness** (`sandbox/image/cdk.mjs`). Fetch extracts
     only the two npm files and runs `npm ci --ignore-scripts` against the
     mirror, with a userconfig of its own. Execute unpacks the project and
     that `node_modules`, runs the app, and uploads only the assembly's
     manifests, templates and metadata.
   - **`collect`** (`lambda/sandbox-dispatch/cdk.py`) reads that assembly
     as hostile input. It parses and re-serialises every template, and
     writes each one, with a *source map* beside it, to
     `scans/<pr_id>/<app>/cdk.out/`. No uploader can put a file there,
     because `SKIP_DIRS` drops `cdk.out`, so the path itself marks a
     template as synthesized.
   - **iac-scanner** scans those templates as the CloudFormation they are.
     It turns each finding into `target_type: cdk` with an `origin`, the
     source line that made its resource. **mapping-agent** maps them for
     an app the PR touches. **remediation-agent** never drafts them: that
     is step 3.
   - **The check run** annotates a finding on its source line, never on
     the template. Its summary says what happened to each app.

   `scripts/sandbox.py synth DIR` runs one app through the sandbox without
   GitHub, and `sandbox/fixtures/cdk-app` is the probe app to run it on.

   Building it settled §4's open measurement and corrected the spec in
   five places:

   - **`--ignore-scripts` is enough for a CDK app**, measured on one: the
     probe app installed and synthesized with it, 242 MB of `node_modules`
     and 79 MB compressed. One app is not a corpus. The first app that
     needs a postinstall step will fail at synth, and is reported, not
     given scripts.
   - **The app runs without the CDK CLI.** The CLI's contract with an app
     is two environment variables: where to write the assembly
     (`CDK_OUTDIR`) and the merged context (`CDK_CONTEXT_JSON`). The
     harness sets them itself, adds `aws:cdk:bundling-stacks: []`, and
     runs `cdk.json`'s `app` command. On the probe app, offline, that took
     31 seconds against the CLI's 66. A CLI pinned in the image would also
     refuse any `aws-cdk-lib` newer than itself, and the project's own CLI
     is more of the PR's code. A lookup with no cached context leaves its
     dummy values in the template and a `missing` entry in the manifest.
     That app is reported as *needs context*, with the providers it asked
     for, and its templates are not scanned.
   - **§6's "the pull request supplies files, never a command line" no
     longer holds for CDK.** `cdk.json`'s `app` is a command line, and
     the execute task runs it through a shell. That command is
     the PR's code like the app it starts, and it runs where that code
     would. What §6 protects still holds: the request names a kind and
     never a command, and the task definition fixes the phase. The app's
     environment holds nothing of the runner's: not the manifest's URL,
     not the run id. The app still runs as the runner's user, so it could
     read them from the runner's process. That is why everything the run
     reports is read as hostile.
   - **A finding is placed by line, not by resource name.** The three
     scanners name CloudFormation resources three ways. Trivy uses a line
     range for some, KICS a tag for others, and checkov a type and logical
     id. All three agree on lines. `collect` therefore records each
     resource's span in the template it wrote itself. The spans matched
     checkov's ranges exactly. A finding's resource is the one whose span
     holds its first line, and its source line comes from that resource's
     creation stack in `<Stack>.metadata.json`. A resource a library made
     for itself takes its nearest ancestor's line. A finding about the
     template as a whole takes the stack's line. Run through the scanner
     image, the probe app gave 41 findings, every one on a source line
     (the table is in the fixture's README). Two settings carry this.
     `CDK_DEBUG=true` records the line that set a property, which step 3's
     fixes will want. `--stack-trace-limit=50` matters because at Node's
     default of ten, a `Vpc`'s subnets had no user frame at all.
   - **A template missing from a scan is not a finding fixed.** When an
     app does not synthesize (the sandbox is off, the app fails, a fork),
     its templates are absent. The scanner would then have marked every
     earlier CDK finding `no_longer_detected`. So a CDK finding is marked
     only if its app's `cdk.out` was scanned this time. In that case a
     missing template is a stack that was removed.

   The app's own words never reach a reader unescaped. The `reason` of a
   failed phase comes from a `result.json` the app could have rewritten,
   and stack names come from its manifest. The check run shows both as
   inline code, where GitHub neither links nor mentions. `log_tail` is
   kept in the run's output and shown nowhere (§10). A finding's `origin`
   is the app's claim about itself (§2). It places an annotation and
   decides nothing. An annotation goes only on a line the PR adds, so a
   claim that names any other line is simply not shown.

   **First run on AWS, 2026-10-10**, after the leak test passed again on
   the new image. `scripts/sandbox.py synth sandbox/fixtures/cdk-app`
   took 118 seconds end to end, and the jobs were the small part of it.
   Fetch's state took 61 seconds, of which the install was 18 (npm's own
   count was 9). Execute's took 55, of which the synth was 7. So each task
   costs about 45 seconds before its job starts, and an app costs two of
   them. The source map matched the local run line for line: 13
   resources, none without a source line, and the ingress rule on
   `lib/network.ts:9`. This is the cold start §7 said to measure, and for
   detection it is paid once per app per push. For step 3's round trip per
   fix it is the number that decides whether a warm worker is needed.

   **End to end, the same day: cascadesec-testbed #4**, which adds the
   fixture as `infra/`. The pipeline took 298 seconds, of which
   `Synthesize` was 129 and `Scan` 116. The check run carries 41
   annotations, every one on `infra/bin/app.ts:4`, `infra/lib/network.ts:7`
   or `:8`, `infra/lib/stack.ts:12` or `infra/lib/storage.ts:6`, the same
   41 the local run placed. Its summary lists `infra` with one stack. It
   offers no Draft fixes, since the PR's only findings are CDK ones.
   mapping-agent mapped 13 of them, through `changed_prefixes`, and
   skipped 28 with no candidate control; it put nothing in `files`. The
   first main-stack apply also hit one deploy-order catch. Step Functions
   refused the new definition, because the role could not "create
   managed-rule" for `.sync`, although the policy granting that had been
   applied seconds before. IAM had not propagated it, and the same apply
   run again went through.

   **Not measured, or not built:**

   - Whether `TimeoutSeconds` on the `.sync:2` state also stops the child
     execution.
   - Execute runs even when fetch failed. It then fails at once with no
     dependencies, but only after a task start. Skipping it needs a state
     that reads fetch's result, which is one more Lambda call per run.
   - npm workspaces, yarn, pnpm, and CDK apps in Python, Java or Go are
     reported as unsupported. So are apps that import from outside their
     own directory, which fail at synth.
   - Approving a fork's app (§8, §10) is not built. A fork's app is
     reported as needing approval, with nothing yet to give it.
3. **CDK remediation.** The yield round trip of §7, and the cold-start
   measurement it exists to get.

   **Measured first, 2026-10-10.** Before changing remediation-agent, the
   fixture app was fixed by hand, the way a CDK author would, and
   re-synthesized and rescanned the way the sandbox does. The comparison
   was by (source, rule, construct path).

   | Resource | Findings | Cleared by one edit to its constructor | Still firing |
   |---|---:|---:|---|
   | the bucket (`Data`) | 16 | 16 | none |
   | the security group (`Net/Ssh`) | 10 | 9 | KICS: a /16 is "open to large scope" |
   | the policy (`AdminPolicy`) | 6 | 5 | KICS: data exfiltration, on `s3:GetObject` |
   | the VPC and its subnet and route | 7 | 2 | KICS ignores the flow log CDK attaches by reference; a public subnet is public by design |
   | the template as a whole | 1 | 0 | KICS's Access Analyzer check |

   The fixes also brought **four new findings**, each correctly placed
   on the line that made it. A new KMS key's policy (KICS) is on
   `storage.ts:6`. The flow log's log group is not encrypted with a
   customer key, which checkov and Trivy both flag, on `network.ts:8`.
   And `allowAllOutbound: false` adds a placeholder egress rule that KICS
   flags as a port range, on `network.ts:9`. Three things follow:

   - **The unit of a CDK fix is a resource, not a finding.** One edit to
     the bucket's constructor cleared all 16 of its findings. Drafting per
     finding, each with a round trip of about a minute through the
     sandbox, would cost sixteen round trips where one suffices. Each
     finding's verdict still comes from the rescan, by its own (source,
     rule, construct path). Construct paths survive a re-synth where
     template lines do not, so the comparison is exact in a way
     Terraform's line-shifted one is not.
   - **Idiomatic fixes create resources, and new resources bring
     findings.** CDK's higher-level constructs make helpers: a key, a log
     group, a role. Under today's rule, cleared and nothing new, three of
     the four fixes above fail.
   - **Some findings cannot be cleared by any reasonable fix.** These are
     a scanner that does not follow CDK's references, and design choices
     such as a public subnet. They need to end as "held for review" in
     one draft, not burn the draft budget.

   **Decided 2026-10-10:**

   - **New findings get one redraft, then the rule is strict.** When a fix
     clears its resource's findings but brings new ones, they are given
     back to the model for one redraft and one more re-synth. Whatever is
     still new after that holds the fix for review, as today. "Nothing
     new" stays the bar. The redraft is the chance for an idiomatic fix to
     finish what it started, such as encrypting the log group it just
     made.
   - **A fix edits one file: the one holding the resource's creation
     line.** That is the per-file chain remediation already has, and
     everything downstream (the diff, the suggestions, the committer)
     assumes one file per fix. A fix that needs another file, such as a
     prop threaded down from the stack, is held for review.

   **The build, in order:**

   1. *The sandbox:* a `cdk-resynth` kind. It is execute only, reuses the
      detection run's installed dependencies (a fix to source does not
      change the lockfile, §7), and overlays one patched file on the
      project. `collect` writes its templates under the fix's own prefix,
      never the PR's scan prefix.
   2. *The snapshot:* a CDK app's own source files join `scans/<pr_id>/`.
      The scanner admits none of them, so nothing new is scanned. Every
      reader that already takes a file's head content from there gets
      them: remediation's base, the suggestions' head, the committer's
      check.
   3. *remediation-agent:* the Map item for CDK is a source file. Within
      it, one draft per resource covers all of that resource's mapped
      findings, and the fix is held on the first. The others are
      superseded if the rescan clears them, and held for review if not.
      The draft yields to the state machine with a re-synth request and
      resumes with its result: scan, compare by construct path, and
      redraft once if anything new appeared. A CDK suppression (checkov
      or cdk-nag metadata, `NagSuppressions`) is refused before the
      sandbox ever runs, as a Terraform one is before the scanner.
   4. *The pipeline:* a `Choice` in the Remediate Map routes a yield
      through `sandbox-run` and back into `RemediateFile`.
   5. *Downstream:* a fix's file is the file it edits, the source file, not
      the template its finding was found in. This touches suggestions, the
      offer, the committer and the dashboard.

   **Built 2026-10-10, tested locally; not yet run on AWS.** All five, in
   that order:

   - `cdk-resynth` in the image and in sandbox-dispatch. The fetch it
     reuses, the file it replaces and the prefix it writes to are each
     checked, and only under this PR's `fixes/`. Each attempt writes to its
     own prefix (`synth-1/`, `synth-2/`), so a redraft is never scanned
     beside its first draft's templates. Detection's `collect` now reports
     its run id, which is what a re-synth reuses.
   - github-gateway adds a runnable app's `.ts` and `.js` files, but not
     `.d.ts`, to the snapshot. A changed source file is therefore a
     changed file, and Draft fixes is offered for a CDK finding whose
     source the PR changed.
   - remediation-agent routes a CDK source file to its own path. It drafts
     one resource at a time, yields a re-synth, and on resuming scans the
     rebuilt templates and compares by (source, rule, construct path).
     Every CDK finding it touches ends the run decided, as `fix-proposed`,
     `superseded`, `needs-human-only` or `not-drafted` with a reason, so a
     resumed invocation never drafts the same resource twice. A fix that
     removes a construct is held, as a dropped resource is in Terraform. A
     fix that does not synthesize, or whose templates do not parse, is
     recorded unverified, with the reason in `scan_errors`. A stale fix is
     reopened on a run's first look at the file, by the function the
     Terraform path uses. `proposed_fix.file` names the source file.
   - The Remediate Map routes a returned `sandbox` request through
     `Resynthesize` (`sandbox-run`, `.sync:2`) and back into
     `RemediateFile`. Every path now carries `$.synth`, so each file can be
     handed the run's synth results.
   - `work_file` (a CDK finding's source file, or any other finding's own
     file) replaces the finding's file wherever a fix is selected, offered,
     posted, previewed, edited or committed. Its three copies are held
     identical by `corpus/test_corpus.py`, as `plan_commit`'s are.

   **Not measured, or not built:**

   - Whether the model writes CDK fixes that pass. This build is the
     harness; the first Draft fixes run on cascadesec-testbed #4 is the
     measurement, along with the round-trip time per fix that §7 asked
     for.
   - Pulling a fix's helper resources into the same draft as the resource
     it fixes, and fixes that span files (decided against above).
4. **Pulumi.** The mock harness and the converter, with a hardened twin for
   every corpus case (multi-iac §7.2: only the hardened twin can fail).
5. **The dependency test gate**, which is when `safe-to-apply` becomes
   reachable (dependency-safety §3).

## 10. Open decisions

- [x] Accept the ~$36/month idle cost of the endpoints (§5), or keep the
      sandbox's Terraform in a module that is applied only while the
      feature is in use. The second keeps dev cheap and makes every
      measurement start with an apply.
      **Decided 2026-10-09: applied only while in use.** It is a separate
      Terraform root, not a module of the main stack, so switching it never
      touches the main stack, and that stack's required variables don't
      come into it. A variable, `active`, controls only what is billed while
      idle: the five interface endpoints. (DNS Firewall was also behind it
      until 2026-10-10. See the next item.)
      `scripts/sandbox.py up` and `down` flip it. Everything else stays,
      because it is free while idle and slow to rebuild: the VPC, security
      groups, S3 gateway endpoint, cluster, task definitions, images, and
      the mirror's cache.
- [x] DNS Firewall (§5): in from the first apply, or accepted as an open
      channel until the leak test reports it. **In from the first apply,
      2026-10-09**, fail-closed. The leak test checks it both ways: a public
      name and a never-seen name must fail, and an endpoint name must still
      resolve.
      **Always on since 2026-10-10**, no longer switched with the
      endpoints. Switching it went wrong. A `down` removed the association
      but not the rule group, and the next `up` recreated the rules but not
      the association. The leak test then ran with the firewall attached to
      nothing, and `example.com` resolved. It bills per query and per
      stored domain, with nothing hourly, so it costs nothing while idle,
      and a VPC that is never without it is the safer default anyway.
- [ ] Python: wheels only (§4) is the proposal. The alternative is building
      sdists in a third, egress-free task, which would be worth it only if
      the corpus shows a real cost.
- [ ] Fork pull requests (§8): approval per pull request, or per head
      commit. Per commit is stricter -- a push after approval is new code
      -- and is what GitHub Actions does.
- [ ] Warm reuse within a pull request (§7): only if step 3's measurement
      makes the cold start the bottleneck.
- [ ] Whether `result.json`'s `log_tail` is shown to reviewers. It is the
      most useful thing in a failed run and entirely attacker-written, so
      it renders as escaped text in a collapsed block, if at all.
      **Not shown anywhere as of step 2 (2026-10-10).** It is kept, clipped
      to 4 KB, in `sandbox-run`'s output, and `scripts/sandbox.py synth
      --log` prints it. The check run gets the phase's short reason, as
      inline code. The dashboard question is still open.
