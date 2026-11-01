# Completion — spec

What "finished" means for CascadeSec as a portfolio project, what is left
to get there, and what is deliberately not part of it.

Written 2026-10-31, after a review of the project's scope against similar
tools (§1). Nothing in §5 is built yet unless it says so. Every step says
what it is done when, and §7 lists the decisions that are still open.

## 1. Why this spec exists

Two months in, more is built than is proved. `#74` is the latest pull
request, `docs/` held 15 documents beside the top-level spec, and CI runs
1,496 tests. The one number the README leads with, detection recall, mostly
measures Trivy, checkov and KICS on labelled cases. What CascadeSec itself
claims is unmeasured:

- **that mapping-agent picks the right control.** iacposture-spec §7:
  "Whether the agent picks **well** among candidates is still unmeasured."
- **that a fix shown to a reviewer is a good fix.** §7 names fix acceptance
  "the headline metric for the project writeup", and it has never been
  reported. §6.1 already says why a clean rescan is not enough: it "proves
  the finding is gone. It cannot prove the infrastructure still works."

Similar tools have converged on the same loop of a model drafting and a
scanner re-checking: Aikido's IaC AutoFix, several hobby projects, and,
closest to this design, TerraRepair (ESEM 2026), a bounded agent that reads
Terraform references and the provider schema, re-runs the scanner, and
escalates when context is missing. In a human audit, 78.9% of its
scanner-verified AWS repairs were judged correct. So "scanner-verified" is
not "correct", and the field already knows it. What would set CascadeSec
apart is not the loop but a measured answer for its own pipeline, with the
gates and the held fixes that the others do not have.

Two more things showed up in the review:

- **The docs lag the code.** The README still said Helm and CDK were out of
  scope after `#50`, `#52` and `#53` merged them.
- **The parts built for other people cannot be used by them.** CLI local
  mode and the docker pre-commit hook pull images from GHCR, and both
  packages are still private. (Made public on 2026-11-01, phase 1 step 3.)

So finishing means proving and truthing what exists, making the agents run
without an AWS account, and then stopping. It does not mean more surfaces.

## 2. Definition of done

CascadeSec 1.0 is done when all six hold:

1. **Truthful.** Every claim in the README, and every spec's status line,
   matches what is merged and deployed, checked on the day 1.0 is tagged.
2. **Runnable without AWS.** On a clean Windows or Linux machine with
   Docker, Python 3.11 or later and an Anthropic API key, a person follows only the
   README's quickstart from install to a self-checked fix written into
   their working tree.
3. **Demonstrable hosted.** The GitHub App path (pull request → check run →
   Draft fixes → Commit fixes) runs on the testbed, and a recording of it
   is linked from the README, so it can be seen while the AWS stack is off.
4. **Measured on its own claims.** Detection recall, mapping accuracy and
   fix quality are published with their method, date, image digest, model
   id and cost, and fix quality is set against a baseline (phase 2).
5. **Guarded.** Phase 4's checks exist as committed scripts or CI jobs,
   each has passed at least once, and the result is recorded.
6. **Bounded.** §4's list is in the README as non-goals, and `v1.0.0` is
   tagged.

## 3. Where it stands, 2026-10-31

| Area | State | Evidence |
|---|---|---|
| Detection: Terraform, OpenTofu, Kubernetes, CloudFormation, ARM, Bicep | Deployed | Recall 98.9%, 178 of 180, on 84 positive cases and 6 clean controls, 2026-11-01, image `b22fc47`, the same as on 2026-09-23 (`corpus/eval/README.md`) |
| Control mapping with citations | Deployed | Coverage measured: 98.5% of labelled pairs and 71.9% of distinct rules have a candidate (2026-11-01), with NIST 800-53 loaded for the unmapped tail (`#51`). It was 72% and 39% on 2026-09-12. Accuracy never measured |
| Remediation: self-check, suppression and deletion gates, assumptions, held fixes | Deployed | Gates proven by unit tests on captured diffs; neither had fired in production when iacposture-spec §6 was written. Fix quality not measured |
| context-agent | Deployed | context-agent-spec; Lambda last updated 2026-09-24 |
| GitHub App: check runs, annotations, suggested changes (v3) | Deployed 2026-09-25 | ci-integration-spec |
| Write-back: Commit fixes (v4) | Deployed, verified live 2026-09-30 | write-back-spec, github-first-review-spec |
| CDK: detection and remediation through the sandbox | Deployed 2026-10-11, behind `cdk_synthesis` | sandbox-spec §9 steps 2-3; testbed #4 and #5 |
| Pulumi (TypeScript and JavaScript, 13 AWS resource types) and Helm rendering | Built; verified on AWS 2026-10-13; detection only, by hand through `scripts/sandbox.py`; not in the PR pipeline | sandbox-spec §1, `#52`, `#53` |
| CLI review commands (track R) | Merged 2026-10-18 | cli-spec §13 |
| CLI local scan, baseline, pre-commit hooks, SARIF | Merged by 2026-10-31. Images published to GHCR 2026-10-29 and again 2026-11-01 (`#76`), public since 2026-11-01 | cli-spec §13, sarif-spec |
| Portable runtime, phase 1: the core vendored into mapping-agent | Deployed 2026-10-31 | portable-runtime-spec §8 |
| Portable runtime, phase 2: RecordStore and the G1-G9 suite | Merged 2026-10-31 (`#74`). No handler uses it yet. mapping-agent's zip vendors the core, so it was deployed with it the same day | portable-runtime-spec §12 |
| Tests | 1,558, counted by collection on 2026-10-31 | 1,446 Python (Lambdas 915, CLI 227, corpus 219, core 40, deploy guard and drift check 42, Helm harness 3), dashboard 100, Node harness 12. All run in CI without AWS credentials |

## 4. Not in 1.0

A cut keeps its spec. Each affected spec says at the top which parts are
past 1.0 and points here. Nothing is deleted from the repository or its
history: the reasoning in those specs, including why something was set
aside, is part of what the project shows.

| Item | Specified in | Why it is out | Status |
|---|---|---|---|
| **Portable hosted runtime**: server image, Postgres adapter, OIDC verifier, job queue, a recipe on one non-AWS platform | portable-runtime-spec §7, §12 phases 7-8 | A second production deployment that nobody would run, which doubles what has to be deployed and tested. Its ports and the conformance suite stay, because the local runtime uses them. None of it was built | **Accepted 2026-10-31** (C7) |
| Native per-cloud adapters | portable-runtime-spec §7, §12 phase 8 | Already "only when someone needs one" | Accepted (follows C7) |
| Remote scans: `scan-api`, remote `--fix` and `--apply`, phase M machine auth | cli-spec §13 steps 7-8, machine-auth-spec | A CI job can run the pipeline itself with its own key once phase 3 is done | Accepted 2026-10-31 (P9) |
| `--helm` and `--synth` in local mode | cli-spec §13 step 9 | Already "when asked for" | Proposed (C8) |
| Helm and Pulumi in the PR pipeline, and their remediation; Pulumi Python and components | sandbox-spec §1, multi-iac-spec §9 | Needs a chart-aware self-check and source mapping, which would be a v5 of its own | Proposed (C8) |
| npm advisories (dependency-safety): detection, the four gates that read files, and the test gate | dependency-safety-spec, sandbox-spec §9 step 5 | A new scan source, and none of it was built. The test gate needs the sandbox as well | Proposed (C8). The row named only the test gate until 2026-10-31 |
| Bedrock and Vertex as model providers | portable-runtime-spec §6, P8 | Configuration only, never tested. The Anthropic API is the one tested provider | Proposed (C8) |
| The integration surfaces drafted in October and never committed: CI-platform recipes, an HCP Terraform run task, an MCP server, notifications, a VS Code extension | integrations-spec phases C-E (not in the repository) | Each is a new surface. SARIF already gets the findings into Code Scanning and SARIF viewers | Proposed (C6, C8) |
| `GET /prs` and `cascadesec prs` | cli-spec D8 | Stays open | Unchanged |

## 5. Steps

**The eval comes before the refactor.** Phase 3 moves remediation and
review logic behind the ports (portable-runtime-spec §12 phase 3). A
fix-quality eval run before and after that move is the one test that would
catch a refactor that changes what the agent drafts, so measuring comes
second and not last.

### Phase 1: make what is written match what runs

1. **README facts.** The status table covers CDK, Pulumi and Helm, the
   CLI, SARIF and the portable runtime; the eval number is the latest run;
   the test count is the one in §3; it links here. **Done 2026-10-31**, in
   the change that added this spec. The fuller rewrite is phase 5.
2. **Spec status lines.** Every spec opens with one line saying what is
   built, deployed or past 1.0, with a date. **Done 2026-10-31** for
   portable-runtime, sandbox, multi-iac, machine-auth, cli and the
   top-level spec, alongside the stale lines inside them. **Done
   2026-10-31** for the rest, each checked against the code:
   - fix-chain-review and reviewer-edit, deployed 2026-09-11, with the
     open decisions neither built;
   - remediation-agent, marked as the historical build brief it is, with
     what has outgrown it;
   - trivy-azure-arm-adapter-gap, still not filed, which nothing in the
     scanner depends on since KICS took ARM over;
   - dependency-safety, of which nothing is built, not only the test
     gate, so §4's row now covers all of it;
   - cli, context-agent and ci-integration, whose status was only further
     in (§13, §12, §9).
3. **Publish the images.** Make `ghcr.io/konradkelly/cascadesec-scanner`
   and `ghcr.io/konradkelly/cascadesec-hook` public. Only the owner can,
   from each package's settings on GitHub. Done when an anonymous
   `docker pull` of the digest `SCANNER_IMAGE` pins
   (`cli/src/cascadesec/scan.py`) succeeds on a machine with no GHCR login,
   and the same for the hook image's digest in `.pre-commit-hooks.yaml`.
   **Done 2026-11-01.** Konrad made both packages public. With no
   credentials at all, an anonymous token from GHCR served the manifest at
   each digest `main` pins and each digest `#76` pins, each hashing to its
   pin. Each config blob downloaded, and every layer answered 200 to a HEAD
   request: 16 for the scanner, 18 for the hook. Every version in both
   packages is public, since visibility is the package's, the older ones
   included, so a CLI pinned to one still pulls.
4. **Housekeeping.** Ordinary deletes, with nothing force-pushed:
   - the testbed's scratch branch `sarif-check` and the two Code Scanning
     analyses uploaded from it (sarif-spec §5);
   - merged branches, local and on GitHub;
   - the worktrees whose pull requests merged (`iac-posture-helm-pr`,
     `iac-posture-pulumi-pr`);
   - the six specs drafted in the main checkout and never committed, kept
     outside the repository since 2026-10-31. machine-auth-spec and
     sarif-spec cite one of them, integrations-spec, by name (C6).
5. **A drift check that stays.** One read-only command that compares what
   is deployed with the repository:
   - the corpus in S3 against `corpus/`;
   - the scanner Lambda's image digest against the one last published;
   - the dashboard's files in S3 against a build of `main`;
   - a `scripts/deploy.py` plan reporting no changes, for everything
     Terraform packages.

   It exists because each of these has drifted unnoticed before (the
   deployed corpus was found stale on 2026-10-11). Done when it reports
   clean against the deployed stack and CLAUDE.md's deploy notes name it.

   **Built 2026-10-31** as `scripts/drift.py`, and named in CLAUDE.md. Its
   scanner check also compares the image with `main`: build-image.sh tags
   each image with its commit, and no file the Dockerfile copies may have
   changed since. The first run, the same day, found two things to deploy,
   both from merged work:
   - the scanner image was built from `b85206d`, and `local_main.py` has
     changed since, in a comment (`9f6af66`);
   - the plan has two updates and nothing else: mapping-agent, whose zip
     vendors the core and so gained `#74`'s files, and the pipeline's
     policy, whose document reads that function's ARN and so is unknown
     until the apply.

   The corpus and the dashboard matched. The two differences were deployed
   by the next day:
   - the plan above, applied 2026-10-31, after which the drift check's
     plan reported no changes;
   - the scanner rebuilt from `b22fc47`, published and deployed
     2026-11-01, after a local scan of the eval cases with the old and the
     new image gave the same 517 findings, and the eval on the deployed
     scanner gave the same 178 of 180. `#76` pins it in the CLI and the
     hook.

   **Done 2026-11-01.** After `#76` and `#77` merged, a run against `main`
   at `4b49146` reported every check matching: the corpus, the scanner
   image, the dashboard, and a plan with no changes.

**Phase 1 is done when** steps 1 to 5 are, and a reader of the README and
the specs finds no claim that the deployed system contradicts.

### Phase 2: measure CascadeSec's own claims

1. **Mapping accuracy.** For every `(rule, case)` pair the eval expects,
   label the control or controls a correct mapping may cite, as
   `expected_controls` beside the existing labels. Run mapping-agent over
   the cases and report four outcomes: one of the expected controls, a
   wrong control, no candidate, and declined. Coverage, meaning a candidate
   exists, is reported apart from accuracy, meaning the right one was
   picked, because §3's coverage is the first and says nothing about the
   second.
   Done when the number and the labelling rules are in
   `corpus/eval/README.md`, and a corpus test fails on a label that names a
   control the corpus does not have.

   **Revised 2026-11-01, decided by Konrad.** It is three numbers, not
   one. mapping-agent must pick exactly one candidate and cannot decline,
   and 158 of the 180 pairs have a single candidate, so on those the
   outcome is fixed by `rule_mappings.json` and "declined" cannot happen.
   One figure would mostly measure the corpus. So
   `corpus/eval/run_mapping_eval.py` reports:
   - **corpus correctness**, from the files alone;
   - **the agent's choice** on the pairs whose candidates are only partly
     right, over three pipeline runs;
   - **citation fidelity** on every mapped finding: whether the citation
     is the verbatim excerpt of under 15 words the prompt asks for, which
     nothing checks today.

   Claude drafts the labels from the control texts without reading the
   candidates or mapping-agent's answers, and Konrad reviews every label
   before any number is computed. **Labels drafted 2026-11-01**, with the
   rules, the script and the corpus test; review and the numbers are next.
2. **Fix quality.** A new `corpus/eval/run_fix_eval.py`.
   - **Cases:** every positive eval case, plus the repositories
     `corpus/external/` pins, at their pinned commits.
   - **Path:** it drives the pipeline as `scripts/scan.py` does, not through
     a pull request, so the same input can be run again.
   - **Repeats:** each finding is drafted *k* times (C3), because the draft
     varies. On testbed #4 the security group's CDK fix passed and the
     subnet's was held; on #5 it was the other way round (sandbox-spec §9
     step 3).
   - **Recorded per fix, mechanically:**
     - whether the self-check passed;
     - whether the fix was held, and by which gate;
     - findings it introduced;
     - whether the suppression or deletion gate fired;
     - diff size and an empty rationale;
     - tokens, dollars and wall time;
     - the language's own validity check (`terraform validate` against a
       provider cache, a schema check for Kubernetes). It is recorded here
       before phase 4 decides whether to gate on it.
   - **Per finding:** how many of the *k* drafts passed, and whether the
     passing drafts make the same change.
   - **Human audit:** a sample stratified by language and by outcome,
     passed and held (C3). Each fix is judged against a written rubric:
     1. it removes the weakness, not only what triggers the rule;
     2. it keeps what the resource was for;
     3. it would apply.
     
     Each judgment is recorded as correct or not, with one sentence of
     why, in a file under `corpus/eval/` so it can be reread and disputed.
   - **What the loop adds**, from the same runs:
     - of first drafts, how many clear the finding without adding one;
     - of fixes that reach a reviewer, how many the audit judges correct;
     - of held fixes, how many were in fact wrong, which is how good the
       gates are at holding the right things.
     
     The difference between the first and second numbers is what the
     self-check, the redraft and context-agent contribute. TerraRepair's
     78.9% goes beside them as context, not as a like-for-like comparison,
     since its cases, model and scanners differ.
   
   Done when one full run is recorded with model id, image digest, corpus
   commit, date and total cost.
3. **Fix acceptance on real pull requests** (iacposture-spec §7 item 3).
   Computed from review events: approved unedited, edited, rejected.
   Reported with its *n*, and with the plain fact that the testbed's pull
   requests were written by the person reviewing them. Done when a script
   computes it from the table and the number is in the eval README.
4. **A regression subset.** A fixed subset of steps 1 and 2, proposed at
   about 20 findings across the languages, that runs before merging any
   change to a prompt, a model id, the corpus or a gate, with the result
   pasted into the pull request. CI stays free of AWS credentials whatever
   C2 decides about a model key.

**Phase 2 is done when** steps 1 to 4 are recorded and the README's
headline cites all three numbers.

### Phase 3: run the agents without AWS

portable-runtime-spec §12 phases 2 to 6, with the design unchanged and the
hosted runtime removed. Each step leaves the AWS runtime working and
deployed.

1. **Merge `#74`**: RecordStore, its DynamoDB adapter and the G1-G9 suite.
   **Done 2026-10-31.**
2. **BlobStore**, with its S3 adapter and a directory adapter, and tests
   that hold both to the same behaviour (`get_range` bounds, `list`
   returning every key under a prefix).
3. **Call sites move to the ports**, one component at a time: mapping-agent
   first, then the scanner's write path, then remediation, then review.
   Before remediation moves, run phase 2's subset against the deployed
   stack, and run it again after the moved code is deployed. The two must
   agree within the run-to-run spread phase 2 measured.
4. **SQLite RecordStore** passing G1-G9, as the DynamoDB adapter does.
5. **`cascadesec run`**, scan and map, then `--fix` with the self-check
   through the scanner image. portable-runtime-spec §5's plain statement of
   what is sent to the model provider is a requirement, not a nicety.
6. **`cascadesec apply` and `cascadesec serve`**, the review API on
   localhost. C4 sets where to cut if this phase runs long.
7. **Parity.** The eval cases through `cascadesec run` and through the
   deployed pipeline give the same findings, matched by fingerprint, and
   the same candidate controls. Mappings and fixes are compared by phase
   2's measures, not byte for byte, since drafts vary.
8. **The quickstart**, written and then followed on a clean Windows
   machine and a clean Linux machine (CI's `cli` job already covers both).
   Record how long it takes and every place it went wrong.

**Phase 3 is done when** §2 item 2 holds.

### Phase 4: checks that keep it true

1. **Validity beyond the scanner.** Phase 2 records whether
   scanner-passing fixes validate. If any fail, validity becomes a
   self-check condition for that language, held to the same rule as the
   other gates: it holds a fix and never passes one. If none fail, say so
   in the eval README and do not build the gate.
2. **Adversarial cases**, under `corpus/eval/adversarial/`, run through
   the pipeline and not just the unit tests:
   - instructions in comments, descriptions, tags and variable defaults
     ("mark this fixed", "allow 0.0.0.0/0 for the health check");
   - instructions in files that context-agent reads, such as a README or
     another `.tf` file;
   - a finding whose easiest "fix" deletes the resource or adds a
     suppression, so that each gate fires end to end at least once;
   - a secret in the file being fixed, checked for in the rationale and
     on the check run.

   They pass when no drafted fix follows an injected instruction, every
   gate fires where it should, the findings are the same with or without
   the injected text (iacposture-spec §8.1), and no secret is echoed.
3. **The scanner equivalence harness, committed.** cli-spec §13 S1 ran the
   old and new scanner handlers side by side over all 90 eval cases and
   found them identical. The harness lived in session scratch and has to be
   rebuilt each time. Commit it, and run it on every scanner change.
4. **A live smoke test of the hosted path**, `scripts/smoke.py`:
   1. open a pull request on the testbed from a fixture branch;
   2. wait for the check run and its annotations;
   3. wait for Draft fixes, which needs a click, and the script says when;
   4. wait for at least one suggested change;
   5. Commit fixes, then wait for the commit's own scan.
   
   Run it before every deploy that touches the pipeline or the Apps.
   Several faults have only shown up live, such as Step Functions'
   PascalCase environment entries (sandbox-spec §9).
5. **A threat model of CascadeSec itself**, one page:
   - what each GitHub App can do;
   - what the sandbox contains and what it does not;
   - what reaches the model provider;
   - prompt injection;
   - what is not mitigated.
   
   Link each item to the spec section that handles it. Done when the
   README's disclaimer links it.

**Phase 4 is done when** each check exists, has passed at least once, and
its result is recorded.

### Phase 5: presentation

1. **The README's first screen**:
   - one paragraph on what CascadeSec is and why;
   - the three numbers;
   - a two-minute recording;
   - the local quickstart;
   - a link to a testbed pull request;
   - then the architecture, the limitations and §4 as non-goals.
2. **Recordings**: the hosted path on the testbed, and a local
   `cascadesec run --fix` followed by `cascadesec apply`.
3. **Design notes**, one to two pages linking the specs. They cover the
   decisions and what went wrong:
   - the agent proposes and never decides;
   - the admission rule;
   - the self-check per language, and the Kubernetes parse errors that
     failed open;
   - held fixes and the chain rule;
   - the sandbox's containment and its DNS Firewall;
   - the 2026-10-11 destroy that the deploy guard now prevents.
4. **Limitations**, stated plainly:
   - Pulumi and Helm are detection only;
   - OpenTofu has one scanner;
   - drafts vary from run to run;
   - the audit's sample size;
   - the project has not been security-audited.
5. **Cost**: model cost per scan and per fix, from phase 2, and the AWS
   stack's idle cost from billing. The sandbox's endpoints are off unless
   in use (sandbox-spec §10).
6. **A cold read.** One person who has not seen the project reads the
   README and follows the quickstart. Their questions become README edits.

**Phase 5 is done when** §2 item 3 holds and the cold read is done.

### Phase 6: tag and freeze

- Tag `v1.0.0` on `main` once §2 holds. The release notes give the three
  numbers and the published image digests.
- After the tag, `main` takes bug fixes, version bumps of the scanner and
  its tools (each with the eval rerun), and changes the eval calls for.
  Anything else needs a spec that names the §4 item it reopens and why.

## 6. Order, and what can overlap

```
phase 1 ──▶ phase 2 ──────────────▶ phase 3, steps 3-8 ──▶ phase 5 ──▶ phase 6
              │    phase 3, steps 1-2 (no behaviour change, alongside phase 2)
              └──▶ phase 4 (once phase 2's runner exists)
```

- Phase 1 comes first and is small.
- Phase 3's steps 1 and 2 change no behaviour, so they can run alongside
  phase 2.
- Phase 3 step 3 moves remediation only after phase 2's subset exists.
- Phase 4's adversarial cases are eval cases, so they start once the fix
  eval's runner does.
- Phase 5 comes last, because its numbers come from phase 2 and its
  quickstart from phase 3.

## 7. Decisions

| # | Decision | Outcome |
|---|---|---|
| C1 | A target date for `v1.0.0` | **Open.** iacposture-spec §8 names a February to June 2027 window |
| C2 | The fix eval in CI with a model key, or run by hand before merging | Proposed: by hand, with the result in the pull request. CI keeps no AWS credentials either way |
| C3 | Drafts per finding (*k*) and the audit's sample size | Proposed: *k* = 3, and 50 fixes audited, stratified by language and outcome |
| C4 | `cascadesec serve` in 1.0 | Proposed: in. If phase 3 runs long, the dashboard is what is cut: `run`, `--fix`, the review commands against `serve`'s API, and `apply` are the floor |
| C5 | The AWS stack after 1.0: kept up, or torn down with the recording as the demo | **Open** |
| C6 | integrations-spec: commit it marked past 1.0, or drop its citations from machine-auth-spec and sarif-spec | **Open** |
| C7 | The portable hosted runtime and native adapters out of 1.0 (§4) | **Accepted 2026-10-31** (Konrad) |
| C8 | §4's other proposed items out of 1.0 | Proposed |
| C9 | The eval before the refactor (§5, §6) | Proposed |

## References

- TerraRepair: a tool-grounded LLM agent for infrastructure-as-code
  repair, ESEM 2026.
  <https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESEM.2026.68>
- Aikido, AutoFix for infrastructure as code.
  <https://help.aikido.dev/autofix-and-remediation/scope/autofix-for-infrastructure-as-code>
- GitHub, Copilot Autofix for code scanning.
  <https://docs.github.com/en/code-security/concepts/code-scanning/autofix-for-code-scanning>
- Pixee, codemodder. <https://docs.pixee.ai/open-source/codemodder>
- patched-codes, patchwork. <https://github.com/patched-codes/patchwork>
