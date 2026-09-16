# dependency-safety — spec (draft)

Adds npm dependency advisories as a scan source alongside tfsec and Checkov.

## 1. Why this component is shaped differently

Every existing scan path has the same shape: a deterministic tool finds a
problem, and the agent drafts a fix because no tool can. There is no
`tfsec --fix`. Drafting is the agent's job by default, and the self-check
exists to keep that drafting honest.

Dependencies invert this. `npm audit fix` already produces the correct version
bump, deterministically and for free. An agent that re-derives it adds nothing
and introduces a hallucination surface where none needs to exist.

So the agent's job here is not *what is the fix* but *is the known fix safe to
apply*. That is a different question, and it is the one nobody's tooling
answers well: `npm audit fix` will cheerfully take a major version, and
`--force` is a byword for breaking a build on a Friday.

This is the same principle the project already runs on, applied one step
further out. The agent proposes; it never decides. Here it does not even
propose the change, only the verdict on it.

## 2. Verdicts

Three, mapping onto statuses the pipeline already has:

| Verdict | Meaning | Status |
|---|---|---|
| `safe-to-apply` | Every deterministic gate is green | `fix-proposed` |
| `needs-changes` | The bump requires accompanying source edits, which are drafted and self-checked like any other fix | `fix-proposed` |
| `needs-human-only` | A gate failed or could not be evaluated | `needs-human-only` |

`needs-changes` is the only path where an LLM writes code, and it re-enters the
existing remediation flow rather than inventing a second one.

## 3. The gates

Four of the five checks are deterministic. This matters more than it sounds:
each one is a fact a tool can prove, so none of them is the model's to assert.

| Gate | How it is decided | Model involved |
|---|---|---|
| Major version bump | `npm audit --json` reports `fixAvailable.isSemVerMajor` directly | No |
| Package actually used | Import graph over source, direct vs. transitive-only | No |
| New advisories introduced | Re-run audit after the bump, diff advisory ids | No |
| Tests still pass | Run the suite before and after | No |
| Removed or changed API the app uses | Exported-surface diff between versions, intersected with call sites | Partly |

Only the last needs analysis, and even that is largely mechanical: resolve the
package's exports at both versions, diff them, intersect against call sites.
The model's contribution is the residue — judging whether a signature change is
actually breaking for the way this codebase calls it, and writing the
explanation a reviewer reads.

### 3.1 Two gates that need care

**Tests must be run before as well as after.** A suite that was already red
proves nothing about the upgrade, and "tests fail" would otherwise be reported
as an upgrade risk when it is a pre-existing condition. Before-state is
recorded, not assumed.

**Transitive-only is not the same as unused.** A vulnerable package nothing
imports directly is still executed by whatever does import it. Reachability
lowers urgency; it never establishes safety. The gate records which of the two
it found, and `needs-human-only` is the answer when it cannot tell.

## 4. What the existing pipeline gives us for free

Deciding this lives inside IaCPosture rather than beside it buys three things
already built and tested:

- **Supersede.** One transitive bump routinely clears several advisories at
  once, which is exactly what `superseded` / `superseded_by` was built for.
- **Chains.** Several upgrades against one lockfile are a chain, not a set, in
  the same way several fixes to one Terraform file are. `applies_after` and the
  enforcement in `docs/fix-chain-review-spec.md` apply unchanged.
- **Review and audit.** Dashboard, review API, and the ReviewEvent log need no
  new concepts, only a finding whose `iac_type` is new.

## 5. The hard problem: this component executes the code it scans

Everything in the pipeline today reads files. Running `npm install` executes
install scripts from the dependency tree, and running the test suite executes
the repository's own code. Both are untrusted by definition, and one of them is
the supply chain we are ostensibly defending against.

That is a genuinely different security posture from `tfsec main.tf`, and it is
the main design risk in this component rather than a deployment detail.

Lambda is a poor fit regardless: the execution ceiling, image size for a full
`node_modules`, and no useful isolation story. Candidates:

- **CodeBuild** — natural fit for "run a build in a box", per-project IAM,
  already an AWS-native service the project would benefit from exercising
- **Fargate task** — more control over the network and the image, more plumbing
- **Container Lambda** — keeps the shape of the existing Lambdas but does the
  least about the actual problem

Whichever wins, three constraints are not negotiable: no credentials in the
execution role beyond reading its own input and writing its own output, no
network egress after the install step, and `--ignore-scripts` on the install
unless a run explicitly opts out.

## 6. Open decisions

- [ ] Sandbox: CodeBuild vs. Fargate vs. container Lambda (§5) --
      Konrad's call, and he is investigating it as part of a wider look
      at moving off Lambda to a container service. If that move happens
      for the whole pipeline, this component stops being the exception
      and the sandbox question narrows to isolation and egress rather
      than which service.
- [ ] Whether the corpus gets a dependency-relevant framework, or advisories
      cite CVE/GHSA directly and skip `mapping-agent` — an advisory already
      carries its own citation, so mapping may be redundant here
- [x] `iac_type` is not the right discriminator, and the field splits rather
      than being renamed: `target_type` (`npm` here) and `finding_class`
      (`vulnerability` here). Decided 2026-09-16 --
      `docs/multi-iac-spec.md` §3.1 carries the argument. `finding_class` is
      what lets this component take the verdict path of §2 while a
      misconfiguration takes the drafting path, without either inferring it
      from the other field.
- [ ] npm only, or the same shape for pip and Go modules once proven
- [ ] Whether a `needs-changes` fix's self-check is the test suite rather than a
      rescan, which would make it the strongest self-check in the project
