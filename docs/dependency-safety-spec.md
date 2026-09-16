# dependency-safety — spec (draft)

Adds npm dependency advisories as a scan source alongside Trivy and Checkov.

**Revised 2026-09-16.** The original draft assumed `npm audit`, which needs
`npm install`, and concluded (§5) that this component executes the code it
scans. That is only true of one gate. Trivy — already in the scanner image,
already pinned — reads `package-lock.json` **statically** and reports the
advisories with their fixed versions, so detection and most of the gates run
in today's Lambda with no new trust surface. §0 records what was measured,
and §3 and §5 are rewritten around it. The argument of §1 is unchanged and
is what the measurement confirms.

## 0. What Trivy gives us, measured

`trivy fs --scanners vuln` against PugetScope's `api/` on 2026-09-16, with no
install step and no network beyond the advisory database:

```
target=package-lock.json  type=npm  class=lang-pkgs
15 vulnerabilities, 15 with a FixedVersion (100%), 9 distinct CVEs, 3 packages
by severity: HIGH 13, MEDIUM 2
```

A record carries `VulnerabilityID` (CVE/GHSA), `PkgName`,
`InstalledVersion`, `FixedVersion`, `Severity`, `Status`, `CVSS`, `CweIDs`,
`PrimaryURL`, `References`, `Title`, `Description`.

Three details that shape the design:

**`FixedVersion` is a list, not a version.** `fast-uri` 3.1.3 reports
`"2.4.3, 3.1.4, 4.1.1"` — a fix on each major line. Choosing the minimal
non-major bump (here 3.1.4) is a semver comparison against
`InstalledVersion`: deterministic, no model, and it means a non-major option
usually exists. The original §3 treated "is it a major bump" as a yes/no
read off `npm audit`; it is better than that — it is a *choice* the tool
hands us, and only the absence of a same-major entry forces the question.

**`Relationship` is absent from this output.** All 15 records lacked it, so
direct-vs-transitive is *not* free from Trivy and must come from
`package.json` plus the lockfile's own tree, or a flag we have not found. §3
records it as derived rather than given.

**Advisories repeat.** 15 records for 9 CVEs across 3 packages — the same
CVE reaches the tree by several paths. That is the shape §8.4 item 3 already
handles for findings (dedup by id before the write); the finding id here
should hash `(source, VulnerabilityID, PkgName, InstalledVersion)` and
deliberately *not* the path.

**What this changes.** The component splits cleanly in two, and only the
second half needs anything new:

| Phase | Needs | Where it runs |
|---|---|---|
| Detect, verdict on the deterministic gates, propose the bump | reading files | today's scanner and remediation-agent, unchanged shape |
| The test-suite gate | executing the repository | a sandbox that does not exist yet (§5) |

The first phase is shippable now. The second is the keystone shared with
Pulumi (`docs/multi-iac-spec.md` §7) and with any future SAST remediation,
and should be specified once for all three rather than here.

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
| `safe-to-apply` | Every gate is green, **including the test suite** | `fix-proposed` |
| `needs-changes` | The bump requires accompanying source edits, which are drafted and self-checked like any other fix | `fix-proposed` |
| `needs-human-only` | A gate failed, could not be evaluated, or was not run | `needs-human-only` |

`needs-changes` is the only path where an LLM writes code, and it re-enters the
existing remediation flow rather than inventing a second one.

*Amended 2026-09-16.* `safe-to-apply` originally read "every deterministic
gate is green", which after §0 would let phase one award it without ever
running a test — the strongest gate being the one that needs the sandbox.
A gate that did not run is not a gate that passed, so an unrun suite lands
in `needs-human-only` with the reason attached. That leaves phase one
unable to produce `safe-to-apply` at all, which is the honest outcome and
is recorded as such in §3.

## 3. The gates

Four of the five checks are deterministic. This matters more than it sounds:
each one is a fact a tool can prove, so none of them is the model's to assert.

| Gate | How it is decided | Model | Executes code |
|---|---|---|---|
| Major version bump | semver compare `InstalledVersion` against each entry in `FixedVersion`; pick the minimal non-major, or report that only a major exists | No | No |
| Package actually used | *Derived, not given* — `Relationship` is absent from Trivy's output (§0), so direct-vs-transitive comes from `package.json` and the lockfile tree | No | No |
| New advisories introduced | edit the lockfile to the chosen version, re-run `trivy fs`, diff `VulnerabilityID`s | No | No |
| Removed or changed API the app uses | exported-surface diff between versions, intersected with call sites | Partly | Fetching the package to read its exports does not run it — but see §5.1 |
| Tests still pass | run the suite before and after | No | **Yes** |

Four of the five need nothing but files, which is the revision's main
consequence: **a verdict is reachable without ever executing the
repository.** The fifth is the strongest gate and the only one that needs
§5's sandbox.

Only the API-surface gate needs analysis, and even that is largely
mechanical: resolve the package's exports at both versions, diff them,
intersect against call sites. The model's contribution is the residue —
judging whether a signature change is actually breaking for the way this
codebase calls it, and writing the explanation a reviewer reads.

**Without the test gate, `safe-to-apply` is not available.** A verdict that
has not been run against the suite is at most "every gate we can check from
the files is green", which is `needs-human-only` with a good explanation —
not `fix-proposed`. Phase one is therefore worth shipping for what it tells a
reviewer, not because it can auto-approve anything. Calling it
`safe-to-apply` before the suite has run would be the same class of error as
a self-check that passes because the file did not parse.

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

## 5. The hard problem, now scoped to one gate

*Rewritten 2026-09-16. The original said "this component executes the code it
scans", which was true of `npm audit` and is not true of `trivy fs` (§0).
Detection and four of five gates read files. What follows applies to the test
gate alone — but it applies undiminished, because the test gate is the one
that makes `safe-to-apply` mean anything.*

Running the test suite executes the repository's own code, and getting to a
runnable state executes install scripts from the dependency tree — which is
the supply chain we are ostensibly defending against. That is a genuinely
different security posture from `trivy config main.tf`, and it is the main
design risk in phase two rather than a deployment detail.

Lambda is a poor fit: the execution ceiling, image size for a full
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

**This sandbox is not this component's alone.** Pulumi needs it to run
`pulumi preview` (`docs/multi-iac-spec.md` §7), and any future SAST
remediation needs it to run the same suite for the same reason — a code fix
that passes the rule and breaks the application is exactly what §6.1 warns
about. Three roadmaps converge on one piece of infrastructure, and it should
be specified once, on its own, rather than three times in passing.

### 5.1 The lighter execution nobody notices

The API-surface gate resolves a package's exports at two versions, which
means fetching the package. `npm pack` and reading the tarball does not run
anything; `npm install` does. The distinction is easy to lose in
implementation and worth stating: **fetch and read, never install** — and
even fetching is egress to a registry, from a function that today makes none.
If that is unacceptable, the gate degrades to `unknown` rather than being
skipped silently.

## 6. Open decisions

- [ ] Sandbox: CodeBuild vs. Fargate vs. container Lambda (§5) --
      Konrad's call. Now shared with Pulumi and SAST remediation, so it
      wants its own spec rather than a decision taken here. Note that
      §4.3 chose a container image for the scanner on 2026-09-13 and
      explicitly declined Fargate for the pipeline; that argument was
      about duration and cold starts, and does not settle this one,
      which is about isolation and egress.
- [ ] Whether phase one ships before the sandbox exists (§0, §3). It can:
      detection and four gates need no execution. What it cannot do is
      say `safe-to-apply`, so the question is whether a verdict of
      "clean as far as files can tell" is worth a reviewer's time on its
      own. Leaning yes -- it is strictly more than the reviewer has now,
      and it is how the advisory reaches the dashboard at all.
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
- [ ] npm only, or the same shape for pip and Go modules once proven.
      Cheaper than it was: `trivy fs` reads `requirements.txt`,
      `poetry.lock`, `go.mod` and the rest with the same command and the
      same record shape, so phase one is close to language-agnostic. The
      gates are not -- semver, import graphs and test runners differ per
      ecosystem.
- [ ] Whether a `needs-changes` fix's self-check is the test suite rather than a
      rescan, which would make it the strongest self-check in the project
