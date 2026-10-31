# SARIF output — spec

A SARIF 2.1.0 writer for CascadeSec findings, so GitHub Code Scanning,
Azure DevOps, GitLab, and SARIF-aware editors can show them without
integration code of their own.

Written before building, 2026-09-25. Part of integrations-spec, phase A.
**Built 2026-10-31** for local mode, as `cascadesec scan --format sarif`,
and uploaded to the testbed (§5). What building it changed is marked
**Built:** where it applies. Remote mode's citations and fixes wait for
remote mode itself (cli-spec §4).

## 1. Where it runs

One pure module, `sarif.py`: findings in, a SARIF document out, with no I/O.
It lives in `cli/` and is vendored into the gateway's zip if D2 decides the
App should upload. Callers:

- `cascadesec scan --format sarif`, in both modes. This is the main one.
- Later, possibly github-gateway (D2).

**Built:** `cli/src/cascadesec/sarif.py`. The CLI gives it the scanned
directory's path from the repository root (`git rev-parse --show-prefix`),
so `cascadesec scan infra` reports `infra/s3.tf`, which is where a consumer
reads paths from. Outside a repository the paths stay relative to the scan.
`--format` is taken before or after the command, which it was not until
this spec's own example (`cascadesec scan . --format sarif`) tried it.

## 2. Mapping

One `run` per scan. `tool.driver.name` is `CascadeSec`, `version` is the
CLI version, and `properties.scannerImage` is the image digest.

**Rules.** One `reportingDescriptor` per distinct `source:rule_id`:

| SARIF | From |
|---|---|
| `id` | `trivy:AWS-0086`, `checkov:CKV_AWS_18`, `kics:<query id>`. Prefixed, because rule ids collide across tools |
| `shortDescription.text` | scanner `title` |
| `fullDescription.text` | scanner `description`. **Built:** or the title, when the tool gives none, as checkov never does: GitHub rejects an empty one |
| `help.text` | **Built:** the description, then the candidate controls with their titles, or why there are none. GitHub requires it |
| `helpUri` | the tool's rule page, when the scanner reported one. **Built:** none yet. A finding keeps no rule URL (local_main's `FINDING_FIELDS`), so carrying one is a scanner change and a new image |
| `properties.tags` | `security`, `target_type`, and each candidate or mapped control as `CIS-AWS-1.4/3.9`. **Built:** at most 20, GitHub's limit for a rule |
| `properties.security-severity` | CRITICAL `9.5`, HIGH `8.0`, MEDIUM `5.5`, LOW `3.0` |

`security-severity` is what GitHub uses to bucket alerts into
critical/high/medium/low: over 9.0 critical, 7.0 to 8.9 high, 4.0 to 6.9
medium, 0.1 to 3.9 low (GitHub's SARIF documentation, read 2026-10-31). The
testbed's alerts came back `high` for 8.0 and `medium` for 5.5. UNKNOWN
severity (a tool that reported none) gets no `security-severity`, and falls
back to `level`. GitHub also rejects a description over 1024 characters,
so longer ones are cut.

**Results.** One per finding:

| SARIF | From |
|---|---|
| `ruleId` | as above |
| `level` | CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/UNKNOWN → `note` |
| `message.text` | `<title> (<resource>)`, scanner text only. **Built:** without the resource when it names nothing: KICS's `n/a`, or Trivy's position for a CloudFormation resource (`template.yaml:5-8`), which the location already gives. The test is the scanner fingerprint's own, held equal by a test |
| `locations[0]` | `file`, relative to the repository root, and `line_range` as `region.startLine`/`endLine`. A whole-file finding (`[None, None]`) gets no `region`. **Built:** with `uriBaseId: %SRCROOT%`, as CodeQL writes it, and percent-encoded |
| `partialFingerprints.cascadesec/v1` | the fingerprint (integrations §3.2). **Built:** also as `primaryLocationLineHash`, `<fingerprint>:<n>`, because that is the only key GitHub reads. `n` counts findings that share a fingerprint, in line order, as upload-sarif's own hashes do (D4) |
| `properties` | `finding_id`, `status`, `controls` (mapped citations for remote scans, candidates for local, labelled which). **Built:** `finding_id`, `severity`, `target_type`, `candidate_controls`, and `raw_reason` or `detection_only` where they apply. A local finding has no status. Cited controls get their own key with remote mode |
| `fixes` | remote only: the chain-tip corrected file as one `artifactChange` per hunk, **only** for a verified, postable file (ci-integration-spec §4.3's rules, reused). **Not built:** remote mode does not exist yet |
| `baselineState` | `unchanged` for a baselined finding. The `new`/`absent` states are left to consumers. §4 |

**Scan errors are not dropped.** Each `scan_errors` file becomes a
`toolExecutionNotification` with `level: error`, and
`invocations[0].executionSuccessful` is `false` when there are any. A SARIF
consumer that only reads `results` will still show a clean run. That's why
the CLI's exit code (cli-spec §5), not the SARIF file, is the gate.
**Built:** an app that was not run is an error notification too, and an
app `skip_apps` names is a `note` carrying the team's reason.

**No model prose.** `rationale` and `assumptions` never enter SARIF. The file
gets uploaded to places whose readers include anyone who can read the
repository (integrations §2.3).

## 3. GitHub Code Scanning

### 3.1 From a workflow (phase A, no App change)

```yaml
permissions: { contents: read, security-events: write }
steps:
  - uses: actions/checkout@v4
  - run: pipx install "git+https://github.com/konradkelly/CascadeSec@<commit>#subdirectory=cli"
  - run: cascadesec scan . --format sarif --fail-on none > cascadesec.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: ${{ !cancelled() }}
    with: { sarif_file: cascadesec.sarif, category: cascadesec }
```

`--fail-on none`, because the gate is the Code Scanning status, and failing
before the upload would lose the results. An incomplete scan still exits 3,
which fails the job; `!cancelled()` uploads what was found anyway. Private
and internal repositories need GitHub Code Security (GitHub's
documentation), which is why this is a recipe and not the default. The
public testbed took uploads with no plan.

**Built:** `pipx install cascadesec` waits for the PyPI publish (cli-spec
§8), so the recipe installs from the repository at a commit. The runner
pulls the scanner image from GHCR, which needs the package public. The
recipe has not been run in Actions yet. The SARIF goes to stdout, so it is
redirected; `--output` also writes it, but prints it to the job log too.

Upload limits (GitHub's documentation, read 2026-10-31): 10 MB gzipped per
file, 25,000 results and 25,000 rules per run, 20 tags per rule. Over any
of them GitHub rejects the whole file; it does not truncate. PugetScope's
566 findings are far under. Over a limit, the CLI exits 2 and writes
nothing, naming the limit, rather than leave a failed upload behind a
passing scan.

### 3.2 From the App (D2)

The App already annotates the PR's added lines through its check run
(ci-integration-spec §4.3). Code Scanning would add the repository-wide
Security tab and alert lifecycle (open, dismissed, fixed), keyed on
`partialFingerprints`. It would need the `security_events: write`
permission, which every installation must re-approve, and it would put
every finding on the PR twice unless the check run stopped annotating.

Recommended: **don't**, for now. The workflow recipe gives any repository
that wants Code Scanning a way to have it, without widening the App.

## 4. Baselines and GitHub's own state

GitHub tracks an alert across runs by fingerprint, and so it already does
what the CLI's baseline does, with dismissal in its UI. In the Code Scanning
recipe, `--baseline` is therefore optional. Baselined results are still
emitted, marked `baselineState: unchanged` with `suppressions` of kind
`external` and a justification of "in .cascadesec-baseline.json". They're not
omitted. A suppression that's visible can be reviewed. An omitted one can't.

**Measured 2026-10-31: GitHub reads neither `suppressions` nor
`baselineState`.** Its documentation says nothing about them. Uploaded
through the REST API, a baselined finding (Trivy AWS-0096 on the testbed's
SQS queue) became an open alert like every other, with no dismissal. So in
the Code Scanning recipe the baseline changes nothing on GitHub: a team
dismisses there instead, and GitHub keeps the dismissal across runs. The
results stay suppressed in the file for consumers that do read the field,
so D3 stands. Leaving baselined findings out for GitHub would need a flag,
which is not built.

## 5. Validation

Tests validate every emitted document against the SARIF 2.1.0 JSON schema,
vendored into the tests. One recorded upload to the testbed confirms GitHub
accepts it, with fingerprints stable across a run that inserts a line above
a finding. That second test is the reason the fingerprint exists.

**Built:** `cli/tests/test_sarif.py` validates against the OASIS schema
(errata01, in `cli/tests/data`), with jsonschema in CI.

**Uploaded 2026-10-31** to cascadesec-testbed through the REST API, on a
scratch branch `sarif-check` taken from main (f143627). The local scan gave
20 results under 16 rules, one of them baselined, and GitHub processed the
file with no errors. Three commits followed, each scanned and uploaded:

| Commit | What changed | Alerts kept | Closed | Opened |
|---|---|---|---|---|
| 5b05f43 | a line inserted at the top of every file with a finding | 20 of 20, each one line lower | 0 | 0 |
| 1e4577a | a comment added to each flagged `resource` line | 20 of 20 | 0 | 0 |
| 7a8bbfb | the payments bucket moved to the end of `storage.tf` | 20 of 20; its three alerts followed it from line 21 to 55 | 0 | 0 |

The fingerprints were identical in all four scans. A control ran the same
four uploads under another category with only `cascadesec/v1`, no
`primaryLocationLineHash`, and it came out the same: GitHub follows these
changes on its own when it holds both commits. So these tests show that the
fingerprint does no harm in GitHub's key. They do not show a case where
only the fingerprint keeps an alert (D4).

## 6. Decisions

| # | Decision | Outcome |
|---|---|---|
| D1 | Severity → `security-severity` numbers (§2) | Built: GitHub ranked 8.0 high and 5.5 medium |
| D2 | App uploads to Code Scanning | Proposed: no; workflow recipe instead (§3.2) |
| D3 | Emit baselined results as suppressed rather than omit (§4) | Built. GitHub ignores the suppression and opens the alert (§4) |
| D4 | The fingerprint as `primaryLocationLineHash` too, the one key GitHub reads (§2) | Built 2026-10-31: GitHub's alert is then the baseline's finding. A control without it tracked the same three changes (§5) |
