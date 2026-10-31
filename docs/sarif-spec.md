# SARIF output — spec

A SARIF 2.1.0 writer for CascadeSec findings, so GitHub Code Scanning,
Azure DevOps, GitLab, and SARIF-aware editors can show them without
integration code of their own.

Written before building, 2026-09-25. Part of integrations-spec, phase A.
Not started.

## 1. Where it runs

One pure module, `sarif.py`: findings in, a SARIF document out, with no I/O.
It lives in `cli/` and is vendored into the gateway's zip if D2 decides the
App should upload. Callers:

- `cascadesec scan --format sarif`, in both modes. This is the main one.
- Later, possibly github-gateway (D2).

## 2. Mapping

One `run` per scan. `tool.driver.name` is `CascadeSec`, `version` is the
CLI version, and `properties.scannerImage` is the image digest.

**Rules.** One `reportingDescriptor` per distinct `source:rule_id`:

| SARIF | From |
|---|---|
| `id` | `trivy:AWS-0086`, `checkov:CKV_AWS_18`, `kics:<query id>`. Prefixed, because rule ids collide across tools |
| `shortDescription.text` | scanner `title` |
| `fullDescription.text` | scanner `description` |
| `helpUri` | the tool's rule page, when the scanner reported one |
| `properties.tags` | `security`, `target_type`, and each candidate or mapped control as `CIS-AWS-1.4/3.9` |
| `properties.security-severity` | CRITICAL `9.5`, HIGH `8.0`, MEDIUM `5.5`, LOW `3.0` |

`security-severity` is what GitHub uses to bucket alerts into
critical/high/medium/low. The thresholds are at 9.0, 7.0 and 4.0 **(verify)**.
UNKNOWN severity (a tool that reported none) gets no `security-severity`,
and falls back to `level`.

**Results.** One per finding:

| SARIF | From |
|---|---|
| `ruleId` | as above |
| `level` | CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/UNKNOWN → `note` |
| `message.text` | `<title> (<resource>)`, scanner text only |
| `locations[0]` | `file`, relative to the repository root, and `line_range` as `region.startLine`/`endLine`. A whole-file finding (`[None, None]`) gets no `region` |
| `partialFingerprints.cascadesec/v1` | the fingerprint (integrations §3.2) |
| `properties` | `finding_id`, `status`, `controls` (mapped citations for remote scans, candidates for local, labelled which) |
| `fixes` | remote only: the chain-tip corrected file as one `artifactChange` per hunk, **only** for a verified, postable file (ci-integration-spec §4.3's rules, reused) |
| `baselineState` | `unchanged` for a baselined finding. The `new`/`absent` states are left to consumers. §4 |

**Scan errors are not dropped.** Each `scan_errors` file becomes a
`toolExecutionNotification` with `level: error`, and
`invocations[0].executionSuccessful` is `false` when there are any. A SARIF
consumer that only reads `results` will still show a clean run. That's why
the CLI's exit code (cli-spec §5), not the SARIF file, is the gate.

**No model prose.** `rationale` and `assumptions` never enter SARIF. The file
gets uploaded to places whose readers include anyone who can read the
repository (integrations §2.3).

## 3. GitHub Code Scanning

### 3.1 From a workflow (phase A, no App change)

```yaml
permissions: { contents: read, security-events: write }
steps:
  - uses: actions/checkout@v4
  - run: pipx install cascadesec
  - run: cascadesec scan . --format sarif --output cascadesec.sarif --fail-on none
  - uses: github/codeql-action/upload-sarif@v3
    with: { sarif_file: cascadesec.sarif, category: cascadesec }
```

`--fail-on none`, because the gate is the Code Scanning status, and failing
before the upload would lose the results. Code Scanning is free on public
repositories. Private repositories need GitHub Code Security **(verify)**,
which is why this is a recipe and not the default.

Upload limits: 10MB gzipped per file, and a cap on results per run
**(verify the current numbers)**. PugetScope's 566 findings are far under.
Over the cap, the CLI fails with exit 2 rather than letting GitHub truncate
silently.

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

## 5. Validation

Tests validate every emitted document against the SARIF 2.1.0 JSON schema,
vendored into the tests. One recorded upload to the testbed confirms GitHub
accepts it, with fingerprints stable across a run that inserts a line above
a finding. That second test is the reason the fingerprint exists.

## 6. Decisions

| # | Decision | Outcome |
|---|---|---|
| D1 | Severity → `security-severity` numbers (§2) | Proposed |
| D2 | App uploads to Code Scanning | Proposed: no; workflow recipe instead (§3.2) |
| D3 | Emit baselined results as suppressed rather than omit (§4) | Proposed |
