# cascadesec CLI

CascadeSec from the terminal. Design: [docs/cli-spec.md](../docs/cli-spec.md).

Built so far: track R of the spec (§10, §13) -- signing in (`login`,
`logout`, `whoami`), reading a PR's findings (`findings`, `show`), deciding
on a fix (`approve`, `reject`, `edit`), committing the approved ones
(`commit`) -- `scan` in local mode with its `baseline`, the pre-commit
`hook`, and `version`.

## Set up

```powershell
pipx install ./cli            # or, for development: .venv/Scripts/python -m pip install -e cli
```

Point it at a deployment. The `[server]` table is printed by Terraform. It
holds no secrets (the dashboard ships the same values), so it can go in
your own config or be committed in a repository's `.cascadesec.toml`:

```powershell
cd terraform
terraform output -raw cli_config > "$env:APPDATA\cascadesec\config.toml"   # Windows
terraform output -raw cli_config > ~/.config/cascadesec/config.toml        # Linux/macOS
```

Or set `CASCADESEC_API`, `CASCADESEC_AUTH_DOMAIN` and `CASCADESEC_CLIENT_ID`.
Precedence, lowest first: user file, then repository file, then environment.

## Sign in

```
cascadesec login                 # opens the browser; listens on localhost:47811-47813
cascadesec login --no-browser    # SSH: open the URL elsewhere, paste back the redirect
cascadesec whoami
cascadesec logout                # revokes the refresh token, then forgets the session
```

Your account is the dashboard's: an admin creates it (dashboard/README.md).
The session is kept in the OS keyring (Windows Credential Manager, macOS
Keychain, Secret Service). It is never written to a file. A session lasts as
long as the pool's refresh token, which is one day. A person newly added to
`committers` runs `login` again, because groups are fixed when a token is
issued.

## Read a PR's findings

```
cascadesec findings konradkelly/cascadesec-testbed#4      # or the PR's URL, or gh-1388098412-4
cascadesec findings gh-1352957770-50 --status fix-proposed --severity high
cascadesec findings gh-1352957770-50 --file 'k8s/*.yaml' --format json
cascadesec show gh-1388098412-4 3f2a                      # a finding id, or a unique start of one
cascadesec show gh-1388098412-4 3f2a9c01d4e5b6a7 --agent-diff
```

`findings` groups as the dashboard does: fixes to review, then findings with
no fix to review yet, then settled ones. Raw findings follow, one row per
rule, grouped by why they have no control. `show` prints the controls and
citations, the fix's rationale and diff, everything that holds it for review
(assumptions, deleted resources, unmet prerequisites), and the audit trail.

A GitHub PR's review-api id uses the repository's numeric id, so
`owner/repo#123` is looked up on GitHub: anonymously for a public
repository, and with `GITHUB_TOKEN`, `GH_TOKEN` or `gh auth token` for a
private one.

`--format json` prints the API's records (filtered, for `findings`), for
scripts. The table is for reading and may change.

## Decide on a fix

```
cascadesec approve gh-1388098412-5 e069 --notes "checked the CIDR"
cascadesec reject  gh-1388098412-5 4f97 --notes "SSH must stay open to the VPN range"
cascadesec edit    gh-1388098412-5 a367                       # opens $VISUAL / $EDITOR
cascadesec edit    gh-1388098412-5 a367 --file fixed.ts --yes  # a prepared file, for scripts
```

review-api decides what may be approved, as it does for the dashboard. When
it refuses because a fix this one was drafted on is not settled, the CLI
lists each one and why (rejected, reopened, edited since, not decided) with
the `show` command for it. `reject` is never blocked. Any fixes a reject or
an edit reopens are listed.

`edit` opens the fix's corrected file, under its own name so the editor
highlights it. The editor is `$VISUAL`, then `$EDITOR`, then Notepad on
Windows or `vi` elsewhere. A GUI editor needs its wait flag
(`EDITOR="code --wait"`), or the CLI reads the file back before you have
changed it. Save, review the diff it prints, and confirm. The whole file is
sent and review-api computes the diff. Line endings are kept as saved. If
the request fails, the file stays on disk and the error says how to send it
again with `--file`. An edited fix has not been through the scanner, so its
self-check reads as not passed until the next scan.

Exit codes: 0 done, 1 refused by review-api with a reason, 2 usage or
configuration (including an unknown finding id), 4 not signed in, auth or
service error (spec §5, §10).

## Commit the approved fixes

```
cascadesec commit konradkelly/cascadesec-testbed#5
cascadesec commit gh-1388098412-5 --yes --expect-sha infra/lib/network.ts=09a2fbe6...
```

`commit` prints the plan first. For each file it shows the diff from the
branch to the approved fixes, the fix chain with any link that never passed
its self-check marked UNVERIFIED, the content's sha256, and what is held and
why. Only then does it ask. What it confirms to review-api is exactly what
it printed. If the plan moves before the request lands (another approval,
an edit, a push), nothing is committed and the CLI says to look again; it
never retries on its own. Without a terminal, `--yes` also needs an
`--expect-sha` for every file the plan commits, so a script can only
confirm content it was told about.

Committing needs the `committers` group. That is checked before the prompt,
not after, and someone just added to the group signs in again. The commit
is made by the CascadeSec Fixes app and recorded as your request. The CLI
waits for it (`--timeout`, default 300s; `--no-wait` to return once
recorded) and prints the commit and each file's outcome. A request the
committer held exits 1 with its reasons.

## Scan locally

```
cascadesec scan                         # this directory
cascadesec scan ./infra --fail-on medium
cascadesec scan ./infra --format json --output scan.json
```

Runs the pipeline's own scanner image in Docker with no network: the same
Trivy, Checkov and KICS at the same versions, through the same code, so the
findings are the ones a remote scan gets. Nothing leaves the machine, and
no account or model is involved. Each finding lists its **candidates**, the
controls a remote scan would choose among, or why it would stay raw
(`no-control`, `hygiene`, `not-fixable`, `unreviewed`). The citation, and
any fix, need the pipeline.

CDK apps, Pulumi programs and Helm charts are listed as not scanned
locally, because their IaC exists only once they run. That makes the scan
incomplete rather than clean.

Exit codes: 0 nothing at or above `--fail-on` (default `high`), 1 findings
at or above it, 3 incomplete (a file did not parse, or an app was not run;
`--allow-scan-errors` reports the findings' result instead), 2 usage or no
Docker, 4 the scanner image failed. Checkov rates no severity, so its
findings count only with `--fail-on any`.

### On a repository that already has findings

```
cascadesec baseline                       # write .cascadesec-baseline.json; commit it
cascadesec scan                           # leaves the baselined findings out, and counts them
cascadesec scan --changed-only main       # only findings a scan of main does not have
cascadesec baseline --prune               # drop entries that no longer fire; adds nothing
```

The baseline holds each finding's fingerprint, which does not change when
lines move, so a baselined finding stays baselined when code is added above
it. Adding to the baseline is a decision reviewed in its diff: `scan` never
adds to it, and `--prune` only removes. A baselined finding that stops
firing is listed as fixed, and a baseline written with another scanner image
gets a warning, because a newer rule version can fire findings that are not
regressions.

An app local mode cannot run can be skipped in the repository's
`.cascadesec.toml`, with a reason:

```toml
[[skip_apps]]
path = "platforms/lab-cdk"
reason = "Throwaway lab environment; never deployed"
```

### As a pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/konradkelly/CascadeSec
    rev: <a release tag or commit>
    hooks:
      - id: cascadesec
        # args: [--fail-on, medium]
```

```
pre-commit install --hook-type pre-push
```

It runs on push by default, because a cold scan takes 10 to 20 seconds.
Set `stages: [pre-commit]` on the hook to run it on every commit instead.
It scans the directories of the files being pushed, and the same
directories as they were before the push, read from git. A finding blocks
only if the push brought it, wherever it lands: a typo fixed in a file with
old findings goes through, and a variable turned off in `variables.tf` is
blocked for the bucket it opens in `main.tf`. The baseline still applies on
top. With nothing to compare with (a first commit, `pre-commit run
--all-files`), it judges the changed files themselves, and says so. The
two scans run side by side, so comparing adds about a second. The CLI and
Docker must be installed.

Until the image is published, build it and point the CLI at it:

```
docker build --build-context corpus=corpus -t cascadesec-scanner:local lambda/iac-scanner
$env:CASCADESEC_SCANNER_IMAGE = "cascadesec-scanner:local"     # or pass --image
```

A cold scan takes 10 to 20 seconds on a typical repository, and longer on
module-heavy Terraform (81s on terraform-aws-vpc), most of it container
start and Checkov's import (cli-spec §3.4).

## Test

```powershell
cd cli
../.venv/Scripts/python -m pytest -q
```

The tests run a real loopback listener on the callback ports, with a fake
browser and a fake token endpoint. `test_terraform_agreement.py` keeps the
ports in `auth.py` and `terraform/cognito.tf` the same.
