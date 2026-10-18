# cascadesec CLI

CascadeSec from the terminal. Design: [docs/cli-spec.md](../docs/cli-spec.md).

Built so far: signing in (`login`, `logout`, `whoami`), reading a PR's
findings (`findings`, `show`), deciding on a fix (`approve`, `reject`,
`edit`) and `version`. Committing comes next (spec §10, §13 track R).

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

## Test

```powershell
cd cli
../.venv/Scripts/python -m pytest -q
```

The tests run a real loopback listener on the callback ports, with a fake
browser and a fake token endpoint. `test_terraform_agreement.py` keeps the
ports in `auth.py` and `terraform/cognito.tf` the same.
