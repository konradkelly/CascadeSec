# cascadesec CLI

CascadeSec from the terminal. Design: [docs/cli-spec.md](../docs/cli-spec.md).

Built so far: signing in (`login`, `logout`, `whoami`) and `version`. The
review commands come next (spec §10, §13 track R).

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

Exit codes: 0 done, 2 usage or configuration, 4 not signed in, auth or
service error (spec §5).

## Test

```powershell
cd cli
../.venv/Scripts/python -m pytest -q
```

The tests run a real loopback listener on the callback ports, with a fake
browser and a fake token endpoint. `test_terraform_agreement.py` keeps the
ports in `auth.py` and `terraform/cognito.tf` the same.
