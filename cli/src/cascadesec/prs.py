"""Which PR a command means (docs/cli-spec.md §10, "Finding a PR id").

review-api keys a GitHub PR as `gh-<repo_id>-<number>`, where repo_id is
the repository's **numeric** id (webhook-receiver's pr_id) -- stable across
renames and transfers, and known by nobody. So a command also accepts
`owner/repo#123` or the PR's URL and asks GitHub for the id:

  - anonymously first, which is enough for a public repository;
  - then, if GitHub says 404 or 403 (a private repository, or the anonymous
    rate limit), with GITHUB_TOKEN, GH_TOKEN or `gh auth token`, whichever
    is present. Nothing is spawned or sent for a public repository.

Anything else is taken as the id itself: `gh-1352957770-50`, a manual run's
`manual-test-1`, `cli-<project>-<ref>`. The id is checked against the
characters ids are made of, because it becomes part of a request path.
"""

import json
import re
import shutil
import subprocess
import urllib.error
import urllib.request

from cascadesec import __version__
from cascadesec.errors import SERVICE, USAGE, CliError

GITHUB_API = "https://api.github.com"
HTTP_TIMEOUT_SECONDS = 15

_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_REPO = r"[A-Za-z0-9._-]+"
SHORT_REF = re.compile(rf"^(?P<owner>{_NAME})/(?P<repo>{_REPO})#(?P<number>\d+)$")
URL_REF = re.compile(
    rf"^https://github\.com/(?P<owner>{_NAME})/(?P<repo>{_REPO})/pull/(?P<number>\d+)(?:[/?#].*)?$")
PR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


def resolve(ref, env, github_get=None, gh_token=None):
    """The review-api pr_id that `ref` names."""
    github_get = github_get or _github_get
    gh_token = gh_token or _gh_cli_token
    ref = ref.strip()
    match = SHORT_REF.match(ref) or URL_REF.match(ref)
    if match:
        repo_id = _repo_id(match["owner"], match["repo"], env, github_get, gh_token)
        return f"gh-{repo_id}-{int(match['number'])}"
    if not PR_ID.match(ref):
        raise CliError(
            f"{ref!r} is not a PR id or a GitHub PR (owner/repo#123, or the PR's URL)", USAGE)
    return ref


def _repo_id(owner, repo, env, github_get, gh_token):
    url = f"{GITHUB_API}/repos/{owner}/{repo}"
    status, body = github_get(url, None)
    if status in (403, 404):
        token = env.get("GITHUB_TOKEN") or env.get("GH_TOKEN") or gh_token()
        if token:
            status, body = github_get(url, token)
    if status == 200 and isinstance(body, dict) and isinstance(body.get("id"), int):
        return body["id"]
    if status == 404:
        raise CliError(
            f"GitHub has no repository {owner}/{repo} that this machine can see. For a private "
            "repository, set GITHUB_TOKEN or sign in with `gh auth login`; or pass the PR id "
            "(gh-<repo_id>-<number>) from the dashboard's URL.", USAGE)
    raise CliError(f"could not look up {owner}/{repo} on GitHub (HTTP {status})", SERVICE)


def _github_get(url, token):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"cascadesec-cli/{__version__}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise CliError(f"could not reach GitHub: {e}", SERVICE) from None
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, None


def _gh_cli_token():
    """`gh auth token`, when the GitHub CLI is installed and signed in."""
    gh = shutil.which("gh")
    if not gh:
        return None
    try:
        result = subprocess.run([gh, "auth", "token"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    token = result.stdout.strip()
    return token if result.returncode == 0 and token else None
