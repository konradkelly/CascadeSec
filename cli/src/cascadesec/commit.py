"""`cascadesec commit`: land a PR's approved fixes on its branch
(docs/cli-spec.md §10; docs/write-back-spec.md).

review-api decides everything that matters, as for the dashboard's commit
panel: what the plan is, who may commit (the `committers` group), and
whether the plan the person confirmed is still the plan. github-committer
re-reads every file from GitHub before writing and holds one that moved.
This module's job is to make the person look at the plan before it is
confirmed, and to confirm only what they looked at:

  - The plan is printed first -- per file, the head-to-tip diff, the fix
    chain with its unverified links, what is held and why -- and every
    refusal the plan already implies (not a committer, write-back not
    deployed, a request in flight) is reported then, before any prompt.
  - The confirmation sent is built from the printed plan: file, tip and
    content_sha256. If the plan moved in between, review-api refuses with a
    409 and the CLI says to look again. It never re-fetches and retries on
    its own, because that would commit something nobody looked at.
  - Without a terminal, `--yes` is not enough: `--expect-sha FILE=SHA` must
    name every file the plan would commit, with its content hash, so a
    script can only confirm content it was told about.

Then it waits: the request is handed to github-committer asynchronously,
and the CLI polls its record (2s, doubling, 15s cap) until it ends. Polling
is the only way this side waits -- a synchronous invoke that long is what
fails client-side (spec §4.4) -- and a timeout prints the request id
rather than abandoning it.
"""

import sys
import time

from cascadesec import api
from cascadesec.errors import REFUSED, SERVICE, USAGE, CliError

ACTIVE = {"requested", "committing"}
POLL_START, POLL_CAP = 2, 15
DEFAULT_TIMEOUT = 300


def parse_expect(values):
    """--expect-sha FILE=SHA, repeated -> {file: sha}."""
    expected = {}
    for value in values or ():
        path, sep, sha = value.rpartition("=")
        sha = sha.strip().lower()
        if not sep or not path or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise CliError(f"--expect-sha takes FILE=SHA256, got {value!r}", USAGE)
        expected[path] = sha
    return expected


def to_commit(plan):
    return [f for f in plan.get("files") or [] if f.get("outcome") == "commit"]


def refusal_before_prompt(plan, who):
    """The reason this plan cannot be committed by this person now, or None.
    Each is review-api's own rule, read from the plan rather than learnt from
    a 403 after the person has said yes."""
    if not plan.get("write_back_deployed"):
        return "write-back is not deployed in this environment"
    if not plan.get("can_commit"):
        return (f"committing needs membership of the `committers` group, and {who} is not in it "
                "on this token. Someone just added signs in again (`cascadesec login`), because "
                "groups are fixed when a token is issued.")
    latest = plan.get("latest_request") or {}
    if latest.get("status") in ACTIVE:
        return (f"commit request {latest.get('request_id')} for this PR is still "
                f"{latest.get('status')}; wait for it to finish, then look at the plan again")
    return None


def confirmation(plan, expected=None):
    """[{file, tip, content_sha256}] for the files the plan would commit,
    exactly as printed. With `expected`, the plan must match it file for
    file -- a file the script did not name, or a hash it did not expect,
    is a plan nobody confirmed."""
    files = to_commit(plan)
    confirm = [{"file": f["file"], "tip": f["tip"], "content_sha256": f["content_sha256"]}
               for f in files]
    if expected is not None:
        planned = {c["file"]: c["content_sha256"] for c in confirm}
        if planned != expected:
            lines = ["the commit plan is not the one --expect-sha describes:"]
            for path in sorted(set(planned) | set(expected)):
                if path not in expected:
                    lines.append(f"  - {path} would be committed, and was not expected")
                elif path not in planned:
                    lines.append(f"  - {path} was expected, and is not in the plan to commit")
                elif planned[path] != expected[path]:
                    lines.append(f"  - {path} would commit {planned[path]}, not {expected[path]}")
            raise CliError("\n".join(lines), REFUSED)
    return confirm


def request(client, pr_id, confirm):
    """POST the confirmation; the request id. A moved plan is a refusal the
    person resolves by looking again, so it is reported, never retried."""
    try:
        reply = client.request("POST", "prs", pr_id, "commits", body={"confirm": confirm})
    except api.ApiError as e:
        body = e.body if isinstance(e.body, dict) else {}
        if e.status == 409 and body.get("changed") is not None:
            changed = ", ".join(body["changed"]) or "a file"
            raise CliError(f"the commit plan changed after it was shown ({changed}); nothing was "
                           f"committed. Look at it again: `cascadesec commit {pr_id}`", REFUSED) from None
        if e.status == 403:
            raise CliError(str(e), REFUSED) from None
        raise
    return reply["request_id"]


def wait(client, pr_id, request_id, timeout=DEFAULT_TIMEOUT, sleep=time.sleep, now=time.monotonic,
         progress=None):
    """Poll the request until it ends; its final record."""
    progress = progress or (lambda line: print(line, file=sys.stderr, flush=True))
    deadline = now() + timeout
    delay, last = POLL_START, None
    while True:
        record = client.get("prs", pr_id, "commits", request_id)
        status = record.get("status")
        if status != last:
            progress(f"cascadesec: commit request {request_id}: {status}")
            last = status
        if status not in ACTIVE:
            return record
        if now() + delay > deadline:
            raise CliError(f"commit request {request_id} is still {status} after {timeout}s. It "
                           "keeps running; `cascadesec commit` shows it as the latest request.",
                           SERVICE)
        sleep(delay)
        delay = min(delay * 2, POLL_CAP)


def outcome_code(record):
    """Exit code for a finished request: committed is done; held means the
    committer refused with a reason (the branch moved, a file changed);
    failed is the service's fault."""
    status = record.get("status")
    if status == "committed":
        return 0
    if status == "held":
        return REFUSED
    return SERVICE
