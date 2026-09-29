"""github-committer Lambda (docs/write-back-spec.md).

Commits a PR's approved fixes to its branch as one commit, when a reviewer
asks for it in the dashboard.

This module starts with the decision of what to commit, plan_commit, which
is pure: findings, their latest review actions and two readers in, a plan
per file out. review-api carries an identical copy for the dashboard's
preview, and corpus/test_corpus.py keeps the two the same.
"""

import difflib
import hashlib


# ======================================================================
# What gets committed (write-back-spec §5). Copied into review-api; keep
# the copies identical -- corpus/test_corpus.py asserts it.
# ======================================================================

def plan_commit(pr_id, findings, latest_actions, read_fix, read_head):
    """Per file with an approved fix, what committing it would do.

    `findings` are the PR's finding records, `latest_actions` maps a
    finding id to the action of its latest ReviewEvent, `read_fix(key)` is a
    fix's corrected file from S3 (None if missing), and `read_head(path)` is
    (the file at the PR head, None) or (None, why it cannot be read). The
    dashboard's preview reads the head from the S3 snapshot; the committer
    reads it from GitHub, and refuses a symlink or a submodule there.

    Approved means the latest ReviewEvent is "approved" or "edited" -- the
    event log, not status, because status is a lossy cache of the last
    resolving action (fix-chain-review-spec §1). A committed fix, and one
    the scan no longer reports, is not planned again.

    Per file, not per finding: fixes are chained, and only a chain's last
    corrected file was built with every earlier fix in it. The tip is the
    end of the longest chain whose every link is approved and unchanged
    since the chain was built. Its content is a whole file drafted on one
    version, so it may only replace that version: base_sha256 must be the
    head's hash, or committing it would revert whatever changed in between
    (write-back-spec §8). A head already equal to the tip's content is
    "already" -- a retried request, or a person who applied the suggestions.

    Returns [{file, outcome, reason, tip, chain, left_out, content,
    content_sha256, diff}] sorted by file. outcome is "commit", "already" or
    "held"; reason says why a file is held. content_sha256 is what a
    reviewer confirms along with the tip: an edit keeps the finding id and
    changes the content, and the commit has to be the content they saw. chain lists the tip's links with whether each was
    verified by its self-check (an edit never is, write-back-spec §5.5).
    left_out names approved fixes the tip does not carry.
    """
    approved_by_file = {}
    for f in findings:
        fix = f.get("proposed_fix") or {}
        if (fix.get("diff") and not fix.get("committed") and not f.get("no_longer_detected")
                and latest_actions.get(f["finding_id"]) in ("approved", "edited")):
            approved_by_file.setdefault(f["file"], {})[f["finding_id"]] = f

    plans = []
    for path in sorted(approved_by_file):
        approved = approved_by_file[path]
        plan = {"file": path, "outcome": "held", "reason": None, "tip": None, "chain": [],
                "left_out": [], "content": None, "content_sha256": None, "diff": None}
        plans.append(plan)

        tip = approved_tip(approved)
        if tip is None:
            plan["reason"] = ("every approved fix here was drafted on top of one that is not "
                              "approved, or has changed since; see the dashboard")
            plan["left_out"] = sorted(f["rule_id"] for f in approved.values())
            continue
        chain = [link["finding_id"] for link in tip["proposed_fix"].get("applies_after") or []]
        chain.append(tip["finding_id"])
        plan["tip"] = tip["finding_id"]
        plan["chain"] = [{"finding_id": i, "rule_id": approved[i]["rule_id"],
                          "verified": bool(approved[i]["proposed_fix"].get("self_check_passed")),
                          "edited": latest_actions[i] == "edited"} for i in chain]
        plan["left_out"] = sorted(approved[i]["rule_id"] for i in approved if i not in chain)

        head, why = read_head(path)
        if head is None:
            plan["reason"] = why
            continue
        content = read_fix(f"fixes/{pr_id}/{tip['finding_id']}/{path}")
        if content is None:
            plan["reason"] = "the fix's corrected file is missing"
            continue
        if _content_sha256(head) == _content_sha256(content):
            plan["outcome"] = "already"
            continue
        base = tip["proposed_fix"].get("base_sha256")
        if not base:
            plan["reason"] = "drafted before fixes recorded their base; run Draft fixes again"
            continue
        if base != _content_sha256(head):
            plan["reason"] = ("the file has changed since these fixes were drafted; "
                              "run Draft fixes again")
            continue
        plan.update(outcome="commit", content=content, content_sha256=_content_sha256(content),
                    diff=_commit_diff(head, content, path))
    return plans


def approved_tip(approved):
    """The end of the longest chain made only of approved fixes, or None.

    github-gateway's chain_tip with "approved" in place of "verified". A
    chain is valid if every link is approved and its diff is the one the
    chain was built on (applies_after records each link's hash): a link
    edited since, or never approved, means the tip's file carries a change
    nobody said yes to. Links from before the chain carried hashes are bare
    ids and cannot be checked, so they fail closed. Ties on length go to
    the larger finding id, as chain_tip's do.
    """
    def valid(fix):
        for link in fix["proposed_fix"].get("applies_after") or []:
            if not isinstance(link, dict):
                return False
            prior = approved.get(link.get("finding_id"))
            if prior is None or _diff_sha256(prior["proposed_fix"]["diff"]) != link.get("diff_sha256"):
                return False
        return True

    candidates = [f for f in approved.values() if valid(f)]
    if not candidates:
        return None
    return max(candidates, key=lambda f: (len(f["proposed_fix"].get("applies_after") or []),
                                          f["finding_id"]))


def _commit_diff(head, content, path):
    """What the reviewer confirms: the head to the tip, the whole change the
    commit makes to this file -- not any one fix's diff, which is in the
    line numbers of an intermediate file."""
    return "".join(difflib.unified_diff(
        head.splitlines(keepends=True), content.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}",
    ))


def _diff_sha256(diff_text):
    """Must stay identical to remediation-agent's helper of the same name."""
    return hashlib.sha256(diff_text.encode("utf-8")).hexdigest()


def _content_sha256(content):
    """Must stay identical to remediation-agent's helper of the same name,
    which records the hash of the file a chain was drafted on."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
