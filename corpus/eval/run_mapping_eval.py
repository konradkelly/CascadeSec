#!/usr/bin/env python3
"""Mapping accuracy (docs/completion.md phase 2 step 1), as three numbers.

  python run_mapping_eval.py                                  # corpus correctness: no AWS, no model
  python run_mapping_eval.py --pr-id eval-map-1 --pr-id eval-map-2 --pr-id eval-map-3
  python run_mapping_eval.py ... --report results.json

Each labelled pair in cases/*/expected.json names the controls a correct
mapping of that finding may cite (`expected_controls`, rules in README.md).
mapping-agent must pick exactly one of the corpus's candidates for a rule,
and 158 of the 180 pairs have only one, so on most pairs the model makes no
choice at all. One accuracy figure would mostly measure rule_mappings.json
and dilute the agent's real choices, so this reports three:

  corpus      read from the files alone: for each pair, whether every
              candidate is right (the agent cannot be wrong), some are (its
              choice decides), none is (it cannot be right), or there is no
              candidate, and whether no candidate was right to offer.
  choice      from pipeline runs: on the pairs whose candidates are only
              partly right, how often the agent picked a right one, per run
              and across runs, since the answer varies.
  citation    from the same runs: whether each mapped finding's citation is
              what the prompt asks for, a verbatim excerpt of under 15 words
              from the chosen control's text. Nothing checks it in the
              pipeline, and the dashboard shows it in quotation marks.

The runs are made beforehand, against the deployed stack, with the pipeline
stopped after mapping:

  python scripts/scan.py corpus/eval/cases --pr-id eval-map-1 --no-remediate

Scoring reads those runs' findings from DynamoDB and changes nothing.
Needs AWS credentials only when --pr-id is given.
"""

import argparse
import collections
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CASES = HERE / "cases"
CORPUS = HERE.parent
REPO = CORPUS.parent
sys.path.insert(0, str(REPO / "core"))
from cascadesec_core.mapping import candidates_for  # noqa: E402

sys.path.insert(0, str(HERE))
from run_eval import CASE_FILE_TARGET_TYPES  # noqa: E402

CITATION_MAX_WORDS = 15
# Pairs, by what their candidates allow the agent to do.
EVERY_RIGHT, SOME_RIGHT, NONE_RIGHT = "every candidate right", "some candidates right", "no candidate right"
RIGHTLY_EMPTY, MISSED = "no candidate, rightly", "no candidate, though one applies"


def control(entry):
    return (entry["framework"], entry["control_id"])


def load_pairs(cases_dir=CASES):
    """[{case, source, rule_id, target_type, expected: {(framework, id)}}]."""
    pairs = []
    for case in sorted(p for p in cases_dir.iterdir() if p.is_dir()):
        target_types = {CASE_FILE_TARGET_TYPES[p.name] for p in case.iterdir() if p.name in CASE_FILE_TARGET_TYPES}
        assert len(target_types) <= 1, f"{case.name} mixes target types {target_types}"
        for entry in json.loads((case / "expected.json").read_text(encoding="utf-8"))["expected"]:
            pairs.append({"case": case.name, "source": entry["source"], "rule_id": entry["rule_id"],
                          "target_type": next(iter(target_types), None),
                          "expected": {control(c) for c in entry["expected_controls"]}})
    return pairs


def load_corpus(corpus=CORPUS):
    """The candidate lists, and {(framework, id): {title, text}}: mapping-agent
    shows the model both, so a citation may come from either."""
    mappings = json.loads((corpus / "rule_mappings.json").read_text(encoding="utf-8"))["mappings"]
    controls = {}
    for path in (corpus / "frameworks").glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        controls.update({(data["framework"], c["control_id"]): {"title": c["title"], "text": c["text"]}
                         for c in data["controls"]})
    return mappings, controls


def classify(pair, mappings):
    """What the candidates leave the agent able to do on this pair."""
    offered = {control(c) for c in candidates_for(mappings, pair)}
    right = offered & pair["expected"]
    if not offered:
        return RIGHTLY_EMPTY if not pair["expected"] else MISSED
    if right == offered:
        return EVERY_RIGHT
    return SOME_RIGHT if right else NONE_RIGHT


def score_corpus(pairs, mappings):
    return collections.Counter(classify(p, mappings) for p in pairs)


def words(text):
    return re.findall(r"\S+", text)


VERBATIM, FROM_TITLE, ELIDED = "verbatim", "verbatim, from the title", "elided, the cut marked"
REWORDED, NOT_AN_EXCERPT = "reworded", "not an excerpt"
CITATION_VERDICTS = (VERBATIM, FROM_TITLE, ELIDED, REWORDED, NOT_AN_EXCERPT)
ELLIPSIS = re.compile(r"\s*(?:\.\.\.|…)\s*")


def citation_verdict(citation, control):
    """What the citation is, against the control it cites ({title, text}),
    and whether it is under the word limit. In order:

      verbatim                 the text has it, whitespace and quotes aside
      verbatim, from the title the title has it; the prompt asks for the text
      elided, the cut marked   pieces joined by '...', each in the text, in order
      reworded                 the same words, with case or punctuation changed
      not an excerpt           none of these: words changed or joined unmarked

    The first three are faithful quotations. The first run found every
    citation that missed the first check in the second or third, but for an
    unmarked rewrite of a NIST template's [Selection] brackets."""
    def squash(s, loose=False):
        s = " ".join(words(s.strip().strip("\"'“”‘’")))
        return re.sub(r"[^\w\s]", "", s.lower()) if loose else s
    quoted = squash(ELLIPSIS.sub(" ... ", citation.strip().strip("\"'“”‘’")).strip(" .…"))
    text, title = squash(control.get("text", "")), squash(control.get("title", ""))
    pieces = [p for p in ELLIPSIS.split(quoted) if p]
    if not pieces:
        verdict = NOT_AN_EXCERPT
    elif len(pieces) == 1 and pieces[0] in text:
        verdict = VERBATIM
    elif len(pieces) == 1 and pieces[0] in title:
        verdict = FROM_TITLE
    elif len(pieces) > 1 and _in_order(pieces, text):
        verdict = ELIDED
    elif squash(" ".join(pieces), True) in squash(text, True):
        verdict = REWORDED
    else:
        verdict = NOT_AN_EXCERPT
    return verdict, len(words(ELLIPSIS.sub(" ", citation))) < CITATION_MAX_WORDS


def _in_order(pieces, text):
    at = 0
    for piece in pieces:
        found = text.find(piece, at)
        if found < 0:
            return False
        at = found + len(piece)
    return True


def score_run(pairs, mappings, findings):
    """Each labelled pair's findings in one run, scored. `findings` are the
    run's records: file (case/...), source, rule_id, status, and
    control_mappings once mapped."""
    by_pair = collections.defaultdict(list)
    for f in findings:
        by_pair[(f["file"].split("/", 1)[0], f["source"], f["rule_id"])].append(f)
    scored = []
    for pair in pairs:
        kind = classify(pair, mappings)
        for f in by_pair.get((pair["case"], pair["source"], pair["rule_id"]), []):
            chosen = [control(m) for m in f.get("control_mappings") or []]
            if chosen:
                outcome = "right" if chosen[0] in pair["expected"] else "wrong"
            elif kind in (RIGHTLY_EMPTY, MISSED):
                outcome = "no candidate"
            else:
                outcome = "not mapped"    # candidates existed; the call failed or was refused
            scored.append({"pair": pair, "kind": kind, "outcome": outcome, "finding": f,
                           "chosen": chosen[0] if chosen else None})
    return scored


def citations(findings, controls):
    """[(verdict, under the limit, finding)] for every mapped finding in a
    run, labelled or not: the dashboard shows all of them."""
    out = []
    for f in findings:
        for m in f.get("control_mappings") or []:
            verdict, short = citation_verdict(m.get("citation_span", ""), controls.get(control(m), {}))
            out.append((verdict, short, f))
    return out


# ---------- the run ----------

def findings_of(pr_id, table):
    """Every finding record of a run, paginated."""
    items, kwargs = [], {"KeyConditionExpression": "pk = :pk AND begins_with(sk, :sk)",
                         "ExpressionAttributeValues": {":pk": f"PR#{pr_id}", ":sk": "FINDING#"}}
    while True:
        page = table.query(**kwargs)
        items += page["Items"]
        if "LastEvaluatedKey" not in page:
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def table_from_terraform():
    out = subprocess.run(["terraform", f"-chdir={REPO / 'terraform'}", "output", "-raw", "findings_table_name"],
                         capture_output=True, text=True, check=True)
    import boto3
    return boto3.resource("dynamodb").Table(out.stdout.strip())


def pct(n, d):
    return f"{n}/{d} = {100 * n / d:.1f}%" if d else f"{n}/0"


def report(pairs, mappings, controls, runs, out=print):
    corpus = score_corpus(pairs, mappings)
    out(f"CORPUS  {len(pairs)} labelled pairs, by what their candidates allow (rule_mappings.json)")
    for kind in (EVERY_RIGHT, SOME_RIGHT, NONE_RIGHT, RIGHTLY_EMPTY, MISSED):
        out(f"  {kind:34} {corpus[kind]:4}")
    cannot_err = corpus[EVERY_RIGHT] + corpus[RIGHTLY_EMPTY]
    out(f"  the agent cannot be wrong on       {pct(cannot_err, len(pairs))}")
    out(f"  the agent cannot be right on       {pct(corpus[NONE_RIGHT] + corpus[MISSED], len(pairs))}")
    result = {"corpus": dict(corpus), "runs": {}}
    if not runs:
        return result

    out(f"\nCHOICE  on pairs where only some candidates are right ({corpus[SOME_RIGHT]} pairs)")
    picks = collections.defaultdict(list)
    for pr_id, findings in runs.items():
        scored = score_run(pairs, mappings, findings)
        outcomes = collections.Counter(s["outcome"] for s in scored)
        choosing = [s for s in scored if s["kind"] == SOME_RIGHT]
        right = sum(s["outcome"] == "right" for s in choosing)
        out(f"  {pr_id}: {pct(right, len(choosing))} of findings; all labelled findings {dict(outcomes)}")
        for s in choosing:
            picks[(s["pair"]["case"], s["pair"]["source"], s["pair"]["rule_id"])].append(s["outcome"])
        cited = citations(findings, controls)
        result["runs"][pr_id] = {
            "outcomes": dict(outcomes), "choice_right": right, "choice_total": len(choosing),
            "citations": dict(collections.Counter(v for v, _, _ in cited)),
            "citations_over_limit": sum(not short for _, short, _ in cited),
            "scored": [{"case": s["pair"]["case"], "source": s["pair"]["source"], "rule_id": s["pair"]["rule_id"],
                        "kind": s["kind"], "outcome": s["outcome"], "chosen": s["chosen"]} for s in scored],
        }
    steady = sum(len(set(v)) == 1 for v in picks.values())
    out(f"  pairs answered the same way in every run: {pct(steady, len(picks))}")

    out("\nCITATION  every mapped finding, labelled or not")
    for pr_id, r in result["runs"].items():
        total = sum(r["citations"].values())
        faithful = sum(r["citations"].get(v, 0) for v in (VERBATIM, FROM_TITLE, ELIDED))
        out(f"  {pr_id}: a faithful quotation {pct(faithful, total)}; "
            f"{CITATION_MAX_WORDS} words or more {r['citations_over_limit']}")
        for verdict in CITATION_VERDICTS:
            out(f"    {verdict:26} {r['citations'].get(verdict, 0):4}")
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pr-id", action="append", default=[], help="a pipeline run of the cases to score; repeat")
    ap.add_argument("--report", type=pathlib.Path, help="also write the full result as JSON")
    args = ap.parse_args(argv)
    pairs = load_pairs()
    mappings, controls = load_corpus()
    table = table_from_terraform() if args.pr_id else None
    runs = {pr_id: findings_of(pr_id, table) for pr_id in args.pr_id}
    result = report(pairs, mappings, controls, runs)
    if args.report:
        args.report.write_text(json.dumps(result, indent=2, default=list), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
