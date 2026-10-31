"""Which controls a finding may be mapped to, and why it stays raw when none
may: the deterministic half of mapping, decided before any model is asked.

mapping-agent calls these with the corpus it loads from S3. iac-scanner's
local_main.py keeps copies to label local findings the same way, held to
these by corpus/test_corpus.py until the scanner image ships this package
too: local output predicts what the pipeline will do, so it must decide it
the same way.
"""

# Mapped, but never handed to remediation: detection only until a fix to
# their source can be verified by synthesizing again (sandbox-spec §9).
DETECTION_ONLY_TARGET_TYPES = {"cdk", "pulumi"}

# The reason a rule with no candidate gets when rule_mappings.json's
# `unmapped` section does not name it.
UNREVIEWED = "unreviewed"


def candidates_for(rule_mappings, finding):
    """The candidate controls that apply to this finding.

    A rule's candidates are keyed by (source, rule_id), which is all a rule
    normally needs: CKV_AWS_145 only ever fires on Terraform. It is not
    enough for the rules that fire on more than one language. CKV_SECRET_6
    is the case that forced this -- a plaintext secret, raised on a .tf file
    and on a Kubernetes manifest alike. The Kubernetes control that fits it
    (CIS Kubernetes 5.4.2, external secret storage) must not be offered as a
    candidate for the Terraform finding, and before this it could only be
    added to both or neither.

    So a candidate may carry an optional `target_type` that scopes it. One
    without it is universal, which is every candidate written before
    2026-09-20 and most written after. One with it is offered only when the
    finding came from that target type.

    A finding with no target_type -- written before the field split
    (multi-iac-spec §3.1) -- matches universal candidates only. That is the
    safe direction: it withholds a control rather than citing one against a
    finding whose language is unknown.
    """
    refs = rule_mappings.get(f"{finding['source']}:{finding['rule_id']}") or []
    target_type = finding.get("target_type")
    # A synthesized CDK template is CloudFormation, and a control scoped to
    # CloudFormation fits it as well as it fits a hand-written template.
    matches = {target_type} | ({"cloudformation"} if target_type == "cdk" else set())
    return [r for r in refs
            if "target_type" not in r or r["target_type"] in matches]


def unmapped_reason(unmapped_rules, finding):
    """Why this finding has no candidate. Keyed on (source, rule_id) like
    the mappings: a rule is triaged once, not per finding or per target.
    The table is passed in, so a runtime loads it from wherever it keeps
    the corpus."""
    entry = unmapped_rules.get(f"{finding['source']}:{finding['rule_id']}")
    return entry["reason"] if entry else UNREVIEWED
