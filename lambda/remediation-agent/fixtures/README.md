# remediation-agent test fixtures

For remediation-agent's self-check step: mock `terraform-scanner`'s response
against these rather than invoking the real deployed Lambda.

## What's here

Two before/after `.tf` pairs, each demonstrating one fix clearing its
target finding(s). `before/main.tf` has the issue; `after/main.tf` is a
hand-written fix for it. Each side's `scan-response.json` is **not
hand-authored** — it's the real, captured response from actually invoking
the deployed `terraform-scanner` (`persist: false`) against that exact
file. Captured 2026-09-01 against tfsec + Checkov, and re-captured
2026-09-12 when the scanner moved to Trivy 0.74.0 + Checkov 3.3.16 (so
findings are `source: trivy` with Trivy's ids, `AWS-0132`). If the
Trivy/Checkov versions change later and something here looks stale,
regenerate by invoking the real Lambda rather than hand-editing these —
that defeats the point of using captured ground truth.

- **`s3-bucket-encryption/`** — adding an
  `aws_s3_bucket_server_side_encryption_configuration` resource with a KMS
  key clears `trivy:AWS-0132` and `checkov:CKV_AWS_145` (15 → 13 findings).
  The bucket's other pre-existing findings (no versioning, no logging, no
  public-access block, etc.) deliberately remain in `after/` — the fixture
  demonstrates fixing *one* specific finding, not making the file fully
  compliant. (Until 2026-09-12 the fix was AES256 and cleared tfsec's
  `aws-s3-enable-bucket-encryption`; Trivy has deprecated that check, since
  AWS encrypts S3 by default, so the customer-managed-key check is the one
  a bare bucket raises now, and the fix moved to KMS to clear it.)
- **`open-ssh-ingress/`** — narrowing a security group's SSH ingress from
  `0.0.0.0/0` to `10.0.0.0/16` clears **both**
  `checkov:CKV_AWS_24` and `trivy:AWS-0107` at once (6 → 4 findings) — a
  good case for testing that your self-check logic handles a fix clearing
  findings from more than one scanner source simultaneously.

Neither pair introduces a new rule_id in `after/` that wasn't already
present in `before/` — both are "clean" fixes, useful for asserting
`self_check_passed = True, self_check_new_findings = []`. If you want a
case where self-check should *fail* (new finding introduced, or the
original issue not actually cleared), you'll need to add one — these two
only cover the success path.

## The unparseable case lives elsewhere

There is deliberately no `before/after` pair here for "the agent returned a
file that doesn't parse". The broken file is
[`lambda/terraform-scanner/fixtures/unparseable/main.tf`](../../terraform-scanner/fixtures/unparseable/main.tf),
and `test_handler.py` reads it from there rather than keeping a copy.

Two reasons. It's the scanner's input as much as the agent's output, so a
copy on each side would drift the moment either was edited. And a captured
`scan-response.json` would add nothing: what the scanner reports for that
file is an empty `findings` list plus a `scan_errors` entry, and it's the
`scan_errors` entry — not any finding — that the gate keys on. The tests mock
that response directly. Everything the ground-truth rule above protects (real
rule_ids, real line ranges, real severities) is absent from this case by
construction.

## Using these

Mock your Lambda's invocation of `terraform-scanner` so that, given the
`before/` snapshot's S3 prefix, it returns `before/scan-response.json`, and
given `after/`'s prefix, `after/scan-response.json`. Your self-check logic
should then determine, from that pair alone: is the finding you're
remediating gone in `after`, and is `after`'s finding set otherwise a
subset of `before`'s? `finding_id` values are deterministic (a hash of
`source`, `rule_id`, `file`, `line_range` — see
[`lambda/terraform-scanner/handler.py`](../../terraform-scanner/handler.py)),
so they'll reproduce exactly if you regenerate these yourself.

`after/main.tf` is also usable as a concrete example of "what a correct
fix looks like" if you want to sanity-check your diff-computation step
(`difflib.unified_diff` against `before/main.tf`) independent of what your
LLM call actually returns.
