# remediation-agent — build brief

I'm building `remediation-agent`, one Lambda in a serverless AppSec
pipeline (`terraform-scanner` and `mapping-agent` are already built and
deployed by a teammate). Here's the full contract to build against — no
AWS credentials needed, everything below is designed to be built and
tested locally against mocks/fixtures.

**The job**: for each finding with `status: "mapped"` in DynamoDB, draft a
fix via the Anthropic API, then *prove it works* by re-scanning the
patched file with the already-deployed `terraform-scanner` Lambda, before
ever showing it to a human. `self_check_passed` must be computed in code
from that re-scan — never asserted by the LLM. This is the project's core
integrity guarantee.

On success, `status` becomes `fix-proposed`. If self-check fails (issue
not cleared, or a new one introduced), `status` becomes `needs-human-only`
— still surfaced to a reviewer, just without a diff attached.

## Invocation contract

Matches the convention used by the other two Lambdas:

```json
{ "pr_id": "manual-test-1" }
```

## Processing steps

1. Query DynamoDB for findings under `pk = PR#<pr_id>`, `status = "mapped"`,
   then **group them by `file` and process each file as a chain**, in a
   deterministic order (position in the file, then identity). Every file in
   the live table carries between 3 and 22 findings, so drafting each fix
   from the pristine snapshot produces that many competing whole-file
   rewrites of the same few lines — on `demo-1`, two of them created the same
   resource address with different arguments, which is Terraform that will
   not validate rather than a merge conflict. Each fix is drafted against the
   file as the previous **scanner-verified** fix in that file left it, and
   `proposed_fix.applies_after` records the ordered finding ids it is built
   on. A fix the scanner rejected does not advance the chain; a fix held for
   human review (deleted resource, declared assumption) does, because the
   rescan still proved it a sound edit.
   Before drafting, check whether an earlier fix in this file already took the
   finding's `(source, rule_id)` to zero. If so, write `status: "superseded"`
   with `superseded_by`, and **do not call the model** — there is nothing left
   to fix. Skipping is not merely an optimisation: the model would be handed a
   file where the issue is already gone, return it unchanged, and the
   self-check would compare a rescan count of 0 against a baseline of 0.
   `0 < 0` is False, so a genuinely resolved finding would be written up as a
   fix that failed to clear it. Only a rule taken to *zero* supersedes —
   clearing one of three instances leaves the finding real.
2. Once per file, fetch the original from
   `s3://<ARTIFACTS_BUCKET>/scans/<pr_id>/<finding.file>`. `finding.file`
   is a path relative to the scan prefix (e.g. `"main.tf"`) — this was
   recently fixed on the deployed scanner (it used to be a broken
   ephemeral `/tmp` path), so make sure you're working from the latest
   `iac-scanner/handler.py`.
3. Call the Anthropic API for a **complete corrected version of the
   file** — not a hand-written diff. Use `output_config.format` with a
   JSON schema for `{corrected_file_content, rationale}`
   (schema-guaranteed JSON, no free-text parsing — see
   `mapping-agent/handler.py` for the exact pattern: Secrets Manager
   fetch-and-cache, `output_config.format` usage).
4. Compute the unified diff yourself in code, via Python's
   `difflib.unified_diff`, between the **base** content this fix was drafted
   against (not the pristine snapshot, unless this is the file's first fix)
   and the corrected content.
   Don't ask the LLM to author the diff directly — a hand-authored diff
   risks not applying cleanly (wrong line numbers/context); a
   mechanically computed one always will.
5. Upload the corrected content to a scratch location:
   `fixes/<pr_id>/<finding_id>/main.tf` — not under `scans/`, which expires,
   because this file is later read back as the base for every fix drafted on
   top of it and overwritten by a reviewer's edit (originally specified as
   `scans/<pr_id>/self-check-<finding_id>/main.tf`, must stay under the
   `scans/` prefix — that's what's IAM-permitted, see below).
6. Invoke `terraform-scanner` synchronously (`lambda:InvokeFunction`) with:
   ```json
   {
     "pr_id": "<pr_id>-self-check-<finding_id>",
     "s3_prefix": "fixes/<pr_id>/<finding_id>/",
     "iac_type": "terraform",
     "persist": false
   }
   ```
   `persist: false` means this re-scan's findings come back to you in the
   response but are never written to DynamoDB — this mode already exists
   on the deployed function.
   The response also carries `scan_errors` — files the scanner could not
   parse. **Check it before step 7 and stop if it is non-empty**: an
   unparseable file yields no findings, and step 7 reads "no findings" as
   the finding having been cleared, so a fix that drops a brace would come
   back `self_check_passed: true`. Write `needs-human-only` with
   `scan_errors` recorded on the fix, and don't compute a verdict — nothing
   was verified either way. Likewise, if the invocation itself returns a
   `FunctionError` (the scanner raises `ScannerError` when a tool produces
   no output at all), leave the finding at `mapped` so a re-run retries it,
   rather than scoring the fix on a scan that never ran.
7. Compute `self_check_passed` in code:
   - **Cleared**: no finding in the re-scan matches the original finding's
     `(source, rule_id)`.
   - **No new findings**: every `(source, rule_id)` in the re-scan was
     already present in the baseline for this fix. The baseline is the
     DynamoDB finding set for the file only for the file's *first* fix;
     after that it is the previous accepted fix's own rescan. Comparing a
     later fix against the original counts would let it silently undo an
     earlier one — a rule the earlier fix cleared is still present in the
     original baseline, so its return would not register as new.
   - `self_check_passed = cleared AND no_new_findings`.
8. Write the result back:
   ```python
   table.update_item(
       Key={"pk": finding["pk"], "sk": finding["sk"]},
       UpdateExpression="SET proposed_fix = :pf, #status = :status, updated_at = :now",
       ExpressionAttributeNames={"#status": "status"},
       ExpressionAttributeValues={
           ":pf": {
               "diff": diff_text,
               "rationale": rationale,
               "self_check_passed": self_check_passed,
               "self_check_new_findings": self_check_new_findings,
               "scan_errors": scan_errors,
               "applies_after": applies_after,
           },
           ":status": "fix-proposed" if self_check_passed else "needs-human-only",
           ":now": now_iso,
       },
   )
   ```

## Env vars

Your `handler.py` should read these via `os.environ` (matching the other
two Lambdas' convention — you won't have real values locally since you're
mocking AWS calls, you just need the names): `DYNAMODB_TABLE`,
`ARTIFACTS_BUCKET`, `ANTHROPIC_SECRET_ARN`, `ANTHROPIC_MODEL`.

## IAM — already granted on your execution role, nothing to request

| Permission | Scope |
|---|---|
| `logs:CreateLogGroup/CreateLogStream/PutLogEvents` | own log group |
| `dynamodb:GetItem/PutItem/UpdateItem/Query` | the findings table |
| `secretsmanager:GetSecretValue` | the Anthropic API key secret |
| `lambda:InvokeFunction` | `terraform-scanner`'s function ARN specifically |
| `s3:GetObject`, `s3:PutObject` | `scans/*` prefix only |

Two gaps to design around rather than assume are covered — both bit the
`terraform-scanner` build already:

- **No `s3:ListBucket`.** If you ever list objects under a prefix
  (`list_objects_v2`/paginator) rather than fetching an exact known key,
  you'll get `AccessDenied` — it's a separate bucket-level grant from
  `GetObject`. The flow above only ever reads a known key, so you likely
  won't need it.
- **No `dynamodb:BatchWriteItem`.** boto3's `Table.batch_writer()` calls
  this under the hood, not `PutItem`. Use `update_item`/`put_item`
  directly (already covered), or flag if you need batch writes.

## Model

Default `claude-opus-5`. Diff drafting is a harder task than
mapping-agent's classification step, so this is a more defensible default
here than it was there — but expose it as an overridable
variable/env var rather than hardcoding, same pattern as
`mapping_agent_model` in the Terraform.

## Testing — no AWS needed

`lambda/remediation-agent/fixtures/` has two before/after `.tf` pairs
(`s3-bucket-encryption/`, `open-ssh-ingress/`), each with a
`scan-response.json` per side that is **real captured output** from
actually invoking the deployed `terraform-scanner` — not hand-written, so
it's guaranteed accurate. Mock your Lambda's invoke call to
`terraform-scanner` to return the appropriate fixture response given the
S3 prefix you pass it, and use these to test the self-check comparison
logic in step 7 above. Both fixtures are "clean fix" cases
(`self_check_passed` should end up `True`, `self_check_new_findings`
empty) — there's no failure-path fixture yet, add one if you want to test
that branch too. README in that folder has more detail.
