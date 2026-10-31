# CascadeSec: notes for Claude

## Deploying (terraform/)

Deploy through `scripts/deploy.py`, never with a bare `terraform apply`:

```
python scripts/deploy.py                  # checks, then `terraform plan -input=false`; applies nothing
python scripts/deploy.py --apply-saved    # applies exactly the plan the last run saved
```

It stops when `terraform.tfvars` lacks a variable that gates resources, when
the code Terraform packages differs from `origin/main`, or when the plan
destroys or replaces anything not named with `--allow-destroy`. See its
docstring for why each check exists.

Rules for you:

- **Never predict what a plan will do.** Run the script, which is read-only
  without `--apply-saved`, and report the plan's real summary: every
  create, update, replace and destroy, by address. "Expect only X to
  change" is a guess, and on 2026-10-11 a guess like that destroyed
  github-committer and set the GitHub App's id to "yes".
- **Explain every change before applying.** An update you cannot trace to
  the change being deployed is a question for the user, not drift.
- **A destroy nobody asked for is a stop.** The usual cause is a variable
  missing from `terraform/terraform.tfvars`: several resources are counted
  on a variable being set (`local.write_back_enabled` on
  `github_writer_app_id`, for one).
- **Apply only after the user has seen the plan,** and only with
  `--apply-saved`, so what is applied is what they read. Terraform refuses
  a saved plan once the state has moved on, which is the point.
- The state is local, in the main checkout's `terraform/`. From a git
  worktree, pass `--terraform-dir` pointing at that root.
- A bare `terraform plan` stops at a precondition on mapping-agent's zip,
  which is built from `build/mapping-agent/`. The script assembles that
  directory before planning, from the files it has just compared with
  `origin/main`. The stop is deliberate: a build directory nobody
  assembled could hold code nobody compared.
