"""CascadeSec's core: the logic every runtime shares (portable-runtime-spec §2).

What makes CascadeSec what it is -- which controls a finding may cite, how a
fix is chained and checked, what a reviewer may approve -- lives here once,
and each runtime (the AWS Lambdas today; the local and portable-hosted ones
later) gives it what it needs. So nothing in this package imports a cloud
SDK, reads the environment, or does I/O: a caller loads what a function
needs from wherever its runtime keeps it, and passes it in.

The zip-packaged Lambdas that import it carry their own copy, vendored into
the zip by Terraform (§8), so a deploy is still one artifact per function
and the deploy guard (scripts/deploy.py) compares this package with
origin/main like any handler.

  mapping   which controls a finding may be mapped to, and why it stays raw
            when none may
  records   the RecordStore port, its conditions, and what a guarantee
            means (§3, §4); adapters live in cascadesec_aws and, later,
            the local and portable-hosted runtimes
  memory    a RecordStore in memory, the conformance suite's reference
"""
