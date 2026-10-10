"""The leak test's expectations (docs/sandbox-spec.md §9 step 1).

The runner inside the sandbox reports only what it observed -- "timeout",
"http:403", "dns-fail" -- and never whether that is good. It shares a
container with whatever a run executes, so it is not the place to decide.
This table is: for each probe and phase, what the containment requires.

Two kinds of row:
  - a *leak* check, which passes when a way out is closed;
  - a *control*, which passes when something that must work does. Without
    controls a broken sandbox passes every leak check: a task whose network
    is down entirely cannot reach the internet either.

A probe the table expects but the result lacks is a failure: a check that
did not run is not a check that passed. Likewise a DNS check whose name
does not resolve outside the sandbox: a lookup that would fail anywhere
proves nothing about the firewall (OUTSIDE_REQUIRED). A probe the table does not know is
reported and does not fail the run, so the runner can grow ahead of it.
"""

BOTH = ("fetch", "execute")

# (probe, phases, op, value, control, what it means)
#   eq / ne          observed == / != value
#   prefix / not_prefix
EXPECTATIONS = [
    # Credentials: absent, not scoped down (spec §3).
    ("env.credentials", BOTH, "eq", "none", False,
     "no AWS credential variables in the environment"),
    ("creds_endpoint", BOTH, "prefix", "no-credentials", False,
     "the ECS credentials endpoint hands out nothing"),
    ("imds", BOTH, "not_prefix", "http:2", False,
     "no EC2 instance metadata"),
    ("tmde.secrets", BOTH, "ne", "present", False,
     "task metadata does not echo the run's URLs or token"),

    # The internet, by address and by name.
    ("tcp.1.1.1.1:443", BOTH, "ne", "connected", False,
     "no route to the internet by IP"),
    ("tcp.8.8.8.8:53", BOTH, "ne", "connected", False,
     "no route to an outside resolver"),
    ("https.example.com", BOTH, "not_prefix", "http:", False,
     "no HTTPS to the internet by name"),

    # DNS as a channel (spec §5).
    ("dns.example.com", BOTH, "eq", "dns-fail", False,
     "DNS Firewall refuses a public name"),
    ("dns.unique", BOTH, "eq", "dns-fail", False,
     "DNS Firewall refuses a never-seen name that resolves publicly (an exfiltration query)"),
    ("dns.endpoint", BOTH, "eq", "resolved", True,
     "DNS still answers for the endpoints"),

    # S3: own objects only (spec §5, §6).
    ("s3.own_put", BOTH, "eq", "http:200", True,
     "the run's own presigned PUT works"),
    ("s3.foreign_unsigned", BOTH, "eq", "http:403", False,
     "another run's key cannot be written without a signature"),
    ("s3.canary", BOTH, "eq", "http:403", False,
     "a valid URL for another bucket is refused by the endpoint policy"),

    # The agent's endpoints are reachable, and useless without credentials.
    ("ecr.unauthenticated", BOTH, "not_prefix", "http:2", False,
     "ECR answers, but not without credentials"),

    # CodeArtifact: the fetch task's only registry, and only the fetch
    # task's (spec §4).
    ("codeartifact.reach", ("fetch",), "eq", "connected", True,
     "fetch reaches the mirror"),
    ("codeartifact.reach", ("execute",), "ne", "connected", False,
     "execute cannot reach the mirror"),
    ("codeartifact.metadata", ("fetch",), "eq", "http:200", True,
     "fetch reads package metadata through the mirror"),
    ("codeartifact.tarball", ("fetch",), "eq", "http:200", True,
     "fetch downloads a package (its assets come over the S3 gateway)"),

    # The filesystem (spec §6).
    ("fs.uid", BOTH, "ne", "0", False,
     "not root"),
    ("fs.root_write", BOTH, "ne", "written", False,
     "the image is read-only"),
    ("fs.work_write", BOTH, "eq", "written", True,
     "/work is writable"),
    ("fs.tmp_write", BOTH, "eq", "written", True,
     "/tmp is writable"),
    ("fs.fresh", BOTH, "eq", "fresh", False,
     "nothing survives from an earlier task"),
]

# Reported, never judged.
INFORMATIONAL = {"env.names"}

# Checks that pass only if the same name resolves outside the sandbox, as
# collect observes from outside its VPC.
OUTSIDE_REQUIRED = {"dns.example.com", "dns.unique"}


def _holds(op, value, observed):
    if op == "eq":
        return observed == value
    if op == "ne":
        return observed != value
    if op == "prefix":
        return observed.startswith(value)
    if op == "not_prefix":
        return not observed.startswith(value)
    raise ValueError(f"unknown op {op!r}")


def describe(op, value):
    return {
        "eq": f"== {value}",
        "ne": f"!= {value}",
        "prefix": f"starts {value}",
        "not_prefix": f"not starts {value}",
    }[op]


def evaluate(phases, outside=None):
    """Grade a leak-test run.

    `phases` maps a phase name to collect's record for it:
    {"status": "ok" | "missing" | ..., "result": {"probes": [...]}}.
    `outside` maps a phase to {probe: "resolved" | "dns-fail"} for the
    OUTSIDE_REQUIRED probes, as resolved from outside the sandbox.
    Only the phases present are graded; a run asked for both and missing one
    is caught by the caller asking for both.
    """
    checks, unknown = [], []
    for phase, record in sorted(phases.items()):
        observed = {}
        if record.get("status") == "ok":
            observed = {p["name"]: p["observed"] for p in record["result"]["probes"]}
        for name, wanted_phases, op, value, control, meaning in EXPECTATIONS:
            if phase not in wanted_phases:
                continue
            seen = observed.get(name)
            if seen is not None:
                shown = seen
            elif record.get("status") == "ok":
                shown = "(not reported)"
            else:
                shown = f"(no result: {record.get('status')})"
            passed = seen is not None and _holds(op, value, seen)
            if name in OUTSIDE_REQUIRED:
                from_outside = ((outside or {}).get(phase) or {}).get(name)
                if from_outside != "resolved":
                    passed = False
                    shown += f" (inconclusive: outside the sandbox it is {from_outside or 'unchecked'})"
            checks.append({
                "phase": phase,
                "probe": name,
                "control": control,
                "expect": describe(op, value),
                "observed": shown,
                "passed": passed,
                "meaning": meaning,
            })
        known = {row[0] for row in EXPECTATIONS} | INFORMATIONAL
        unknown += [f"{phase}:{n}" for n in sorted(observed) if n not in known]
    return {
        "passed": bool(checks) and all(c["passed"] for c in checks),
        "checks": checks,
        "unknown_probes": unknown,
    }
