"""Offline scanner parity for independently written vulnerable/hardened twins.

Requires fixture npm dependencies, Node, Docker and the pinned scanner image.
Runs no AWS calls or provider plugins. Every scanner runs with --network none.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lambda" / "sandbox-dispatch"))
import pulumi_plan

FIXTURE = ROOT / "sandbox" / "fixtures" / "pulumi-twins"


def scanner(image, directory, tool):
    cmd = ["docker", "run", "--rm", "--network", "none", "--mount",
           f"type=bind,source={directory},target=/work,readonly"]
    if tool == "trivy":
        code = (
            "import json,os,handler; "
            "rs,es=handler._run_trivy('/work'); assert not es,es; "
            "ps=[n for n in os.listdir('/work') if n.endswith('.pulumi.plan.json')]; "
            "fs=handler._normalize_trivy(rs,'fixture',{p:'pulumi' for p in ps}); "
            "handler._pulumi_origins(fs,['/work/'+p for p in ps],'/work'); "
            "assert not ps or all(f['file'] in ps and f.get('origin') and f['target_type']=='pulumi' for f in fs),fs; "
            "print(json.dumps({'Results':[{'Misconfigurations':rs}]}))"
        )
        cmd += ["-e", "AWS_DEFAULT_REGION=us-east-1", "-e", "AWS_EC2_METADATA_DISABLED=true",
                "-e", "PYTHONPATH=/opt/python", "--entrypoint", "python", image, "-c", code]
    else:
        cmd += ["-e", "PYTHONPATH=/opt/python", "-e", "CKV_SKIP_PACKAGE_UPDATE_CHECK=true", "--entrypoint", "python", image,
                "-m", "checkov.main", "-d", "/work", "--framework", "terraform,terraform_plan",
                "--output", "json", "--quiet"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if result.returncode not in (0, 1) or not result.stdout.strip():
        raise RuntimeError(f"{tool} failed: {result.stderr[-2000:]}")
    data = json.loads(result.stdout)
    if tool == "trivy":
        return {(c["ID"], c.get("CauseMetadata", {}).get("Resource"))
                for r in data.get("Results", []) for c in r.get("Misconfigurations", [])}
    reports = data if isinstance(data, list) else [data]
    if any(r.get("results", {}).get("parsing_errors") for r in reports):
        raise RuntimeError("checkov reported parsing errors")
    return {(c["check_id"], c["resource"]) for r in reports
            for c in r.get("results", {}).get("failed_checks", [])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="675901257165.dkr.ecr.us-east-1.amazonaws.com/iacposture-dev-iac-scanner:latest")
    args = parser.parse_args()
    results = {}
    with tempfile.TemporaryDirectory(prefix="pulumi-parity-") as temp:
        base = Path(temp)
        app = base / "app"
        app.mkdir()
        for name in ("package.json", "Pulumi.yaml", "index.ts"):
            (app / name).write_bytes((FIXTURE / name).read_bytes())
        modules = app / "node_modules"
        target = FIXTURE / "node_modules"
        if os.name == "nt":
            subprocess.run(["cmd", "/c", "mklink", "/J", str(modules), str(target.resolve())], check=True, capture_output=True)
        else:
            modules.symlink_to(target.resolve(), target_is_directory=True)
        try:
            for hardened in (False, True):
                variant = "hardened" if hardened else "vulnerable"
                capture = base / f"{variant}.json"
                env = {**os.environ, "NODE_OPTIONS": "--stack-trace-limit=50",
                       "PULUMI_CONFIG": json.dumps({"pulumi-adapter-twins:hardened": str(hardened).lower()})}
                subprocess.run(["node", str(ROOT / "sandbox/image/pulumi-mock.mjs"), str(app), str(capture)],
                               cwd=app, env=env, check=True, timeout=60)
                plan = pulumi_plan.build(json.loads(capture.read_text()))
                converted = base / variant / "pulumi"
                terraform = base / variant / "terraform"
                converted.mkdir(parents=True)
                terraform.mkdir(parents=True)
                (converted / "resources.pulumi.plan.json").write_text(json.dumps(plan, indent=2))
                text = (FIXTURE / "twin.tf.template").read_text()
                replacements = {"HARD": str(hardened).lower(), "VERSION": "Enabled" if hardened else "Suspended",
                    "ALGORITHM": "aws:kms" if hardened else "AES256", "TOKENS": "required" if hardened else "optional",
                    "PORT": "443" if hardened else "22", "CIDR": "10.0.0.0/8" if hardened else "0.0.0.0/0",
                    "KMS_FIELD": "kms_master_key_id = aws_kms_key.key.id" if hardened else "",
                    "TRAIL_KEY": "kms_key_id = aws_kms_key.key.id" if hardened else ""}
                for key, value in replacements.items():
                    text = text.replace(key, value)
                (terraform / "main.tf").write_text(text)
                for tool in ("trivy", "checkov"):
                    actual, expected = scanner(args.image, converted, tool), scanner(args.image, terraform, tool)
                    print(f"{variant} {tool}: Pulumi {len(actual)}, Terraform {len(expected)}", flush=True)
                    if actual != expected:
                        raise AssertionError(f"{tool} only in Pulumi: {sorted(actual - expected)}; only in Terraform: {sorted(expected - actual)}")
                    results[variant, tool] = actual
            for tool in ("trivy", "checkov"):
                assert results["vulnerable", tool] - results["hardened", tool], f"{tool}: hardened fixture cleared no checks"
            print("PASS: exact rule/resource parity for both twins; hardening clears checks in both scanners")
        finally:
            if os.name == "nt":
                os.rmdir(modules)  # Remove only the junction; never recurse into installed dependencies.
            else:
                modules.unlink()


if __name__ == "__main__":
    main()
