# Helm sandbox fixture

Render and optionally scan the intentionally privileged Deployment:

```powershell
python scripts/sandbox.py helm sandbox/fixtures/helm-chart --release probe --namespace test --scan
```

Render its values overlay, which disables privileged mode:

```powershell
python scripts/sandbox.py helm sandbox/fixtures/helm-chart --values hardened.yaml --output hardened-manifests.yaml --scan
```

The overlay addresses privileged mode only; other Kubernetes security findings
may remain. Both commands require the updated sandbox image and dispatch Lambda.
Values paths are relative to the repository root passed as the positional argument.
