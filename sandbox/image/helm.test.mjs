import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { helmArgs, renderHelm } from "./helm.mjs";

const chart = fileURLToPath(new URL("../fixtures/helm-chart", import.meta.url));
const root = path.dirname(chart);
const manifest = { APP_DIR: "helm-chart", HELM_RELEASE: "probe", HELM_NAMESPACE: "test" };

test("render default and hardened values with Helm", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-helm-"));
  try {
    for (const [values, privileged] of [[[], true], [["helm-chart/hardened.yaml"], false]]) {
      const dest = path.join(temp, "manifests.yaml");
      const result = await renderHelm(helmArgs({ ...manifest, HELM_VALUES: values,
        HELM_KUBE_VERSION: "1.30.0", HELM_API_VERSIONS: ["apps/v1"] }, root), dest, 30000);
      assert.equal(result.status, "ok", `${result.reason}: ${result.log_tail}`);
      const yaml = fs.readFileSync(dest, "utf8");
      assert.match(yaml, /name: probe/);
      assert.match(yaml, /namespace: test/);
      assert.match(yaml, new RegExp(`privileged: ${privileged}`));
    }
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("missing dependencies and invalid charts fail", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-helm-"));
  try {
    fs.writeFileSync(path.join(temp, "Chart.yaml"), "apiVersion: v2\nname: broken\nversion: 0.1.0\ndependencies:\n  - name: missing\n    version: 1.0.0\n    repository: https://example.com\n");
    const result = await renderHelm(helmArgs({ ...manifest, APP_DIR: "." }, temp),
      path.join(temp, "out.yaml"), 30000);
    assert.equal(result.status, "failed");
    assert.match(result.log_tail, /missing|dependencies/i);
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("spawn failure and timeout return failures", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-helm-"));
  try {
    const dest = path.join(temp, "out.yaml");
    assert.equal((await renderHelm([], dest, 30000, "nonexistent-sandbox-helm")).status, "failed");
    const result = await renderHelm(["-e", "setTimeout(() => {}, 60000)"], dest, 100, process.execPath);
    assert.equal(result.status, "failed");
    assert.match(result.reason, /timed out/);
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test("output is bounded before upload", async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-helm-"));
  try {
    const dest = path.join(temp, "out.yaml");
    const result = await renderHelm(["-e", "process.stdout.write('x'.repeat(11 * 1024 * 1024))"],
      dest, 30000, process.execPath);
    assert.equal(result.status, "failed");
    assert.match(result.reason, /exceeds/);
    assert.ok(fs.statSync(dest).size <= 10 * 1024 * 1024);
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});
