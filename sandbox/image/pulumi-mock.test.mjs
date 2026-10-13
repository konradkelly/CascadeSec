import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const harness = fileURLToPath(new URL("./pulumi-mock.mjs", import.meta.url));
const modules = fileURLToPath(new URL("../fixtures/pulumi-app/node_modules", import.meta.url));

function execute(code, env = {}, extension = "js") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pulumi-mock-test-"));
  try {
    fs.symlinkSync(modules, path.join(dir, "node_modules"), process.platform === "win32" ? "junction" : "dir");
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ main: `index.${extension}` }));
    fs.writeFileSync(path.join(dir, "Pulumi.yaml"), "name: mock-test\nruntime: nodejs\n");
    fs.writeFileSync(path.join(dir, `index.${extension}`), code);
    const output = path.join(dir, "resources.json");
    const run = spawnSync(process.execPath, [harness, dir, output], {
      env: { ...process.env, NODE_OPTIONS: "--stack-trace-limit=50", PULUMI_CONFIG: "{}",
        PULUMI_MOCK_CALLS: "{}", ...env }, encoding: "utf8", timeout: 20000,
    });
    return { ...run, data: fs.existsSync(output) ? JSON.parse(fs.readFileSync(output)) : null };
  } finally {
    // Unlink the junction before deleting only our freshly created temporary directory.
    fs.unlinkSync(path.join(dir, "node_modules"));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("drains registrations without stack exports and captures source and config", () => {
  const r = execute('const p = require("@pulumi/pulumi");\nnew p.CustomResource("test:index:Thing", "thing", { value: new p.Config().require("value") });',
    { PULUMI_CONFIG: JSON.stringify({ "mock-test:value": "configured" }) });
  assert.equal(r.status, 0, r.stderr);
  const resource = r.data.resources.find(r => r.name === "thing");
  assert.equal(resource.inputs.value, "configured");
  assert.deepEqual(resource.source, { file: "index.js", line: 2 });
});

test("redacts Pulumi secret inputs", () => {
  const r = execute('const p = require("@pulumi/pulumi"); new p.CustomResource("test:index:Thing", "secret", { value: p.secret("sensitive-test-value") });');
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.stringify(r.data).includes("sensitive-test-value"), false);
  assert.deepEqual(r.data.resources.find(r => r.name === "secret").inputs.value, { secret: true });
});

test("runs TypeScript", () => {
  const r = execute('import * as p from "@pulumi/pulumi"; const value: string = "typescript"; new p.CustomResource("test:index:Thing", "ts", { value });', {}, "ts");
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.data.resources.find(r => r.name === "ts").inputs.value, "typescript");
  assert.deepEqual(r.data.resources.find(r => r.name === "ts").source, { file: "index.ts", line: 1 });
});

test("captures ESM file URL creation sites", () => {
  const r = execute('import * as p from "@pulumi/pulumi";\nnew p.CustomResource("test:index:Thing", "esm", { value: "esm" });', {}, "mjs");
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.data.resources.find(r => r.name === "esm").source, { file: "index.mjs", line: 2 });
});

test("lookup fixtures compare input objects without relying on key order", () => {
  const r = execute('const p = require("@pulumi/pulumi"); exports.result = p.runtime.invoke("test:index:getThing", { b: 2, a: 1 });',
    { PULUMI_MOCK_CALLS: JSON.stringify({ "test:index:getThing": [{ inputs: { a: 1, b: 2 }, outputs: { id: "fixture" } }] }) });
  assert.equal(r.status, 0, r.stderr);
});

test("missing lookup fixtures fail without a successful artifact", () => {
  const r = execute('const p = require("@pulumi/pulumi"); exports.result = p.runtime.invoke("test:index:getThing", {});');
  assert.notEqual(r.status, 0);
  assert.equal(r.data, null);
  assert.match(r.stderr, /explicit mock response/);
});

test("program failures fail without a successful artifact", () => {
  const r = execute('throw new Error("fixture failure");');
  assert.notEqual(r.status, 0);
  assert.equal(r.data, null);
});

test("captures exact Output dependencies without linking equal constants", () => {
  const r = execute('const p = require("@pulumi/pulumi"); const a = new p.CustomResource("test:index:Thing", "a", {}); new p.CustomResource("test:index:Thing", "b", { linked: a.id, constant: "mock::test:index:Thing::a" });');
  assert.equal(r.status, 0, r.stderr);
  const a = r.data.resources.find(r => r.name === "a");
  const b = r.data.resources.find(r => r.name === "b");
  assert.deepEqual(b.references["/linked"], [a.urn]);
  assert.equal(b.references["/constant"], undefined);
  assert.deepEqual(b.dependencies.linked, [a.urn]);
});
