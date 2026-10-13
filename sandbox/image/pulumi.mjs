// Reuse CDK's script-free dependency fetch; execute a fixed mock harness.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { download, untar, run, tarUp, upload } from "./cdk.mjs";

export async function executePulumi(manifest) {
  const app = path.resolve("/work/src", manifest.APP_DIR);
  await download(manifest.SNAPSHOT_URL, "/work/project.tgz");
  await untar("/work/project.tgz", "/work/src");
  fs.rmSync("/work/project.tgz");
  await download(manifest.DEPS_URL, "/work/deps.tgz");
  await untar("/work/deps.tgz", app);
  fs.rmSync("/work/deps.tgz");
  const out = "/work/pulumi.out";
  fs.mkdirSync(out, { recursive: true });
  const started = Date.now();
  const r = await run(process.execPath, [fileURLToPath(new URL("./pulumi-mock.mjs", import.meta.url)),
    app, `${out}/resources.json`], {
    cwd: app,
    env: { PATH: process.env.PATH, HOME: "/tmp", NODE_OPTIONS: "--stack-trace-limit=50",
      PULUMI_CONFIG: JSON.stringify(manifest.PULUMI_CONFIG ?? {}),
      PULUMI_MOCK_CALLS: JSON.stringify(manifest.PULUMI_MOCK_CALLS ?? {}),
      PULUMI_NODEJS_STACK: "sandbox" },
    timeoutMs: manifest.STEP_TIMEOUT_SECONDS * 1000,
  });
  const duration_ms = Date.now() - started;
  if (r.code !== 0) return { status: r.code === 2 ? "unsupported" : "failed",
    reason: r.timedOut ? "Pulumi mock execution timed out" : `Pulumi mock harness exited ${r.code ?? r.signal}`,
    exit_code: r.code, duration_ms, log_tail: r.tail };
  if (!fs.existsSync(`${out}/resources.json`)) return { status: "failed",
    reason: "Pulumi mock harness wrote no resources", exit_code: 0, duration_ms, log_tail: r.tail };
  await tarUp("/work/output.tgz", out, ["resources.json"]);
  await upload(manifest.OUTPUT_URL, "/work/output.tgz");
  return { status: "ok", exit_code: 0, duration_ms, log_tail: r.tail };
}
