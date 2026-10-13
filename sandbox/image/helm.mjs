// Offline rendering only: dependencies must already be under charts/.
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { download, untar, tarUp, upload } from "./cdk.mjs";

export const MAX_RENDER_BYTES = 10 * 1024 * 1024;

export function helmArgs(manifest, root) {
  const args = ["template", manifest.HELM_RELEASE, path.resolve(root, manifest.APP_DIR),
    "--namespace", manifest.HELM_NAMESPACE, "--include-crds", "--kubeconfig", "/dev/null"];
  for (const file of manifest.HELM_VALUES ?? []) args.push("--values", path.resolve(root, file));
  if (manifest.HELM_KUBE_VERSION) args.push("--kube-version", manifest.HELM_KUBE_VERSION);
  for (const api of manifest.HELM_API_VERSIONS ?? []) args.push("--api-versions", api);
  return args;
}

// Keep stdout as a complete manifest, rather than the shared run helper's
// log tail. Bound it while rendering, and never upload partial output.
export function renderHelm(args, dest, timeoutMs, executable = "helm") {
  return new Promise((resolve) => {
    const fd = fs.openSync(dest, "w");
    const child = spawn(executable, args, { stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: process.env.PATH, HOME: path.dirname(dest),
        HELM_CACHE_HOME: path.dirname(dest), HELM_CONFIG_HOME: path.dirname(dest),
        HELM_DATA_HOME: path.dirname(dest), KUBECONFIG: "/dev/null" } });
    let bytes = 0, tail = Buffer.alloc(0), reason, settled = false;
    const stop = (why) => { reason = why; child.kill("SIGKILL"); };
    const timer = setTimeout(() => stop("Helm rendering timed out"), timeoutMs);
    child.stdout.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_RENDER_BYTES) stop("Helm output exceeds 10MB");
      else if (!reason) fs.writeSync(fd, chunk);
    });
    child.stderr.on("data", (chunk) => { tail = Buffer.concat([tail, chunk]).subarray(-4096); });
    const finish = (code, why) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fs.closeSync(fd);
      resolve({ status: code === 0 && !reason && !why ? "ok" : "failed", exit_code: code,
        reason: reason ?? why ?? (code === 0 ? null : `helm template exited ${code}`),
        log_tail: tail.toString("utf8") });
    };
    child.on("error", (error) => finish(null, `Helm could not start: ${error.code}`));
    child.on("close", (code) => finish(code));
  });
}

export async function executeHelm(manifest) {
  const started = Date.now();
  await download(manifest.SNAPSHOT_URL, "/work/project.tgz");
  await untar("/work/project.tgz", "/work/src");
  fs.rmSync("/work/project.tgz");
  const out = "/work/helm.out";
  fs.mkdirSync(out, { recursive: true });
  const result = await renderHelm(helmArgs(manifest, "/work/src"), `${out}/manifests.yaml`,
    manifest.STEP_TIMEOUT_SECONDS * 1000);
  if (result.status === "ok") {
    await tarUp("/work/output.tgz", out, ["manifests.yaml"]);
    await upload(manifest.OUTPUT_URL, "/work/output.tgz");
  }
  return { ...result, duration_ms: Date.now() - started };
}
