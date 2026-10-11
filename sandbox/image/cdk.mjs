// The cdk-synth harness (docs/sandbox-spec.md §9 step 2). Imported by
// runner.mjs, which owns the manifest and the result upload; this file owns
// what each phase does with a CDK app.
//
//   fetch    the app's package.json and package-lock.json, and nothing
//            else from the project, installed with `npm ci --ignore-scripts`
//            from the CodeArtifact mirror. No user code runs: no lifecycle
//            script, no project .npmrc, no project file but those two. The
//            installed node_modules goes up as this phase's output.
//   execute  the whole project and that node_modules, and the app run the
//            way the CDK CLI runs it -- cdk.json's `app` command with the
//            cloud assembly's directory and context in the environment --
//            but without the CLI. Measured 2026-10-10: 31s direct against
//            66s through the CLI on the same app, and a CLI pinned here
//            would refuse any aws-cdk-lib newer than itself. The assembly's
//            manifests, templates and metadata go up as the output.
//            For cdk-resynth (remediation's self-check, spec §9 step 3) the
//            same, with one file of the project replaced by a fix first,
//            and the dependencies the detection run's fetch installed.
//
// Everything this reports is an observation. Whether a template is a
// template, and which line made which resource, is decided by
// lambda/sandbox-dispatch on the trusted side: from here on, the app has
// run in this container and could have rewritten any of it.

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

const WORK = "/work";
const SRC = `${WORK}/src`;
const OUT_DIR = `${WORK}/cdk.out`;
const LOG_TAIL_BYTES = 4096;

// The project's files that fetch reads. Nothing else is extracted there.
const INSTALL_FILES = ["package.json", "package-lock.json"];

// What execute uploads from the assembly: enough to find every stack, its
// template and its metadata. Not tree.json, assets or bundled code. A Stage
// nests its stacks one directory down, in assembly-<name>/.
const KEEP_RE = /^(?:assembly-[^/]+\/)?(?:manifest\.json|[^/]+\.template\.json|[^/]+\.metadata\.json)$/;

export class Unsupported extends Error {}

// --- small helpers ----------------------------------------------------------

// appDir is repository-relative and was validated by sandbox-dispatch, and
// the project tarball's names by github-gateway; "." is the repository root.
function appRoot(base, appDir) {
  return appDir === "." ? base : path.join(base, appDir);
}

function memberName(appDir, name) {
  return appDir === "." ? name : `${appDir}/${name}`;
}

// A command's exit code and the tail of what it wrote. The tail is the one
// part of a failed run worth reading, and it is whatever the app chose to
// print, so it goes back as data and is never interpreted here.
function run(cmd, args, { cwd, env, timeoutMs }) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let tail = Buffer.alloc(0);
    const keep = (chunk) => {
      tail = Buffer.concat([tail, chunk]);
      if (tail.length > LOG_TAIL_BYTES * 2) tail = tail.subarray(tail.length - LOG_TAIL_BYTES);
    };
    child.stdout.on("data", keep);
    child.stderr.on("data", keep);
    let timedOut = false;
    const timer = timeoutMs && setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeoutMs);
    child.on("close", (code, signal) => {
      if (timer) clearTimeout(timer);
      resolve({
        code: timedOut ? null : code,
        signal,
        timedOut,
        tail: tail.subarray(Math.max(0, tail.length - LOG_TAIL_BYTES)).toString("utf8"),
      });
    });
    child.on("error", (e) => {
      if (timer) clearTimeout(timer);
      resolve({ code: null, signal: null, timedOut: false, tail: `spawn failed: ${e.code ?? e.message}` });
    });
  });
}

async function download(url, dest) {
  const res = await fetch(url, { signal: AbortSignal.timeout(300_000) });
  if (res.status !== 200) throw new Error(`download: http:${res.status}`);
  await pipeline(Readable.fromWeb(res.body), fs.createWriteStream(dest));
}

async function upload(url, file) {
  // A Blob from the file carries its size, so the PUT has a Content-Length:
  // S3 refuses a presigned PUT sent chunked.
  const res = await fetch(url, { method: "PUT", body: await fs.openAsBlob(file),
                                 signal: AbortSignal.timeout(300_000) });
  if (res.status !== 200) throw new Error(`upload: http:${res.status}`);
}

async function untar(archive, dest, members = []) {
  fs.mkdirSync(dest, { recursive: true });
  const r = await run("tar", ["-xzf", archive, "-C", dest, "--no-same-owner", "--no-same-permissions",
                              "--", ...members], { timeoutMs: 300_000 });
  if (r.code !== 0) throw new Error(`untar ${path.basename(archive)}: ${r.tail.slice(-300)}`);
}

async function tarUp(archive, cwd, entries) {
  const r = await run("tar", ["-czf", archive, "-C", cwd, "--", ...entries], { timeoutMs: 300_000 });
  if (r.code !== 0) throw new Error(`tar ${path.basename(archive)}: ${r.tail.slice(-300)}`);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

// --- fetch ------------------------------------------------------------------

export async function fetchPhase(manifest) {
  const appDir = manifest.APP_DIR;
  const app = appRoot(SRC, appDir);
  await download(manifest.SNAPSHOT_URL, `${WORK}/project.tgz`);
  // The two files by name, one at a time, so a missing one is named.
  for (const f of INSTALL_FILES) {
    try {
      await untar(`${WORK}/project.tgz`, SRC, [memberName(appDir, f)]);
    } catch {
      throw new Unsupported(`no ${f} in ${appDir}: only npm projects with a lockfile are installed`);
    }
  }
  fs.rmSync(`${WORK}/project.tgz`);

  const pkg = readJson(path.join(app, "package.json"));
  if (pkg.workspaces) throw new Unsupported("npm workspaces are not supported yet");

  // The mirror, its token, and settings that keep npm from reaching for
  // anything else. A userconfig of our own, and no project .npmrc exists
  // here to override it. replace-registry-host=always sends every
  // lockfile URL to the mirror, not only registry.npmjs.org's.
  const registry = new URL(manifest.CODEARTIFACT_NPM_URL);
  const npmrc = `${WORK}/.npmrc-fetch`;
  fs.writeFileSync(npmrc, [
    `registry=${registry.href}`,
    `//${registry.host}${registry.pathname}:_authToken=${manifest.CODEARTIFACT_TOKEN}`,
    "replace-registry-host=always",
    "ignore-scripts=true",
    "audit=false",
    "fund=false",
    "update-notifier=false",
  ].join("\n") + "\n", { mode: 0o600 });

  const started = Date.now();
  const r = await run("npm", ["ci", "--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=error"], {
    cwd: app,
    env: {
      PATH: process.env.PATH, HOME: "/tmp",
      npm_config_userconfig: npmrc,
      npm_config_globalconfig: "/dev/null",
      npm_config_cache: "/tmp/npm-cache",
    },
    timeoutMs: manifest.STEP_TIMEOUT_SECONDS * 1000,
  });
  fs.rmSync(npmrc);
  if (r.code !== 0) {
    return { status: "failed", reason: r.timedOut ? "npm ci timed out" : `npm ci exited ${r.code}`,
             exit_code: r.code, duration_ms: Date.now() - started, log_tail: r.tail };
  }

  await tarUp(`${WORK}/deps.tgz`, app, ["node_modules"]);
  await upload(manifest.OUTPUT_URL, `${WORK}/deps.tgz`);
  return { status: "ok", exit_code: 0, duration_ms: Date.now() - started, log_tail: r.tail };
}

// --- execute ----------------------------------------------------------------

// What the CLI would have merged from cdk.json and cdk.context.json, plus
// the one setting we add: bundling off for every stack. Bundling runs
// Docker or esbuild over asset code, which is not what is being scanned.
// The CLI rejects aws: keys on its command line, which is why the probe put
// this in cdk.json (multi-iac §7.2 a); here the context is ours to write.
function context(app) {
  const cdkJson = readJson(path.join(app, "cdk.json"));
  const cached = fs.existsSync(path.join(app, "cdk.context.json"))
    ? readJson(path.join(app, "cdk.context.json")) : {};
  return {
    command: cdkJson.app,
    context: {
      ...(cached && typeof cached === "object" ? cached : {}),
      ...(cdkJson.context && typeof cdkJson.context === "object" ? cdkJson.context : {}),
      "aws:cdk:bundling-stacks": [],
    },
  };
}

function keptOutputs(dir) {
  const kept = [];
  const walk = (rel) => {
    for (const entry of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const name = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory() && !rel && entry.name.startsWith("assembly-")) walk(name);
      else if (entry.isFile() && KEEP_RE.test(name)) kept.push(name);
    }
  };
  walk("");
  return kept.sort();
}

export async function executePhase(manifest) {
  const appDir = manifest.APP_DIR;
  const app = appRoot(SRC, appDir);
  await download(manifest.SNAPSHOT_URL, `${WORK}/project.tgz`);
  await untar(`${WORK}/project.tgz`, SRC);
  fs.rmSync(`${WORK}/project.tgz`);
  if (manifest.PATCH_URL) {
    // The fix under test: one file, at a repository path sandbox-dispatch
    // checked, written over the project's own.
    const target = path.join(SRC, manifest.PATCH_PATH);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    await download(manifest.PATCH_URL, target);
  }
  await download(manifest.DEPS_URL, `${WORK}/deps.tgz`);
  await untar(`${WORK}/deps.tgz`, app);
  fs.rmSync(`${WORK}/deps.tgz`);

  if (!fs.existsSync(path.join(app, "cdk.json"))) throw new Unsupported(`no cdk.json in ${appDir}`);
  let synth;
  try {
    synth = context(app);
  } catch (e) {
    throw new Unsupported(`cdk.json or cdk.context.json is not JSON: ${e.message.slice(0, 200)}`);
  }
  if (typeof synth.command !== "string" || !synth.command.trim()) {
    throw new Unsupported("cdk.json has no `app` command");
  }

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const started = Date.now();
  // The app's whole environment. Nothing of the runner's: not the
  // manifest's URL, not the run id. The command is the PR's own, and runs
  // here with nothing but the project to act on.
  const r = await run("/bin/sh", ["-c", synth.command], {
    cwd: app,
    env: {
      PATH: `${app}/node_modules/.bin:${process.env.PATH}`,
      HOME: "/tmp",
      CDK_OUTDIR: OUT_DIR,
      CDK_CONTEXT_JSON: JSON.stringify(synth.context),
      // Adds aws:cdk:propertyAssignment, the line that set a property
      // (multi-iac §7.2 a), which step 3's fixes will want.
      CDK_DEBUG: "true",
      // Library frames come first in a construct's stack. At Node's default
      // of ten, a Vpc's subnets carried no user frame at all.
      NODE_OPTIONS: "--stack-trace-limit=50",
      // npx must use what is installed, and fail at once if it is not.
      npm_config_offline: "true",
      npm_config_cache: "/tmp/npm-cache",
      npm_config_update_notifier: "false",
    },
    timeoutMs: manifest.STEP_TIMEOUT_SECONDS * 1000,
  });
  const duration = Date.now() - started;
  if (r.code !== 0) {
    return { status: "failed", reason: r.timedOut ? "synth timed out" : `the app exited ${r.code ?? r.signal}`,
             exit_code: r.code, duration_ms: duration, log_tail: r.tail };
  }

  const kept = keptOutputs(OUT_DIR);
  if (!kept.includes("manifest.json")) {
    return { status: "failed", reason: "the app wrote no cloud assembly",
             exit_code: 0, duration_ms: duration, log_tail: r.tail };
  }
  await tarUp(`${WORK}/output.tgz`, OUT_DIR, kept);
  await upload(manifest.OUTPUT_URL, `${WORK}/output.tgz`);
  return { status: "ok", exit_code: 0, duration_ms: duration, log_tail: r.tail };
}
