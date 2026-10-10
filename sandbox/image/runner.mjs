// The sandbox's entrypoint (docs/sandbox-spec.md §6). The task definition
// fixes SANDBOX_PHASE; sandbox-dispatch chooses SANDBOX_KIND from a fixed
// set; the run supplies files and nothing else. No dependencies: this runs
// before, and beside, anything a run installs.
//
// Kinds (spec §9 step 1 -- the containment's own tests, nothing else yet):
//   leak-test  try every way out and report what happened (below)
//   sleep      outlive the state's timeout, so the run can show it is stopped
//
// The leak test REPORTS and never judges. It shares a container with
// whatever a run executes, so the verdict is lambda/sandbox-dispatch/leak.py's,
// on the trusted side. Each probe yields a short observation from a small
// vocabulary -- connected, timeout, refused, dns-fail, http:<status> -- and
// never a URL, a token or a response body.

import { promises as dns } from "node:dns";
import fs from "node:fs";
import net from "node:net";

const PHASE = process.env.SANDBOX_PHASE;
const KIND = process.env.SANDBOX_KIND;
const RUN_ID = process.env.SANDBOX_RUN_ID ?? "unknown";

// Everything else -- the run's URLs, and for fetch the CodeArtifact token --
// is in the manifest sandbox-dispatch wrote, which the environment points
// to. Not in the environment itself: ECS caps overrides at 8192 characters,
// and the environment is shown in full in the run's history.
let manifest = {};
const TIMEOUT_MS = 4000;

// --- observation helpers ----------------------------------------------------

function errorCode(e) {
  const c = e?.cause?.code ?? e?.code ?? e?.name ?? "error";
  if (["ENOTFOUND", "EAI_AGAIN", "ENODATA", "ESERVFAIL", "EREFUSED", "ENOTIMP"].includes(c)) return "dns-fail";
  if (["ETIMEDOUT", "UND_ERR_CONNECT_TIMEOUT", "TimeoutError", "AbortError", "UND_ERR_HEADERS_TIMEOUT"].includes(c)) return "timeout";
  if (c === "ECONNREFUSED") return "refused";
  if (["EHOSTUNREACH", "ENETUNREACH"].includes(c)) return "unreachable";
  return `error:${c}`;
}

async function http(url, { method = "GET", body, headers = {}, follow = false } = {}) {
  try {
    const res = await fetch(url, {
      method, headers, body,
      redirect: follow ? "follow" : "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const text = await res.text().catch(() => "");
    return { observed: `http:${res.status}`, status: res.status, text };
  } catch (e) {
    return { observed: errorCode(e), status: null, text: "" };
  }
}

function tcp(host, port) {
  return new Promise((resolve) => {
    const sock = net.connect({ host, port, timeout: TIMEOUT_MS });
    const done = (observed) => { sock.destroy(); resolve(observed); };
    sock.once("connect", () => done("connected"));
    sock.once("timeout", () => done("timeout"));
    sock.once("error", (e) => done(errorCode(e)));
  });
}

async function resolves(name) {
  try {
    await dns.resolve4(name);
    return "resolved";
  } catch (e) {
    return errorCode(e) === "timeout" ? "timeout" : "dns-fail";
  }
}

function tryWrite(path) {
  try {
    fs.writeFileSync(path, "leak-test\n");
    return "written";
  } catch (e) {
    return `error:${e.code ?? "unknown"}`;
  }
}

// --- the probes -------------------------------------------------------------

const CREDENTIAL_VARS = [
  "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN",
];

async function leakTest() {
  const probes = [];
  const add = (name, observed, detail) => probes.push(detail ? { name, observed, detail } : { name, observed });

  // Filesystem first: freshness must be checked before this run writes.
  const markers = ["/work/.leak-marker", "/tmp/.leak-marker"];
  add("fs.fresh", markers.some((m) => fs.existsSync(m)) ? "stale" : "fresh");
  add("fs.uid", String(process.getuid()));
  add("fs.root_write", tryWrite("/leak-root-write"));
  add("fs.work_write", tryWrite(markers[0]));
  add("fs.tmp_write", tryWrite(markers[1]));

  // Credentials.
  const present = CREDENTIAL_VARS.filter((v) => v in process.env);
  add("env.credentials", present.length ? present.join(",") : "none");
  add("env.names", Object.keys(process.env).filter((k) => /^(AWS|ECS)_/.test(k)).sort().join(","));

  const credsPath = process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI ?? "/v2/credentials/";
  const creds = await http(`http://169.254.170.2${credsPath}`);
  add("creds_endpoint", creds.text.includes("AccessKeyId") ? "credentials" : `no-credentials:${creds.observed}`);
  add("imds", (await http("http://169.254.169.254/latest/meta-data/")).observed);

  // Does task metadata echo the run's URLs or token? Only markers are
  // searched for; the body itself is never reported.
  const tmdeBase = process.env.ECS_CONTAINER_METADATA_URI_V4;
  if (tmdeBase) {
    const bodies = [await http(tmdeBase), await http(`${tmdeBase}/task`)];
    const token = manifest.CODEARTIFACT_TOKEN;
    const leaked = bodies.some((b) => b.text.includes("X-Amz-Signature")
      || b.text.includes("X-Amz-Security-Token") || (token && b.text.includes(token)));
    add("tmde.secrets", leaked ? "present" : "absent", bodies.map((b) => b.observed).join(","));
  } else {
    add("tmde.secrets", "absent", "no metadata endpoint");
  }

  // The internet, by address, by name, and over DNS.
  const [t1, t2, web, ex, uniq, ep] = await Promise.all([
    tcp("1.1.1.1", 443),
    tcp("8.8.8.8", 53),
    http("https://example.com/"),
    resolves(manifest.DNS_PUBLIC_NAME),
    // Resolves publicly (nip.io answers any such name), so only the
    // firewall can make it fail; the trusted side checks it does resolve.
    resolves(manifest.DNS_UNIQUE_NAME),
    resolves(`logs.${manifest.AWS_REGION_NAME}.amazonaws.com`),
  ]);
  add("tcp.1.1.1.1:443", t1);
  add("tcp.8.8.8.8:53", t2);
  add("https.example.com", web.observed);
  add("dns.example.com", ex);
  add("dns.unique", uniq);
  add("dns.endpoint", ep);

  // S3: the run's own object, another run's key unsigned, another bucket signed.
  add("s3.own_put", (await http(manifest.OUTPUT_URL, { method: "PUT", body: Buffer.from("leak-test\n") })).observed);
  add("s3.foreign_unsigned", (await http(manifest.FOREIGN_URL, { method: "PUT", body: Buffer.from("x") })).observed);
  add("s3.canary", (await http(manifest.CANARY_URL, { method: "PUT", body: Buffer.from("x") })).observed);

  add("ecr.unauthenticated", (await http(`https://${manifest.ECR_REGISTRY}/v2/`)).observed);

  // CodeArtifact: reachable from fetch only.
  add("codeartifact.reach", await tcp(manifest.CODEARTIFACT_HOST, 443));
  if (PHASE === "fetch") {
    const auth = { authorization: `Bearer ${manifest.CODEARTIFACT_TOKEN}` };
    const meta = await http(`${manifest.CODEARTIFACT_NPM_URL}left-pad`, { headers: auth, follow: true });
    add("codeartifact.metadata", meta.observed);
    let tarball = "skipped";
    try {
      const doc = JSON.parse(meta.text);
      const url = doc.versions[doc["dist-tags"].latest].dist.tarball;
      tarball = (await http(url, { headers: auth, follow: true })).observed;
    } catch {
      // metadata failed; its own probe says so
    }
    add("codeartifact.tarball", tarball);
  }

  return probes;
}

// --- main -------------------------------------------------------------------

async function main() {
  if (!PHASE || !KIND) throw new Error("SANDBOX_PHASE and SANDBOX_KIND are required");

  const m = await http(process.env.MANIFEST_URL);
  if (m.status !== 200) throw new Error(`manifest: ${m.observed}`);
  manifest = JSON.parse(m.text);

  if (KIND === "sleep") {
    console.log(`sleep: ${PHASE} waiting to be stopped`);
    await new Promise((r) => setTimeout(r, 3600 * 1000));
    return;
  }
  if (KIND !== "leak-test") throw new Error(`unknown kind ${KIND}`);

  const probes = await leakTest();
  // Names and observations only: these are safe to log, and the log is
  // what to read when result.json never arrives.
  for (const p of probes) console.log(`${PHASE} ${p.name}: ${p.observed}`);

  const res = await http(manifest.RESULT_URL, {
    method: "PUT",
    body: Buffer.from(JSON.stringify({ phase: PHASE, kind: KIND, probes })),
  });
  console.log(`result upload: ${res.observed}`);
  if (res.status !== 200) process.exit(1);
}

main().catch((e) => {
  console.error(`runner failed: ${e.message}`);
  process.exit(1);
});
