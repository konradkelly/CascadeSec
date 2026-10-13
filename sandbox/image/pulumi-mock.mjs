// Runs only in the execute task. No CLI, backend, provider plugins or credentials.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL, fileURLToPath } from "node:url";

const [appArg, output] = process.argv.slice(2);
const app = path.resolve(appArg);
const require = createRequire(path.join(app, "package.json"));
class Unsupported extends Error {}
const missingCalls = new Set();
function fail(e) {
  const message = missingCalls.size ? `missing lookup mocks: ${[...missingCalls].join(", ")}; needs an explicit mock response`
    : e?.message || String(e);
  console.error(message);
  process.exit(e instanceof Unsupported || missingCalls.size ? 2 : 1);
}
process.on("unhandledRejection", fail);

async function main() {
  let pulumi, yaml;
  try {
    pulumi = require("@pulumi/pulumi");
    // Use the SDK's YAML parser, including when npm nests it under the SDK.
    yaml = createRequire(require.resolve("@pulumi/pulumi"))("js-yaml");
  } catch { throw new Unsupported("the project must install @pulumi/pulumi and its dependencies"); }
  const project = yaml.load(fs.readFileSync(path.join(app, "Pulumi.yaml"), "utf8"));
  const runtime = typeof project?.runtime === "string" ? project.runtime : project?.runtime?.name;
  if (runtime !== "nodejs" || typeof project?.name !== "string")
    throw new Unsupported("Pulumi.yaml must name a nodejs project");
  const options = typeof project.runtime === "object" ? project.runtime.options ?? {} : {};
  // Hooks such as runtime.options.nodeargs are intentionally not executed.
  const pkg = JSON.parse(fs.readFileSync(path.join(app, "package.json"), "utf8"));
  const entryRoot = path.resolve(app, project.main ?? ".");
  if (entryRoot !== app && !entryRoot.startsWith(app + path.sep))
    throw new Unsupported("Pulumi main must stay within the app directory");
  let entry = entryRoot;
  if (fs.statSync(entryRoot).isDirectory()) {
    const nested = path.join(entryRoot, "package.json");
    const entryPkg = fs.existsSync(nested) ? JSON.parse(fs.readFileSync(nested, "utf8")) : {};
    const main = entryPkg.main;
    entry = main ? path.resolve(entryRoot, main) : ["index.ts", "index.js", "index.mjs", "index.cjs"]
      .map(f => path.join(entryRoot, f)).find(f => fs.existsSync(f));
  }
  if (!entry || (entry !== app && !entry.startsWith(app + path.sep)))
    throw new Unsupported("no supported entrypoint within the app directory");
  if (entry.endsWith(".ts")) {
    if (pkg.type === "module" || options.typescript === false)
      throw new Unsupported("TypeScript requires CommonJS and typescript enabled; use compiled JavaScript for ESM");
    try { require("ts-node").register({ transpileOnly: true,
      compilerOptions: { module: "CommonJS", moduleResolution: "Node" } }); }
    catch { throw new Unsupported("TypeScript projects must install ts-node and typescript"); }
  }

  const calls = JSON.parse(process.env.PULUMI_MOCK_CALLS ?? "{}");
  const canonical = value => value && typeof value === "object"
    ? Array.isArray(value) ? value.map(canonical)
      : Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])]))
    : value;
  const resources = [], locations = [], dependencies = [];
  async function traceInputs(value, pointer, refs) {
    if (pulumi.Output.isInstance(value)) {
      const deps = await value.allResources();
      refs[pointer] = await Promise.all([...deps].map(r => r.urn.promise()));
      return;
    }
    if (value instanceof Promise) return traceInputs(await value, pointer, refs);
    if (value && typeof value === "object" && !pulumi.Resource.isInstance(value)) {
      await Promise.all(Object.entries(value).map(([k, v]) => traceInputs(v,
        `${pointer}/${k.replaceAll("~", "~0").replaceAll("/", "~1")}`, refs)));
    }
  }
  const redact = value => {
    if (Array.isArray(value)) return value.map(redact);
    if (value && typeof value === "object") {
      if (value["4dabf18193072939515e22adb298388d"] === "1b47061264138c4ac30d75fd1eb44270")
        return { secret: true };
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redact(v)]));
    }
    return value;
  };
  pulumi.runtime.setMocks({
    newResource(args) {
      if (args.transforms?.length) throw new Unsupported("asynchronous resource transforms are not supported by the mock harness");
      const id = `mock::${args.type}::${args.name}`;
      // Inputs only. No invented provider defaults or claims about real cloud state.
      return { id: args.custom ? id : undefined, state: args.inputs };
    },
    call(args) {
      const responses = calls[args.token];
      const match = Array.isArray(responses) && responses.find(r =>
        JSON.stringify(canonical(r.inputs)) === JSON.stringify(canonical(args.inputs)));
      if (!match) {
        missingCalls.add(args.token);
        const message = `lookup ${args.token} needs an explicit mock response for its inputs`;
        throw Object.assign(new Unsupported(message), { details: message });
      }
      return match.outputs;
    },
  }, project.name, "sandbox", false);
  // The mock monitor's registration request preserves identity and exact SDK dependencies.
  const monitor = pulumi.runtime.getMonitor();
  const register = monitor.registerResource.bind(monitor);
  const rpc = require("@pulumi/pulumi/runtime/rpc");
  monitor.registerResource = (req, callback) => register(req, (error, response) => {
    if (!error) resources.push({ urn: response.getUrn(), type: req.getType(), name: req.getName(),
      custom: req.getCustom(), inputs: redact(rpc.deserializeProperties(req.getObject())),
      dependencies: Object.fromEntries([...req.getPropertydependenciesMap().entries()]
        .map(([key, value]) => [key, value.getUrnsList()])) });
    callback(error, response);
  });
  monitor.readResource = (_req, callback) => callback(Object.assign(
    new Unsupported("reading existing resources is unsupported without cloud state"),
    { details: "reading existing resources is unsupported without cloud state" }));
  await pulumi.runtime.runInPulumiStack(async () => {
    pulumi.runtime.registerStackTransformation(args => {
      const frames = (new Error().stack ?? "").split("\n");
      const source = frames.map(frame => {
        const match = frame.match(/\(([^()]+):(\d+):(\d+)\)$/)
          ?? frame.match(/^\s*at ([^()]+):(\d+):(\d+)$/);
        if (!match) return null;
        const filename = match[1].startsWith("file://") ? fileURLToPath(match[1]) : match[1];
        const file = path.relative(app, filename).replaceAll("\\", "/");
        if (file.startsWith("../") || path.isAbsolute(file) || file.includes("node_modules/") || file === "") return null;
        return { file, line: Number(match[2]) };
      }).find(Boolean) ?? null;
      locations.push({ resource: args.resource, source, refs: {} });
      const location = locations.at(-1);
      dependencies.push(traceInputs(args.props, "", location.refs));
      return undefined;
    });
    return entry.endsWith(".ts") ? require(entry) : await import(pathToFileURL(entry).href);
  });
  await pulumi.runtime.waitForRPCs();
  await Promise.all(dependencies);
  const origins = new Map(await Promise.all(locations.map(async l =>
    [await l.resource.urn.promise(), l])));
  for (const resource of resources) {
    const origin = origins.get(resource.urn);
    resource.source = origin?.source ?? null;
    resource.references = origin?.refs ?? {};
  }
  if (missingCalls.size) throw new Unsupported(`missing lookup mocks: ${[...missingCalls].join(", ")}`);
  const provider_versions = {};
  try { provider_versions.aws = require("@pulumi/aws/package.json").version; } catch {}
  fs.writeFileSync(output, JSON.stringify({ schema_version: 2, mode: "mock", project: project.name,
    stack: "sandbox", provider_versions, resources }, null, 2));
}

main().catch(fail);
