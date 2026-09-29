// Opt-in contract test against the installed, original application binaries.
// Each application gets an empty HOME/DB and a fixture-only access helper.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { createInterface } from "node:readline";
import { setTimeout as delay } from "node:timers/promises";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";

function run(...args) {
  const result = promisify(execFile)(...args);
  // OpenCode reads piped stdin before dispatching even with a message in argv.
  result.child.stdin.end();
  return result;
}
const adapters = path.dirname(fileURLToPath(import.meta.url));
const scratch = process.env.OAUTH_TEST_TMPDIR;
assert.ok(scratch?.startsWith("/"), "Set OAUTH_TEST_TMPDIR to an approved temporary directory");

async function fixture() {
  const root = await mkdtemp(path.join(scratch, "oauth-stock-"));
  const helper = path.join(root, "helper");
  const countFile = path.join(root, "calls");
  const configFile = path.join(root, "config.json");
  await writeFile(configFile, "{}", { mode: 0o600 });
  await writeFile(countFile, "0");
  const claims = Buffer.from(JSON.stringify({ "https://api.openai.com/auth": { chatgpt_account_id: "fixture-account" } })).toString("base64url");
  await writeFile(helper, `#!${process.execPath}
import fs from "node:fs";
const file = ${JSON.stringify(countFile)};
const count = Number(fs.readFileSync(file, "utf8")) + 1;
fs.writeFileSync(file, String(count));
const accessToken = "fixture.${claims}." + count;
console.log(process.argv.includes("--raw") ? accessToken : JSON.stringify({ accessToken, accountId: "fixture-account", expiresAt: Date.now() + 3600000 }));
`, { mode: 0o700 });
  // The helper is extensionless; explicitly make its directory an ESM package.
  await writeFile(path.join(root, "package.json"), '{"type":"module"}');
  await mkdir(path.join(root, "config"));
  const env = {
    PATH: process.env.PATH,
    HOME: root,
    TMPDIR: root,
    XDG_CONFIG_HOME: path.join(root, "xdg-config"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
    OPENCODE_CONFIG_DIR: path.join(root, "config"),
    OPENCODE_DB: path.join(root, "opencode.db"),
    OPENCODE_DISABLE_FILEWATCHER: "true",
    OPENCODE_DISABLE_MODELS_FETCH: "true",
    OPENCODE_TEST_HOME: root,
    PI_CODING_AGENT_DIR: path.join(root, "omp"),
  };
  return { root, helper, countFile, configFile, env };
}

test("stock OpenCode uses native ChatGPT requests with access-only credentials", { timeout: 60000 }, async (t) => {
  assert.ok(process.env.OPENCODE_BIN?.startsWith("/"), "Set OPENCODE_BIN to the original binary (without a profile wrapper)");
  const f = await fixture();
  const password = randomUUID();
  const headers = { authorization: `Basic ${Buffer.from(`opencode:${password}`).toString("base64")}` };
  const captured = [];
  const upstream = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    captured.push({ headers: request.headers, body: JSON.parse(body) });
    const message = { id: "msg_fixture", type: "message", role: "assistant", status: "completed",
      content: [{ type: "output_text", text: "shared-oauth-ok", annotations: [] }] };
    const complete = { id: "resp_fixture", object: "response", created_at: 1, status: "completed",
      model: "gpt-5.5", output: [message], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } };
    const events = [
      { type: "response.created", response: { ...complete, status: "in_progress", output: [] } },
      { type: "response.output_item.added", output_index: 0, item: { ...message, status: "in_progress", content: [] } },
      { type: "response.content_part.added", item_id: message.id, output_index: 0, content_index: 0, part: { type: "output_text", text: "", annotations: [] } },
      { type: "response.output_text.delta", item_id: message.id, output_index: 0, content_index: 0, delta: "shared-oauth-ok" },
      { type: "response.output_text.done", item_id: message.id, output_index: 0, content_index: 0, text: "shared-oauth-ok" },
      { type: "response.output_item.done", output_index: 0, item: message },
      { type: "response.completed", response: complete },
    ];
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.end(events.map((event, sequence_number) => `event: ${event.type}\ndata: ${JSON.stringify({ ...event, sequence_number })}\n\n`).join(""));
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  t.after(() => upstream.close());
  const capturePlugin = path.join(f.root, "capture-plugin");
  await mkdir(capturePlugin);
  await writeFile(path.join(capturePlugin, "server.js"), `
export default { id: "oauth-test.capture", async setup(ctx) {
  await ctx.session.hook("http.request", async (event) => {
    if (event.request.url !== "https://chatgpt.com/backend-api/codex/responses") throw new Error("Unexpected native ChatGPT endpoint");
    event.request = new Request("http://127.0.0.1:${upstream.address().port}/responses", {
      method: event.request.method, headers: event.request.headers, body: await event.request.arrayBuffer(),
    });
  }, { providerID: "provenance-openai-chatgpt" });
} };
`);
  const server = spawn(process.env.OPENCODE_BIN, ["serve", "--stdio", "--hostname", "127.0.0.1", "--port", "0"], {
    cwd: f.root,
    env: { ...f.env, OPENCODE_PASSWORD: password, OPENCODE_CONFIG_CONTENT: JSON.stringify({
      plugins: [{ package: adapters, options: { command: f.helper, configFile: f.configFile } }, { package: capturePlugin }],
    }) }, stdio: ["pipe", "pipe", "pipe"],
  });
  t.after(() => server.kill());
  const ready = createInterface({ input: server.stdout });
  const [line] = await once(ready, "line", { signal: AbortSignal.timeout(10000) });
  const { url } = JSON.parse(line);
  // The stock model endpoint does not wait for initial plugin activation.
  // Keep the same server alive until its public catalog is ready.
  let models;
  const deadline = Date.now() + 10000;
  do {
    const response = await fetch(`${url}/api/model?location[directory]=${encodeURIComponent(f.root)}`, { headers });
    assert.equal(response.status, 200);
    models = (await response.json()).data;
    if (models.some((model) => model.providerID === "provenance-openai-chatgpt")) break;
    await delay(50);
  } while (Date.now() < deadline);
  const plugins = await (await fetch(`${url}/api/plugin?location[directory]=${encodeURIComponent(f.root)}`, { headers })).json();
  assert.ok(models.some((model) => model.providerID === "provenance-openai-chatgpt"), JSON.stringify(plugins));
  assert.equal(await readFile(f.countFile, "utf8"), "0", "catalog listing does not fetch a credential");
  const result = await run(process.env.OPENCODE_BIN, ["run", "--server", url, "--model", "provenance-openai-chatgpt/gpt-5.5", "--title", "OAuth contract", "Reply with the fixture text"], {
    cwd: f.root, env: { ...f.env, OPENCODE_PASSWORD: password }, timeout: 30000, maxBuffer: 1024 * 1024,
  });
  assert.match(result.stdout + result.stderr, /shared-oauth-ok/);
  assert.ok(captured.length > 0);
  for (const request of captured) {
    assert.match(request.headers.authorization, /^Bearer fixture\./);
    assert.equal(request.headers["chatgpt-account-id"], "fixture-account");
    assert.equal(request.body.store, false);
    assert.ok(Array.isArray(request.body.input), "uses the native Responses protocol");
  }
});

test("stock OMP preserves Codex models and reruns the access command on auth retry", { timeout: 60000 }, async () => {
  assert.ok(process.env.OMP_BIN?.startsWith("/"), "Set OMP_BIN to the original binary (without a profile wrapper)");
  const f = await fixture();
  const extension = path.join(f.root, "contract.ts");
  const proof = path.join(f.root, "proof.json");
  await writeFile(extension, `
import { install } from ${JSON.stringify(path.join(adapters, "omp.mjs"))};
import fs from "node:fs/promises";
export default function (pi) {
  install(pi, ${JSON.stringify({ command: f.helper, configFile: f.configFile })});
  pi.on("session_shutdown", async (_event, ctx) => {
    const registry = ctx.modelRegistry;
    const first = await registry.getApiKeyForProvider("openai-codex");
    const cached = await registry.getApiKeyForProvider("openai-codex");
    const refreshed = await registry.getApiKeyForProvider("openai-codex", undefined, { forceRefresh: true });
    await fs.writeFile(${JSON.stringify(proof)}, JSON.stringify({
      received: typeof first === "string" && first.startsWith("fixture."),
      cached: first === cached, refreshed: refreshed !== cached,
    }));
  });
}
`);
  const result = await run(process.env.OMP_BIN, ["models", "openai-codex", "--json", "--no-extensions", "--extension", extension], {
    cwd: f.root, env: f.env, timeout: 50000, maxBuffer: 8 * 1024 * 1024,
  });
  assert.doesNotMatch(result.stderr, /Failed to load extension/);
  assert.match(result.stdout, /openai-codex/);
  assert.deepEqual(JSON.parse(await readFile(proof, "utf8")), { received: true, cached: true, refreshed: true });
});
