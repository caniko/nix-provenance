import { test } from "node:test";
import assert from "node:assert/strict";
import { install as openCode } from "./opencode.mjs";
import { install as omp } from "./omp.mjs";
import { readAccess } from "./access.mjs";

test("OpenCode isolates shared auth, preserves native model definitions, and rotates HTTP/WS access", async () => {
  const hooks = new Map();
  let registered;
  let calls = 0;
  const sourceModel = { id: "gpt-5.5", modelID: "gpt-5.5", providerID: "openai", variants: [],
    limit: { context: 100, output: 200 }, capabilities: { tools: true }, settings: { apiKey: "old-app-key" } };
  await openCode({ provider: { transform: (callback) => callback({
    get: () => ({ models: new Map([["gpt-5.5", sourceModel]]) }), add: (record) => { registered = record; },
  }) }, session: { hook: (name, callback, filter) => {
    assert.equal(filter.providerID, "provenance-openai-chatgpt"); hooks.set(name, callback);
  } } }, async () => ({ accessToken: `access-${++calls}`, accountId: "workspace", expiresAt: Date.now() + 3600000 }));
  assert.equal(registered.info.activation, "enabled");
  assert.equal(registered.info.integrationID, undefined);
  assert.equal(registered.models[0].package, "@opencode/ai/providers/openai");
  assert.equal(registered.models[0].settings.apiKey, undefined);
  assert.equal(sourceModel.settings.apiKey, "old-app-key");
  const request = { request: new Request("https://chatgpt.com/backend-api/codex/responses") };
  await hooks.get("http.request")(request);
  assert.equal(request.request.headers.get("authorization"), "Bearer access-1");
  assert.equal(request.request.headers.get("chatgpt-account-id"), "workspace");
  const handshake = { url: "wss://chatgpt.com/backend-api/codex/responses", headers: {} };
  await hooks.get("experimental.ws.handshake")(handshake);
  assert.equal(handshake.headers.authorization, "Bearer access-2");
  for (const url of ["http://chatgpt.com/backend-api/codex/responses", "https://example.com/backend-api/codex/responses", "https://chatgpt.com/other", "https://chatgpt.com:8443/backend-api/codex/responses"]) {
    await assert.rejects(() => hooks.get("http.request")({ request: new Request(url) }), /incompatible endpoint/);
  }
  assert.equal(calls, 2, "untrusted endpoints must not even acquire credentials");
});

test("OMP uses access-only command override and retains the stock model catalog", () => {
  let registration;
  omp({ registerProvider: (id, config) => { registration = { id, config }; } },
    { command: "/helper with'quote", configFile: "/config.json" });
  assert.equal(registration.id, "openai-codex");
  assert.deepEqual(Object.keys(registration.config), ["apiKey"]);
  assert.equal(registration.config.apiKey, "!'/helper with'\\''quote' '--config' '/config.json' 'access' '--raw'");
});

test("helper rejects refresh-bearing output and redacts failed child output", async () => {
  const output = { accessToken: "access", accountId: "account", expiresAt: Date.now() + 3600000 };
  assert.deepEqual(await readAccess(process.execPath, ["-e", `console.log(${JSON.stringify(JSON.stringify(output))})`]), output);
  await assert.rejects(readAccess(process.execPath, ["-e", `console.log(${JSON.stringify(JSON.stringify({ ...output, refreshToken: "secret" }))})`]), /Invalid nix-provenance/);
  for (const field of ["accessToken", "accountId"]) {
    const malformed = { ...output, [field]: "secret\r\ninvalid-header" };
    await assert.rejects(readAccess(process.execPath, ["-e", `console.log(${JSON.stringify(JSON.stringify(malformed))})`]), /Invalid nix-provenance/);
  }
  await assert.rejects(readAccess(process.execPath, ["-e", "console.log('secret-access'); console.error('secret-refresh'); process.exit(1)"]), (error) => {
    assert.equal(error.message, "nix-provenance OAuth helper failed; check provenance-oauth status");
    assert.equal(error.stdout, undefined);
    return true;
  });
});
