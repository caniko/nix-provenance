import { helperOptions, readAccess } from "./access.mjs";

const providerID = "provenance-openai-chatgpt";
const baseURL = "https://chatgpt.com/backend-api/codex";

// Plugin objects use the stock V2 Promise plugin contract; no runtime package
// imports or app source patches are needed.
export default {
  id: "nix-provenance.oauth.chatgpt",
  async setup(ctx) {
    const helper = helperOptions(ctx.options);
    await install(ctx, () => readAccess(helper.command, helper.args));
  },
};

export async function install(ctx, access) {
  // A separate integration ID prevents resolution/refresh of an app-local
  // OpenAI credential. Models retain the original native OpenAI wire driver.
  await ctx.provider.transform((editor) => {
    const source = editor.get("openai");
    if (!source) throw new Error("The stock OpenAI provider is required for shared ChatGPT authorization");
    const models = [...source.models.values()].filter(eligible).map((model) => ({
      ...model,
      providerID,
      canonical: "openai",
      package: "@opencode/ai/providers/openai",
      // Do not inherit route, auth, or header overrides from a different
      // account. Variants keep generation options, never credential settings.
      settings: cleanSettings(model.settings),
      headers: {},
      body: { ...model.body, store: false },
      variants: model.variants.map((variant) => ({ ...variant, settings: cleanSettings(variant.settings), headers: {} })),
      enabled: true,
      cost: [],
      limit: { ...model.limit, context: 400_000, input: 272_000 },
    }));
    if (!models.length) throw new Error("The stock catalog contains no compatible ChatGPT models");
    editor.add({ info: {
      id: providerID, name: "ChatGPT (nix-provenance)", canonical: "openai",
      activation: "enabled", package: "@opencode/ai/providers/openai",
      settings: { baseURL, transport: "http" },
      headers: { originator: "opencode", "x-codex-beta-features": "remote_compaction_v2" },
      body: { store: false },
    }, models });
  });

  await ctx.session.hook("model.request", (event) => {
    event.baseURL = baseURL;
    event.headers.originator = "opencode";
    event.headers["session-id"] = event.sessionID;
  }, { providerID });

  await ctx.session.hook("http.request", async (event) => {
    assertDestination(event.request.url, "https:");
    const grant = await access();
    const headers = new Headers(event.request.headers);
    headers.set("authorization", `Bearer ${grant.accessToken}`);
    headers.set("chatgpt-account-id", grant.accountId);
    event.request = new Request(event.request, { headers, redirect: "error" });
  }, { providerID });

  await ctx.session.hook("experimental.ws.handshake", async (event) => {
    assertDestination(event.url, "wss:");
    const grant = await access();
    event.headers.authorization = `Bearer ${grant.accessToken}`;
    event.headers["chatgpt-account-id"] = grant.accountId;
  }, { providerID });
}

function cleanSettings(settings) {
  const { apiKey, accessToken, authToken, baseURL: url, headers, auth, ...rest } = settings ?? {};
  return rest;
}

function assertDestination(value, protocol) {
  const url = new URL(value);
  if (url.protocol !== protocol || url.hostname !== "chatgpt.com" || url.port || url.username || url.password
    || !["/backend-api/codex/responses", "/backend-api/codex/responses/compact"].includes(url.pathname)) {
    throw new Error("Refusing to send shared ChatGPT credentials to an incompatible endpoint");
  }
}

// Mirrors the pinned stock client's ChatGPT catalog policy, not a fabricated
// model list. Model definitions and capabilities come from the loaded catalog.
function eligible(model) {
  if (model.body?.reasoning?.mode === "pro") return false;
  const id = model.modelID ?? model.id;
  if (["gpt-5.5-pro", "gpt-5.6"].includes(id)) return false;
  if (["gpt-5.5", "gpt-5.3-codex-spark"].includes(id)) return true;
  const match = /^gpt-(\d+)(?:\.(\d+))?/.exec(id);
  return !!match && (+match[1] > 5 || (+match[1] === 5 && +(match[2] ?? 0) > 4));
}
