import { helperOptions } from "./access.mjs";

const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;

export function install(pi, options) {
  const helper = helperOptions(options);
  // OMP owns its original Codex protocol/catalog. Its command cache is
  // invalidated by the stock auth-retry resolver when a bearer expires.
  pi.registerProvider("openai-codex", {
    apiKey: `!${[helper.command, ...helper.args, "--raw"].map(quote).join(" ")}`,
  });
}
