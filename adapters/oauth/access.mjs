import { execFile } from "node:child_process";

export function readAccess(command, args) {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 9000, maxBuffer: 128 * 1024, encoding: "utf8" }, (error, stdout) => {
      // Node's ExecFile error embeds stdout/stderr. Never propagate it into
      // application logs, which could otherwise contain credential material.
      if (error) return reject(new Error("nix-provenance OAuth helper failed; check provenance-oauth status"));
      let access;
      try { access = JSON.parse(stdout); }
      catch { return reject(new Error("Invalid nix-provenance access response")); }
      if (!access || typeof access.accessToken !== "string" || !access.accessToken
        || typeof access.accountId !== "string" || !access.accountId
        || !/^[\x21-\x7e]+$/.test(access.accessToken) || !/^[\x21-\x7e]+$/.test(access.accountId)
        || !Number.isSafeInteger(access.expiresAt) || access.expiresAt <= Date.now()
        || Object.keys(access).some((key) => !["accessToken", "accountId", "expiresAt"].includes(key))) {
        return reject(new Error("Invalid nix-provenance access response"));
      }
      resolve(access);
    });
  });
}

export function helperOptions(options) {
  if (typeof options.command !== "string" || !options.command.startsWith("/")
    || typeof options.configFile !== "string" || !options.configFile.startsWith("/")) {
    throw new Error("nix-provenance OAuth needs absolute command and configFile paths");
  }
  return { command: options.command, args: ["--config", options.configFile, "access"] };
}
