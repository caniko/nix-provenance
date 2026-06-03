# Phase 03 — Integrate the `vikunja-provision` tenant into the flake

> **Recommended Codex model: GPT 5.5 medium**
>
> Broad but mechanical: wire one crate into the flake the way `immich`/`rauthy`
> already are — package, checks, NixOS module, eval test, REUSE/docs. It spans
> several shared files (`flake.nix`, `packages.nix`, `checks.nix`), so it earns
> `medium` for the "don't silently drop a concern / don't clobber a neighbour"
> orchestration: the `nixosModules.vikunja` name is already taken and the existing
> `vikunja-module-eval` keys off a different unit. Not `high` — every edit has a
> direct in-repo template; the judgement is naming/placement, not design.

## Working tree

`/data/nvme0/can/Projects/nix-provenance`. **Depends on Phase 02** (the module
defaults to the `vikunja-provision` package and references its CLI flags; the
checks build/lint/test the crate). Capstone of this plan. Build with `nix develop`
/ the flake.

## Goal

`vikunja-provision` is a first-class tenant of the flake: a
`services.vikunja.provision` NixOS module (sibling of `services.immich.provision`)
exposed as `nixosModules.vikunjaProvision`, a `packages.vikunja-provision` built
with isolated `cargoArtifacts`, flake `checks` that build/lint/test the crate and
eval the module to a concrete `Type=oneshot` `serviceConfig`, and updated
`REUSE.toml`/licensing/README/architecture bookkeeping — all following the
`docs/architecture.md` "Adding a tenant" checklist, without clobbering the existing
config-only Vikunja SSO tenant.

## Why this matters now

Phase 02 produces the binary; without this phase it isn't packaged, isn't checked,
and has no NixOS surface, so canix can't consume it and CI can't guard it. This is
the wiring that turns the crate into a deployable, regression-guarded tenant.

## Out of scope

- Crate logic (Phase 02) and the SSO-claim cleanup (Phase 01).
- Any Stalwart-016-owned file: `nix/lib/stalwart.nix`, `nix/modules/ldap/stalwart.nix`,
  `nix/modules/test/stalwart-eval.nix`, the `stalwart-module-eval` check.
- Editing the config-only Vikunja SSO module (`nix/modules/config-only/vikunja.nix`)
  or its `vikunja-oidc-env` unit or the existing `vikunja-module-eval` check — the
  new tenant is **additive and parallel**.
- Minting the token or deploying to a host (canix-side; out of this repo).

## Plan

1. **NixOS reconciler module** `nix/modules/service-oidc/vikunja.nix` — model on
   `nix/modules/service-oidc/immich.nix`:
   - Signature `{self}: {config, lib, pkgs, ...}:`; `cfg =
     config.services.vikunja.provision`.
   - Options under `services.vikunja.provision`: `enable`; `package` (default
     `self.packages.${pkgs.stdenv.hostPlatform.system}.vikunja-provision`);
     `endpoint` (default derived from the running Vikunja — inspect the upstream
     `services.vikunja` options for the listen interface/port, e.g.
     `"http://localhost:${toString config.services.vikunja.<port-opt>}"`; bracket
     bare IPv6 like immich does if applicable); `tokenFile` (path to the runtime
     secret holding `tk_…`); `botUsername` (str — the token's service account, to
     exclude from membership reconcile); `teams` (`attrsOf` submodule `{ present
     (bool, default true); members (listOf str); admins (listOf str, default []);
     description (nullOr str) }`); `readyTimeoutSeconds` (default 30);
     `acceptInvalidCerts` (bool); `allowTeamDelete` (bool, global delete lock);
     `serviceAfter` (listOf str, default `["vikunja.service"]`).
   - Render the teams attrset to a `builtins.toJSON` state file via
     `pkgs.writeText "vikunja-provision-state.json" (builtins.toJSON { teams = …; })`
     (mirror immich's `userManifest`/`stateFile`).
   - `provisionScript` (`pkgs.writeShellScript`): read the token from
     `$CREDENTIALS_DIRECTORY/vikunja-token`, then `exec` the binary with `--url`,
     `--state`, `--token-file`, `--bot-username`, `--ready-timeout`, and the
     `--accept-invalid-certs`/`--allow-team-delete`/`--no-auto-remove` flags as
     configured (use `lib.escapeShellArgs`).
   - `systemd.services.vikunja-provision`: `Type=oneshot`, `RemainAfterExit=true`,
     `after`/`requires` = `cfg.serviceAfter`, `wantedBy=["multi-user.target"]`,
     `ExecStart = provisionScript`, **`LoadCredential = ["vikunja-token:${cfg.tokenFile}"]`**
     (the token is a static secret → `LoadCredential`, as `kanidm-credentials` does;
     never a Nix store path or argv), `User`/`Group` = the Vikunja service user.
   - Assertions: `services.vikunja.enable`; `cfg.tokenFile != null`;
     `cfg.botUsername != ""`; present teams are well-formed.
2. **Expose the module** in `flake.nix` `nixosModules`: add
   `vikunjaProvision = import ./nix/modules/service-oidc/vikunja.nix {inherit self;};`.
   **Do not reuse the `vikunja` attr** — it is already bound to the config-only SSO
   module (`nix/modules/config-only/vikunja.nix`). Consumers import both.
3. **Overlay** in `flake.nix` `overlays.default`: add
   `vikunja-provision = self.packages.${final.stdenv.hostPlatform.system}.vikunja-provision;`
   (mirror the immich/rauthy entries).
4. **Package** in `nix/packages.nix`: add `vikunja-provision` to `mkArgs`/the
   `buildDepsOnly` set/`packages` (mirror `rauthy-provision`); `meta` with
   `mainProgram = "vikunja-provision"`, `description`, `license = with lib.licenses;
   [mit asl20]`.
5. **Eval test** `nix/modules/test/vikunja-provision-eval.nix` (new file; do NOT
   edit the existing `vikunja-eval.nix`): `imports = [self.nixosModules.vikunjaProvision]`,
   enable `services.vikunja` (minimal) + `services.vikunja.provision` with a sample
   team + a `tokenFile` + `botUsername`, `system.stateVersion`.
6. **Checks** in `nix/checks.nix` (mirror the rauthy entries):
   - `vikunja-provision = packages.vikunja-provision;` (build)
   - `vikunja-clippy = mkClippy "vikunja-provision";`
   - `vikunja-test = craneLib.cargoTest (args.vikunja-provision // {cargoArtifacts =
     cargoArtifacts.vikunja-provision;});`
   - `vikunja-provision-module-eval` — eval `vikunja-provision-eval.nix` and assert
     `systemd.services.vikunja-provision.serviceConfig` is non-empty (and
     `ExecStart` is executable, like `kanidm-credentials-module-eval`). **Use this
     distinct name** — the existing `vikunja-module-eval` (config-only SSO,
     `vikunja-oidc-env`) must remain untouched and passing.
   - Add `vikunjaEval = evalSystem ./modules/test/vikunja-provision-eval.nix;` to the
     `let` block (alongside the existing eval bindings) — pick a non-colliding
     binding name (e.g. `vikunjaProvisionEval`).
   - *(Optional hardening)* extend `license-firewall` to also assert
     `crates/vikunja-provision/Cargo.toml` does not depend on `immich-provision`.
7. **Bookkeeping** (the "Adding a tenant" checklist):
   - `REUSE.toml`: SPDX `MIT OR Apache-2.0` for `crates/vikunja-provision/**`,
     `nix/modules/service-oidc/vikunja.nix`, `nix/modules/test/vikunja-provision-eval.nix`.
   - `docs/src/reference/licensing.md`: add the new paths to the per-path SPDX map.
   - `README.md`: add `vikunja-provision` to the Crates table and the flake-outputs
     list (`nixosModules.vikunjaProvision`, `packages.<system>.vikunja-provision`).
   - `docs/architecture.md`: add `vikunja-provision` to the `service-oidc/` tenant
     row (note it reconciles teams via the API while OIDC stays SSO-only).
8. Validate: `alejandra --check flake.nix nix`, `nix build .#vikunja-provision`,
   `nix build .#checks.<sys>.{vikunja-clippy,vikunja-test,vikunja-provision-module-eval,vikunja-module-eval,tls-feature-isolation,license-firewall}`.

## Acceptance criteria

- [ ] `nix build .#vikunja-provision` succeeds.
- [ ] `nix build .#checks.<sys>.vikunja-provision-module-eval` passes: the new
      module evaluates `services.vikunja.provision` to a concrete `Type=oneshot`
      `RemainAfterExit` `serviceConfig` with `LoadCredential` carrying the token
      (no store path), ordered after `vikunja.service`.
- [ ] `nix build .#checks.<sys>.vikunja-module-eval` (the pre-existing config-only
      SSO check) still passes — not renamed, not clobbered.
- [ ] `vikunja-clippy` (`-D warnings`) and `vikunja-test` checks pass.
- [ ] `tls-feature-isolation` and `license-firewall` still pass with the new crate.
- [ ] `flake.nix` exposes `nixosModules.vikunjaProvision` (distinct from `vikunja`)
      and `overlays.default.vikunja-provision`.
- [ ] `REUSE.toml`, `docs/src/reference/licensing.md`, `README.md`, and
      `docs/architecture.md` list the new tenant; `alejandra --check flake.nix nix`
      is clean.
- [ ] No Stalwart-016-owned file was modified (`git diff --name-only` shows none of
      `nix/lib/stalwart.nix`, `nix/modules/ldap/stalwart.nix`,
      `nix/modules/test/stalwart-eval.nix`).

## Files likely touched

- `nix/modules/service-oidc/vikunja.nix` — new reconciler module.
- `nix/modules/test/vikunja-provision-eval.nix` — new eval test.
- `flake.nix` — `nixosModules.vikunjaProvision` + overlay entry.
- `nix/packages.nix` — `vikunja-provision` args/deps/package.
- `nix/checks.nix` — build/clippy/test + `vikunja-provision-module-eval` (+ optional
  `license-firewall` extension).
- `REUSE.toml`, `docs/src/reference/licensing.md`, `README.md`, `docs/architecture.md`.

## Pitfalls

- **`nixosModules` attr-name clash.** `vikunja` is already bound to the config-only
  SSO module. Reusing it silently overrides one of them. Symptom: SSO or provisioning
  module "disappears". Cause: duplicate `vikunja` key. Recovery: name the new one
  `vikunjaProvision`.
- **Clobbering the existing eval/check.** `vikunja-module-eval` evaluates the
  `vikunja-oidc-env` unit from a test file (`vikunja-eval.nix`) that imports the SSO
  module. Create a **new** test file and a **new** check name
  (`vikunja-provision-module-eval`); do not edit `vikunja-eval.nix` or rename the
  existing check. Two distinct `let`-bindings, two distinct checks.
- **Token as a store path.** Rendering `cfg.tokenFile` into the state JSON or the
  argv leaks it into the world-readable Nix store. Use `LoadCredential` +
  `$CREDENTIALS_DIRECTORY` (as `kanidm-credentials.nix` does), `--token-file` only.
- **Wrong endpoint derivation.** Vikunja's listen option name differs from immich's
  `host`/`port`; check the actual `services.vikunja` option set before hardcoding.
  A wrong endpoint makes the readiness probe time out. Provide an `endpoint` option
  with a sensible default and let the consumer override.
- **Packaging drift.** Each crate gets its **own** isolated `cargoArtifacts`
  (`-p vikunja-provision`); do not share a workspace `cargoArtifacts` (it would
  union TLS features). Mirror the `mkArgs`/`buildDepsOnly` pattern exactly.
- **Accidentally touching Stalwart files.** Phase 05 of the stalwart-016 plan owns
  `nix/lib/stalwart.nix` and friends and is in flight. Keep `git diff` clear of them.

## Reference

- Mirror templates: `nix/modules/service-oidc/immich.nix` (module shape, state file,
  oneshot), `nix/modules/kanidm/credentials.nix` (`LoadCredential` token pattern),
  `nix/packages.nix` + `nix/checks.nix` (rauthy entries), `nix/modules/test/rauthy-eval.nix`.
- Tenant checklist: [../../architecture.md](../../architecture.md) "Adding a tenant".
- Stay-clear constraint: [../stalwart-016/05-kanidmldap-016-schema.md](../stalwart-016/05-kanidmldap-016-schema.md)
  (Phase 05 owns the Stalwart lib/module/check).
- Depends on: Phase 02 (the crate + its CLI flags).
