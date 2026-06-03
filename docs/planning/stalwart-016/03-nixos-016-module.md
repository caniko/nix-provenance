# Phase 03 — Local NixOS module for Stalwart 0.16 (the transport)

> **Recommended Codex model: GPT 5.5 high**
>
> Frontier-leaning design with an orchestrator role: there is **no upstream NixOS
> module for 0.16** (the nixpkgs one is incompatible and its rewrite, #511880, is
> unfinished), so this phase trail-blazes the JSON-bootstrap + datastore + headless
> registry-provisioning transport that every later phase and the live deploy depend
> on. `5.5 high` (not `max`): it's a bounded module against a now-known run model
> (phase 02), not open-ended research — but a weaker model would produce a module
> that boots in a VM yet mis-handles the datastore/secret/listener wiring and fails
> on the real host. The blast radius (it gates 04 and 07) justifies high.

## Working tree

`/data/nvme0/can/Projects/nix-provenance`. New NixOS module, housed here for
modularity (canix consumes it). **Prerequisite:** phase 02's `notes/02-run-model.md`
is the contract — do not start until it authoritatively describes the bootstrap
file, listeners, and headless provisioning.

## Goal

A self-contained NixOS module (e.g. `nixosModules.stalwart016`) that runs **Stalwart
0.16.7** with: the JSON **bootstrap** config (datastore connection only), a systemd
service using the phase-01 package, the datastore (PostgreSQL, as today), the three
mail listeners (25/587/993) + TLS/ACME, and a **headless registry-provisioning** hook
(so listeners/directories/etc. land in the datastore on activation, not via a web UI).
No TOML. It boots clean in a NixOS VM test.

## Why this matters now

The pinned nixpkgs `services.stalwart` renders TOML and runs `--config=stalwart.toml`;
0.16.7 has no TOML parser, so that module cannot drive 0.16 at all. We carry a local
module until #511880 lands. This module is the foundation the kanidm cutover (04/05)
and the live deploy (07) sit on; the data migration (06) restores *into* the datastore
this module manages.

## Out of scope

- The kanidm LDAP **directory object** itself (phase 05 builds it; phase 04 pushes it).
  This module provides the *mechanism* to provision registry objects, not the kanidm
  content.
- The live `thething` data migration (phase 06) and deploy (phase 07).
- Upstreaming to nixpkgs. Keep options clean/generic so it *could* be upstreamed, but
  do not open a PR.

## Plan

1. From `notes/02-run-model.md`, lock the transport decisions: the bootstrap
   `config.json` content (datastore = PostgreSQL connection), the headless provisioning
   path (`stalwart-cli apply` and/or recovery mode), and how listeners/TLS are
   represented.
2. Define the module options surface — keep it generic + upstreamable. At minimum:
   `enable`, `package` (default the phase-01 0.16.7 overlay), `cliPackage`
   (stalwart-cli 1.0.0), datastore connection (reuse the host's PostgreSQL +
   `LoadCredential` for the password, preserving the gen-50 PG-password fix pattern),
   listeners (25/587/993 with TLS modes), ACME/cert config, admin bootstrap, and a
   `registryConfig`/`provision` hook (a declarative blob or a list of `apply`
   documents) that phase 04 fills.
3. Render the **bootstrap config.json** via `pkgs.formats.json` (NOT toml) and pass it
   as `-c`. Secrets via systemd `LoadCredential` + the native `@type` `file` secret
   variant (or the `%{file}%` macro only if phase 02 proved it expands in registry
   objects).
4. Write the **systemd service**: ExecStart of the 0.16.7 binary with the bootstrap
   file; ordering after `postgresql.target`; `StateDirectory`/`DynamicUser` as
   appropriate; the three listeners' firewall ports handled by the consumer (don't use
   a blanket openFirewall — mirror the existing canix stalwart.nix which opens only
   25/587/993).
5. Implement the **headless registry provisioning**: a oneshot (ordered after the
   stalwart service is up + healthy) that applies the `registryConfig` via
   `stalwart-cli apply` (and/or recovery mode for first boot), idempotently. This is
   the mechanism; phase 04 supplies the content (listeners, directory, accounts).
6. Add a **NixOS VM test** (`nixosTest`) that boots the module, asserts the service is
   active, :25/:587/:993 are listening, and a trivially-provisioned account/listener
   shows up in the registry. Wire it into `nix/checks.nix`.
7. Register the module in `flake.nix` `nixosModules`. Keep it independent of the
   kanidm/ldap module (phase 05) — composition happens at the canix consumer.

## Acceptance criteria

- [ ] `nixosModules.stalwart016` exists, registered in `flake.nix`, and a `nixosTest`
      in `nix/checks.nix` **boots Stalwart 0.16.7** (the phase-01 package) and passes:
      service active, :25/:587/:993 listening, no TOML config file referenced.
- [ ] The module renders a **JSON bootstrap** (via `pkgs.formats.json`), not TOML, and
      `--config` points at it; `grep`-asserting the unit's ExecStart shows the JSON file.
- [ ] PostgreSQL datastore wiring preserves the gen-50 pattern (password via
      `LoadCredential`, `postgresql-setup` empty-password guard, owner = postgres) —
      reused/adapted, not regressed.
- [ ] A **headless provisioning** oneshot applies a sample `registryConfig` (one
      listener + one account) via `stalwart-cli apply` (or recovery mode) idempotently;
      the VM test proves a re-run is a no-op and the objects are present.
- [ ] The module options are documented and generic (no canix-only assumptions) so the
      module could be lifted toward #511880 later.

## Files likely touched

- `nix/modules/mail/stalwart016.nix` *(new)* — the module.
- `nix/modules/test/stalwart016-vmtest.nix` *(new)* — the nixosTest.
- `flake.nix` — register `nixosModules.stalwart016`.
- `nix/checks.nix` — wire the VM test.
- Possibly `nix/lib/stalwart.nix` — shared bootstrap-render helpers (kept distinct
  from the kanidmLdap directory helper, which phase 05 owns).

## Pitfalls

- **Re-implementing the TOML module's surface.** Don't port `settings`-as-TOML. The
  0.16 model is bootstrap-JSON + registry-via-`apply`. Designing options as "render
  this giant TOML-equivalent" reproduces the incompatibility.
- **First-boot chicken-and-egg.** A fresh datastore has no registry config; the
  service may need recovery mode or a first-boot `apply` before it can serve. Make the
  provisioning oneshot handle empty-datastore bootstrap, not just incremental apply.
  Symptom: service up but rejects all connections / no listeners. Recovery: drive
  recovery-mode bootstrap from phase 02's mechanics.
- **Datastore password regression.** The gen-50 PG-password-wipe bug (`postgresql-setup`
  clearing the role password) must not return — carry the owner=postgres + empty-guard
  fix into this module's datastore wiring.
- **Listener/TLS represented wrong.** If listeners live in the registry (not bootstrap),
  the systemd service alone won't open :25/:587/:993 — the provisioning oneshot must run
  and succeed first. Order + assert this in the VM test, or a deploy will come up with no
  mail ports.
- **Secret leakage / macro assumption.** Use `LoadCredential` + `@type` file secrets;
  don't bake secrets into the JSON in the store. Only use `%{file}%` macros if phase 02
  proved they expand in registry objects.

## Reference

- Contract: `docs/planning/stalwart-016/notes/02-run-model.md` (phase 02).
- gen-50 PG-password fix + listener firewall pattern: canix
  `root/hosts/thething/server/stalwart.nix` (the current 0.15.5 module usage) — reuse
  the *patterns*, not the TOML.
- Upstream module-rewrite tracking: NixOS/nixpkgs#511880 (for alignment, not a dep).
- Consumed by: phase 04 (fills `registryConfig`), phase 07 (deploys on thething).
</content>
