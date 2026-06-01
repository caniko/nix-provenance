# Architecture

`nix-provenance` is a DRY monorepo of declarative identity/OIDC provisioners and
their NixOS modules. Every tenant shares one **spine**:

> a Nix option tree → `builtins.toJSON` state file (`writeText`) → an idempotent
> HTTP-admin reconciler binary → a `Type=oneshot RemainAfterExit` systemd unit
> ordered `after` the system it provisions, with the credential resolved from a
> runtime file/env, never a Nix store path.

Reconcilers share the same control shape:

```
match (spec.present, current) {
  (true,  None)    => create,
  (true,  Some(x)) => update if drifted,
  (false, Some(x)) => delete if allowed,
  (false, None)    => noop,
}
```

## Tenant taxonomy

A **tenant is not always a crate.** The `nix/modules/` directory encodes the kind:

| Directory | Kind | Reconciler | Examples |
|-----------|------|-----------|----------|
| `idp/` | provisions an **identity provider** | Rust crate | `rauthy-provision` (kanidm uses upstream `kanidm-provision`) |
| `service-oidc/` | wires a **downstream service** to OIDC + reconciles its users | Rust crate | `immich-provision` |
| `config-only/` | service OIDC via **shared Nix only** | none | Vikunja-style (future) |
| `ldap/` | **LDAP**-backed services | none (not the HTTP spine) | Stalwart migration (future) |

## Shared code

- `crates/provenance-core` (`MIT OR Apache-2.0`) — the permissive reconciler
  plumbing shared by both binaries (HTTP client builder, readiness poll,
  response/error handling, secret resolution, present-spec serde, set ops, the
  `Summary` counter). See [../LICENSING.md](../LICENSING.md) for why the core
  must stay permissive.
- `nix/lib/` — `usersFromKanidmPersons` per tenant (the immich and rauthy
  variants have opposite semantics; they are **not** merged).

## Adding a tenant

1. Pick the kind → the `nix/modules/<kind>/` directory.
2. **Crate tenants** (`idp`/`service-oidc`):
   - `crates/<name>/` — depend on `provenance-core`; keep service-specific
     request-building and reconcile bodies local; keep `reqwest` TLS features
     **per-crate** (never hoist into `[workspace.dependencies]`).
   - add the member to the root `Cargo.toml`.
   - `nix/modules/<kind>/<name>.nix` — `services.<svc>.provision`, rendering the
     option tree to a `toJSON` state file run by a oneshot unit.
   - `nix/modules/test/<name>-eval.nix` + a `*-module-eval` check.
   - add `packages.<name>` (isolated `cargoArtifacts`) and the crate's checks.
   - tag releases as `<name>-vX`.
3. **Config-only / LDAP tenants:** add only the `nix/modules/<kind>/<name>.nix`
   wiring; no crate, no package, no `cargoArtifacts`.
4. Update `REUSE.toml` with the new paths' SPDX and `README.md`'s tables.
