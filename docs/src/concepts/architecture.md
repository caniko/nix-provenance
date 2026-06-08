# Architecture

`nix-provenance` is a DRY monorepo of declarative identity/OIDC provisioners and
their NixOS modules. Every tenant shares one **spine**:

> a Nix option tree → `builtins.toJSON` state file (`writeText`) → an idempotent
> HTTP-admin reconciler binary → a `Type=oneshot RemainAfterExit` systemd unit
> ordered `after` the system it provisions, with the credential resolved from a
> runtime file/env, never a Nix store path.

The spine does not imply that every upstream field is in scope. Credentials are
owned by the identity plane: Kanidm for internal humans and Rauthy's
set-password email flow for external users. Service-side modules manage
downstream users, profile metadata, roles, groups, claims, and OIDC settings,
but not app-local password or PIN fields. The field-level contract is documented
in [Per-user Fields](../reference/per-user-fields.md).

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

A **tenant is not always a crate.** The `nix/modules/` directory encodes the
kind:

| Directory | Kind | Reconciler | Examples |
|-----------|------|------------|----------|
| `idp/` | provisions an **identity provider** | Rust crate | `rauthy-provision` (kanidm uses upstream `kanidm-provision`) |
| `service-oidc/` | wires a **downstream service** to OIDC plus reconciles its users | Rust crate | `immich-provision`, `vikunja-provision` (teams via API; OIDC remains SSO-only) |
| `config-only/` | service OIDC via **shared Nix only** | none | Vikunja SSO |
| `ldap/` | **LDAP**-backed services | none (not the HTTP spine) | Stalwart |
| `adapter/` | a **non-tenant** third-party app's users plus OIDC client, into kanidm or rauthy | none (writes the IdP's own provisioner) | pink-raven (consumer) |

Stalwart has two module surfaces because 0.16 changed the configuration model
from the nixpkgs 0.15 TOML service to a JSON datastore bootstrap plus registry
objects applied over JMAP. `nixosModules.stalwart016` owns the 0.16 mail
transport: it renders `/etc/stalwart016/config.json`, runs the server as
`stalwart.service`, and uses `stalwart-cli apply` in recovery mode for
NetworkListener and migration/registry documents. `nixosModules.stalwart`
remains the Kanidm LDAP directory helper that emits the 0.16 `Ldap` registry
object consumed by the transport module or by a host-specific registry plan.

The Kanidm LDAP helper deliberately keeps `bindDn = "dn=token"` and
`bindAuthentication = true`: Stalwart must search with a Kanidm service-account
token, then bind as the user. Setting `bindAuthentication = false` makes
Stalwart attempt a local password-hash comparison that Kanidm cannot satisfy.
The directory swap must change only `storage.directory` and the directory
registry object; `storage.data`, `storage.blob`, `storage.fts`, and
`storage.lookup` stay on the mailbox datastore so mailbox contents survive.
Kanidm's LDAP gateway exposes only POSIX-enabled persons, so mailbox users need
POSIX attributes and a `mail` value before cutover.

The `adapter/` kind is the inverse of the others: instead of giving a system a
tenant, it lets an **out-of-scope app reuse existing tenants** (rauthy and/or
kanidm) from a uniform, backend-agnostic user schema, so a closed-source app
like pink-raven integrates its users without earning a module, lib, or crate
here. It is pure-Nix wiring on top of `services.rauthy.provision` /
`services.kanidm.provision`; it owns no reconciler. The reusable
`passwordInitByEmail` credential primitive (Rauthy's emailed set-password flow,
requiring SMTP such as Stalwart) lives here. See
[Third-party External Apps](../guides/external-apps.md).

## Shared code

- `crates/provenance-core` (`MIT OR Apache-2.0`): the permissive reconciler
  plumbing shared by both binaries (HTTP client builder, readiness poll,
  response/error handling, secret resolution, present-spec serde, set ops, the
  `Summary` counter). See [Licensing](../reference/licensing.md) for why the
  core must stay permissive.
- `nix/lib/`: `usersFromKanidmPersons` per tenant (the immich and rauthy
  variants have opposite semantics; they are not merged).

## Adding a tenant

1. Pick the kind: the `nix/modules/<kind>/` directory.
2. **Crate tenants** (`idp` / `service-oidc`):
   - `crates/<name>/`: depend on `provenance-core`; keep service-specific
     request-building and reconcile bodies local; keep `reqwest` TLS features
     per-crate.
   - add the member to the root `Cargo.toml`.
   - `nix/modules/<kind>/<name>.nix`: render the option tree to a `toJSON`
     state file run by a oneshot unit.
   - `nix/modules/test/<name>-eval.nix` plus a `*-module-eval` check.
   - add `packages.<name>` and the crate's checks.
   - tag releases as `<name>-vX`.
3. **Config-only / LDAP tenants:** add only the `nix/modules/<kind>/<name>.nix`
   wiring unless the upstream service also needs a packaged binary or overlay.
   Stalwart 0.16 is the exception: it exposes `packages.<system>.stalwart`,
   `packages.<system>.stalwart-cli`, `overlays.stalwart016`, and
   `nixosModules.stalwart016` because nixpkgs' 0.15 TOML module is not
   compatible with the 0.16 registry model.
4. Update `REUSE.toml` with the new paths' SPDX and `README.md`'s tables.
