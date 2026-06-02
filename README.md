# nix-provenance

Declarative identity & OIDC provisioning for NixOS, Kanidm, and Rauthy — a DRY
monorepo of reconcilers and NixOS modules.

Each **tenant** reconciles one system from a Nix-rendered JSON state file via a
`Type=oneshot` systemd unit ordered after that system. A tenant is not always a
Rust crate — the directory taxonomy makes that explicit:

| Kind | Provisions | Tenants |
|------|-----------|---------|
| **IdP** (`nix/modules/idp/`) | an identity provider | `rauthy-provision` |
| **service-side OIDC** (`nix/modules/service-oidc/`) | a downstream service's users + OIDC wiring | `immich-provision` |
| **config-only** (`nix/modules/config-only/`) | service OIDC via shared Nix only, no crate | Vikunja |
| **LDAP** (`nix/modules/ldap/`) | LDAP-backed services | _Stalwart-style (future)_ |

## Crates

| Crate | Provisions | License |
|-------|-----------|---------|
| [`immich-provision`](crates/immich-provision) | Immich users via a patched short-lived provision-token | `AGPL-3.0-only` |
| [`rauthy-provision`](crates/rauthy-provision) | Rauthy users / groups / roles / OIDC clients | `MIT OR Apache-2.0` |

See [LICENSING.md](LICENSING.md) for the per-path SPDX map and the
permissive-core rule. See [docs/architecture.md](docs/architecture.md) for the
tenant taxonomy and the add-a-tenant checklist.

## Flake outputs

- `packages.<system>.{immich-provision,rauthy-provision}`
- `nixosModules.{immich,rauthy,vikunja}` (plus `default = rauthy`, a back-compat alias
  retained only during the canix migration)
- `lib.{immich,rauthy,vikunja}` — `usersFromKanidmPersons` for Immich/Rauthy,
  plus service-specific `kanidmOAuth2System` helpers for Immich and Vikunja

## Development

```sh
cargo test
nix flake check --no-build
nix flake check
```
