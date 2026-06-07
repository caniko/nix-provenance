# Introduction

`nix-provenance` is a DRY monorepo of declarative identity and OIDC
provisioners plus their NixOS modules.

Each tenant reconciles one system from a Nix-rendered JSON state file via a
`Type=oneshot` systemd unit ordered after the system it provisions. A tenant is
not always a Rust crate:

| Kind | Provisions | Tenants |
|------|------------|---------|
| **IdP** (`nix/modules/idp/`) | an identity provider | `rauthy-provision` |
| **service-side OIDC** (`nix/modules/service-oidc/`) | a downstream service's users plus OIDC wiring | `immich-provision`, Forgejo |
| **config-only** (`nix/modules/config-only/`) | service OIDC via shared Nix only, no crate | Vikunja |
| **LDAP** (`nix/modules/ldap/`) | LDAP-backed services | Stalwart, Stalwart 0.16 transport |
| **adapter** (`nix/modules/adapter/`) | a non-tenant third-party app's users plus OIDC client, into kanidm or rauthy | pink-raven |

## Crates

| Crate | Provisions | License |
|-------|------------|---------|
| `immich-provision` | Immich users via a patched short-lived provision token | `AGPL-3.0-only` |
| `rauthy-provision` | Rauthy users, groups, roles, and OIDC clients | `MIT OR Apache-2.0` |
| `vikunja-provision` | Vikunja teams and memberships via the API | `MIT OR Apache-2.0` |

See [Architecture](./concepts/architecture.md) for the tenant taxonomy and the
add-a-tenant checklist. See [Licensing](./reference/licensing.md) for the
mixed-license boundary that keeps the shared core permissive.

## Flake outputs

- `packages.<system>.{identity-cli,immich-provision,rauthy-provision,vikunja-provision,stalwart,stalwart-cli,docs,site}`
- `nixosModules.{immich,rauthy,vikunja,vikunjaProvision,forgejo,stalwart,stalwart016,kanidmCredentials,externalApp}`
- `lib.{immich,rauthy,vikunja,forgejo,stalwart,adapter}`

## Key guides

- [Third-party External Apps](./guides/external-apps.md): backend-agnostic
  adapter wiring for out-of-scope applications such as pink-raven.
- [Immich Kanidm OIDC Migration](./guides/kanidm-oidc-migration.md): the
  cutover checklist for existing Immich deployments that already hold user
  libraries.
- [RFC 0001: Trusted Local Provisioning for Immich](./rfcs/0001-trusted-local-provisioning.md):
  the design for short-lived local provisioning tokens in Immich.
