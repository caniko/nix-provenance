# nix-provenance

Declarative identity & OIDC provisioning for NixOS, Kanidm, and Rauthy — a DRY
monorepo of reconcilers and NixOS modules.

Each **tenant** reconciles one system from a Nix-rendered JSON state file via a
`Type=oneshot` systemd unit ordered after that system. A tenant is not always a
Rust crate — the directory taxonomy makes that explicit:

| Kind | Provisions | Tenants |
|------|-----------|---------|
| **IdP** (`nix/modules/idp/`) | an identity provider | `rauthy-provision` |
| **service-side OIDC** (`nix/modules/service-oidc/`) | a downstream service's users + OIDC wiring | `immich-provision`, `vikunja-provision`, Forgejo |
| **config-only** (`nix/modules/config-only/`) | service OIDC via shared Nix only, no crate | Vikunja SSO |
| **LDAP** (`nix/modules/ldap/`) | LDAP-backed services | Stalwart, Stalwart 0.16 transport |
| **adapter** (`nix/modules/adapter/`) | a non-tenant third-party app's users + OIDC client, into kanidm or rauthy | pink-raven (consumer) |

## Crates

| Crate | Provisions | License |
|-------|-----------|---------|
| [`immich-provision`](crates/immich-provision) | Immich users via a patched short-lived provision-token | `AGPL-3.0-only` |
| [`rauthy-provision`](crates/rauthy-provision) | Rauthy users / groups / roles / OIDC clients | `MIT OR Apache-2.0` |
| [`vikunja-provision`](crates/vikunja-provision) | Vikunja teams and memberships via the API | `MIT OR Apache-2.0` |

See [LICENSING.md](LICENSING.md) for the per-path SPDX map and the
permissive-core rule. See [docs/architecture.md](docs/architecture.md) for the
tenant taxonomy and the add-a-tenant checklist.

## Flake outputs

- `packages.<system>.{identity-cli,immich-provision,rauthy-provision,vikunja-provision,stalwart,stalwart-cli,docs,site}`
- `nixosModules.{immich,rauthy,vikunja,vikunjaProvision,forgejo,stalwart,stalwart016,kanidmCredentials,externalApp}` (plus
  `default = rauthy`, a back-compat alias retained only during the canix migration)
- `lib.{immich,rauthy,vikunja,forgejo,stalwart,adapter}` — `usersFromKanidmPersons`
  for Immich/Rauthy, service-specific `kanidmOAuth2System` helpers for Immich,
  Vikunja, and Forgejo, Stalwart's kanidm LDAP helpers, and `adapter` — the
  backend-agnostic primitives third-party flakes use (see below)

## Third-party adapter (`lib.adapter` / `nixosModules.externalApp`)

For **non-OSS or out-of-scope apps that should not earn a tenant** here (e.g.
pink-raven), the adapter lets a third-party flake integrate its own users +
OIDC client into **kanidm or rauthy** from a uniform, backend-agnostic schema —
no module/lib/crate added per app. Each user is tagged with a credential
strategy:

- `adapter.kanidmLogin` — the user already has a kanidm identity (federated;
  nothing emailed). On the rauthy backend this is a passwordless auto-link user.
- `adapter.passwordInitByEmail { redirectUri ? null; }` — a native Rauthy user
  Rauthy emails a one-time set-password link to. **Requires SMTP (e.g. relaying
  through Stalwart) on the Rauthy host.** Rauthy-backend only.

```nix
services.provenance.externalApps.pink-raven = {
  backend = "rauthy";                                  # outward-facing → Rauthy
  loginUrl = "https://raven.tartanoglu.com/login";
  redirectUris = ["https://raven.tartanoglu.com/auth/callback"];
  users = {
    can.email = "can@tartanoglu.com";
    can.credential = inputs.nix-provenance.lib.adapter.kanidmLogin;        # canix
    eric = { email = "efirley@protonmail.com";
             credential = inputs.nix-provenance.lib.adapter.passwordInitByEmail {}; };
    caroline = { email = "carolinestahl@gmx.net";
                 credential = inputs.nix-provenance.lib.adapter.passwordInitByEmail {}; };
  };
};
```

See the [Third-party External Apps guide](docs/src/guides/external-apps.md) for
the full surface, the `accessGroup` option, the kanidm backend, and the canix
consumer wiring.

## Development

```sh
cargo test
nix flake check --no-build
nix flake check
```
