# nix-provenance

<!-- simit:badges:start -->

![CI](https://img.shields.io/badge/CI-managed-2088ff) [![docs](https://img.shields.io/badge/docs-enabled-6f42c1)](docs) [![crates.io](https://img.shields.io/badge/crates.io-ready-f46623)](https://crates.io/crates/forgejo-provision)

<!-- simit:badges:end -->

Declarative identity & OIDC provisioning for NixOS, Kanidm, and Rauthy — a DRY
monorepo of reconcilers and NixOS modules.

## Identity model

nix-provenance is intentionally opinionated about credentials. Internal human
credentials live in Kanidm, and internal users reach downstream services through
OIDC either directly from Kanidm or through Rauthy when Rauthy fronts external
apps. External users without Kanidm identities are initialized through Rauthy's
email-based set-password flow.

Downstream service provisioners manage app-side users, profile metadata, roles,
groups, OIDC claims, and service configuration. App/platform-local passwords
are supported only as runtime password-file references, normally
`config.age.secrets.<name>.path`; modules load those files through systemd
credentials and reconcilers store only rotation-marker hashes. Plaintext
passwords must never enter Nix-rendered JSON, the Nix store, argv, logs, or
environment variables. PINs, app-local password-reset flows, and notification
emails remain out of scope unless the identity model changes again. Public SSH
authentication keys are a separate non-secret exception: Forgejo may reconcile
declared public keys, while private keys and all password-like material remain
outside this repository's state.

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
| [`forgejo-provision`](crates/forgejo-provision) | Forgejo SSH public keys via the administrative API | `MIT OR Apache-2.0` |
| [`provenance-oauth`](crates/provenance-oauth) | Host/user-scoped OAuth enrollment, refresh, and access-only app adapters | `MIT OR Apache-2.0` |

See [LICENSING.md](LICENSING.md) for the per-path SPDX map and the
permissive-core rule. See [docs/architecture.md](docs/architecture.md) for the
tenant taxonomy and the add-a-tenant checklist.

## Flake outputs

- `packages.<system>.{identity-cli,immich-provision,rauthy-provision,vikunja-provision,forgejo-provision,stalwart016-provision,forgejo-cli,forgejo-cli-nushell-completion,docs,site}`
- `nixosModules.{immich,rauthy,vikunja,vikunjaProvision,forgejo,stalwart,stalwart016,kanidmCredentials,externalApp}` (plus
  `default = rauthy`, a back-compat alias retained only during the canix migration)
- `lib.{immich,rauthy,vikunja,forgejo,stalwart,adapter,passwords}` — `usersFromKanidmPersons`
  for Immich/Rauthy, service-specific `kanidmOAuth2System` helpers for Immich,
  Vikunja, and Forgejo, Stalwart's kanidm LDAP helpers, and `adapter` — the
  backend-agnostic primitives third-party flakes use (see below)
- `homeModules.fj` — installs nixpkgs' `forgejo-cli` plus its validated Nushell
  completion and provides `nix-provenance.fj.enable`.
- `packages.<system>.{provenance-oauth,oauth-adapters}`, `nixosModules.oauth`, and
  `homeModules.oauth` — shared provider authorization for compatible stock
  applications. OpenAI ChatGPT is supported through OpenCode V2 plugins and OMP
  extensions. See the [shared OAuth guide](docs/src/guides/shared-oauth.md) for
  enrollment, recovery, and the host/user trust boundary.

Enable the CLI in Home Manager, then add a CodeFloe application token
interactively:

```nix
imports = [ inputs.nix-provenance.homeModules.fj ];
nix-provenance.fj.enable = true;
```

```console
$ fj -H codefloe.com auth add-token
application token: …
```

The token remains in fj's per-user credential store; it is not placed in the
Nix store, agenix, or Home Manager configuration.

For a token already managed by agenix, let the module register it after the
agenix user service is ready. The token is read from the transient agenix path
and passed to fj over stdin; no persistent Home Manager token file is created:

```nix
nix-provenance.fj.applicationToken = {
  enable = true;
  host = "codefloe.com";
  tokenFile = config.age.secrets.can-codefloe-token.path;
};
```

## Stalwart 0.16 listener PROXY trust

On an explicitly declared listener, `proxyTrustedNetworks` restricts which
connection sources may supply a HAProxy PROXY header:

```nix
services.stalwart016.listeners.submission = {
  bind = ["10.77.0.2:587"];
  protocol = "smtp";
  useTls = true;
  proxyTrustedNetworks = ["10.77.0.1/32"];
};
```

Declare the other required listeners alongside it. The addresses above are
examples; use the enrolled proxy's exact transport address and restrict listener
admission separately in the firewall. Trusting a proxy supplies client metadata,
not SMTP relay permission or application authentication. HAProxy sends the header
with `send-proxy`, before STARTTLS or implicit TLS. Health probes from a trusted
source also need that header.

The option has three reconciliation states:

- `null` (default): leave the listener's registry override unmanaged.
- A nonempty list: replace `overrideProxyTrustedNetworks` with that exact set.
- `[]`: clear the listener override and inherit
  `SystemSettings.proxyTrustedNetworks`. Clearing does **not** disable a nonempty
  system-wide trust policy. Keep the system setting empty for listener-only trust.

`stalwart016-proxy-eval` checks serialization and invalid address rejection.
`stalwart016-proxy-vmtest` exercises the actual Stalwart/HAProxy listeners,
STARTTLS/IMAPS, client identity, relay rejection and set/unmanaged/replace/clear
transitions. The fixture generates its credentials inside the test VM.

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
- `adapter.passwordFromFile { passwordFile; }` — a native Rauthy user whose
  initial password is loaded from a runtime password file such as an agenix
  secret. Rauthy owns the password after account creation; later declarative
  changes warn and update only the marker hash. Rauthy-backend only.

```nix
services.provenance.externalApps.pink-raven = {
  backend = "rauthy";                                  # outward-facing → Rauthy
  loginUrl = "https://raven.tartanoglu.com/login";
  redirectUris = ["https://raven.tartanoglu.com/auth/callback"];
  postLogoutRedirectUris = ["https://raven.tartanoglu.com/"];
  allowedOrigins = ["https://raven.tartanoglu.com"];
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
