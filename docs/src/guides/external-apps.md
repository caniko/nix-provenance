# Third-party External Apps

`lib.adapter` and `nixosModules.externalApp` let apps outside this flake's
tenant scope, including closed-source apps, declare users
and an OIDC client in Rauthy or Kanidm. The adapter has no reconciler: it
maps one user schema to `services.rauthy.provision` / `services.kanidm.provision`
in Nix.

## Two axes

| Axis | Choice | Meaning |
|------|--------|---------|
| **backend** | `rauthy` | the app federates with Rauthy (outward-facing services). Required for emailed and password-file users. |
| | `kanidm` | the app federates with kanidm directly (internal services). |
| **per-user credential** | `kanidmLogin` | the user already has a kanidm identity. Federated; nothing emailed or stored here. |
| | `passwordInitByEmail` | a native Rauthy user Rauthy emails a one-time set-password link to. **Rauthy backend only.** |
| | `passwordFromFile` | a native Rauthy user whose initial password is loaded from a runtime file such as an agenix secret. Rauthy owns the password after creation. **Rauthy backend only.** |

`passwordInitByEmail` **requires a mail or SMTP server (for example Stalwart)
reachable from the Rauthy host**. Rauthy drives its `request_reset` flow once
at user creation, and without working SMTP the link is never delivered. The
module emits a build warning for emailed users until you set
`mailServerConfigured = true` to acknowledge that SMTP is wired.

## `lib.adapter` primitives

A flake that wants finer control can call the primitives directly instead of the
module:

- `adapter.kanidmLogin`: credential descriptor (constant)
- `adapter.passwordInitByEmail { redirectUri ? null; }`: credential descriptor;
  the module defaults `redirectUri` to the app's `loginUrl`.
- `adapter.passwordFromFile { passwordFile; }`: credential descriptor for a
  native Rauthy initial password loaded from a runtime file such as
  `config.age.secrets.<name>.path`. It renders to Rauthy's
  `initialPasswordFile`, so later password-file changes warn and update only
  the marker hash for existing users.
- `adapter.rauthyUsers { users, loginUrl ? null, language ? "en", commonGroups ? []; }`:
  renders `services.rauthy.provision.users`, keyed by email. `commonGroups`
  supplements each user's `groups`. Federated users carry
  `requiredAuthProvider = "kanidm"`; emailed users carry
  `sendPasswordEmail = true` and the redirect; file-backed users carry
  `initialPasswordFile`.
- `adapter.rauthyGroupsOf users`: the distinct rauthy group names referenced
- `adapter.kanidmOAuth2System { originUrl, group, ... }`: generic OAuth2 system
  attrset for `services.kanidm.provision.systems.oauth2.<name>`. The Immich,
  Forgejo, and Vikunja helpers specialize this shape.
- `adapter.kanidmPersons { users, group; }`: renders
  `services.kanidm.provision.persons` for `kanidmLogin` users only

## Ergonomic module

In this `services.provenance.externalApps.<name>` example, `alice` reuses a
Kanidm identity; `bob` and `carol` have no Kanidm identities. Rauthy emails
them a one-time set-password link to the app's `/login`.

```nix
{ inputs, ... }:
let adapter = inputs.nix-provenance.lib.adapter;
in {
  imports = [
    inputs.nix-provenance.nixosModules.externalApp
    inputs.nix-provenance.nixosModules.rauthy
  ];

  services.provenance.externalApps.example-app = {
    backend = "rauthy";
    displayName = "Example App";
    loginUrl = "https://app.example.com/login";
    redirectUris = ["https://app.example.com/auth/callback"];
    postLogoutRedirectUris = ["https://app.example.com/"];
    allowedOrigins = ["https://app.example.com"];
    mailServerConfigured = true;

    users = {
      alice = {
        email = "alice@example.com";
        displayName = "Alice";
        credential = adapter.kanidmLogin;
      };
      bob = {
        email = "bob@example.com";
        displayName = "Bob";
        credential = adapter.passwordInitByEmail {};
      };
      carol = {
        email = "carol@example.com";
        displayName = "Carol";
        credential = adapter.passwordInitByEmail {};
      };
    };
  };
}
```

This sets:

- `services.rauthy.provision.clients.example-app`: a public PKCE client
  (`confidential = false` by default, `enablePkce = true`) with the redirect URI
  and scopes
- `services.rauthy.provision.users."alice@example.com"`: passwordless,
  federated auto-link user
- `services.rauthy.provision.users."bob@example.com"` and
  `"carol@example.com"`: native users with `sendPasswordEmail = true` and
  `passwordEmailRedirectUri` set to `loginUrl`

Leave `accessGroup` unset when the app gates access with `oidcSeedUsers`.
Rauthy authenticates users; the app assigns roles.

### The `accessGroup` option

`accessGroup` controls whether the adapter provisions an app-wide group:

- **rauthy backend** — optional. When set (e.g. `accessGroup = "example-app-users"`)
  the group is created **and assigned to every one of the
  app's users**. When unset (the default), no group is created — leave it unset
  when the app gates access itself.
- **kanidm backend** — a group is always required (it is the OAuth2 scopeMap
  target); an unset `accessGroup` falls back to `"<name>-users"`.

## Kanidm backend

For a directly federated internal app, set `backend = "kanidm"` and give each
user `kanidmLogin`. `basicSecretFile` is a runtime path:

```nix
services.provenance.externalApps.internal-tool = {
  backend = "kanidm";
  confidential = true;
  redirectUris = ["https://tool.example.com/oauth2/callback"];
  basicSecretFile = "/run/secrets/internal-tool-oauth2-basic";
  users.alice = {
    email = "alice@example.com";
    displayName = "Alice";
    credential = adapter.kanidmLogin;
  };
};
```

This sets `services.kanidm.provision.systems.oauth2.internal-tool` (the OAuth2
resource server), `services.kanidm.provision.persons.alice`, and the
`internal-tool-users` group.

## Multi-source federation merge

In a consumer fleet's Rauthy host configuration, internal users can be federated
with `usersFromKanidmPersons` while external users are added with
`sendPasswordEmail`. The `adapter-module-eval` check covers the worked example
in `nix/modules/test/adapter-eval.nix`. Deployments are gated in the consumer
repo.

- **A user can be written by both the federation and the adapter.** A consumer
  can federate every internal human (including `alice`) into Rauthy with shared
  groups (for example `internal`/`shared-app`), and *also* list `alice` in the
  `example-app` adapter block with `adapter.kanidmLogin`. Both definitions key
  the same email, so they **merge into one Rauthy user**. For the merge to be
  conflict-free the scalar fields must agree: give the adapter user the **same
  `displayName` as the kanidm person** so the derived given/family names match.
  Groups are list-merged (union), so `alice` keeps the federation's groups and
  the adapter adds none (no `accessGroup`).
- **`mailServerConfigured = true` is the SMTP acknowledgement.** On that host
  Rauthy relays the set-password mail through Stalwart (the `SMTP_*` env in the
  Rauthy environment file), so the warning is acknowledged. Without a working
  mail path, `bob`/`carol` never receive their link.

## Resending set-password emails (`identity-cli rauthy`)

The set-password email is sent **once, on user creation** — the reconciler never
re-sends it (`rauthy-provision` only drives `request_reset` for a newly created
user). So if a user's link expired or never arrived, there is no declarative way
to resend. `identity-cli` closes that gap with a `rauthy` subcommand that reads
the provision **state file** (the source of truth for which users are
email-derived and where their link lands) and drives the same `request_reset`
flow on demand:

```console
# List every email-derived user defined in the state (one per emailed user):
$ identity-cli rauthy --state /path/to/rauthy-provision-state.json list-email-users
bob@example.com            Bob
carol@example.com          Carol

# Resend one a fresh link (match by email, email local-part, or name):
$ identity-cli rauthy --url https://id.example.com \
    --state /path/to/rauthy-provision-state.json reset-password bob
reset_email_sent=bob@example.com
```

`--url` (env `RAUTHY_URL`) and `--state` (env `RAUTHY_PROVISION_STATE`) make it
ergonomic to run from anywhere that can reach Rauthy over HTTP — e.g. **from the
app host against Rauthy on the IdP host**, since
`request_reset` is unauthenticated (Proof-of-Work gated, solved locally). The
state file is host-agnostic JSON: install it (or a minimal email-derived subset)
alongside `identity-cli` on whichever host operators use. Rauthy answers 200 even
for unknown emails (enumeration safety), so confirm delivery via the Rauthy /
mail-server logs, not the command's exit code.

## Pitfalls

- Emailed users without SMTP: verify delivery through Rauthy and Stalwart
  journals, not just the HTTP status.
- `passwordInitByEmail` on the kanidm backend: asserted against; use
  `kanidmLogin`. Kanidm has its own credential-reset path.
- `passwordFromFile` on the kanidm backend: asserted against; the adapter
  currently creates Kanidm persons but does not initialize primary credentials.
- Rauthy backend without importing `nixosModules.rauthy`: the adapter writes
  `services.rauthy.provision.*`, so import the module and enable provisioning
  on the same host.
- Two apps keying the same email: Rauthy keys users by email, so the collision
  surfaces as a Nix merge conflict.
- `kanidmLogin` users with local credential drift: reconciliation checks
  password/passkey state and provider linkage. The Rauthy API cannot remove
  those credentials or block later reset/passkey flows. Provisioning fails;
  fix the account manually in Rauthy before retrying.
