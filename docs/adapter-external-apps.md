# Third-party identity adapter

`lib.adapter` + `nixosModules.externalApp` let a **third-party flake integrate
its own users + OIDC client into the identity plane (kanidm or rauthy)** without
earning a first-class tenant in this repo. It is for apps this flake does **not**
support directly — closed-source or otherwise out-of-scope projects such as
**pink-raven** — that still want declarative users behind our IdPs.

It is the inverse of a tenant: a tenant gives a *system* a provisioner; the
adapter lets an *app* reuse the existing rauthy/kanidm provisioners. It owns no
reconciler — it is pure-Nix wiring that writes `services.rauthy.provision` /
`services.kanidm.provision` values from a uniform, backend-agnostic user schema.

## Two axes

| Axis | Choice | Meaning |
|------|--------|---------|
| **backend** | `rauthy` | the app federates with Rauthy (outward-facing services). Required for emailed and password-file users. |
| | `kanidm` | the app federates with kanidm directly (internal services). |
| **per-user credential** | `kanidmLogin` | the user already has a kanidm identity. Federated; nothing emailed or stored here. |
| | `passwordInitByEmail` | a native Rauthy user Rauthy emails a one-time set-password link to. **Rauthy backend only.** |
| | `passwordFromFile` | a native Rauthy user whose initial password is loaded from a runtime file such as an agenix secret. Rauthy owns the password after creation. **Rauthy backend only.** |

`passwordInitByEmail` **requires a mail/SMTP server (e.g. Stalwart) reachable
from the Rauthy host** — Rauthy drives its `request_reset` flow once at user
creation, and without working SMTP the link is never delivered. The module emits
a build warning for emailed users until you set `mailServerConfigured = true` to
acknowledge that SMTP is wired.

## `lib.adapter` primitives

A flake that wants finer control can call the primitives directly instead of the
module:

- `adapter.kanidmLogin` — credential descriptor (constant).
- `adapter.passwordInitByEmail { redirectUri ? null; }` — credential descriptor.
  `redirectUri` defaults to the app `loginUrl` when used through the module.
- `adapter.passwordFromFile { passwordFile; }` — credential descriptor for a
  native Rauthy initial password loaded from a runtime file such as
  `config.age.secrets.<name>.path`. It renders to Rauthy's
  `initialPasswordFile`, so later password-file changes warn and update only
  the marker hash for existing users.
- `adapter.rauthyUsers { users, loginUrl ? null, language ? "en"; }` →
  a `services.rauthy.provision.users` attrset (keyed by email). `kanidmLogin`
  users are passwordless/federated and carry
  `requiredAuthProvider = "kanidm"`; `passwordInitByEmail` users carry
  `sendPasswordEmail = true` + the redirect; `passwordFromFile` users carry
  `initialPasswordFile`.
- `adapter.rauthyGroupsOf users` → the distinct rauthy group names referenced.
- `adapter.kanidmOAuth2System { originUrl, group, … }` → a generic
  `services.kanidm.provision.systems.oauth2.<name>` attrset (the federation
  client). The per-tenant immich/forgejo/vikunja helpers are specialisations of
  this shape.
- `adapter.kanidmPersons { users, group; }` →
  a `services.kanidm.provision.persons` attrset (kanidmLogin users only).

## `services.provenance.externalApps.<name>` (the ergonomic module)

Worked example — **pink-raven**, an outward-facing app (→ rauthy backend) whose
users are `can` (existing kanidm login, see canix), `eric`, and `caroline`
(external; credential by email):

```nix
{ inputs, ... }:
let adapter = inputs.nix-provenance.lib.adapter;
in {
  imports = [
    inputs.nix-provenance.nixosModules.externalApp
    inputs.nix-provenance.nixosModules.rauthy   # rauthy backend → also import this
  ];

  services.provenance.externalApps.pink-raven = {
    backend = "rauthy";
    displayName = "Pink Raven";
    loginUrl = "https://raven.tartanoglu.com/login";          # emailed-link landing
    redirectUris = ["https://raven.tartanoglu.com/auth/callback"];
    postLogoutRedirectUris = ["https://raven.tartanoglu.com/"];
    allowedOrigins = ["https://raven.tartanoglu.com"];
    mailServerConfigured = true;                              # Rauthy SMTP via Stalwart

    users = {
      # can authenticates via his existing kanidm identity (federated,
      # passwordless). His kanidm person is defined in canix.
      can = {
        email = "can@tartanoglu.com";
        displayName = "Can";
        credential = adapter.kanidmLogin;
      };
      # eric + caroline are external — no kanidm. Rauthy emails them a one-time
      # set-password link that lands back at pink-raven's /login.
      eric = {
        email = "efirley@protonmail.com";
        displayName = "Eric";
        credential = adapter.passwordInitByEmail {};           # redirect ← loginUrl
      };
      caroline = {
        email = "carolinestahl@gmx.net";
        displayName = "Caroline";
        credential = adapter.passwordInitByEmail {};
      };
    };
  };
}
```

This sets, with no per-app boilerplate:

- `services.rauthy.provision.clients.pink-raven` — a public PKCE client
  (`confidential = false` default) with the redirect URI and scopes.
- `services.rauthy.provision.users."can@tartanoglu.com"` — passwordless
  (federated auto-link), and `"efirley@protonmail.com"` /
  `"carolinestahl@gmx.net"` — native with `sendPasswordEmail = true` and
  `passwordEmailRedirectUri = loginUrl`.

No rauthy group is created here: `accessGroup` is unset, because pink-raven
gates access from its own `oidcSeedUsers` allowlist. Set `accessGroup =
"pink-raven-users"` if you want an app-wide group created and assigned to every
user instead.

> Access control still lives where it belongs: pink-raven gates logins from its
> own `oidcSeedUsers` allowlist. Being a Rauthy user here only lets these three
> *authenticate*; the app decides their roles.

### kanidm backend

For an internal app that federates with kanidm directly, set `backend = "kanidm"`
and give every user `kanidmLogin` (emailed-init is rauthy-only and asserted):

```nix
services.provenance.externalApps.internal-tool = {
  backend = "kanidm";
  confidential = true;
  redirectUris = ["https://tool.example.com/oauth2/callback"];
  basicSecretFile = "/run/secrets/internal-tool-oauth2-basic";   # runtime path
  users.dejana = {
    email = "dejana@tartanoglu.com";
    displayName = "Dejana";
    credential = adapter.kanidmLogin;
  };
};
```

This sets `services.kanidm.provision.systems.oauth2.internal-tool` (the OAuth2
resource server), `…persons.dejana`, and the `internal-tool-users` group.

## Relationship to the hand-written canix wiring

The adapter factors out the pattern previously hand-written in canix
`root/hosts/thething/server/rauthy.nix` — `usersFromKanidmPersons` for the
federated internal humans, then external users appended with
`sendPasswordEmail`/`passwordEmailRedirectUri`. The same three pink-raven users
(can federated, eric/caroline emailed) now come from one uniform block. Migrating
canix to the adapter is a separate, deploy-gated change on that repo; this flake
ships the reusable surface and the eval-gated worked example
(`nix/modules/test/adapter-eval.nix`, the `adapter-module-eval` check).

## Pitfalls

- **Emailed users without SMTP.** `passwordInitByEmail` needs a working mail
  server on the Rauthy host (Stalwart here). Rauthy returns 200 from
  `request_reset` for enumeration safety even when delivery fails — confirm via
  the Rauthy/Stalwart journals, not the HTTP status.
- **`passwordInitByEmail` on the kanidm backend.** Asserted against — kanidm has
  its own credential-reset path, not Rauthy's emailed flow. Use `kanidmLogin`.
- **`passwordFromFile` on the kanidm backend.** Asserted against — the adapter
  currently creates Kanidm persons but does not initialize primary credentials.
- **Rauthy backend without importing `nixosModules.rauthy`.** The adapter writes
  `services.rauthy.provision.*`; those options must be declared (and provisioning
  enabled) by importing the rauthy module on the same host.
- **Two apps keying the same email.** Rauthy keys users by email, so two apps
  declaring the same address is a real Nix merge conflict (loud) — intentional.
- **Kanidm-derived users with local credential drift.** `kanidmLogin` users are
  checked during reconciliation for password/passkey state and provider
  linkage. The current Rauthy API cannot remove those credentials or block a
  later reset/passkey flow, so drift fails provisioning and requires manual
  remediation in Rauthy before retrying.
