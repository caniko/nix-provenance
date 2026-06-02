# Third-party External Apps

`lib.adapter` plus `nixosModules.externalApp` let a **third-party flake
integrate its own users plus OIDC client into the identity plane (kanidm or
rauthy)** without earning a first-class tenant in this repo. It is for apps
this flake does not support directly, closed-source or otherwise out-of-scope
projects such as **pink-raven**, that still want declarative users behind our
IdPs.

It is the inverse of a tenant: a tenant gives a *system* a provisioner; the
adapter lets an *app* reuse the existing rauthy or kanidm provisioners. It owns
no reconciler. It is pure-Nix wiring that writes
`services.rauthy.provision` / `services.kanidm.provision` values from a
uniform, backend-agnostic user schema.

## Two axes

| Axis | Choice | Meaning |
|------|--------|---------|
| **backend** | `rauthy` | the app federates with Rauthy (outward-facing services). Required for any emailed user. |
| | `kanidm` | the app federates with kanidm directly (internal services). |
| **per-user credential** | `kanidmLogin` | the user already has a kanidm identity. Federated; nothing emailed or stored here. |
| | `passwordInitByEmail` | a native Rauthy user Rauthy emails a one-time set-password link to. **Rauthy backend only.** |

`passwordInitByEmail` **requires a mail or SMTP server (for example Stalwart)
reachable from the Rauthy host**. Rauthy drives its `request_reset` flow once
at user creation, and without working SMTP the link is never delivered. The
module emits a build warning for emailed users until you set
`mailServerConfigured = true` to acknowledge that SMTP is wired.

## `lib.adapter` primitives

A flake that wants finer control can call the primitives directly instead of the
module:

- `adapter.kanidmLogin`: credential descriptor (constant)
- `adapter.passwordInitByEmail { redirectUri ? null; }`: credential descriptor
- `adapter.rauthyUsers { users, loginUrl ? null, language ? "en"; }`:
  renders `services.rauthy.provision.users`
- `adapter.rauthyGroupsOf users`: the distinct rauthy group names referenced
- `adapter.kanidmOAuth2System { originUrl, group, ... }`: generic OAuth2 system
  attrset for kanidm
- `adapter.kanidmPersons { users, group; }`: renders
  `services.kanidm.provision.persons` for `kanidmLogin` users only

## Ergonomic module

Worked example for **pink-raven**, an outward-facing app on the `rauthy`
backend:

```nix
{ inputs, ... }:
let adapter = inputs.nix-provenance.lib.adapter;
in {
  imports = [
    inputs.nix-provenance.nixosModules.externalApp
    inputs.nix-provenance.nixosModules.rauthy
  ];

  services.provenance.externalApps.pink-raven = {
    backend = "rauthy";
    displayName = "Pink Raven";
    loginUrl = "https://raven.tartanoglu.com/login";
    redirectUris = ["https://raven.tartanoglu.com/auth/callback"];
    mailServerConfigured = true;

    users = {
      can = {
        email = "can@tartanoglu.com";
        displayName = "Can";
        credential = adapter.kanidmLogin;
      };
      eric = {
        email = "efirley@protonmail.com";
        displayName = "Eric";
        credential = adapter.passwordInitByEmail {};
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

This sets:

- `services.rauthy.provision.clients.pink-raven`: a public PKCE client
- `services.rauthy.provision.users."can@tartanoglu.com"`: passwordless,
  federated auto-link user
- `services.rauthy.provision.users."efirley@protonmail.com"` and
  `"carolinestahl@gmx.net"`: native users with `sendPasswordEmail = true`
- `services.rauthy.provision.groups."pink-raven-users"`: the access group

Access control still lives in the application. Being a Rauthy user here only
lets these users authenticate; the app decides their roles.

## Kanidm backend

For an internal app that federates with kanidm directly, set
`backend = "kanidm"` and give every user `kanidmLogin`:

```nix
services.provenance.externalApps.internal-tool = {
  backend = "kanidm";
  confidential = true;
  redirectUris = ["https://tool.example.com/oauth2/callback"];
  basicSecretFile = "/run/secrets/internal-tool-oauth2-basic";
  users.dejana = {
    email = "dejana@tartanoglu.com";
    displayName = "Dejana";
    credential = adapter.kanidmLogin;
  };
};
```

This sets `services.kanidm.provision.systems.oauth2.internal-tool`,
`services.kanidm.provision.persons.dejana`, and the `internal-tool-users`
group.

## Pitfalls

- Emailed users without SMTP: verify delivery through Rauthy and Stalwart
  journals, not just the HTTP status.
- `passwordInitByEmail` on the kanidm backend: asserted against; use
  `kanidmLogin`.
- Rauthy backend without importing `nixosModules.rauthy`: the adapter writes
  `services.rauthy.provision.*`, so those options must exist on the same host.
- Two apps keying the same email: Rauthy keys users by email, so the collision
  is a real Nix merge conflict.
