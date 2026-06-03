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
- `adapter.rauthyUsers { users, loginUrl ? null, language ? "en", commonGroups ? []; }`:
  renders `services.rauthy.provision.users`. `commonGroups` is applied to every
  user (on top of each user's own `groups`)
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
  (`confidential = false`, `enablePkce = true`)
- `services.rauthy.provision.users."can@tartanoglu.com"`: passwordless,
  federated auto-link user
- `services.rauthy.provision.users."efirley@protonmail.com"` and
  `"carolinestahl@gmx.net"`: native users with `sendPasswordEmail = true` and
  `passwordEmailRedirectUri = loginUrl`

No rauthy group is created here: `accessGroup` is unset, because pink-raven
gates access from its own application-side allowlist. Access control still
lives in the application — being a Rauthy user here only lets these users
authenticate; the app decides their roles.

### The `accessGroup` option

`accessGroup` controls whether the adapter provisions an app-wide group:

- **rauthy backend** — optional. When set (e.g. `accessGroup =
  "pink-raven-users"`) the group is created **and assigned to every one of the
  app's users**. When unset (the default), no group is created — leave it unset
  when the app gates access itself.
- **kanidm backend** — a group is always required (it is the OAuth2 scopeMap
  target); an unset `accessGroup` falls back to `"<name>-users"`.

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

## Real-world consumer: canix

The adapter factors out a pattern that canix previously hand-wrote in
`root/hosts/thething/server/rauthy.nix` — `usersFromKanidmPersons` to federate
the internal humans, then external users appended with `sendPasswordEmail`. The
live wiring there shows two details worth copying:

- **A user can be written by both the federation and the adapter.** canix
  federates every internal human (including `can`) into Rauthy with the
  `internal`/`bekiper` groups (for a separate app), and *also* lists `can` in
  the pink-raven adapter block with `adapter.kanidmLogin`. Both definitions key
  the same email, so they **merge into one Rauthy user**. For the merge to be
  conflict-free the scalar fields must agree: give the adapter user the **same
  `displayName` as the kanidm person** so the derived given/family names match.
  Groups are list-merged (union), so `can` ends up with the federation's
  `internal`/`bekiper` groups and the adapter adds none (no `accessGroup`).
- **`mailServerConfigured = true` is the SMTP acknowledgement.** On that host
  Rauthy relays the set-password mail through Stalwart (the `SMTP_*` env in the
  Rauthy environment file), so the warning is acknowledged. Without a working
  mail path, `eric`/`caroline` never receive their link.

## Pitfalls

- Emailed users without SMTP: verify delivery through Rauthy and Stalwart
  journals, not just the HTTP status.
- `passwordInitByEmail` on the kanidm backend: asserted against; use
  `kanidmLogin`.
- Rauthy backend without importing `nixosModules.rauthy`: the adapter writes
  `services.rauthy.provision.*`, so those options must exist on the same host.
- Two apps keying the same email: Rauthy keys users by email, so the collision
  is a real Nix merge conflict.
