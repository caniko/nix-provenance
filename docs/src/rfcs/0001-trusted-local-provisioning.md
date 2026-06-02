# RFC 0001: Trusted Local Provisioning for Immich

## Summary

Add a local-only Immich server command that mints a short-lived admin session
token for provisioning tools, and allow admin-created users to omit `password`
when OAuth is enabled.

This lets NixOS and similar systems declare Immich users and OIDC settings
without storing a long-lived admin API key, without scraping the UI, and
without writing directly to Immich's database.

## Motivation

Immich already exposes most of the required declarative surface:

- system configuration can be supplied through `IMMICH_CONFIG_FILE`
- OAuth settings are represented in normal Immich system config
- OAuth login links an existing local account by matching email when `oauthId`
  is empty

The missing piece is safe bootstrap authentication for headless provisioning.
Today an operator must either keep a long-lived admin API key, perform manual UI
actions, or mutate the database out of band. Those choices are a poor fit for
NixOS-style declarative systems and for high-value photo libraries.

Kanidm's recovery and local-administration discussion and Rauthy's bootstrap
API-key discussion both point at the same principle: local root already has
authority over the service, so the service should expose a narrow, auditable
local path instead of forcing operators to persist broad remote credentials.

## Proposal

Add:

```sh
immich-admin provision-token --ttl 300
```

The command:

1. Runs only inside the server environment, with database access.
2. Finds the existing Immich admin account.
3. Creates a normal admin session with `expiresAt = now + ttl`.
4. Prints the raw bearer token to stdout.
5. Does not persist token material outside the existing session table.

Also change `UserAdminCreateDto.password` from required to optional. The
existing `UserAdminService.create` already rejects passwordless creates when
OAuth is disabled, so the runtime authorization policy remains centralized in
service code.

## Security model

- The command grants no power beyond what local root and service-user access
  already have.
- The token is short lived and uses the existing session validation path.
- Consumers should pass the token by a private runtime file or pipe, not a Nix
  store path, agenix secret, or process argument.
- The command should fail if no admin user exists.
- It should reject non-positive or unreasonably large TTL values.

## Declarative provisioning semantics

Provisioners should:

- match users by normalized email
- create OAuth-only users without password when OAuth is enabled
- never write `oauthId`
- let first OAuth login set `oauthId` through Immich's existing email-link
  behavior
- make destructive operations opt-in with explicit double locks

## Alternatives

- Long-lived API key: works today, but turns a bootstrap implementation detail
  into a permanent secret.
- Direct database writes: fragile across Immich releases and bypasses business
  logic.
- Manual UI provisioning: not repeatable and does not satisfy declarative
  infrastructure goals.
- Pre-setting `oauthId`: brittle because the exact subject value is controlled
  by the OIDC provider and may be pairwise or otherwise provider-defined.

## Test requirements

- `immich-admin provision-token --ttl 300` returns a bearer token accepted by
  an admin API endpoint.
- The token stops working after expiry.
- The command fails when no admin account exists.
- Admin user creation without password succeeds only when OAuth is enabled.
- OAuth callback for a matching-email, empty-`oauthId` user still links that
  existing user rather than creating a duplicate.
