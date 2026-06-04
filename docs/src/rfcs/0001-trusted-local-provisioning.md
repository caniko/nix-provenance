# Trusted Local Provisioning for Immich

## Summary

Add `immich-admin provision-token`, a server-local command that mints a
short-lived admin session token for infrastructure automation running on the
Immich host. The token is a normal Immich session token. It is then used against
the existing admin API.

Also allow `UserAdminCreateDto.password` to be omitted when OAuth is enabled.
Together, these changes let declarative operators manage Immich users and OIDC
without storing a long-lived admin API key, scraping the UI, or writing directly
to the database.

## Motivation

Immich already supports most of the surfaces a declarative operator needs.
System settings can come from `IMMICH_CONFIG_FILE`, OAuth settings are part of
normal system config, and users can be reconciled through the admin API. The
missing piece is bootstrap authentication for automation that already controls
the local service.

API keys are the right default for ordinary third-party applications. They are
not a good bootstrap primitive for host-level automation, because a persistent
admin credential has to exist before the automation can safely manage the
instance. That pushes operators toward manual setup, secret sprawl, or database
writes.

This proposal keeps Immich's API-first administration model. It only adds a
short local bridge from service access to a temporary session, then returns to
the existing API surface.

## Fit with Immich

Immich already has an administrative server CLI for local recovery and
operations, including password reset, password-login toggles, OAuth-login
toggles, maintenance mode, and user listing. `provision-token` belongs in that
same family:

- It is run inside the server environment by an operator that already has
  service-level access.
- It creates a normal session through Immich's existing session storage and
  validation path.
- It adds no remote endpoint and no new API authentication scheme.
- It leaves provisioning actions on the documented admin API, where normal
  validation and business logic still apply.

The intended users are NixOS modules, Ansible roles, Kubernetes operators, Helm
post-install jobs, Terraform or OpenTofu providers, GitOps systems, and similar
host-owned automation. Desktop clients, mobile clients, and general third-party
integrations should continue to use Immich's normal authentication flows and API
keys.

## API contract impact

This is not a fourth authentication scheme. Immich continues to authenticate API
requests through its existing session, API-key, and shared-key paths.
`provision-token` only gives local automation a short-lived session that the API
already knows how to validate.

Making `UserAdminCreateDto.password` optional is a real API contract change, but
the intended contract is narrow:

- Existing clients may keep sending `password`.
- Passwordless create is valid only for admin-created OAuth users.
- The service layer rejects passwordless create when OAuth is disabled.
- The web UI does not need to expose a new passwordless local-user workflow.
- OpenAPI and generated SDKs should show `password` as optional, with endpoint
  documentation explaining the OAuth-enabled precondition.

## Proposal

```sh
immich-admin provision-token --ttl 300   # seconds, 1..3600, default 300
```

The command runs inside the server environment, finds the admin account, creates
a normal admin session with `expiresAt = now + ttl` through the **existing**
session table, and prints the raw bearer token to stdout. It adds no new auth
primitive and persists nothing outside the session table.

Separately, make `UserAdminCreateDto.password` optional. `UserAdminService.create`
already rejects passwordless creates when OAuth is disabled, so the authorization
policy stays centralized in service code.

Reference implementation:
`crates/immich-provision/patches/immich/0001-add-trusted-local-provision-token.patch`
(verified to apply against Immich v2.7.5).

## Security model

- Grants no power beyond existing local root / service-user access.
- The token is short-lived and validated through the existing session path.
- The command fails if no admin exists and rejects non-positive or oversized TTLs.
- Consumers must pass the token via a private runtime file or pipe, never a Nix
  store path, agenix secret, or process argument.

## Declarative semantics

Provisioners should match users by normalized email, create OAuth-only users
without a password when OAuth is enabled, and avoid writing `oauthId`.

The `oauthId` value is provider-defined and may be pairwise. Letting Immich set
it during OAuth login avoids guessing the subject in external tooling. For
freshly provisioned users, the first OAuth login is expected to bind the
provider identity. That linking behavior should be covered by tests if Immich
accepts passwordless OAuth-user creation. For migrations of existing local users
with attached libraries, operators must still verify the email-linking behavior
against the exact Immich version before enabling the migration.

Destructive operations should remain explicitly gated. A reconciler should not
delete users unless both a global delete flag and a per-user delete flag are set.

## Alternatives

- **Long-lived API key**: works today, but turns a bootstrap detail into a
  permanent admin secret. API keys remain the right answer for many
  integrations, but they are a poor fit for first-run host automation.
- **Direct database writes**: fragile across releases and bypass business logic.
- **Manual UI provisioning**: not repeatable.
- **Pre-setting `oauthId`**: brittle because the subject comes from the provider
  and may be pairwise.
- **Remote bootstrap endpoint**: easier for automation to call, but it creates a
  new remotely reachable privileged path. A server-local CLI keeps the bootstrap
  boundary tied to existing host access.

## Test requirements

- `provision-token --ttl 300` returns a token that an admin API endpoint
  accepts, the token stops working after expiry, and the command fails when no
  admin exists.
- The minted token validates through Immich's existing session/token validation
  code path.
- Passwordless admin creation succeeds only when OAuth is enabled.
- Passwordless admin creation fails when OAuth is disabled.
- No create or update request from the provisioner writes `oauthId`.
- An OAuth callback for a matching-email, empty-`oauthId` user is covered by an
  integration test or version-specific migration check before relying on it for
  existing libraries.
