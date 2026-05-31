# Immich patch set

Apply `0001-add-trusted-local-provision-token.patch` to an Immich checkout before
using the NixOS module in production.

The patch is intentionally small:

- `immich-admin provision-token --ttl <seconds>` mints a short-lived admin
  session token through Immich's normal session table.
- `UserAdminCreateDto.password` becomes optional, relying on
  `UserAdminService.create` to reject passwordless users when OAuth is disabled.

The project treats this as the upstreamable feature boundary. `immich-provision`
does not implement a long-lived API-key fallback.
