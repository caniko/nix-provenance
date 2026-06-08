# Per-user Fields

`nix-provenance` is opinionated about where credentials live. Internal human
credentials are owned by Kanidm. External users without Kanidm identities are
initialized through Rauthy's email-based set-password flow. Downstream service
provisioners manage app-side users, profile metadata, groups, roles, claims,
and service configuration; they do not manage app-local passwords, PINs,
password-reset flows, or notification emails.

This means credential-bearing fields such as Immich `password`, Immich
`pinCode`, and app-local notification-email flows are intentionally unsupported
by service-side provisioners.

## Immich

`services.immich.provision.users` is keyed by a stable local name. `email` and
`name` are required when `present = true`; every other per-user field is managed
only when explicitly set.

| Nix option | State field | Behavior |
|------------|-------------|----------|
| `present` | `present` | Defaults to `true`; set `false` to delete, gated by both `allowUserDelete` and `delete.force` |
| `email` | `email` | Primary Immich email identity |
| `name` | `name` | Immich display name |
| `isAdmin` | `isAdmin` | Optional admin flag |
| `storageLabel` / `clearStorageLabel` | `storageLabel` | Set a storage label or explicitly clear it with `null` |
| `quotaSizeInBytes` / `clearQuota` | `quotaSizeInBytes` | Set a quota or explicitly clear it with `null` |
| `avatarColor` / `clearAvatarColor` | `avatarColor` | Set an Immich avatar color or explicitly clear it with `null` |
| `shouldChangePassword` | `shouldChangePassword` | Optional Immich password-change flag; this does not provision a password |
| `delete.force` | `delete.force` | Per-user delete lock |

The reconciler deliberately never sends `password`, `pinCode`, `notify`, or
`oauthId`. Users are created as OAuth-only users through the patched short-lived
local provision token, and OAuth account linking is left to Immich.

## Rauthy

`services.rauthy.provision.users` is keyed by primary email address. Rauthy
users are created passwordless unless `sendPasswordEmail = true` is explicitly
set for external users.

| Nix option | State field | Behavior |
|------------|-------------|----------|
| `present` | `present` | Defaults to `true`; set `false` to delete unless `autoRemove = false` |
| `givenName` / `clearGivenName` | `given_name` | Set or explicitly clear the profile value |
| `familyName` / `clearFamilyName` | `family_name` | Set or explicitly clear the profile value |
| `birthdate` / `clearBirthdate` | `birthdate` | Set or explicitly clear the Rauthy user value |
| `timezone` / `clearTimezone` | `timezone` | Maps to Rauthy's `user_values.tz`; set or explicitly clear it |
| `street` / `clearStreet` | `street` | Set or explicitly clear the Rauthy user value |
| `zip` / `clearZip` | `zip` | Set or explicitly clear the Rauthy user value |
| `city` / `clearCity` | `city` | Set or explicitly clear the Rauthy user value |
| `country` / `clearCountry` | `country` | Set or explicitly clear the Rauthy user value |
| `phone` / `clearPhone` | `phone` | Set or explicitly clear the Rauthy user value |
| `language` | `language` | Defaults to `en` |
| `userExpires` | `user_expires` | Optional Unix timestamp in seconds; unmanaged when unset |
| `roles` | `roles` | Additive reconciliation; declared roles are ensured but unmanaged roles are preserved |
| `groups` | `groups` | Additive reconciliation; declared groups are ensured but unmanaged groups are preserved |
| `preferredUsername` / `clearPreferredUsername` | `preferred_username` | Set or explicitly clear through Rauthy's preferred-username endpoint |
| `attributes` | `attributes` | Custom Rauthy user attribute values, rendered as JSON |
| `sendPasswordEmail` | `send_password_email` | On creation only, request Rauthy's set-password email flow |
| `passwordEmailRedirectUri` | `password_email_redirect_uri` | Required when `sendPasswordEmail = true` |

Unset nullable profile fields are unmanaged and are omitted from rendered state.
Use the matching `clear*` option only when you want the reconciler to send an
explicit delete/null operation, and only when the Rauthy user-values policy
allows that value to be absent.

## Vikunja, Forgejo, And Stalwart

These integrations do not expose direct app-local per-user profile management
in `nix-provenance`.

Vikunja provisioning manages teams and memberships by username; OIDC user
creation/linking remains Vikunja's responsibility. Forgejo wiring configures
the OIDC login surface. Stalwart uses Kanidm LDAP for mailbox authentication and
must bind against Kanidm rather than compare local app passwords.
