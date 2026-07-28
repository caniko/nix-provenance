# Per-user Fields

`nix-provenance` is opinionated about where credentials live. Internal human
credentials are owned by Kanidm. External users without Kanidm identities can be
initialized through Rauthy's email-based set-password flow or through
platform-local passwords read from runtime password files.

Password files should normally be agenix secrets referenced as
`config.age.secrets.<name>.path`. NixOS modules load them with systemd
`LoadCredential`, reconcilers read the runtime credential path, and only a
password-content hash is stored in the service state directory as a rotation
marker. Plaintext passwords must never be rendered into JSON, the Nix store,
argv, logs, or environment variables.

PINs, app-local password-reset flows, and notification-email flows remain
unsupported unless the repository identity model changes again.

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
| `shouldChangePassword` | `shouldChangePassword` | Optional Immich password-change flag |
| `passwordFile` | `passwordFile` | Runtime file containing the Immich password; loaded through systemd credentials and applied only on create or marker-driven rotation |
| `delete.force` | `delete.force` | Per-user delete lock |

The reconciler never sends `pinCode`, `notify`, or `oauthId`. Users without
`passwordFile` are created as OAuth-only users through the patched short-lived
local provision token and require Immich OAuth to be enabled. Users with
`passwordFile` can be created as local-password users. Existing-user password
rotation happens only when the password file content hash differs from the
stored marker.

## Rauthy

`services.rauthy.provision.users` is keyed by primary email address. Rauthy
users are created passwordless unless `sendPasswordEmail = true` or
`passwordFile` is explicitly set.

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
| `requiredAuthProvider` | `required_auth_provider` | Reconciliation-time assertion that the user is credential-free and linked or auto-linkable through the named upstream provider |
| `sendPasswordEmail` | `send_password_email` | On creation only, request Rauthy's set-password email flow |
| `passwordEmailRedirectUri` | `password_email_redirect_uri` | Required when `sendPasswordEmail = true` |
| `initialPasswordFile` | `initial_password_file` | Runtime file containing the native Rauthy password applied only when creating a new user; mutually exclusive with `sendPasswordEmail` |

Unset nullable profile fields are unmanaged and are omitted from rendered state.
Use the matching `clear*` option only when you want the reconciler to send an
explicit delete/null operation, and only when the Rauthy user-values policy
allows that value to be absent.

Kanidm-derived users set `requiredAuthProvider = "kanidm"` automatically through
the adapter helpers. The guard rejects local password/passkey state during
reconciliation, but the current Rauthy API does not provide continuous
per-user enforcement or declarative credential removal.

## Vikunja, Forgejo, And Stalwart

These integrations do not expose direct app-local per-user profile or password
management in `nix-provenance`.

Vikunja provisioning manages teams and memberships by username; OIDC user
creation/linking remains Vikunja's responsibility. Forgejo wiring configures the
OIDC login surface and can reconcile public SSH keys:

```nix
services.forgejo.provision.sshKeys.can.hm-identity = {
  key = "ssh-ed25519 AAAA...";
  # readOnly = true;
};
```

Keys are keyed by Forgejo username and stable title. `present` defaults to
`true`; undeclared keys are left untouched, key/title or `readOnly` drift fails
closed, and deletion requires both `present = false` and the explicit global
`allowSshKeyDelete` gate. The administrator password is still a runtime
`adminPasswordFile` loaded through systemd credentials; private SSH keys never
enter the state.

Stalwart uses Kanidm LDAP for mailbox authentication and must bind against
Kanidm rather than compare local app passwords.

## External App Adapter

`lib.adapter.passwordFromFile { passwordFile; }` maps a backend-agnostic
external app user to `services.rauthy.provision.users.<email>.initialPasswordFile`.
It is valid only on the Rauthy backend. The Kanidm backend currently creates
Kanidm persons but does not own primary credential initialization through the
adapter.
