# rauthy-provision

Declarative provisioning client for [Rauthy](https://github.com/sebadob/rauthy) —
a [kanidm-provision](https://github.com/oddlama/kanidm-provision) analogue.

`rauthy-provision` reads a JSON state file describing the desired **users**,
**groups**, **roles**, and **OIDC clients**, and reconciles a running Rauthy
instance toward it over the `/auth/v1` admin API using a Rauthy **API key**.
It is idempotent: create-if-missing plus minimal drift updates.

Ships with a NixOS module (`services.rauthy.provision`) that renders the option
tree to a state file and runs the reconciler as a `oneshot` unit after Rauthy.

## CLI

```
rauthy-provision --url <BASE_URL> --state <state.json> \
    [--api-key-file <FILE> | RAUTHY_PROVISION_API_KEY=...] \
    [--no-auto-remove] [--accept-invalid-certs]
```

The base URL has `/auth/v1` appended automatically; point it at Rauthy's local
listener (e.g. `http://127.0.0.1:8080`) to bypass the reverse proxy.

### API key

Use a Rauthy bootstrap API key or an already assembled API key with these
access groups, each granting `read`+`create`+`update`+`delete`:

- `Users`, `Groups`, `Roles`, `Clients`, `Scopes`, `UserAttributes`,
  `AuthProviders`

Add `Secrets` `update` when any client sets `generated_secret_file`; Rauthy
requires that right to rotate/generate confidential client secrets. The
reconciler consumes the full `<name>$<secret>` value via `--api-key-file` or
`RAUTHY_PROVISION_API_KEY`.

For fully declarative bring-up, set Rauthy's `BOOTSTRAP_API_KEY` to a base64
`ApiKeyRequest` JSON value and keep `BOOTSTRAP_API_KEY_SECRET` in an
environment file. In the NixOS module, point `apiKeyEnvironmentFile` at that
same environment file; the unit assembles `<apiKeyName>$<secret>` at runtime
without putting the secret in argv or the Nix store.

With Rauthy's generated bootstrap-secret support, prefer
`services.rauthy.provision.generatedApiKey.enable = true`. The module renders a
bootstrap `api_keys.json` entry with `secret = "generate"`, asks Rauthy to write
its encrypted generated-secret container, then extracts the generated API key
with `rauthy bootstrap get --config-file ... --kind api-key --field token`.

When `--transient-api-key` is used, the manager key must also grant `ApiKeys`
`read`+`create`+`update`+`delete`; the transient reconciliation key itself does
not receive `ApiKeys` rights.

## State file

```json
{
  "groups": { "internal": { "present": true } },
  "roles":  { "admin":    { "present": true } },
  "users": {
    "alice@example.com": {
      "present": true,
      "given_name": "Alice",
      "family_name": "Smith",
      "language": "en",
      "roles": ["admin"],
      "groups": ["internal"]
    }
  },
  "clients": {
    "my-app": {
      "present": true,
      "name": "My App",
      "confidential": true,
      "redirect_uris": ["https://app.example.com/callback"],
      "scopes": ["openid", "profile", "email"],
      "flows_enabled": ["authorization_code", "refresh_token"],
      "enable_pkce": true,
      "generated_secret_file": "/run/rauthy-clients/my-app.secret"
    }
  }
}
```

Every entity has a `present` flag (default `true`). Setting `present: false`
deletes the entity if it exists; pass `--no-auto-remove` to skip deletions.

### Semantics & limits

- **Users** are created **passwordless** — no credential is set and **no email
  is sent**. With an upstream OIDC provider configured and *Auto-Link User*
  enabled, a passwordless local user whose email matches the upstream identity
  is auto-linked on first federated login.
- `given_name`, `family_name`, and `language` are applied **at creation only**;
  updates reconcile **roles and groups** only, so upstream profile-claim sync is
  never fought.
- **Clients**: when `generated_secret_file` is set on a confidential client,
  the reconciler creates the file only if it is missing by rotating/generating a
  Rauthy client secret and writing it with mode `0600`. Existing files are
  preserved, so normal reconciliation does not rotate working client secrets.
- **No orphan auto-removal**: Rauthy has no tracking-group equivalent, so the
  only way to delete is an explicit `present: false`.

## NixOS module

```nix
{
  inputs.rauthy-provision.url = "git+https://github.com/caniko/rauthy-provision.git";

  # in a host module:
  imports = [ inputs.rauthy-provision.nixosModules.default ];

  services.rauthy.provision = {
    enable = true;
    endpoint = "http://127.0.0.1:8080";
    apiKeyEnvironmentFile = config.age.secrets.rauthy-env.path;
    groups.internal = {};
    users."alice@example.com" = {
      givenName = "Alice";
      groups = [ "internal" ];
    };
  };
}
```

The module's `package` default resolves the right-arch build of the flake's own
package via `pkgs.stdenv.hostPlatform.system`, so it works unchanged on aarch64
hosts.

## License

Dual-licensed under MIT or Apache-2.0.
