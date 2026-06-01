# immich-provision

Declarative Immich identity provisioning for NixOS and Kanidm.

`immich-provision` is a small reconciler plus NixOS module. It renders desired
Immich users from Nix, obtains a short-lived local provisioning token from a
patched `immich-admin provision-token`, and reconciles users through Immich's
admin API. It deliberately does not support long-lived Immich API keys.

## Model

- Immich OAuth settings stay declarative through `services.immich.settings`.
- Users are matched by normalized email address.
- New users are created OAuth-only, without a password. This requires the
  included Immich patch until the behavior is accepted upstream.
- `oauthId` is never written by this tool. Immich links an existing account to
  the OIDC subject on first OAuth login when the email matches and `oauthId` is
  empty.
- User deletion requires both `--allow-user-delete` and
  `users.<name>.delete.force = true`.

## CLI

```sh
immich-provision \
  --url http://127.0.0.1:2283 \
  --state ./state.json \
  --token-file /run/immich-provision/provision-token
```

State file:

```json
{
  "users": {
    "can": {
      "email": "can@tartanoglu.com",
      "name": "Can H. Tartanoglu",
      "isAdmin": true,
      "storageLabel": "can",
      "quotaSizeInBytes": null,
      "shouldChangePassword": false
    }
  }
}
```

The create request intentionally omits `password` and `oauthId`.

## NixOS

```nix
{
  inputs.immich-provision.url = "git+ssh://git@codeberg.org/caniko/immich-provision.git";

  imports = [inputs.immich-provision.nixosModules.default];

  services.immich.provision = {
    enable = true;
    oauth = {
      enable = true;
      issuerUrl = "https://auth.tartanoglu.com/oauth2/openid/immich";
      clientId = "immich";
      clientSecretFile = config.age.secrets.immichOidcClientSecret.path;
    };
    users = inputs.immich-provision.lib.usersFromKanidmPersons {
      persons = config.services.kanidm.provision.persons;
      adminUsers = ["can"];
    };
  };
}
```

Kanidm side:

```nix
services.kanidm.provision.systems.oauth2.immich =
  inputs.immich-provision.lib.kanidmOAuth2System {
    originUrl = "https://immich.example.com";
    originLanding = "https://immich.example.com/";
    basicSecretFile = config.age.secrets.immichOidcClientSecret.path;
  };
```

## Immich patch

`patches/immich/0001-add-trusted-local-provision-token.patch` adds:

- `immich-admin provision-token --ttl <seconds>`
- password-optional admin user creation when OAuth is enabled
- upstream unit coverage for the token and DTO behavior

The token is a short-lived admin session token. The NixOS module stores it in a
private runtime file and passes it to the reconciler via `--token-file`.

## Development

```sh
cargo test
nix flake check --no-build
nix flake check
```

The full Immich patch tests require an Immich checkout with the patch applied.

For first-time cutovers of existing Immich libraries to Kanidm OIDC, read
`docs/kanidm-oidc-migration.md` before deploying.
