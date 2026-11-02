# Windmill and n8n Bootstrap

`nixosModules.windmillProvision` and `nixosModules.n8nProvision` give two
services without SSO a declared admin login and API credentials, with no UI
step. Secrets come only from runtime files (for example
`config.age.secrets.<name>.path`) loaded as systemd credentials.

## Windmill

```nix
services.windmill = {
  enable = true;
  provision = {
    enable = true;
    superadminSecretFile = config.age.secrets.windmill-superadmin.path;
    workspaces.studio.name = "Studio";
    users.can = {
      email = "can@example.com";
      passwordFile = config.age.secrets.windmill-can.path;
      workspaces = ["studio"];
      admin = true;
    };
    tokens.paperclip-studio = {
      user = "can";
      workspace = "studio";
      group = "studio";
      mode = "0640";
    };
  };
};
```

- `windmill-server` gets `SUPERADMIN_SECRET` from a root-owned 0600
  `EnvironmentFile` rendered by `ExecStartPre=+` (Windmill has no `_FILE`
  variant); see the service-root-secret exception in the architecture document.
- `windmill-provision.service` runs after the server. The open-source server
  rejects user creation and password changes over HTTP, so users are written to
  the local `password` table as argon2id hashes (via `psql` as `postgres`,
  hash on stdin) when their password file changes; the stock
  `admin@windmill.dev` account is locked when `disableDefaultAdmin` is set
  (default, requires an `admin = true` user). Workspaces and membership use the
  superadmin bearer token. Open-source Windmill allows two workspaces besides
  `admins`.
- Tokens are minted by logging in as `user`, stored at `path`
  (default `/var/lib/windmill-provision/tokens/<label>`) with the declared
  `owner`/`group`/`mode`, kept while Windmill accepts them and re-minted
  otherwise.

The VM test runs against both the default nixpkgs windmill (1.601.1) and the
one Canix/Atlas runs (1.839.0, test-only input `nixpkgs-windmill`), because the
tenant writes the `password` table directly. The `psql` step runs as the
`postgres` OS user over the local socket (peer auth), so a cluster using a
custom `identMap` must map `postgres` to the `postgres` role (a `/^(.*)$ \1`
rule does).

## n8n

```nix
services.n8n = {
  enable = true;
  provision = {
    enable = true;
    owner = {
      email = "can@example.com";
      passwordFile = config.age.secrets.n8n-owner.path;
    };
    credentials.studio-webhook = {
      type = "httpHeaderAuth";
      data.name = "X-Studio-Token";
      dataFiles.value = config.age.secrets.n8n-webhook.path;
    };
  };
};
```

- The owner is env-managed: an `ExecStartPre=+` step writes the bcrypt hash of
  the password file to `/run/n8n-provision/owner.env` (0600). The hash is kept
  in `N8N_USER_FOLDER/owner.bcrypt` and reused while the password is
  unchanged.
- `n8n-provision.service` logs in as the owner and upserts credentials by name
  through the internal REST API (n8n's public API has no credential list).
  A digest marker per credential keeps reruns from rewriting unchanged
  credentials. `httpHeaderAuth` takes the fields `name` and `value`.
