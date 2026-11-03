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

- Tokens: a re-mint (changed user, workspace or scopes, or an invalid file)
  deletes the previous token(s) of that label, so one live token per label
  remains. Windmill caches authenticated tokens for up to two minutes, so a
  revoked token can keep working that long.
- Pruning: logins the tenant created are marked in Windmill (`company =
  'provisioned'`). A marked login whose email is no longer declared (removed
  or changed email) is locked (no password verifies, no instance admin, all its
  tokens deleted, its workspace memberships removed), and a token entry removed
  from the declaration is revoked and its file deleted. A pre-existing login
  that is declared is adopted (marked), so it is locked too once its
  declaration goes; undeclared logins the tenant never touched are left alone.
- n8n: a credential this tool created is deleted when its declaration is
  removed (tracked by id; same-named credentials made in the UI are never
  deleted).
- A token's spec includes its owner's email and admin flag, so demoting a user
  or changing an email re-mints and revokes the old token.
- Not done: renaming a user (a changed `users` key leaves the old username in
  place; the role update resolves the real username by email) and removing
  memberships of users that stay declared.
- Declared emails must be lowercase (Windmill lowercases the login). Declaring
  `admin@windmill.dev` is rejected, and at most two workspaces besides `admins`
  can be declared (open-source limit).
- `psql` errors are reported as exit status plus SQLSTATE only.

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

- The owner is env-managed: the root `n8n-owner-env` oneshot (required by n8n; it runs
  at its own start or restart, not on every n8n start) writes the bcrypt hash of
  the password file to `/run/n8n-provision/owner.env` (0600). The hash is kept
  in `/var/lib/n8n-owner-env/owner.bcrypt` (root-only, 0700) and reused while the password is
  unchanged.
- `n8n-provision.service` logs in as the owner and upserts credentials by name
  through the internal REST API (n8n's public API has no credential list).
  A digest marker per credential keeps reruns from rewriting unchanged
  credentials. `httpHeaderAuth` takes the fields `name` and `value`.

## Known limits

- Rotation watch: path units watch each secret file and its parent directory,
  so an agenix generation switch (symlink swap) re-runs provisioning.
- Token ownership: a token kept on disk is trusted when Windmill answers 200
  with the declared user's email, or 403 (a scoped token that cannot call
  `whoami` on a workspace it is not a member of). A 403 cannot reveal the
  owner, so treating it as invalid would re-mint on every run. Token
  directories must therefore be writable only by root.
- Token directories must sit under root-owned ancestors that are not group or
  world writable. The reconciler runs as root and renames into the declared
  path; an ancestor a consumer can modify could be swapped for a symlink.
- n8n credential drift: a credential edited in the n8n UI is not detected,
  because the marker covers the declared data and credential id, and n8n does
  not hand stored secrets back for comparison. Re-applying happens when the
  declaration, a secret file, or the target credential changes; remove the
  marker (`/var/lib/n8n-provision/markers`) to force a rewrite.
