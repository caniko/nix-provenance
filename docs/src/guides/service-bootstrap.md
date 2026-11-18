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
    workspaces.studio = {
      name = "Studio";
      scripts."f/fleetix_hub/comfy_generate" = {
        language = "bun";
        contentFile = ./registry/windmill/comfy_generate.ts;
        summary = "Submit ComfyUI prompts";
        # The worker pool the hub's procedures run on.
        tag = "hub";
      };
      variables."f/fleetix_hub/hub_token" = {
        valueFile = config.age.secrets.fleetix-hub-windmill-token.path;
        description = "Fleetix Hub receipt bearer";
      };
    };
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
- Scripts are keyed by full Windmill path (`f/<folder>/<name>`,
  `u/<user>/<name>` or `g/<group>/<name>`; alphanumerics, `_` and `-`).
  `contentFile` is code, so a store path (a path literal, or
  `"''${pkgs.writeText ...}"`) is normal; a path literal is interpolated, so
  the file enters the closure and editing it changes the state file (and the
  units' restart trigger). The reconciler reads the latest deployed version and
  calls `scripts/create` only when the content, language or `tag` differs, so
  Windmill's version history stays one entry per real change. `tag` (for
  example `hub`) routes runs and the lock job to a worker pool that listens for
  it; leaving it null keeps the deployed tag, because a new version does not
  inherit its parent's. Windmill 1.839.0 also applies a `// tag <name>` badge
  from the top of the script source over the tag sent with the deploy, so a
  source badge that disagrees with the declaration is refused before the
  version is deployed, and the stored tag is read back and compared (a version
  with the wrong tag would deploy "successfully" and then run nowhere). A
  deploy then waits (bounded; `deployTimeoutSeconds`, 300 by default, passed
  only when a script is declared) for the dependency job to write the version's
  lock: a version without a lock is not
  runnable, so a queued or failed lock job fails the run instead of matching the
  source on the next run and reporting success. The failure names the job id
  instead of copying the job's logs into the journal. The reconcile unit's
  `TimeoutStartSec` is derived from the declared script count times that budget
  plus startup headroom, because deploys are serial. The `schema`, `lock`,
  dependencies and permissions are Windmill's.
- Variables are upserted by full path. `valueFile` is a runtime secret
  (`config.age.secrets.<name>.path`), loaded as a systemd credential; the value
  is read at run time, sent to Windmill, and never enters the store, the state
  file, argv or logs. A path unit re-runs provisioning when the file rotates.
  The reconciler compares the value, `isSecret` and `description` with
  Windmill's read-back (which decrypts secrets for a superadmin) and writes only
  on a difference.
- Tokens are minted by logging in as `user`, stored at `path`
  (default `/var/lib/windmill-provision/tokens/<label>`) with the declared
  `owner`/`group`/`mode`, kept while Windmill accepts them and re-minted
  otherwise. `owner`/`group` are Unix names or ids, so a consumer running as
  its own system user (for example `fleetix-hub`) reads its token directly.

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
      data.name = "Authorization";
      dataFiles.value = config.age.secrets.n8n-webhook.path;
      # The Header Auth value: "Bearer <raw token file content>".
      dataFilePrefixes.value = "Bearer ";
    };
    workflows.fleetix-hub-claim = {
      file = ./n8n/workflows/fleetix-hub-claim.json;
      credentials."Fleetix Hub webhook token" = "studio-webhook";
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
  credentials. `httpHeaderAuth` takes the fields `name` and `value`;
  `dataFilePrefixes.<field>` prepends a constant to the file's value at run
  time, so the raw token file can stay exactly that (no `Bearer ` inside the
  secret) and the prefix stays visible in the declaration.
- Workflows are imported by the declared name (the file's own `name`, `id` and
  `active` are ignored) from an export's `nodes`, `connections`, `settings` and
  `meta`. The export is copied into the Nix store, which every process can read
  and every generation keeps, so it must be sanitized **before it enters the
  flake source**: a credential reference or an n8n expression (`=...`) carries a
  secret, never a literal. Nix has already copied the source by the time this
  module evaluates, so nothing here can keep a literal out of the store; the
  reconciler refuses an export holding a literal `Authorization`,
  `apiKey`/`api-key` or `password` value at run time, which only stops the
  deployment, not the copy. Before writing, every node credential reference is
  rewritten from its JSON name to the provisioned credential's id:
  `credentials."<name in the JSON>" = "<declared credential>"`, and a reference
  with no entry must itself be a declared credential name. The node's credential
  type must match the declared credential's `type`, so a postgres node cannot be
  handed a Header Auth credential.
- A node that calls another workflow (`n8n-nodes-base.executeWorkflow`) names it
  in `parameters.workflowId.value`, as the studio-pipeline exports do. The
  dependency edges use n8n's own predicate: a disabled node is skipped, only the
  `database` source (the default) counts, and a `=` value is evaluated at run
  time. n8n reads only `workflowId.value` or the string and never the locator's
  `mode`, so a "by URL" locator without a remote `source` is still a local id
  there and is treated as one here. n8n generates workflow ids and validates
  that reference by id when the caller is published, so declared workflows are
  imported in dependency order and the reference is rewritten to the live id. A
  cycle between declared workflows is an error, and so is a reference to a
  workflow that is neither declared nor already present in n8n (for example a
  leftover id from another instance). A reference may name a workflow by its id
  instead of its name.
- n8n allows two workflows with one name. One lookup resolves names for
  reconciliation, deactivation and reference binding alike: a name that matches
  several live workflows (or several live credentials, for credentials) fails
  and names the ids instead of picking one. Deactivation is the exception that
  cannot be ambiguous: every workflow carrying a deactivated declaration's name
  is deactivated, since leaving one serving is exactly the failure the flag
  prevents.
- Idempotency comes from the live copy, not a marker: the reconciler reads the
  workflow back and writes only when a managed field differs. Nodes are compared
  field for field (only the ids n8n generates and the `webhookId` it mints are
  ignored) and connections exactly, so a UI edit that adds `disabled` to a node
  or drops a connection is drift and is put back, without a redeclaration. An
  unchanged declaration writes nothing. Settings are compared key by key,
  because n8n merges a PATCH into the stored object: the declaration's keys must
  hold their values, and a key set in n8n that the declaration does not name is
  reset through n8n's own `"DEFAULT"` token (its `removeDefaultValues` drops the
  key). `executionTimeout` is the exception n8n treats differently: it deletes a
  saved timeout equal to the instance default, so the reconciler reads that
  default from n8n's own `/rest/settings` when a declaration names a timeout. An
  absent live key then matches a declared default, a different stored value is
  drift, and the PATCH sends the declared default back, which resets it. A
  declaration that never names `executionTimeout` leaves the stored value alone.
  Any other settings key n8n cannot reset (and does not delete) is reported once
  and excluded, so it cannot cause a rewrite on every run. The activation
  converges separately:
  `active = true` (default) publishes the version just written, `active = false`
  deactivates a running workflow. A declared `active = false` is applied by
  `n8n-deactivate.service` — a oneshot that loads only the owner password and
  runs before the unit that loads the field credentials — so a missing
  credential file, which makes systemd refuse to start that unit, or a corrupt
  credential registry cannot leave the old webhook serving. That unit reads its
  own state file, which holds only the URL, the owner and the inactive names, so
  a declaration the reconciler would reject cannot stop the unpublish. The main
  unit repeats the deactivation for a workflow reactivated out of band.
  Deactivation is the only removal: a workflow dropped from the declaration is
  left in n8n.
- A transient failure does not need a manual start. `Requires=` keeps the
  pre-pass fail-closed, but systemd cancels the provisioning job before it runs
  when that dependency fails, which no `Restart=` on either unit can observe.
  `n8n-provision-retry.timer` therefore re-runs the pair once a minute while
  provisioning is not active (a start job pulls the failed pre-pass in with it),
  and goes idle as soon as it is. A declaration that is genuinely broken stays
  failed between ticks and keeps re-reporting why. The oneshots pull the timer
  in with `Wants=`, and it is `PartOf=` them and `n8n.service`, so it stops
  whenever they do: a timer enabled on its own would tick in the stop→start
  window of a NixOS switch, start the units still loaded from the old
  generation, leave them `active (exited)` so the switch's own start is a no-op,
  and hold a newly declared `active = false` (or an explicit stop of n8n) off.
  It is wired only when a workflow is declared, so a host pinning an older
  `provisionPackage` without the `deactivate` subcommand still starts.

## Known limits

- Rotation watch: path units watch each secret file and its parent directory,
  so an agenix generation switch (symlink swap) is noticed. Restarting the
  server or n8n for the superadmin secret or owner password only happens when
  the secret content really changed (a recorded digest is compared); plain
  deploys do not restart them.
  Windmill uses one watcher for all its inputs (superadmin secret, user
  passwords, variable values): a real superadmin change restarts the server,
  anything else re-runs provisioning once, so one activation that rotates
  several files never restarts the oneshot over itself. n8n's retry timer has
  no start limit, so a crash-looping n8n cannot strand provisioning.
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
- Adopted n8n credentials: a declared name that matches one existing n8n
  credential is adopted and overwritten, but only credentials this tool
  created are recorded for pruning. Removing an adopted one from the
  declaration leaves it in n8n with the last declared values; delete it by
  hand.
- Windmill script drift is only detected through `content`, `language` and a
  declared `tag`: a `summary` edit in the declaration does not redeploy a
  version, and a script edited in the Windmill UI is put back on the next run.
  Version history and old versions are Windmill's to prune.
- A Windmill script keeps whatever `schema`, `lock`, dependencies, permissions
  and triggers it already has; the tenant writes path, content, language,
  summary and `tag` (when declared). A script that must run on a tagged worker
  pool needs that worker listening for the tag (`WORKER_TAGS`).
- n8n workflows are matched by their name, which n8n does not require to be
  unique: a declared name that matches several live workflows fails the run
  (naming their ids) until one is renamed or deleted. Renaming a workflow in n8n
  while it stays declared imports a second one under the declared name; the
  renamed copy is left in place. A workflow dropped from the declaration is left
  in n8n untouched — not deactivated and never deleted.
- A settings key the declaration does not name and n8n's own `"DEFAULT"` reset
  does not cover (an `executionTimeout` set in the n8n UI, say) stays as set in
  n8n and is logged once per run; declare it to manage it.
- n8n credentials referenced by a declared workflow must be provisioned in the
  same declaration; a workflow whose reference resolves to nothing fails the
  run instead of importing a workflow that cannot execute.
