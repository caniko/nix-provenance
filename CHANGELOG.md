# Changelog

## [Unreleased]

### Added

- Google Drive device authorization and rclone configuration export; rclone refreshes the Drive grant. Download the OAuth client JSON from Google Cloud Console Credentials, pass it to `authorize --client-file`, and delete it after enrollment.
- `google/antigravity` enrolls agy's existing Google sign-in with
  `authorize --token-file` and exports it with `agy-token`. Home Manager can
  install profile copies from this enrollment instead of a legacy `tokenFile`,
  leaving agy's rewritten copies alone until the source changes.
- `services.windmill.provision.deployTimeoutSeconds` is the bound on one
  deployed version's lock generation job. Scripts deploy serially, so the
  reconcile unit's `TimeoutStartSec` is that budget times the number of declared
  scripts plus startup headroom instead of a fixed 15 minutes a growing
  declaration can outgrow.
- `services.n8n.provision.dataFilePrefixes` builds a credential field from
  a raw token file and a runtime prefix (`Bearer ` plus an age-decrypted
  token), so a Header Auth credential can hold `Bearer <token>` without the
  prefix or the token entering the store.
- `services.windmill.provision.workspaces.*.scripts` deploys Windmill scripts
  from a content file and pushes a new version only when the content or
  language differs from the latest deployed one.
  `workspaces.*.variables` creates or updates workspace variables whose value
  is read from a runtime file (systemd credential), never the store, and
  rotates with it. `scripts.*.tag` declares the worker-pool tag (`hub`); a
  redeploy that leaves it null carries the deployed tag forward, because a new
  version does not inherit its parent's.
- `services.n8n.provision.workflows` imports or updates n8n workflows by name
  from a JSON export, rewrites each node's credential references to the
  provisioned credential ids, and activates or deactivates them to match
  `active`. An unchanged declaration writes nothing; a UI edit is reverted.
  A node that calls another declared workflow by name (`parameters.workflowId`)
  is imported after it and its reference is rewritten to the live id, which is
  what n8n validates when the caller is published.
- `homeModules.antigravity` (`nix-provenance.antigravity.googleAuth`) registers
  one Antigravity Google sign-in in every listed agy profile. A user oneshot
  copies agy's `acp_token.json` from a runtime agenix file into each
  `GEMINI_HOME` as a private 0600 file, refuses a file without a refresh
  grant, and leaves an unchanged copy alone, since agy rewrites it on every
  launch. A path unit re-registers it when the source changes.
- `services.immich.provision.apiKeys` declares admin-owned Immich API keys.
  `immich-provision` creates each key with its permissions, writes the secret
  once to a mode-0600 file under its state directory for `LoadCredential=`
  consumers, fixes drifted permissions, and replaces keys whose file is
  missing or no longer authenticates.
- `homeModules.paperclip-archive` (`nix-provenance.paperclip-archive`) exports
  every Paperclip company on a timer into a git-LFS repository and restores
  declared companies from a pinned copy only when no company with that slug
  exists. The forge token is read at runtime by a git credential helper and
  never enters the store, argv, or the remote URL.

### Fixed

- Keep GitHub's shared `nix flake check` from running KVM tests alongside crate
  builds. The same VM tests now run in the Nix matrix and can be built locally
  via `.#nixosTests.x86_64-linux.<test>`.
- n8n provisioning retries a transient failure on its own: a failed
  `Requires=` dependency makes systemd cancel the reconciling job before the
  unit runs, so `Restart=` on either oneshot never sees it and the pair stayed
  down until someone started it by hand. `n8n-provision-retry.timer` re-runs the
  pair while provisioning is not active — a start job pulls the failed pre-pass
  in with it — and goes idle once it is. The oneshots pull the timer in with
  `Wants=` and it is `PartOf=` them and `n8n.service`, so it stops whenever they
  do: enabled on its own it ticked in the stop→start window of a NixOS switch,
  started the units still loaded from the old generation, left them
  `active (exited)` so the switch's own start did nothing, and held a newly
  declared `active = false` (or an explicit stop of n8n) off. `Requires=`/
  `After=` still make the pre-pass fail-closed, and the pre-pass, its state file
  and the timer are wired only when a workflow is declared, so a host pinning an
  older `provisionPackage` without the `deactivate` subcommand still starts.
- `n8n-deactivate` reads its own state file, which holds only the URL, the
  owner and the names declared inactive. A declaration the reconciler rejects
  (a credential name over n8n's 128-character limit, a missing field credential)
  used to make the pre-pass exit before contacting n8n, leaving the webhook it
  should unpublish serving.
- An n8n workflow export that declares `executionTimeout` equal to the instance
  default no longer PATCHes on every run, and declaring that default now resets
  a stored override: n8n 2.39.6 deletes a saved timeout equal to its
  `EXECUTIONS_TIMEOUT` (`removeDefaultValues`), so the reconciler reads that
  default from n8n's own `/rest/settings` when a declaration names one. An
  absent live key matches a declared default, a different stored value is drift
  and the PATCH sends the declared default back. The module no longer mirrors
  the default from `EXECUTIONS_TIMEOUT` (`lib.toInt` broke on `"060"` and
  ignored `EXECUTIONS_TIMEOUT_FILE`), and the state schema is unchanged again.
- The Windmill `// tag` badge check no longer treats prose as a badge:
  Windmill 1.839.0 ignores a value with whitespace or over 50 bytes
  (`// tag this for review`) and keeps scanning for the first valid one, and the
  check mirrors it.
- The n8n module's evaluation-time literal-credential lint is gone: Nix has
  already copied the flake source before it evaluates that check, so it could
  never keep a value out of the store and broke evaluation on a non-string
  header `name`. The reconciler's runtime check is the deployment guard, and the
  option text and guide now say exports must be sanitized before they enter the
  flake source.
- The `executeWorkflow` dependency predicate reads only `parameters.source`:
  n8n never consults the locator's `mode`, so a `mode: "url"` locator with a
  `database` source is a local id it validates, and is now treated as one
  instead of being skipped.
- n8n deactivates a workflow declared `active = false` in
  `n8n-deactivate.service`, a oneshot that loads only the owner password and
  runs before the unit that loads the field credentials. systemd resolves a
  unit's whole `LoadCredential=` before its first step, so a missing credential
  file (or a corrupt credential registry) used to keep the webhook serving
  because the reconciling unit could not start at all. The main unit now orders
  after and requires the pre-pass, and a duplicate workflow name is refused by
  one shared name lookup instead of being picked first for deactivation and last
  for reference binding (all live copies of a deactivated name are deactivated).
- n8n workflow settings converge: n8n merges a PATCH into the stored settings,
  so a key an operator added (a `timezone`, say) survived every write and was
  re-PATCHed forever. The update sends n8n's own `"DEFAULT"` reset token for
  every resettable key the declaration leaves out, settings are compared key by
  key, and a key n8n cannot reset is reported once and excluded. The dependency
  order of `executeWorkflow` nodes now uses n8n's predicate: a disabled node,
  a `localFile`/`url`/`parameter` source, an empty id or an `=` expression is
  not a reference.
- n8n and Windmill provisioning no longer copy sensitive detail into journald or
  the store: a failed Windmill lock job is reported by version hash and job id
  (its logs stay in the job), and an n8n export that carries a literal
  `Authorization`, `apiKey`/`api-key` or `password` value fails the run, because
  exports are copied into the Nix store. The module and guide say exports must
  be sanitized.
- Windmill scripts declare a worker tag that a `// tag <name>` badge in the
  source would silently override on 1.839.0: a conflicting badge is refused
  before the deploy, and the stored tag is verified on read-back.
- Windmill and n8n provisioning state files now interpolate `contentFile` and
  workflow `file` path literals instead of `toString`-ing them: the string keeps
  its store context, so the file is in the closure and editing it changes the
  units' restart trigger. A deploy also waits (bounded) for the version's lock
  job and fails on a failed or still-queued job, instead of treating an
  unrunnable version as deployed and skipping it next run. The modules omit
  `scripts`, `variables`, `workflows` and `data_file_prefixes` when empty, gate
  n8n's `deactivate` unit, its state file and the retry timer on a declared
  workflow, and pass `--deploy-timeout` only when a script is declared, so a
  host pinning an older provisioner still starts and parses the state.
  `windmill-provision` now has a start timeout that covers that wait.
- n8n workflow reconciliation deactivates every existing workflow declared
  `active = false` before credentials and content, so a failing replacement
  export or credential write cannot leave the old webhook serving. Workflows
  are compared node by node (ignoring only the ids and `webhookId` n8n
  generates) and connection by connection, so a UI edit such as adding
  `disabled` to a node is drift again. Two declared credentials that resolve to
  one n8n id now fail before any write instead of overwriting each other's
  secret.
- Rauthy provisioning evicts users that Rauthy's email lookup still serves
  from its cache after the database row is gone (its magic-link cleanup
  deletes with raw SQL), then reconciles them as absent instead of failing
  with HTTP 500 on dependent writes. A paged user listing never triggers
  eviction. An email-only stale entry is overwritten by re-saving the
  recreated user, or cleared through a temporary row when the user is
  declared absent or provider-backed. Both repairs take the new id from the
  create response, so a user listing that starts paging cannot strand them.
- Rauthy users with `requiredAuthProvider` are onboarded by their upstream
  provider on first sign-in instead of being pre-created, which mailed them a
  set-password link and let Rauthy's magic-link cleanup delete them after
  they linked upstream. The provider must enable `autoOnboarding`. A
  `rauthy-provision-onboarding` timer reloads provisioning every 15 minutes,
  so their declared roles, groups and attributes are applied once Rauthy has
  created them, without restarting units that require provisioning.
- Proton VPN accounts stay age-encrypted at rest and decrypt natively only in
  short-lived locked, non-dumpable memory with a logind sleep inhibitor. Home
  login now uses `encryptedFile` and `identityPaths`; agenix plaintext installation
  must be disabled. Enrollment streams to an encryption pipe and rejects file output.

- Stalwart proxy fixtures wait for listener readiness after configuration
  switches before checking trust replacement and clearing.
- Kanidm credential wiring checks read the built script directly, avoiding
  early pipe closure failures while preserving every configuration assertion.
- Vikunja project and label response IDs remain available to reconciliation
  logging when combining the durable rbw and Proton VPN integration branches.
- The development environment fails closed on shell-loading errors and watches
  optional Cargo configuration without requiring a pre-existing `.cargo` directory.
- Tuwunel bootstrap fixtures resolve their shell from the test environment so
  lifecycle tests run in Nix sandboxes without `/usr/bin/env`.
- Tuwunel registration bootstrap tolerates delayed asynchronous config reloads
  with bounded retries of explicit registration-disabled refusals, attempts to
  restore the closed config after failures, and never retries ambiguous
  transport errors.
- Identity CLI featureless and Bitwarden-only builds no longer pull in the
  Kanidm-only generated-secret dependency and its TLS-dependent HTTP helper;
  the Forgejo OIDC secret binary correctly requires the Kanidm feature.
- Room-owner login reuses the initialized HTTP transport so construction cannot
  fail between login and the reconciliation/logout path.
- Private-room verification no longer mistakes unrelated state events for
  encryption or access policy.
- Direnv now uses the locked flake inputs without requiring a sibling
  nix-opencode-lsp checkout.
- Preserve host-owned Kanidm profiles, existing Tuwunel account reconciliation,
  and the Kanidm-only aarch64 identity CLI configuration when consuming trunk.
- Direnv loads the Rust tools and OpenCode LSP configuration through one shell,
  preventing repeated cache invalidation between the two shell loads.

### Added

- `github-provision` and `homeModules.github`: per-account Home Manager user
  units that reconcile a GitHub account's SSH and OpenPGP public keys, invite
  collaborators to owned or named repositories, and accept invitations only
  from trusted owners. Runs on activation, token rotation, and daily.
- A Home Manager rbw adapter with durable private login state, guarded legacy
  migration, shared client/agent paths, and metadata-only recovery diagnostics.
- Nullable Stalwart 0.16 listener PROXY trust overrides, with explicit set,
  replace, unmanaged, and clear semantics and isolated HAProxy/mail fixtures.
- `proton-vpn-auth enroll --stdin --stdout` validates credential documents through
  private pipes for direct vault-to-encryption imports, including base32 and
  compatible authenticator URI normalization without plaintext files.
- Official Proton VPN clients can enroll an existing account from a private
  runtime credential document through a Home Manager module and Rust adapter,
  including TOTP, session reuse, bounded retries, and redacted errors.
- `proton-vpn-auth enroll` securely prompts for existing account credentials and
  creates a private runtime document for a consumer's secret-manager import.
- Protocol regression tests and a disposable Tuwunel VM gate cover private-room
  creation, observed-ID pinning, unsafe-state rejection and device logout.
- Tuwunel can create initially encrypted, invite-only rooms as a declared
  service account, verify live membership, and pin their observed room IDs.
  Reconciliation refuses alias drift and unsuitable existing rooms and logs
  out the room-provisioning device after either success or failure.
- A reusable treefmt module for the repository's Alejandra formatting policy.
- Host/user-scoped OpenAI ChatGPT OAuth enrollment with serialized refresh,
  rollback fencing, encrypted recovery checkpoints, and access-only adapters for
  stock OpenCode V2 and OMP. NixOS and Home Manager modules provide runtime
  enrollment and automatic compatible-consumer bindings.
