# Rauthy Bootstrap Generate Research Dossier

## Goal And Trigger

The goal is to plan a multi-wave upstream Rauthy implementation that reaches PR 2 for fully declarative bootstrap API keys without manual API-key secret provision.

The requested target shape is:

- PR 1 opens first and contains the base generated-secret mechanism for clients and users, the encrypted local container, the offline `rauthy bootstrap {get,purge}` CLI, output formatting, and auto-purge.
- PR 2 is built locally on top of PR 1 but not published until PR 1 is accepted. It adds generated API-key secrets so a declarative provisioner key can be defined without manually supplying `bootstrap.api_key_secret` or a plaintext/encrypted `api_keys.json` secret.
- PR 3 remains out of scope for this wave and covers Kubernetes-native Secret writes through a ServiceAccount.

## Current Reality

Rauthy upstream already has JSON bootstrapping for API keys on `origin/main`. After `git fetch origin --prune`, `origin/main` advanced from `89246ddf` to `38725aab`; the current `origin/main` tree contains `bootstrap/api_keys.json`, `book/src/config/bootstrap.md`, and `src/data/src/migration/bootstrap/api_key.rs`.

The local Rauthy checkout is on `feat/bootstrap-api-keys-json`, but `git fetch caniko --prune` reported the remote branch as deleted. Treat that branch as historical evidence only, not as the implementation base for new PRs.

Bootstrap API-key JSON today still requires a supplied secret. `src/data/src/migration/bootstrap/types.rs` defines `ApiKey.secret: ApiKeySecret`, and `ApiKeySecret` has only `Plain(String)` and `Encrypted(String)` variants. The `bootstrap_api_keys_json` path creates an API key, discards the generated token returned by `ApiKeyEntity::create`, then reads the operator-supplied secret and overwrites the stored hash with `set_api_key_secret`.

Client bootstrap already distinguishes public clients from confidential clients by whether `Client.secret` is present. In `src/data/src/migration/bootstrap/clients.rs`, absent `secret` means no DB secret and forced `S256`; a generated confidential client therefore needs an explicit `Generate` sentinel, not an omitted secret.

User bootstrap requires `User.password: UserPassword`; `UserPassword` currently supports only `Plain(String)` and `Argon2ID(String)`. Adding `Generate` is additive and does not collide with an existing omitted-field meaning.

Rauthy already has the primitives needed to generate and encrypt the first two entity kinds:

- `Client::generate_new_secret()` generates a 64-character secret and returns both plaintext and encrypted bytes.
- `ApiKeyEntity::create()` already generates a 64-character token, stores `EncValue(sha256(secret))`, and returns the usable `{name}${secret}` token.
- Existing bootstrap client code already encrypts supplied client secrets with `EncValue::encrypt_with_key_id`.
- Existing API-key code already uses `EncValue` and `EncKeys::get_static()` for encrypted DB state.

Rauthy CLI currently has top-level commands such as `Serve`, `GenerateConfig`, `ValidateConfig`, `GenerateEncKey`, `GenerateSecrets`, and `HashPassword`. There is no `bootstrap` subcommand yet, so PR 1 owns the CLI namespace.

The proposed `${data_dir}` maps to Hiqlite's `[cluster].data_dir` / `HQL_DATA_DIR`, not to a generic Rauthy data directory. Rauthy also supports `USE_VAULT_CONFIG=true`, where config is fetched from Vault instead of read from disk. That supports the earlier decision to store the encrypted generated-secret container under the server-writable data directory rather than next to `config.toml`.

## Evidence Inventory

| Evidence | What It Proves |
|---|---|
| `/data/nvme0/can/Projects/rauthy`, `git fetch origin --prune` | Upstream `origin/main` is current at `38725aab`; planning must target that, not the stale local branch. |
| `/data/nvme0/can/Projects/rauthy`, `git fetch caniko --prune` | The local branch's remote counterpart `caniko/feat/bootstrap-api-keys-json` was deleted; do not publish on that branch. |
| `git show origin/main:src/data/src/migration/bootstrap/types.rs` lines 77-141 | `ApiKey` and `ApiKeySecret` already exist; `ApiKeySecret` lacks `Generate`. |
| `git show origin/main:src/data/src/migration/bootstrap/types.rs` lines 144-160 and 220-231 | `Client.secret` is optional and `ClientSecret` lacks `Generate`; absent secret already has a public-client meaning. |
| `git show origin/main:src/data/src/migration/bootstrap/types.rs` lines 234-281 | `User.password` is required and `UserPassword` lacks `Generate`. |
| `git show origin/main:src/data/src/migration/bootstrap/clients.rs` lines 33-65 and 71-75 | Bootstrap treats present client secret as confidential and absent secret as public S256. |
| `git show origin/main:src/data/src/migration/bootstrap/users.rs` lines 52-56 | User bootstrap hashes plaintext or accepts an Argon2id hash; generated passwords can reuse this path after minting plaintext. |
| `git show origin/main:src/data/src/migration/bootstrap/api_key.rs` lines 54-72 | API-key JSON bootstrap currently discards the generated token and overwrites it with the supplied secret. |
| `git show origin/main:src/data/src/entity/api_keys.rs` lines 35-88 and 124-163 | API-key creation and rotation already generate secrets; creation returns `{name}${secret}` and stores only the hashed/encrypted verifier. |
| `git show origin/main:src/data/src/entity/clients.rs` lines 848-860 | Rauthy already has a 64-character client secret generator and encrypts the result. |
| `git show origin/main:src/data/src/rauthy_config.rs` lines 1037-1060, 1380-1422, 2427-2442, 3425-3433 | Config can come from Vault; bootstrap config currently has no secrets-container fields; Hiqlite cluster parsing is where data-dir resolution must be sourced or exposed. |
| `git show origin/main:src/bin/src/cli_args.rs` lines 3-22 and `src/bin/src/main.rs` lines 29-50 | CLI command namespace exists and has no `bootstrap` command yet. |
| `upstreaming/round-2/rauthy-1584-reply-2.md` | Captures maintainer-aligned decisions: per-type `Generate`, `${data_dir}`, default 600s auto-purge plus startup check, `rauthy bootstrap {get,purge}`, API keys in PR 2, Kubernetes deferred. |

## Existing Plan Status

| Plan | Item | Status | Evidence | Next action |
|---|---|---|---|---|
| `upstreaming/round-1/rauthy-1585-comment.md` | Get API-key advanced bootstrap JSON reviewed and merged. | done | `origin/main` contains `bootstrap/api_keys.json` and `src/data/src/migration/bootstrap/api_key.rs`; `upstreaming/bridges.md` records sebadob/rauthy#1585 merged on 2026-06-03. | Do not re-open this. Build on it. |
| `upstreaming/round-2/rauthy-1584-encrypted-container-rfc.md` | Use per-type `Generate` sentinel and avoid a unified secret enum. | done as design constraint | `rauthy-1584-reply-2.md` records maintainer-aligned per-type `Generate`; current source lacks the variants. | Carry into PR 1 and PR 2. |
| `upstreaming/round-2/rauthy-1584-encrypted-container-rfc.md` | Store generated secrets in an encrypted container under `${data_dir}`. | partial | Maintainer-aligned note exists; current source has no container module or bootstrap config fields. | PR 1 implementation. |
| `upstreaming/round-2/rauthy-1584-encrypted-container-rfc.md` | Add offline CLI retrieval. | partial | Current CLI has no `bootstrap` subcommand; reply note narrows command to `rauthy bootstrap {get,purge}`. | PR 1 implementation with `get --format json|env|raw`; no CLI `export` in PR 1 unless upstream asks. |
| `upstreaming/round-2/rauthy-1584-encrypted-container-rfc.md` | Add API-key `Generate`. | partial | API-key JSON bootstrap exists but still requires `Plain` or `Encrypted`; `ApiKeyEntity::create()` already returns the generated token. | PR 2, built on PR 1 and held unpublished until PR 1 lands. |
| `upstreaming/round-2/rauthy-1584-encrypted-container-rfc.md` | K8s native handling. | not-started | Reply note says K8s is TBD and out of first PRs; user's current target keeps it in PR 3. | Keep out of PR 1 and PR 2 except for preserving extension points. |

## Work That Should Survive

- Use a per-type unit `Generate` variant serialized as the JSON string `"generate"`.
- Keep client absent-secret behavior unchanged: absent `secret` means public PKCE; `secret: "generate"` means confidential generated secret.
- Keep bootstrap first-boot-only and empty-DB/JWKS gated. Generated containers are a first-boot artifact, not reconciliation state.
- Store generated plaintexts in a single encrypted container using existing cryptr / `ENC_KEYS`; no new key material.
- Use `${data_dir}/bootstrap.secrets.enc` as the default location, with the exact data-dir resolution made explicit in code and docs.
- Default auto-purge to 600 seconds, allow `0` to disable, and purge expired files on startup to cover shutdown-before-timer cases.
- Make `rauthy bootstrap get` support `json`, `env`, and `raw` formats.
- Keep Kubernetes-native Secret writes out of PR 1 and PR 2.

## Blockers And Missing Artifacts

No foundational blocker was found for planning PR 1 and PR 2.

The main implementation unknown is not a missing artifact but a code-design choice: where to expose Hiqlite's resolved `data_dir` to bootstrap code and CLI path resolution. The upstream source proves `[cluster].data_dir` exists in config/docs, but the research did not find a generic `RauthyConfig.vars.data_dir` field. PR 1 should resolve this explicitly rather than guessing:

- Preferred producer: Rauthy PR 1 implementation.
- Regeneration command if source drifts: `git -C /data/nvme0/can/Projects/rauthy fetch origin --prune`.
- Validation command: inspect `origin/main:src/data/src/rauthy_config.rs` and `origin/main:config.toml` for `data_dir` / `HQL_DATA_DIR`, then run the PR 1 test suite.

## Risks And Constraints

- API-key `Generate` depends on the PR 1 container writer. The generated token returned by `ApiKeyEntity::create()` is otherwise unrecoverable after being zeroized or dropped.
- Users and API keys both have the same plaintext-only-in-container property. Client secrets are different because they are decryptable from DB with `ENC_KEYS`; user passwords and API-key tokens are not.
- The CLI must not initialize the full server or talk to HTTP. It should load only enough config or environment to initialize `ENC_KEYS` and decrypt the local file.
- `USE_VAULT_CONFIG=true` can make a naive offline CLI non-offline if it tries to fetch full config from Vault. The CLI should accept `ENC_KEYS` / `ENC_KEY_ACTIVE` directly from env or flags and only read a config file when needed.
- The startup purge check needs an unencrypted deadline in the file header, or it cannot delete expired files without initializing and using `ENC_KEYS`.
- Atomic write matters because generated user passwords and API-key tokens cannot be reconstructed if the DB insert succeeds and the container write is torn. PR 1 should use a same-directory temporary file, create with mode `0600`, fsync, and rename.
- A tail-only container write is unsafe. Generated plaintext must be sealed into the container before the DB row that depends on it is inserted or updated. If the write-ahead container update fails, bootstrap must fail hard before making that generated secret live in the database.
- The local Rauthy branch is not a clean base. Start new work from fresh `origin/main` in a new branch/worktree.

## Design Clarifications From Review

### Purge Lifecycle

The intended lifecycle is both runtime and startup purge.

- Runtime: when Rauthy writes `bootstrap.secrets.enc` with a positive TTL, it should spawn a background Tokio task that sleeps until the cleartext deadline and then purges the file.
- Startup: every server startup should cheaply inspect the cleartext header and delete the file if the deadline is already expired. This is only the fallback for crashes, shutdowns, and missed runtime timers.
- TTL `0` disables both deadline enforcement and runtime auto-purge for operators who intentionally want to keep the encrypted container until manual `rauthy bootstrap purge`.

This means the default 600-second container should not sit on disk for weeks during a normal long-running server process.

### Vault And Offline CLI

PR 1 should not implement Vault-client logic in the bootstrap CLI.

The CLI should support two local modes:

- Config-file mode for ordinary local deployments: read enough config to find `ENC_KEY_ACTIVE`, `ENC_KEYS`, and the default secrets-file path.
- Explicit-key mode for Vault-backed deployments: require operators to pass `ENC_KEY_ACTIVE` and `ENC_KEYS` via environment variables or flags when invoking `rauthy bootstrap get`.

If `USE_VAULT_CONFIG=true` and explicit keys are not present, the CLI should fail with a direct message explaining that offline decrypt requires local `ENC_KEYS`/`ENC_KEY_ACTIVE`. This keeps the CLI genuinely offline and avoids adding a Vault dependency to the first PR.

### Transactional Failure Mode

The bootstrap implementation should fail closed, not log-and-continue.

For generated secrets, "container write failed" is a fatal bootstrap error. Continuing would create users or API keys whose generated plaintext cannot ever be recovered. However, simply crashing after DB writes is not sufficient because Rauthy's first-boot gate may skip bootstrap on restart once JWKS/initial state exists.

PR 1 should therefore use write-ahead ordering for generated secrets:

1. Generate the plaintext.
2. Prepare the DB representation in memory, such as encrypted client secret bytes or hashed user password.
3. Atomically upsert the generated plaintext into `bootstrap.secrets.enc`.
4. Insert the DB row that makes the generated credential live.

If step 3 fails, bootstrap returns an error before step 4. If step 4 later fails, the container may contain a stale value for a row that was not created; that is less severe and can be purged, while avoiding the unrecoverable "live row but lost plaintext" case.

PR 2 should apply the same principle to API keys by refactoring creation enough to generate the token and DB verifier before insertion, instead of relying only on `ApiKeyEntity::create()` as an insert-and-return primitive.

### Env Output Schema

`get --format env` should include the entity kind and secret type in the variable name to avoid collisions.

Recommended names:

- Client secret: `RAUTHY_BOOTSTRAP_CLIENT_<SANITIZED_ID>_SECRET`
- User generated password: `RAUTHY_BOOTSTRAP_USER_<SANITIZED_ID>_PASSWORD`
- API-key token: `RAUTHY_BOOTSTRAP_API_KEY_<SANITIZED_ID>_TOKEN`

Sanitization should uppercase ASCII letters, preserve digits, map all other characters to `_`, collapse repeated `_`, and trim leading/trailing `_`. If sanitization produces an empty string, the CLI should fail rather than emit an ambiguous variable.

The JSON output should preserve structured identity and avoid sanitized-name ambiguity:

```json
{
  "kind": "client",
  "id": "grafana",
  "field": "secret",
  "value": "..."
}
```

### Day-2 Bootstrap Behavior

The design remains first-boot-only.

If Rauthy has already initialized the production database and an operator adds `"generate"` to `clients.json`, `users.json`, or `api_keys.json` on day 30, the advanced bootstrap path should not run, should not append to the container, and should not reset the TTL. This matches the existing JWKS-gated bootstrap contract.

Docs should state this explicitly: the encrypted container is an extraction mechanism for first-boot generated values, not a day-2 secret reconciliation store.

## Candidate Next Steps

Wave 0: prepare a clean upstream base.

- Create a fresh branch or worktree from `origin/main`, not from `feat/bootstrap-api-keys-json`.
- Preserve the old branch only as a reference for API-key JSON docs/tests if needed.
- Run the upstream baseline checks before editing, at minimum `cargo test -p rauthy-data parses_api_keys_bootstrap_example` and the project's normal formatter/pre-PR command if available.

Wave 1: PR 1, container skeleton before entity integration.

- Add a small bootstrap generated-secrets module in `rauthy-data`, with structs for header metadata, secret entries, encrypted container read/write, TTL expiry, and purge.
- Add config fields under `[bootstrap]` for the secrets file path, TTL seconds, and optional cleartext `secrets_export_path` only if we decide to include the maintainer-suggested export path in PR 1.
- Add startup purge check after config initialization and before/around migration. This should be safe even when no DB is available because it is a file cleanup.
- Add runtime purge task scheduling for newly written containers when TTL is positive.
- Add unit tests for container roundtrip, wrong magic/version, expired header, env/json/raw formatting, and purge.

Wave 2: PR 1, clients and users.

- Add `Generate` to `ClientSecret` and `UserPassword`.
- For clients, route `Generate` through the same generated 64-character secret and DB encryption behavior used for confidential clients.
- For users, mint a high-entropy password and hash it through the existing plaintext password path.
- Persist each generated plaintext to the encrypted container before inserting the DB row that depends on it.
- Gate generated-container writes to first-boot production bootstrap only. Avoid writing a container from dev bootstrap paths.

Wave 3: PR 1, CLI and docs.

- Add `rauthy bootstrap get` and `rauthy bootstrap purge`.
- Implement `get --format raw|json|env`; diagnostics to stderr, secret values to stdout only.
- Document first-boot-only semantics, TTL behavior, startup purge, `USE_VAULT_CONFIG` implications, and the fact that API-key `Generate` is intentionally in PR 2.
- Open PR 1.

Wave 4: PR 2 local branch, built on top of PR 1 and held unpublished.

- Add `Generate` to `ApiKeySecret`.
- Refactor API-key creation so the generated token and hashed/encrypted verifier can be prepared before DB insertion.
- In `bootstrap_api_keys_json`, for `Generate`, write the full usable `{name}${secret}` token to the encrypted container before inserting the API-key row; do not call `set_api_key_secret`.
- For `Plain` and `Encrypted`, preserve current behavior exactly: create key, discard generated token, decrypt/read supplied secret, and call `set_api_key_secret`.
- Add tests proving `Generate` stores a valid API-key verifier and emits the usable `{name}${secret}` token into the container.
- Extend docs to show `api_keys.json` with `"secret": "generate"` and an example provisioner key with `Scopes`, `UserAttributes`, `Secrets`, `Users`, `Groups`, `Roles`, and `Clients` rights.
- Do not publish PR 2 until PR 1 review either lands or forces API changes; keep it rebased locally.

Wave 5: local consumer proof for nix-provenance/canix, after PR 2 exists locally.

- Patch the Rauthy package to the PR 2 branch in nix-provenance or canix.
- Render a bootstrap `api_keys.json` for `rauthy-provision` with `secret = "generate"` and the full permissions required by the reconciler.
- Add a one-shot extraction path that runs `rauthy bootstrap get --format env` locally and writes the generated provisioner key to the secret path consumed by `rauthy-provision`.
- Validate with a fresh empty test DB/VM; do not claim this solves existing live DBs unless a migration/runbook rotates the existing key.

## Open Decisions For The User

- Should PR 1 include `secrets_export_path`, or keep PR 1 strictly to encrypted container plus CLI `get/purge`?
- Should the CLI subcommand name be exactly `rauthy bootstrap`, matching the maintainer-aligned reply, or `rauthy bootstrap-data` if upstream prefers a less broad namespace?
- Should Wave 5 be a nix-provenance VM test, a canix host dry-run, or both?
