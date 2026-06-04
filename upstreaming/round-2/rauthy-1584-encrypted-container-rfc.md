# RFC: Encrypted bootstrap-secret container for Rauthy

> Continuation of #1584. Posting here per @sebadob's confirmation (2026‑06‑03) that the encrypted-container mechanism belongs on this issue now that #1585 (`api_keys.json`) has merged. I (caniko) have a backend implementation in progress and will open a draft PR once the shape below is agreed.

## 0. Resolved with @sebadob (these supersede the body where they conflict)

Maintainer decisions after the first round — folded in; older body text that conflicts is overridden by this list:

- **Separate enums, not a unified `BootstrapSecret`** — confirmed; per-type `Generate` variant. `"generate"` sentinel confirmed (clients: absent already = public+PKCE).
- **No key-id work on our side** — cryptr's header already carries the enc-key id and auto-selects while the key is in `ENC_KEYS`; reads are rotation-safe for free. (§5's "we tag it" framing is dropped.)
- **Exposure correction** — API-key secrets are sha256-hashed *and* encrypted (fast hash on purpose; not decryptable). They behave like argon2'd **user** passwords: for **both users and API keys the container is the sole plaintext**; only **clients** are DB-recoverable. So API-key `generate` is **not** a unique new exposure — users already carry it. sebadob: **include API keys.** (Supersedes §9's "one genuinely NEW exposure" framing.)
- **Auto-purge: default-on 600s, `0` off — plus a startup check.** A shutdown before the timer would strand the file, so also purge-if-expired on every startup; stamp the deadline in the **cleartext** header so startup checks with stat+read, no decrypt. (Extends §6.)
- **Location:** `${data_dir}` — confirmed (Q1 closed).
- **CLI:** drop `-secrets` → `rauthy bootstrap {get,purge}`. `get --format raw|json|env` (env = KEY=VALUE/line). Cleartext export via a **`secrets_export_path` config option** (server writes cleartext at first boot), not a CLI `export` (CLI `export` deferred). (Supersedes §7's name + verbs.)
- **K8s: TBD, out of the first PRs.** Preferred future = give the Rauthy pod a **ServiceAccount** and have the **server write generated secrets straight into a native K8s `Secret` via the K8s API** — in that mode no encrypted container / no our-side crypto is needed. This supersedes §8's CLI-image-Job-as-primary.
- **Open micro-questions:** subcommand name `bootstrap` vs `bootstrap-data`; ship `secrets_export_path` in PR 1 (CLI `export` later)?

## 1. Framing

In #1584 you redirected away from an admin-token/UDS CLI and described the mechanism you'd actually want:

> "auto-generate all sorts of secrets … store them in an encrypted container next to the config file. This container then would be readable with the CLI, since it has access to the Enc keys."

and the prerequisite:

> "Having the API Keys available via JSON instead of from the config directly would be a prerequisite anyway to make the encrypted container work."

That prerequisite is now satisfied — `api_keys.json` (#1585) merged. This RFC specifies the rest:

1. **Generate** — let a confidential client, a user, and an API key declare "Rauthy should mint this secret" during first-boot bootstrap, instead of the operator authoring it.
2. **Store** — write every minted plaintext into a single ENC_KEYS-encrypted container file, reusing `cryptr` exactly as the DB columns already do.
3. **Retrieve** — read it back via an offline `rauthy` CLI subcommand that loads `ENC_KEYS` the same way `serve` does and never talks to the running server.

The point is your stated one: operators should **never commit a secret to CI/git — not even an encrypted one**. With this, the operator commits only the *declaration* `"generate"`; Rauthy mints the value and seals it. This is the outbound counterpart to what bootstrap already does inbound — it already *ingests* ENC_KEYS-encrypted secrets via the `Encrypted` variant in `clients.json` / `api_keys.json`; this closes the loop.

This design is the merge of two internal proposals after adversarial review. **Where reviewers flagged unresolved tension or low acceptance, it is surfaced honestly in §10–§12 rather than buried** — most importantly the "this relocates the plaintext-store problem to the PVC/backups" objection, which drove the **auto-purge-by-default** decision in §6.

## 2. Goals / Non-Goals

**Goals**
- Auto-generate secrets for confidential clients, users, and API keys at first-boot bootstrap.
- Persist them in one `ENC_KEYS`-encrypted file, no new key material, no new crypto.
- Retrieve via an **offline, local-file** `rauthy` CLI subcommand (decrypts a file; does not control the server).
- Build additively on Advanced Bootstrapping (empty-DB / JWKS-gated / INSERT-only). Default bootstrap admin stays in config.
- Bound the plaintext lifetime so the file is not a forever-secret on the data volume.

**Non-Goals**
- **No UDS / peer-cred transport.** ("UDS … most probably NOT happen at all.")
- **No new admin-token type.** ("only increase code complexity with no real advantage.")
- **No trusting external (config-management) state** as an auth/identity source.
- **No live reconcile.** Bootstrap stays first-boot-only; changing JSON later "would simply be ignored" (#1554). The container is a first-boot artifact, not a live secret store.
- **No server control channel / HTTP retrieval endpoint** (would reintroduce the auth surface you rejected, and violate `cli.md`: the CLI "does NOT … control a Rauthy instance … never will").

## 3. Bootstrap JSON contract change

One new variant per existing secret enum in `src/data/src/migration/bootstrap/types.rs` (the single source of truth). All existing JSON keeps parsing unchanged.

| Type | Today | New |
|---|---|---|
| `ClientSecret` | `Plain(String) \| Encrypted(String)` | `+ Generate` |
| `ApiKeySecret` | `Plain(String) \| Encrypted(String)` | `+ Generate` |
| `UserPassword` | `Plain(String) \| Argon2ID(String)` | `+ Generate` |

`Generate` is a **unit variant**, expressed in JSON as the string `"generate"`:

```jsonc
// clients.json
{ "id": "my-confidential-client", "name": "...", "secret": "generate", ... }
// api_keys.json
{ "name": "ci-provisioner", "exp": 1717459200, "secret": "generate", "access": [ ... ] }
// users.json
{ "email": "svc@example.com", "password": "generate", ... }
```

Why a sentinel and not "omitted secret":

- **Clients:** an *absent* `secret` already means **public client + forced S256 PKCE** (`clients.rs`: `challenge = if secret.is_none() { Some("S256") } …`, and the `confidential` column is set from secret presence). Overloading "absent" to mean "generate" would silently flip public→confidential. So `Generate` is the explicit "confidential client + 64-char minted secret" signal; absent stays public; `Plain`/`Encrypted` stay supplied-confidential.
- **API keys & users:** `secret`/`password` are required fields today. `"generate"` is the minimal additive opt-in.

No length validation is needed for `Generate` (Rauthy controls the length, reusing the existing `SECRET_LEN_CLIENTS = 64`, `API_KEY_LENGTH = 64`, and a 24-char default for user passwords matching the admin-password precedent). Mixed files are fine. `Debug` for these enums already prints `<hidden>`, so `Generate` inherits safe debug.

**Optional length override** (`{"generate":{"len":N}}`, `N >= constant`) is deferred — bare `"generate"` ships first. (Open question Q4.)

## 4. The container

- **File name & location:** `bootstrap.secrets.enc`, in the **data directory** — the directory that already holds the SQLite/hiqlite store, JWKs, and `config-generated.toml` (`/app/data`, UID 10001 writable in the container). New config key `[bootstrap].secrets_file` (env `BOOTSTRAP_SECRETS_FILE`); default resolved relative to the data dir, fallback `${bootstrap_dir}/../bootstrap.secrets.enc`.

  > **Deviation from your "next to the config file" wording, flagged for your call (Q1).** Reason: under `USE_VAULT_CONFIG=true` (`rauthy_config.rs:1039`) there may be **no config.toml on disk at all**, and the server only reliably owns the *data* dir. Tying the file to the data dir also means it rides the same PVC + backup boundary the server already writes — which is the precondition that makes K8s retrieval (§8) possible. There is no single `data_dir` config var today, so the exact resolution rule needs your blessing.

- **On-disk bytes:** the raw `cryptr` `EncValue` produced by `EncValue::encrypt(&json_bytes)?.into_bytes()`, prefixed with an **8-byte magic + 1-byte format version** so the CLI can reject a wrong/garbage/half-written file *before* handing bytes to cryptr:

  ```
  "RAUTHYSC" (8 bytes) | format_version (u8 = 1) | <cryptr EncValue bytes>
  ```

  This prefix is **mandatory, not optional** (reviewer fix): `cryptr`'s `EncValueHeader::try_extract` uses `bytes::Buf` getters that **panic** on a short buffer, so the CLI must length-check + verify the magic before `EncValue::try_from`, or it panics on a truncated file. Not base64 on disk (base64 is only the in-JSON `Encrypted(...)` convention).

- **Plaintext structure (what gets encrypted):**

  ```jsonc
  {
    "version": 1,
    "generated_at": 1717459200,
    "rauthy_version": "0.36.x",
    "enc_key_id": "<id used to seal, mirrored from header for inspection>",
    "expires_at": 1717459800,        // auto-purge deadline (see §6); null if disabled
    "secrets": [
      { "kind": "client",  "id": "<client_id>",        "secret": "<64-char plaintext>" },
      { "kind": "api_key", "id": "<key_name>",          "secret": "<name$plaintext token>", "exp": 1717459200 },
      { "kind": "user",    "id": "<email-or-user-id>",  "secret": "<plaintext password>" }
    ]
  }
  ```

  - **Keyed by `(kind, id)`** — `client_id` for clients, API-key `name` for keys, email (preferred) or user id for users. The CLI filters on these.
  - For API keys the stored value is the **full usable `{name}${secret}` token** (the exact form `ApiKeyEntity::create()` returns), because the DB stores only `EncValue(sha256(secret))` (one-way) — **the container is the only place a generated API-key token can ever exist.**
  - Two independent version fields: this `version` gates the plaintext schema; cryptr's own header `version`/`alg` (each `TryFrom<u8>`) versions the crypto envelope.

- **One blob, whole-file.** All entries are serialized to one JSON document and encrypted as **one** `EncValue`. Not per-entry, not one-file-per-secret — see §5 for the crypto reason.

- **Permissions — atomic 0600-on-create (reviewer fix).** Write to a temp file in the same dir opened with `OpenOptions::new().write(true).create_new(true).mode(0o600)`, `fsync`, then `rename` over the target. **Do not** use the write-then-`chmod` pattern (`gen_config.rs:976`) or cryptr's `encrypt_to_file` (plain `fs::write`, no mode) — both leave a umask-window where the file is briefly world-readable, and a mid-write crash would strand the operator with secrets already committed to the DB (and, for API keys, unrecoverable). Atomic temp+rename closes both holes.

## 5. Encryption

Reuse `cryptr 0.10.0` + `ENC_KEYS` verbatim — byte-for-byte the same calls the DB columns use (`api_key.rs:86`, `clients.rs:58`, `api_keys.rs:43`).

- **AEAD:** ChaCha20-Poly1305 (cryptr's only AEAD — *not* XChaCha, *not* AES-GCM).
- **Nonce:** 12-byte (96-bit) random from `OsRng`, fresh per encryption. Layout `nonce(12) || ciphertext || tag(16)`, wrapped by the `EncValue` header.
- **Single blob ⇒ one nonce use per write.** This is the deliberate reason for whole-file encryption: it keeps messages-per-key far below the ~2³² random-nonce birthday bound. Per-entry encryption would multiply nonce uses and header overhead for zero benefit (one trusted holder of `ENC_KEYS` reads the whole file). A unit test will assert exactly one `EncValue` per container so a future refactor can't silently reintroduce per-entry collision risk.
- **Key-id tagging:** the cryptr header is `version(u8) | alg(u8) | length(u16) | chunk_size(u16) | enc_key_id(UTF-8)`. The **active key id is embedded per value**, so any holder of the full `ENC_KEYS` set decrypts regardless of which key was active at write time.
- **Encrypt:** `EncValue::encrypt(&serde_json::to_vec(&container)?)?.into_bytes()` (note the borrow — `encrypt` takes `&[u8]`). **Decrypt:** `EncValue::try_from(bytes)?.decrypt()?`.
- **AAD caveat (honest):** cryptr 0.10 does **not** put the header in the AEAD AAD. The ciphertext body is authenticated; header tampering surfaces as a key-not-found / parse error rather than an auth-tag failure. The header therefore leaks `enc_key_id` and approximate secret count/size in cleartext to a file-only attacker. Acceptable (same as every DB blob), noted in §11.
- **No `EncKeysSealed` / password seal.** That seals *keys* and introduces a second secret to manage — exactly the "new secret to commit" we're eliminating. Plain `EncValue` under `ENC_KEYS` is the minimal fit.

**Behavior across `ENC_KEY` rotation:**
- **Reads are rotation-safe** as long as the writing key remains in `ENC_KEYS` (standard "keep old keys until migration completes" guidance) — identical to DB rows.
- **The file is NOT auto-migrated.** `POST /encryption/migrate` → `migrate_encryption_alg` walks DB rows + JWKS only (`service/src/encryption.rs`), never files. If the writing key is *removed* before the container is consumed, the file becomes permanently undecryptable.
- **Mitigation (shipped, not deferred):** because the container is short-lived by default (§6), this window is small. Additionally: (a) `/encryption/migrate` will **warn if a `bootstrap.secrets.enc` exists** sealed with a key about to be removed; (b) a `bootstrap-secrets reseal` subcommand (§7) decrypts with any available key and re-encrypts under the active key for operators who deliberately keep it.

## 6. Generation flow, idempotency, lifecycle

**When:** only inside `migrate_init_prod()` — gated on `!dev_mode && is_primary_node` **and** an empty `jwks` table (`mod.rs:61`, the `SELECT * FROM JWKS; if !jwks.is_empty() { return Ok(()) }` check at `mod.rs:70`). No CLI subcommand ever generates. Generation is a pure side effect of first-boot, exactly where the random admin password is minted today.

**Capture:** thread a `&mut GeneratedSecrets` accumulator (a `Vec` in a `Zeroize`-on-drop wrapper) through `bootstrap_additional_data()` into the `clients` / `users` / `api_key` loops. Each `Generate` branch:
- **client:** mint `get_rand(SECRET_LEN_CLIENTS)`, set `confidential = true`, store via `EncValue::encrypt_with_key_id(plain, active_kid)` (unchanged path), push plaintext.
- **api_key (corrected vs both source designs):** the current `api_keys.json` path **requires** an operator secret — `ApiKeyEntity::create()` mints a throwaway, `generated_secret.zeroize()` discards it (`api_key.rs:45,68`), then `set_api_key_secret(name, operator_supplied)` overwrites the stored value (`api_key.rs:71`). So `Generate` is **not** "just don't discard". It means: make `api_key.secret` effectively optional (`"generate"`), **skip `set_api_key_secret`**, and **capture the `{name}${secret}` string `create()` returns** (which already stored `EncValue(sha256(secret))`). The earlier framing that the primitive "is already there" was a misread of #1585 — corrected here so the PR maps 1:1.
- **user:** mint `get_rand(24)`, argon2id-hash (unchanged path), push plaintext.

**Write:** at the tail of `bootstrap_additional_data()`, if the accumulator is non-empty, write the atomic 0600 container (§4), stamp `expires_at`, then drop/zeroize the in-memory plaintexts.

**Dev/test guard (reviewer fix):** `bootstrap_additional_data()` is *also* called from `db_migrate_dev.rs:232`. The container write must be gated to the prod first-boot path (or behind a flag) so dev/integration runs never emit `bootstrap.secrets.enc`.

**Idempotency / second boot:** on a non-empty `jwks` table `migrate_init_prod()` returns **before** any bootstrapping. So a normal restart never regenerates, never rewrites, never clobbers the file. A container written at first boot persists untouched for later retrieval. A DB wipe (empty `jwks`) is a fresh first-boot: it overwrites the file wholesale (correct — the old secrets' rows are gone).

**Auto-purge — DEFAULT ON (the central security decision).** This directly answers the sharpest reviewer objection: *"this trades 'encrypted secret in git' for 'encrypted secret on the backup volume forever' — a lateral move sebadob is likely to reject on his own grounds."* So:

- New `[bootstrap].secrets_file_ttl_secs`, **default `600`** (mirrors your "expire after 10 minutes" instinct for bootstrap API keys). At first boot the server spawns a one-shot task that deletes the container after the TTL.
- The TTL deadline is stamped as `expires_at` inside the plaintext; the CLI **refuses to decrypt past the deadline** and reports it as expired (defense in depth if the file outlives the task, e.g. server killed).
- Setting the TTL to `0` disables auto-purge for deliberate long-lived use (opt-out, not the default) — Rauthy's "secure by default, opt out if you must" philosophy.
- Manual `bootstrap-secrets purge` remains for early cleanup.

**Rotation of generated secrets:** out of scope for bootstrap (first-boot-only). Rotating a client/API-key secret afterward is the existing Admin-UI/API job and does not touch the container. The container reflects first-boot generation only — stated plainly so it isn't mistaken for a live store.

## 7. CLI surface

New top-level subcommand `BootstrapSecrets(ArgsBootstrapSecrets)` in `cli_args.rs`, dispatched in `main.rs`. **First non-`serve` subcommand to load `ENC_KEYS`** — and it loads *only* `ENC_KEYS`, never the DB or the server.

Shared flags: `-c, --config-file <PATH>` (default `./config.toml`, honors `LOCAL_TEST`), `--secrets-file <PATH>` (override the container path).

```
rauthy bootstrap-secrets list                                   # (kind, id, generated_at, expires_at) — NEVER values
rauthy bootstrap-secrets get  --kind <client|api_key|user> --id <id> [--format raw|json|env]
rauthy bootstrap-secrets export [--format json|env]             # all secrets, for piping into a K8s Secret / .env
rauthy bootstrap-secrets purge [--yes]                          # delete the container after retrieval
rauthy bootstrap-secrets reseal                                 # decrypt w/ any key, re-encrypt under active key (rotation)
```

- **Output formats:** `raw` = bare value to stdout (pipe/`$(...)`); `json` = `{"kind","id","secret"}` (or array for `export`); `env` = `RAUTHY_SECRET_<KIND>_<SANITIZED_ID>=<value>`. Secrets go to **stdout only**, never through `tracing`. Diagnostics to stderr.
- **Exit codes:** `0` success; `1` not-found; `2` decrypt failure — and when the cause is a missing key the message is specific: *"key `<id>` not in loaded ENC_KEYS — was it rotated out?"* (reviewer fix); `3` file-not-found (hint: nothing was generated, or already purged/expired); `4` expired (past `expires_at`).
- **No `--with-password`** (unlike cryptr's CLI) — the only key material is `ENC_KEYS`.

**Config-load path (impl detail, reviewer-verified):** the subcommand must **not** call `RauthyConfig::init_static()` — it consumes `self`, also runs `Pow::init_bytes()` and sets the global `CONFIG` (one-shot). Add a narrow `RauthyConfig::load_enc_keys_only(config_file)` helper that parses far enough to get `[encryption].key_active` + `keys`, then `EncKeys::try_parse(key_active, keys)?.init()` once (the `OnceLock` errors on double-init).

**Doctrine:** strictly "decrypt a local file with `ENC_KEYS`", never a control channel — consistent with `cli.md` and your "readable with the CLI, since it has access to the Enc keys".

> **`USE_VAULT_CONFIG` honesty (reviewer fix).** `Vars::load` fetches config from Vault over the network when `USE_VAULT_CONFIG=true` (`rauthy_config.rs:1046`) — so naively the "offline CLI" promise breaks in that mode. Resolution: `load_enc_keys_only` accepts `ENC_KEYS` / `ENC_KEY_ACTIVE` **directly from env/flags and bypasses Vault entirely** when present (the CLI only needs the keys, not the whole config). The CLI is then truly local as long as the operator supplies `ENC_KEYS`; if they rely on Vault for keys, the CLI inherits the same Vault dependency as the server, documented as such.

## 8. K8s story (phased, honestly)

You called K8s "very cumbersome" with the distroless image; this does not pretend otherwise. The load-bearing precondition for every option is that the file lives on the **server-written data PVC** (§4).

**Phase 1 — local / host / docker-with-shell (ships first; the only thing you committed to).** The same `rauthy` binary runs `rauthy bootstrap-secrets get|export -c <config>` against the mounted data dir with `ENC_KEYS` in env. No DB, no server, no new infra. Fully delivered by the CLI.

**Phase 2 — K8s (deferred but specified).** Runtime image is `gcr.io/distroless/cc-debian12:nonroot` — no shell, `kubectl exec … sh` impossible. Proposed least-bad path, in preference order:

1. **A second image whose ENTRYPOINT is `rauthy bootstrap-secrets export`, run as a post-boot `Job`** (your "specialized CLI container" — note **no shell is strictly required** if the entrypoint is the binary). Mounts the data PVC + the existing `ENC_KEYS` Secret, emits secrets, optionally `purge`s. This is the cleanest hand-off.
   - **Must run as a `Job`, not an init-container (reviewer fix):** init-containers run *before* the main container, so on a fresh deploy the file doesn't exist yet. The file is written by the server's first boot, so retrieval must run *after* the server starts.
   - **PVC topology must be stated (reviewer fix):** an RWO data PVC can't be mounted by the Job while the server pod holds it. Supported topologies: **(a)** RWX data volume; **(b)** the server writes the container to a small dedicated RWX volume separate from the RWO data PVC; or **(c)** documented "scale server to 0, run Job". The RFC commits to documenting these explicitly rather than hand-waving "mount the PVC".
2. **Secret-projection Job:** the same image runs `export --format json`, then a ServiceAccount with `create secret` RBAC writes a native K8s `Secret` for downstream charts, then self-`purge`s. Cleanest for GitOps consumers.
3. **Manual `kubectl debug` / ephemeral container** sharing the PVC + `ENC_KEYS`, once a CLI-capable image exists.

The **init-container + memory-backed `emptyDir` shared-volume** pattern (Vault-Agent-Injector style) is **demoted to discouraged/last-resort**: it transiently writes plaintext into a pod volume readable by anyone with pod exec/read, reintroducing the very "plaintext lying around" exposure this feature exists to remove. If used, the volume must be `medium: Memory` and the consumer Job short-lived.

The distroless **server** image stays shell-less and unchanged; only an auxiliary CLI image is added, and it can lag the core mechanism. **Until that image ships, K8s users can generate secrets they cannot yet retrieve in-cluster** — stated plainly. Recommendation: ship at least the Job-entrypoint image in the same release so K8s users are never stranded.

## 9. Threat model

| Attacker holds | Outcome |
|---|---|
| **The file only** (PVC read / stolen backup, no `ENC_KEYS`) | ChaCha20-Poly1305 ciphertext + ~40-byte cleartext header (leaks `enc_key_id`, approx count/size). **No plaintext.** Tamper of the body fails decrypt. 0600 + container UID add host-level defense. This is the primary attacker the design defeats — same posture as the encrypted DB columns. |
| **`ENC_KEYS`** | By design, can decrypt the container — and the entire DB. The container is exactly as strong as `ENC_KEYS`, no stronger. Same trust boundary you accepted ("readable with the CLI, since it has access to the Enc keys"). |
| **DB only** (no `ENC_KEYS`) | Client secrets are ENC_KEYS-encrypted in-row; API-key secrets are `sha256` one-way. No plaintext, and DB access doesn't yield the container. |

**The one genuinely NEW exposure, stated up front:** for **API keys**, the DB stores only `EncValue(sha256(secret))` (one-way). The container is therefore the **only** place a generated API-key token's plaintext exists. An `ENC_KEYS` holder reading a stale container recovers a live bearer token that was previously irrecoverable even with DB + `ENC_KEYS`. This is a real widening vs supply-only API keys. Mitigations: auto-purge default-on (§6), atomic 0600, the in-plaintext `expires_at` the CLI enforces. **Open question Q5:** exclude API-key `Generate` from v1 (keep supply-only) and add it once the trade is blessed, vs. ship it gated behind the short default TTL.

**Audit (reviewer fix, honest gap):** the offline CLI cannot emit a server-side audit event — it never contacts the server, so retrieval is inherently unauditable through Rauthy's event system. The design does **not** paper over this. Partial mitigations: (a) the CLI emits a `tracing` event to stderr on every `get`/`export` (the fact of a read, never the value); (b) optionally the CLI appends to a local access log next to the container. A SIEM-grade audit of "who decrypted the file" is out of scope of an offline tool and is called out as a residual limitation.

## 10. Phased implementation plan (caniko's draft PR)

To match your minimal-complexity preference, the **first PR is deliberately small**; the five-verb CLI and folding-in the admin password are follow-ups.

**PR 1 (the shape):**
- `types.rs`: `Generate` on `ClientSecret` + `UserPassword` (additive, backward-compatible).
- `clients.rs` / `users.rs`: `Generate` branches + `&mut GeneratedSecrets` capture.
- `mod.rs`: write the atomic 0600 container at the tail of `bootstrap_additional_data()`, prod-first-boot-gated; dev path guarded.
- Config: `[bootstrap].secrets_file`, `[bootstrap].secrets_file_ttl_secs` (default 600) + one-shot purge task.
- `cli_args.rs` / `main.rs`: `bootstrap-secrets` with `get` + `export` + `purge`; `load_enc_keys_only` helper; magic-prefix + length-guard read path.
- Docs: bootstrap.md `Generate` variants, "Retrieving generated secrets", the no-reconcile + consume/expiry warnings.

**PR 2:** API-key `Generate` (the `set_api_key_secret`-skip + capture-`create()`-return refactor) — separated so the API-key plaintext-at-rest trade (Q5) is decided on its own.

**PR 3:** `list`, `reseal`, `/encryption/migrate` warn-if-container-exists, optional admin-password folding, length-override `{"generate":{"len":N}}`, the K8s CLI image + Job manifests.

Files map 1:1 to the above; the line references in this RFC are verified against `v0.35.2-6-gab9f3b7d` (post-#1585).

## 11. Open questions for @sebadob

1. **Location:** data dir (`${data_dir}/bootstrap.secrets.enc`) vs literally "next to config.toml"? Data dir handles `USE_VAULT_CONFIG` (no on-disk config) and matches the server's write ownership / PVC. There is no single `data_dir` config var today — confirm the resolution rule and the name (`[bootstrap].secrets_file` / `BOOTSTRAP_SECRETS_FILE`)?
2. **Auto-purge default:** I propose **TTL default 600s, on by default** (your "10-minute" stance), `0` to opt out. Agree? This is the lynchpin of the "not a forever-secret-on-the-PVC" answer.
3. **CLI shape/name:** `rauthy bootstrap-secrets {get,export,purge,list,reseal}` with `--format raw|json|env`. Acceptable, or flatter (`rauthy read-secrets`)? Want `export --format env` in v1 for direct K8s-Secret piping?
4. **`Generate` marker:** unit variant `"generate"` (vs null) — confirmed for clients (null already = public)? Bare marker in v1, options later?
5. **API-key `Generate`:** OK with a generated API-key token living (briefly, TTL-bounded) in the container — the only place its plaintext can exist — or keep API keys supply-only in v1 (PR 2 separates this for exactly this decision)?
6. **Rotation:** ship `reseal` + a `/encryption/migrate` warning from day one, or docs-only "consume before removing the old key"?
7. **K8s image:** second image whose **entrypoint is `rauthy bootstrap-secrets`** (smaller/safer, no shell) vs a shell-bearing variant for interactive `exec`? And are you OK committing in the RFC to shipping it (vs "pattern TBD")?
8. **Capture plumbing:** thread `&mut GeneratedSecrets` through the per-type `bootstrap()` fns, or have each return a typed `Vec` that `mod.rs` aggregates? Affects those fn signatures.
9. **Admin password:** fold the currently-logged random admin password into the container so K8s deployments can retrieve it, or leave it log-only?

## 12. Alternatives considered

1. **Admin-token / UDS (the original #1584 RFC, à la kanidm#1747).** Rejected by you explicitly — "only increase code complexity with no real advantage"; "UDS … most probably NOT happen at all." Not pursued.
2. **`cryptr` `EncKeysSealed` (Argon2id password-sealed blob).** Rejected — seals *keys*, introduces a second secret to manage/commit, contradicting "no new secrets." Plain `EncValue` under `ENC_KEYS` is minimal.
3. **Per-entry / one-file-per-secret encryption.** Rejected — multiplies 96-bit random-nonce uses + header overhead, complicates atomic write/list/purge, no benefit (one trusted CLI reads all). Single whole-file blob.
4. **base64 on disk.** Rejected for the standalone file — raw `EncValue` matches the server's own `.into_bytes()` storage; base64 stays only for the in-JSON `Encrypted(...)` variant.
5. **Streaming `EncValue::encrypt_to_file`.** Unnecessary — container is tiny; one-shot in-memory is correct and stays far under the nonce bound. (Also it does plain `fs::write` with no mode — incompatible with the atomic-0600 requirement.)
6. **HTTP retrieval endpoint on the server.** Rejected — violates the "CLI never controls an instance" doctrine, reintroduces the auth surface the admin-token RFC was killed for, needs the server running.
7. **Reconciling/idempotent bootstrap** (re-read JSON each boot, generate missing). Rejected — contradicts the first-boot-only / JWKS-gated / INSERT-only contract you reaffirmed in #1554 ("would simply be ignored").
8. **Write generated secrets back into the operator's bootstrap JSON.** Rejected — Rauthy writing into the operator's source-controlled input dir invites exactly the commit-the-secret anti-pattern this feature exists to remove.
9. **systemd-creds-compatible container** (`$CREDENTIALS_DIRECTORY`). Attractive for the local/systemd story but a different at-rest format (host/TPM, AES-GCM) that wouldn't reuse cryptr/`ENC_KEYS`. Deferred as a possible later layer on top of `export`, not v1.

---

**Residual tensions I'm not hiding** (reviewers rated the broader/un-hardened forms of this design *medium*/*low* acceptance): (a) data-dir vs your "next to config" wording (Q1); (b) the API-key plaintext-at-rest widening (§9, Q5) — the single thing most likely to give you pause, which is why PR 2 isolates it; (c) `ENC_KEY` removal can orphan the file unless consumed/`reseal`ed (§5); (d) K8s remains genuinely cumbersome and phased, gated on an image you've only mused about (Q7); (e) retrieval is unauditable by construction (§9). Auto-purge-default-on (§6) and the atomic-0600 + mandatory-magic-prefix + panic-guard hardening are the deltas that, per review, move this from "relocates the problem" to mergeable. I'd like your read on Q1/Q2/Q5/Q7 before opening the draft PR.

---

Verification artifacts (all checked against the local tree at `v0.35.2-6-gab9f3b7d`, post-#1585): JWKS gate at `migration/bootstrap/mod.rs:61/70`; API-key discard-then-overwrite at `migration/bootstrap/api_key.rs:45,68,71` and `ApiKeyEntity::create -> Result<String>` returning `{name}${secret}` at `entity/api_keys.rs:36-51`; client `confidential`/`secret_kid`/S256 logic at `migration/bootstrap/clients.rs:26,58,72`; `USE_VAULT_CONFIG` network fetch at `rauthy_config.rs:1039-1046`; dev bootstrap call site at `migration/db_migrate_dev.rs:232`; `EncValue::encrypt(&[u8])` at `cryptr-0.10.0/src/value.rs:225`.
