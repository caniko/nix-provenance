# PR #1599 review — changes to apply

`feat(bootstrap): add generated bootstrap secret extraction` — sebadob left
**CHANGES_REQUESTED** with 10 inline comments (no summary text, no conversation
comments). Grouped below by theme, with the concrete change and the two items
that **supersede earlier design decisions**.

Files in play: `src/data/src/migration/bootstrap/generated_secrets.rs`,
`src/bin/src/utils/bootstrap.rs`, `book/src/config/cli.md`.

---

## Required — correctness / UX

### 1. CLI: drop all key + file flags, just parse the existing config ⚠️ supersedes RFC §7
**Comments:** `cli.md:126`, `cli.md:138`.
sebadob: passing `--enc-keys` / `--enc-key-active` via arg **or** ENV is "a very
bad thing… enc keys in clear text in shell history, visible in process
inspection." And: *"we don't even need to parse any enc keys at all… Just parse
the existing config."* Same for `--file`: *"just parse the current config. If any
custom file exists, it will be set inside it."* Plus: *"the active key is never
needed when only decrypting."*

**Change:**
- Remove `--enc-keys`, `--enc-key-active`, and `--file` from `rauthy bootstrap
  {get,purge}`.
- Load the **standard Rauthy config** the same way `serve` does; take `ENC_KEYS`
  and the container path (`bootstrap.secrets_file`) from it.
- Decrypt path must not require `ENC_KEY_ACTIVE` — cryptr selects the key by the
  per-value header id; only the key **set** is needed.
- This also dissolves the old `USE_VAULT_CONFIG` "offline CLI breaks" caveat and
  the `load_enc_keys_only` bypass: by loading config normally, the CLI inherits
  exactly the server's behavior. **Drop `load_enc_keys_only`.**

> **Supersedes** the RFC §7 design (`--secrets-file` + env/flag key loading). New
> rule: the CLI is config-driven, zero secret-bearing flags.

### 2. Use UTC everywhere, never `SystemTime`/local for the deadline
**Comment:** `generated_secrets.rs:136`.
sebadob: always work in **UTC**. On an NFS volume mounted to multiple hosts with
skewed clocks, a `SystemTime`-based deadline could make another instance delete
the container thinking it's expired. Convert to local **only** for display.

**Change:** compute the TTL deadline and all expiry comparisons as UTC
timestamps (`chrono::Utc::now().timestamp()` / the crate's existing UTC helper).
The deadline stored in the container and checked at startup/CLI is UTC seconds.

### 3. Async-safe file I/O; drop the redundant reopen-fsync
**Comments:** `generated_secrets.rs:196` (+ `:193`).
sebadob: `std::fs::rename` (and the `File::open()` below) are **blocking calls in
an async context — use the `tokio` versions.** Also: *"Not sure why you are
opening it to do another fsync? This is done automatically on drop."*

**Change:**
- `tokio::fs::rename`, `tokio::fs::File` for the atomic write/rename path.
- Remove the second `File::open(...)` + `sync_all()` reopen entirely (fsync
  happens on drop).
- `:193` — the in-write `sync_all()` is optional ("keeping it would be fine"); a
  single explicit `sync_all()` before rename is acceptable, just don't reopen.

### 4. Remove needless allocations (work with borrowed data / `Bytes`)
**Comment:** `generated_secrets.rs:175`.
sebadob: the `Vec<_>` allocation isn't needed — `EncValue::encrypt`/`decrypt`
take borrowed data, and `zeroize()` works on borrowed too; only `.to_vec()`
copies. `Bytes` usually doesn't allocate.

**Change:** drop the `.to_vec()` on both the encrypt result and the `decrypted`
path; pass `&payload` / operate on the `Bytes` directly. Keep zeroization of the
plaintext buffer (that still applies to the owned plaintext you build before
encrypting).

### 5. Temp-file naming: `<name>~`, no nanos, no PID
**Comment:** `generated_secrets.rs:335`.
sebadob: nanos precision is unnecessary; no need for PID-based conflict avoidance
— only one Rauthy process runs and bootstrapping is single-threaded. He uses the
editor convention `<original name>~`.

**Change:** write to `${path}~` (sibling temp), `tokio::fs::rename` over the
target. Drop the `UNIX_EPOCH … as_nanos()` + PID temp-name logic.

---

## Recommended — clear maintainer preference, simplifies ⚠️ supersedes header design

### 6. Replace the manual `MAGIC\nVERSION\ndeadline\n` header with an encrypted struct
**Comment:** `generated_secrets.rs:300`. sebadob is *"fine with both versions"* but
his preference is explicit and it simplifies our code:

> *"You could just have a wrapping struct that has a field for the `exp`/`deadline`
> and then `Vec<_>`s for the secrets. Encrypt the whole thing and write it to the
> file without the manual header handling. cryptr uses AEAD (ChaCha20Poly1305) —
> if decryption succeeds, the data is valid, so you don't need a magic str or
> versioning."*

**Change (recommended — adopt it):**
- Define one serde struct, e.g. `BootstrapSecretContainer { version: u8, deadline:
  i64 /*UTC*/, secrets: Vec<GeneratedSecret> }`.
- `serde_json::to_vec` → `EncValue::encrypt(&bytes)` → write raw `EncValue` bytes.
  **No external magic/version/deadline header.**
- Read = `EncValue::try_from(bytes)?.decrypt()?` → `serde_json::from_slice`. AEAD
  guarantees integrity; a wrong/garbage file fails decryption cleanly.
- Keep a `version` field **inside** the struct for schema evolution (cheap, future-proof).

> **Supersedes two earlier decisions:**
> - the magic+version cleartext prefix from the RFC §4, **and**
> - the "stamp the deadline in the *cleartext* header so startup purge can check
>   without decrypting" answer I gave sebadob last round. With the deadline inside
>   the encrypted struct, **startup purge now decrypts to read the deadline** —
>   which is fine and cheap: the server always has `ENC_KEYS`, and the file is tiny.

> **Caveat to preserve:** without the magic prefix you still must **length-guard
> before `EncValue::try_from`** and treat any decrypt/parse failure as "no/invalid
> container" — cryptr's header parse can panic on a too-short/truncated buffer.
> Add a minimal length+`Result` guard so a half-written or empty file can't panic
> the server or CLI. (If keeping the manual header instead: switch it to
> fixed-width bytes with explicit **LE/BE** integers, never native byte order —
> per his note — but the struct approach avoids this entirely.)

---

## Nits — cheap, just do them

### 7. `write!` instead of `format!` in the env output
**Comment:** `bootstrap.rs:153`. Replace `out.push_str(&format!("{}={}\n", …))`
with `write!(out, "{}={}\n", entry.env_name(), entry.value)?` (use
`std::fmt::Write`) — no extra `String` allocation. ("Not a big deal for a CLI,"
but trivial.)

### 8. `ErrorResponse` shorthand
**Comment:** `generated_secrets.rs:344`. sebadob: *"start adding these shorthands
to the `ErrorResponse impl` directly… I have that on the TODO anyway."* Move the
local `internal(msg)` helper onto `impl ErrorResponse` (e.g.
`ErrorResponse::internal(msg)`). Low priority; if it risks a wider refactor,
mention you're adding just `internal` (+ maybe the ones you use) and leave the
rest to his TODO so it doesn't balloon the PR.

---

## Suggested commit grouping

1. `cli: drop key/file flags, load from config` (items 1) — the load-bearing UX change.
2. `bootstrap: UTC deadlines` (2).
3. `bootstrap: async fs + atomic temp~ rename, no reopen-fsync` (3, 5).
4. `bootstrap: encrypted container struct, drop manual header` (6) — keep the length guard.
5. `bootstrap: avoid needless allocations` (4).
6. `bootstrap: write! + ErrorResponse::internal + nits` (7, 8).

Then reply on the PR confirming each point (esp. that you adopted the encrypted-
struct form and the config-only CLI), push, and re-request review from @sebadob.
Run `just fmt` + `just pre-pr-checks` before pushing.

## Decisions to confirm in your PR reply
- **Header:** confirm you're taking his encrypted-struct form (recommended) — say
  so explicitly since he offered both.
- **`ErrorResponse::internal`:** ask whether to add just the shorthands you use
  now, or hold for his broader impl pass, to keep PR 1 tight.
