# Plan: identity-cli-2fa — kanidm credential CLI (posix + TOTP) → Bitwarden → Stalwart LDAP cutover

> **Recommended Codex model for orchestrating this plan set: GPT 5.5 high**
>
> Coordinating a green-field Rust crate, a cross-repo "subsume" wiring, and a
> production identity/mail cutover (which already caused one outage this session)
> is complex orchestration with a real high-risk capstone. A smaller orchestrator
> would mis-sequence the production deploy or under-protect the rollback. Not
> `max` — the orchestration is bounded by this README; `max` is reserved for the
> capstone phase itself (05).

## Scope and current state

Build a **feature-flagged Rust CLI in nix-provenance** (`crates/identity-cli`)
that provisions a kanidm account's credentials non-interactively — a posix
password (for mail/LDAP) and a TOTP (so even mail/LDAP gets 2FA via kanidm's
`password+TOTP` unix bind) — and exports the secrets to a **Bitwarden** vault via
`bw`. Structure it as a lib + thin bin so **canix can subsume the library**. Then
use it to enable the **Stalwart → kanidm-LDAP directory cutover** that has been
blocked all session.

**Why blocked / current state (read before planning execution):**
- Stalwart on `thething` runs on the **internal** principal directory (kanidm-LDAP
  cutover deferred). This is **gen 50**, the live boot default, healthy: stalwart +
  rauthy up, SMTP working. A latent `postgresql-setup` secret-permission bug that
  wiped the stalwart PG role password was fixed this session (secret owner →
  `postgres` + a fail-loud guard) — keep that fix.
- The kanidm-LDAP bind fails with `Invalid credentials (49)` because kanidm rejects
  a person's **primary** password for LDAP binding; it needs a **posix** password
  with `ldap-allow-unix-password-bind` enabled. kanidm 1.10 has **no declarative**
  way to set posix passwords — hence this CLI.
- **Crucial:** the `kanidm_client` crate (verified in the kanidm 1.10.3 source,
  `libs/client/src/lib.rs`) exposes the entire flow non-interactively:
  `auth_simple_password`,
  `idm_account_credential_update_{begin,set_password,init_totp,check_totp,backup_codes_generate,commit}`,
  `idm_person_account_unix_cred_put`, `idm_set_ldap_allow_unix_password_bind`.
  **No kanidm server patch is required.** This is a client-side admin tool.

**Environment facts every phase may need:**
- kanidm server: `auth.tartanoglu.com` (HTTPS origin `https://auth.tartanoglu.com`,
  on thething via Caddy → `127.0.0.1:8443`), LDAP gateway `[::]:3636`. On thething,
  `auth.tartanoglu.com` is loopback-pinned. baseDn = `dc=auth,dc=tartanoglu,dc=com`.
- kanidm version: 1.10.3 (`pkgs.kanidmWithSecretProvisioning_1_10`, armv8-rebuilt).
- idm_admin password: agenix secret on thething (`kanidm/idm-admin-password`,
  used today by `kanidm-seed-credentials` in canix `root/hosts/thething/server/kanidm-provision.nix`).
- The four mail accounts: `can`, `dejana` (humans), `noreply`, `stalwart-ldap`
  (service) — all already POSIX-enabled in kanidm-provision.nix `extraJsonFile`.
- Existing agenix secrets to reuse as posix passwords (so mail passwords don't
  change): `stalwart-account-can`, `stalwart-account-dejana`,
  `stalwart-account-noreply`, `stalwart-ldap-bind-password`.
- nix-provenance is a Rust workspace; `Cargo.toml` deliberately does **not** hoist
  `reqwest` (TLS-feature-union hazard) — `kanidm_client` pulls reqwest, so keep it
  member-local in the new crate.

## Phases

| Phase | File | Depends on | Touches | Parallel with | Model | Blocking? |
|---|---|---|---|---|---|---|
| 01 | [01-scaffold-identity-cli.md](01-scaffold-identity-cli.md) | — | `crates/identity-cli/*`, workspace `Cargo.toml`, `nix/{packages,checks}.nix`, `REUSE.toml`, `LICENSING.md` | — | 5.5 medium | yes (foundation) |
| 02 | [02-kanidm-provision-command.md](02-kanidm-provision-command.md) | 01 | `crates/identity-cli/src/kanidm.rs` (+ subcommand reg in `lib.rs`/`main.rs`) | 03 | 5.5 high | gates 04, 05 |
| 03 | [03-bitwarden-export.md](03-bitwarden-export.md) | 01 | `crates/identity-cli/src/bitwarden.rs` (+ subcommand reg) | 02 | 5.5 medium | gates 04 |
| 04 | [04-canix-subsume.md](04-canix-subsume.md) | 01,02,03 | **canix** `cli/Cargo.toml`, `cli/src/commands/*` | 05 | 5.5 medium | no |
| 05 | [05-stalwart-ldap-cutover.md](05-stalwart-ldap-cutover.md) | 02 | **canix** `root/hosts/thething/server/{stalwart,kanidm-provision}.nix` | 04 | 5.5 max | no (capstone) |

## Parallelism layer

- **Wave 0:** **01** alone (scaffolds the crate; everything else needs it). Resolve
  the `kanidm_client` crates.io version that speaks the 1.10.3 protocol here — it
  is the single biggest unknown and blocks 02.
- **Wave 1:** **02** and **03** in parallel — distinct modules (`kanidm.rs` vs
  `bitwarden.rs`). **Serialization point:** both register a clap subcommand in
  `src/lib.rs`/`src/main.rs`; whichever lands second must rebase that small
  registration block (flagged in both phases). Keep `provision` and `bitwarden`
  as **separate composable commands** (provision emits JSON; bitwarden consumes it)
  to keep the modules independent.
- **Wave 2:** **04** (canix subsumes the lib) and **05** (the production cutover)
  in parallel — different repos, different files. 05 is the high-risk capstone and
  needs the CLI from 02 working; it does **not** need 03 or 04.

## Whole-set acceptance criteria

- [ ] `nix build .#identity-cli` succeeds; `cargo clippy -p identity-cli -- -D warnings` clean.
- [ ] `identity-cli kanidm provision <acct> --with-totp` provisions a kanidm account so that `ldapsearch -D <acct>@auth.tartanoglu.com -w "<posixpw><totp>"` binds (currently `Invalid credentials (49)`).
- [ ] `identity-cli bitwarden upsert …` against an unlocked vault produces a login item with a working TOTP, idempotently.
- [ ] canix `cargo build` + `nix build .#canix` succeed with the subsumed commands under `canix secret kanidm …`.
- [ ] thething (gen ≥ 51) runs Stalwart on the **kanidm** directory: `noreply` SMTP-AUTH accepted, rauthy connects, `can` IMAP auth with `pw+totp`; rollback path to the gen-50 fixed-internal config documented and rehearsed.

## Global constraints

- **Production identity/mail is live (gen 50).** Every deploy/secret-read/ldapsearch
  step is permission-gated and must be surfaced to the user before running. Never
  roll back to a generation older than gen 50 (older gens carry the PG-password bug).
- Keep secrets out of logs/transcripts; pass passwords by file/stdin, never echo.
- Do not patch the kanidm server — the client API suffices.

## Reference

- Originating investigation + the full prior plan: this session's transcript and
  `~/.claude/plans/jiggly-baking-seahorse.md`.
- kanidm 1.10.3 source (client API): realised at
  `/nix/store/akp98h1lkc1icbq78rvkmsp9ndjd345g-source` (`libs/client/src/lib.rs`,
  `libs/client/src/person.rs`).
</content>
