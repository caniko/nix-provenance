# Phase 02 — kanidm credential provisioning command (posix password + TOTP + backup codes)

> **Recommended Codex model: GPT 5.5 high**
>
> Complex coding with real design content: driving kanidm's stateful
> credential-update **session** (begin → set-password → init-totp → read the
> server-generated secret → compute & check the TOTP code → backup codes → commit),
> correct error handling against a live IdP, and secret hygiene. The session
> state-machine and the TOTP confirm step are easy to get subtly wrong (e.g.
> committing before the TOTP is checked, or mis-deriving the `otpauth` URI). Not
> `max` — it's a single bounded command, not a multi-system orchestration — but
> `medium` would likely ship a flow that half-works against the real server.

## Working tree

`/data/nvme0/can/Projects/nix-provenance`. **Depends on Phase 01** — the
`identity-cli` crate, `kanidm_client`/`kanidm_proto`/`totp-rs` deps, and the
`kanidm` feature must already build. Runs in parallel with Phase 03; both register
a clap subcommand in `src/lib.rs`/`src/main.rs` — if 03 lands first, rebase that
small registration block before editing it.

## Goal

`identity-cli kanidm provision <account> [--with-totp] [--posix-from <file>] [--primary-from <file>] [--json]`
authenticates to kanidm as `idm_admin` and provisions the account: sets a primary
password and (with `--with-totp`) enrolls a TOTP + backup codes via a
credential-update session, and sets the **posix password** used for LDAP/mail; and
`identity-cli kanidm set-ldap-unix-bind <true|false>` toggles the domain flag.
Success = a throwaway kanidm person provisioned this way can LDAP-bind with
`<posixpw>` (service mode) or `<posixpw><totp>` (2FA mode).

## Why this matters now

This command is what unblocks the entire Stalwart LDAP cutover (Phase 05): kanidm
rejects primary-password LDAP binds (`ldap_bind: Invalid credentials (49)` observed
this session), so each mail account needs a **posix** password set non-interactively
— which kanidm-provision and `kanidmd scripting` cannot do, but the `kanidm_client`
credential API can. Adding a TOTP lets even mail/LDAP be 2FA (kanidm's unix bind
accepts `password+TOTP`).

## Out of scope

- Bitwarden export (Phase 03) — `provision` only emits the secrets (to stdout/JSON);
  a separate `bitwarden` command consumes them.
- Provisioning the **real** mail accounts or any deploy (Phase 05). Test only
  against a throwaway kanidm person.
- canix changes (Phase 04).

## Plan

1. **Client + auth.** Build a `kanidm_client::KanidmClient` for
   `https://auth.tartanoglu.com` (allow `--url` override; on thething it is
   loopback-pinned). Authenticate with `auth_simple_password("idm_admin", <pw>)`
   where the password comes from `--idm-admin-password-file` / `KANIDM_IDM_ADMIN_PASSWORD_FILE`
   (never an argv literal).
2. **`provision <account>`:**
   1. `idm_account_credential_update_begin(account)` → a `CredentialUpdateSessionToken`.
   2. `idm_account_credential_update_set_password(&token, primary_pw)` — `primary_pw`
      from `--primary-from` or generated (CSPRNG, ~24 alnum).
   3. If `--with-totp`:
      - `idm_account_credential_update_init_totp(&token)`.
      - `idm_account_credential_update_status(&token)` → read the `TotpSecret` from
        the `MfaRegStateStatus::TotpCheck(secret)` state.
      - Derive the current 6-digit code from that secret with `totp-rs` (or
        `kanidm_proto`'s `Totp`), matching kanidm's step/algorithm
        (`TOTP_DEFAULT_STEP`, SHA-256 unless the secret says otherwise).
      - `idm_account_credential_update_check_totp(&token, code)`. Retry once across a
        step boundary if it returns a "wrong code" status.
      - `idm_account_credential_update_backup_codes_generate(&token)` → capture codes.
   4. `idm_account_credential_update_commit(&token)`.
   5. `idm_person_account_unix_cred_put(account, posix_pw)` — `posix_pw` from
      `--posix-from` or generated. (This is the LDAP/mail credential.)
   6. Emit a result: primary pw, posix pw, TOTP `otpauth://totp/...?secret=...` URI
      (build from the `TotpSecret`), backup codes. `--json` for machine consumption
      (Phase 03 reads it); default human format. **Never** log secrets at info level.
3. **`set-ldap-unix-bind <bool>`** → `idm_set_ldap_allow_unix_password_bind(bool)`.
4. **Library surface.** Put the logic in `src/kanidm.rs` as public async fns
   (`provision(...) -> ProvisionResult`, `set_ldap_unix_bind(...)`) returning typed
   results; `main.rs` only parses args and prints. (Phase 04 calls these fns.)
5. **Verify against a throwaway person** on the live kanidm (gated; ask the user to
   run, or run with their go-ahead). Create `testacct` (or reuse an existing
   non-mail person), `provision testacct --with-totp`, then from thething:
   `nix shell nixpkgs#openldap -c ldapsearch -x -H ldaps://auth.tartanoglu.com:3636 -D "testacct@auth.tartanoglu.com" -w "<posixpw><totp>" -b "dc=auth,dc=tartanoglu,dc=com" "(name=testacct)" name` → must bind (requires `set-ldap-unix-bind true` first). Clean up the throwaway after.

## Acceptance criteria

- [ ] `identity-cli kanidm provision <acct> --with-totp --json` emits valid JSON with non-empty `primary_password`, `posix_password`, `totp_uri` (a parseable `otpauth://totp/...secret=...`), and `backup_codes`.
- [ ] After `set-ldap-unix-bind true` + provisioning, `ldapsearch -D <acct>@auth.tartanoglu.com -w "<posixpw><totp>"` binds and returns the entry (was `Invalid credentials (49)`).
- [ ] Provisioning **without** `--with-totp` yields an account that binds with `-w "<posixpw>"` alone (service-account mode).
- [ ] No secret value appears in the process's info/stderr logging (only in the explicit result output / `--json`).
- [ ] `cargo clippy -p identity-cli -- -D warnings` clean.

## Files likely touched

- `crates/identity-cli/src/kanidm.rs` (new — the command logic + library fns)
- `crates/identity-cli/src/lib.rs`, `crates/identity-cli/src/main.rs` (subcommand registration — **shared with Phase 03**, rebase if 03 landed first)
- `crates/identity-cli/Cargo.toml` only if a dep feature needs enabling

## Pitfalls

- **Committing before the TOTP check (symptom: account ends with no/invalid TOTP).**
  The session must `check_totp` (accepted) *before* `commit`. If `check_totp`
  returns a retry status, recompute across the step boundary; don't commit on failure.
- **TOTP algorithm/step mismatch (symptom: `check_totp` always rejects the code).**
  Derive the code with the same algorithm + step kanidm used to generate the secret
  (read it from the `TotpSecret`, don't assume SHA-1/30s). kanidm defaults are in
  `credential/totp.rs` (`TOTP_DEFAULT_STEP`).
- **Admin-on-behalf permissions (symptom: `begin` or `unix_cred_put` returns 403).**
  `idm_admin` must be allowed to start a credential update for the target person and
  to set its unix cred; the persons are in the `staff`/mail groups. If denied, check
  the kanidm default ACPs rather than escalating to `admin`.
- **unix_cred_put on a non-posix account (symptom: error about missing posix class).**
  The four mail accounts are already `enableUnix`; a throwaway test person must be
  posix-extended first (`enableUnix` + gidNumber via kanidm-provision or `kanidm person posix set`).
- **Leaking secrets into the transcript (symptom: password in chat/logs).** Read
  password files, pass via the client API as values; print the result block only to
  stdout, and prefer `--json` piped to the consumer.

## Reference

- Plan index: [README.md](README.md). Consumes the crate from [01-scaffold-identity-cli.md](01-scaffold-identity-cli.md); feeds [03-bitwarden-export.md](03-bitwarden-export.md) and [05-stalwart-ldap-cutover.md](05-stalwart-ldap-cutover.md).
- Confirmed client methods (kanidm 1.10.3): `/nix/store/akp98h1lkc1icbq78rvkmsp9ndjd345g-source/libs/client/src/lib.rs` lines ~1257 (`auth_simple_password`), 1744–1949 (`credential_update_*`), 2034 (`idm_set_ldap_allow_unix_password_bind`); `libs/client/src/person.rs:198` (`idm_person_account_unix_cred_put`).
- TOTP generation flow in kanidm: `server/lib/src/idm/credupdatesession.rs` (`Totp::generate_secure`, `MfaRegState::TotpInit`, `credential_primary_check_totp`).
</content>
