# Phase 03 — Bitwarden export command (`bw` upsert of password + TOTP)

> **Recommended Codex model: GPT 5.5 medium**
>
> Moderate coding: shell out to the `bw` CLI, build a login-item JSON (with a
> working `login.totp` otpauth field), and make create-or-update **idempotent** by
> looking the item up first. The design content is small but real — JSON shape,
> session/unlock handling, idempotency — above pure-mechanical. `low` risks a
> non-idempotent or malformed-item implementation; `high` is overkill.

## Working tree

`/data/nvme0/can/Projects/nix-provenance`. **Depends on Phase 01** (the crate +
`bitwarden` feature). Runs in parallel with Phase 02 — distinct module
(`bitwarden.rs`). Both phases register a clap subcommand in `src/lib.rs`/`src/main.rs`;
if Phase 02 landed first, rebase that small registration block.

## Goal

`identity-cli bitwarden upsert --name <itemname> --username <spn> --password-from <file|-> [--totp <otpauth-uri>] [--folder <name>]`
creates or updates (idempotently) a Bitwarden **login** item in the user's vault
via the `bw` CLI, with the password and an optional TOTP (`login.totp` = the
`otpauth://` URI). It accepts the JSON emitted by `identity-cli kanidm provision
--json` on stdin (`--from-json -`) as a convenience so the two commands compose by
pipe. Success = after running against an unlocked vault, `bw get item <name>` shows
the password and a TOTP that generates valid codes; re-running updates in place
(no duplicate).

## Why this matters now

The plan's whole point is that humans (can, dejana) get a posix password **and** a
TOTP for 2FA mail, and those secrets must live somewhere usable — the user's
Bitwarden vault, which stores both the password and the TOTP seed (and generates
the rotating code). Without this, the human credentials from Phase 02 are only on
the terminal.

## Out of scope

- kanidm provisioning (Phase 02) — this command does not talk to kanidm; it only
  consumes already-generated secrets.
- Managing the `bw` session/login itself beyond reading `BW_SESSION` and failing
  clearly if the vault is locked. Do **not** prompt for or store the master password.
- canix (Phase 04) / deploy (Phase 05).

## Plan

1. **Preflight.** Require `bw` on PATH and an unlocked vault: read `BW_SESSION` from
   env (or `--session`); run `bw status --session …` and require `"status":"unlocked"`.
   If locked/absent, exit non-zero with a clear message ("run `bw unlock` and export
   `BW_SESSION`"). Do not auto-unlock.
2. **Input.** Accept explicit flags (`--name`, `--username`, `--password-from`,
   `--totp`, `--folder`) and/or `--from-json -` reading the Phase-02 `ProvisionResult`
   JSON from stdin (map `posix_password`→item password by default, `totp_uri`→totp;
   add a `--use-primary` switch to pick the primary password instead).
3. **Idempotent upsert.**
   - Look up an existing item: `bw list items --search <name> --session …`, match
     exactly on `name` (and folder if given).
   - Build the item JSON via `bw get template item` → set `type=1` (login),
     `name`, `login.username`, `login.password`, `login.totp` (the otpauth URI),
     `folderId` (resolve `--folder` via `bw list folders`).
   - If found: `bw edit item <id> <base64-json> --session …`. Else:
     `bw create item <base64-json> --session …`. (`bw` reads the item as base64 of
     the JSON on stdin/arg per its CLI contract — follow the installed `bw`'s
     encoding convention.)
   - `bw sync` afterward if needed.
4. **Library surface.** Logic in `src/bitwarden.rs` as a public fn
   (`upsert_login(item: BwLoginItem) -> Result<()>`) so Phase 04 can call it.
5. **Verify** against the user's unlocked vault (gated; the user runs it or grants
   go-ahead): pipe a Phase-02 `--json` provision of a throwaway account into
   `bitwarden upsert --from-json -`; confirm `bw get item <name>` shows the password
   and `bw get totp <name>` returns a 6-digit code; re-run and confirm a single item
   (no duplicate).

## Acceptance criteria

- [ ] `identity-cli bitwarden upsert` against an unlocked vault creates a login item; `bw get item <name>` shows the username + password, and `bw get totp <name>` returns a valid 6-digit code when `--totp` was supplied.
- [ ] Re-running the same `upsert` updates the existing item in place — `bw list items --search <name>` returns exactly one match.
- [ ] With a locked/absent vault the command exits non-zero with a clear "vault locked" message and writes nothing.
- [ ] `identity-cli kanidm provision <acct> --with-totp --json | identity-cli bitwarden upsert --from-json - --name <acct>` round-trips (composition works).
- [ ] No secret is written to info/stderr logs; `cargo clippy -p identity-cli -- -D warnings` clean.

## Files likely touched

- `crates/identity-cli/src/bitwarden.rs` (new)
- `crates/identity-cli/src/lib.rs`, `crates/identity-cli/src/main.rs` (subcommand registration — **shared with Phase 02**, rebase if 02 landed first)

## Pitfalls

- **`bw` item encoding (symptom: `bw create item` errors on malformed input).** The
  `bw` CLI expects the item object as base64-encoded JSON (version-dependent: arg vs
  stdin). Detect the installed `bw` version and follow its contract; start from
  `bw get template item` so required fields aren't missed.
- **Non-idempotent create (symptom: duplicate items on re-run).** Always search +
  match first; only `create` when no exact-name match exists.
- **TOTP field format (symptom: Bitwarden shows no code / wrong code).** `login.totp`
  accepts either a bare base32 secret or a full `otpauth://` URI — pass the full URI
  from Phase 02 (it carries algorithm/digits/period so non-default kanidm TOTP still
  works).
- **Leaking the session/password (symptom: `BW_SESSION` or password in logs).** Pass
  `--session` from env, never echo it; read passwords from file/stdin.

## Reference

- Plan index: [README.md](README.md). Consumes the crate from [01-scaffold-identity-cli.md](01-scaffold-identity-cli.md); composes with [02-kanidm-provision-command.md](02-kanidm-provision-command.md).
- Bitwarden CLI: `bw` (`bw --help`, `bw get template item`, `bw create/edit item`, `bw get totp`).
</content>
