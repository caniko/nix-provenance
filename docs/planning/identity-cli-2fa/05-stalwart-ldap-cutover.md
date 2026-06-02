# Phase 05 — Stalwart → kanidm-LDAP directory cutover (production)

> **Recommended Codex model: GPT 5.5 max**
>
> Frontier-risk capstone: a production deploy to `thething`, the IdP + mail host
> for the whole fleet. The *same* cutover already caused a mail/identity outage
> this session (a latent PG-password bug surfaced; LDAP SMTP-AUTH was rejected). It
> requires staged verification, live secret/ldap probes, correct ordering, and a
> rehearsed rollback to a non-buggy generation. Mediocre work ships a subtle
> mail-auth outage. This is exactly the complexity × top-level-risk coordinate that
> warrants `max` plus a full pre-mortem.

## Working tree

`/data/nvme0/can/Projects/canix`. **Depends on Phase 02** (the `identity-cli kanidm
provision` command must work; built via Phase 01). Does **not** need Phases 03/04.
Runs in parallel with Phase 04 (different files/repo). canix's working tree carries
unrelated in-flight changes — touch only `root/hosts/thething/server/{stalwart,kanidm-provision}.nix`.

## Goal

Stalwart on `thething` authenticates against the **kanidm LDAP** directory instead
of its internal one: the four accounts (`can`, `dejana`, `noreply`, `stalwart-ldap`)
have posix passwords (humans also TOTP) provisioned via the Phase-02 CLI,
`ldap-allow-unix-password-bind` is on, `stalwart.nix` re-enables `kanidmLdap`, and a
deployed `thething` (test → switch) passes mail smoke: `noreply` SMTP-AUTH accepted,
rauthy connects, `can` IMAP auth works (`pw+totp`). Rollback target is the current
**gen 50** fixed-internal config.

## Why this matters now

This realizes the original goal — unified kanidm identity for mail. It is the
capstone the CLI was built for. Current blocker (observed this session):
`ldap_bind: Invalid credentials (49)` for `stalwart-ldap`, because no posix password
was set; once Phase 02 sets posix passwords + enables unix-pw-bind, the bind works.

## Out of scope

- Building the CLI (Phases 01–02) or canix subsumption (Phase 04).
- Any change to `thething` beyond the Stalwart directory + kanidm-seed ordering.
- Touching the gen-50 PG-password fix (`stalwart-pg-password` owner = `postgres` +
  the `postgresql-setup` empty-password guard) — **keep it**.

## Risk profile

- R1 — A bad activation breaks Stalwart → **all fleet mail down** (services + humans).
- R2 — Rolling back to a generation **older than gen 50** re-triggers the
  PG-password-wipe bug and bricks Stalwart's DB auth.
- R3 — kanidm LDAP user-bind needs `pw+totp` for humans; a mail client that only
  sent `pw` would fail IMAP after cutover (UX, not outage).
- R4 — `test`-mode activation does not change the boot default; a reboot before
  `switch` reverts — fine, but a `switch` to a broken config persists the outage.
- R5 — Provisioning order: if `set-ldap-unix-bind true` or the posix passwords are
  not in place before Stalwart restarts on the kanidm directory, every SMTP/IMAP
  auth is rejected (`auth-not-allowed`).

## Strategy (commit/deploy ladder, with revert costs)

1. **Provision first, deploy nothing.** Run the Phase-02 CLI (gated; user go-ahead)
   to set posix passwords for all four accounts (reuse the existing
   `stalwart-account-{can,dejana,noreply}` / `stalwart-ldap-bind-password` values so
   mail passwords don't change), `--with-totp` for `can`/`dejana`, and
   `set-ldap-unix-bind true`. Revert cost: nil (no deploy yet).
2. **Prove the bind before touching mail.** From thething:
   `ldapsearch -x -H ldaps://auth.tartanoglu.com:3636 -D "stalwart-ldap@auth.tartanoglu.com" -w "<stalwart-ldap posix pw>" -b "dc=auth,dc=tartanoglu,dc=com" "(class=person)" name mail`
   → must succeed and return persons (currently error 49). Also bind `noreply` with
   its posix pw. **Gate the whole cutover on this passing.** Revert cost: nil.
3. **Re-enable the cutover in Nix.** Edit `stalwart.nix` (reverse this session's
   deferral, keep the PG fix): `kanidmLdap.enable = true`;
   `bindDn = "stalwart-ldap@auth.tartanoglu.com"`; bind secret =
   `stalwart-ldap-bind-password`; `session.auth.directory = "'kanidm'"`; remove the
   explicit `storage.directory = "internal"` (the module sets `"kanidm"`);
   `stalwartSeedAccounts.enable = false`. Order Stalwart after kanidm seeding
   (`systemd.services.stalwart.after`/`wants += "kanidm-seed-credentials.service"`).
   Revert cost: a one-line `enable = false` + redeploy.
4. **Build + `canix rebuild test thething`** (activate, no boot-default change).
   Smoke (below). Revert cost: re-activate gen 50 or redeploy with
   `kanidmLdap.enable = false`.
5. **Only if smoke is green: `canix rebuild switch thething`** to persist. Revert
   cost: redeploy `kanidmLdap.enable = false` (back to gen-50-equivalent).

## Rollback drill (rehearse before step 4; SLA: service restored < 3 min)

- Fast path (no reboot): redeploy the fixed-internal config —
  set `kanidmLdap.enable = false` (+ restore `storage.directory = "internal"`,
  `session.auth.directory = "'internal'"`, `stalwartSeedAccounts.enable = true`),
  rebuild, `canix rebuild test thething`. This is exactly the gen-50 config; it is
  known-good this session.
- Do **not** `switch-to-configuration` an older generation: gen ≤ 49 re-wipes the
  Stalwart PG password (R2). gen 50 is the floor.

## Plan

1. Phase-02 provisioning of the four accounts + `set-ldap-unix-bind true` (gated).
2. ldapsearch bind proof for `stalwart-ldap` and `noreply` (step 2 above) — **gate**.
3. `stalwart.nix` edits (step 3 above) + the kanidm-seed ordering.
4. Build the crossbow closure with emulation
   (`nix build .#nixosConfigurations.thething-crossbow.config.system.build.toplevel --extra-platforms aarch64-linux`),
   then `canix rebuild test thething`.
5. Smoke (all gated, read-only where possible):
   - `systemctl is-active stalwart rauthy kanidm postgresql` → all active; stalwart
     not crash-looping; no `auth-not-allowed` in `journalctl -u stalwart`.
   - `noreply` SMTP-AUTH on `:587` accepted (rauthy log shows
     `Successfully connected via STARTTLS`).
   - `can` IMAP/submission auth with `pw+totp`.
6. Green → `canix rebuild switch thething`; record the new generation. Not green →
   run the rollback drill.

## Acceptance criteria

- [ ] `ldapsearch` as `stalwart-ldap@auth.tartanoglu.com` (posix pw) binds and returns persons with `mail` attributes (was `Invalid credentials (49)`).
- [ ] After `canix rebuild test thething`: `systemctl is-active stalwart rauthy` = `active`; `journalctl -u stalwart` for the boot shows **no** `auth-not-allowed`; rauthy log shows `Successfully connected via STARTTLS`.
- [ ] `noreply` SMTP-AUTH succeeds (a test submission authenticates) and `can` IMAP auth succeeds with `password+TOTP`.
- [ ] `services.stalwart.settings.storage.directory == "kanidm"` and `directory.kanidm` present in the deployed config; the gen-50 PG-password fix (`stalwart-pg-password` owner `postgres` + guard) is still in place.
- [ ] On green, `canix rebuild switch thething` persisted (new boot default ≥ gen 51); the rollback drill was rehearsed and documented.

## Files likely touched

- canix `root/hosts/thething/server/stalwart.nix` (re-enable `kanidmLdap`, auth/storage directory, seed-accounts, ordering)
- canix `root/hosts/thething/server/kanidm-provision.nix` (only if the kanidm-seed ordering / posix-enable needs adjustment)

## Pitfalls / Failure modes and recoveries

- **F1 — `auth-not-allowed` after cutover (cause: posix passwords / unix-pw-bind not
  set before Stalwart restarted, R5).** Symptom: stalwart up but every SMTP/IMAP auth
  rejected; rauthy crash-loops on SMTP. Recovery: confirm step-2 ldapsearch still
  binds; if not, re-run Phase-02 provisioning + `set-ldap-unix-bind true`, restart
  stalwart; if mail must come back now, run the rollback drill.
- **F2 — `Invalid credentials (49)` on the bind (cause: posix pw mismatch / wrong
  bindDn / unix-pw-bind off).** Recovery: re-provision the bind account's posix pw to
  the exact `stalwart-ldap-bind-password` value; verify `set-ldap-unix-bind true`;
  confirm `bindDn = "stalwart-ldap@auth.tartanoglu.com"`.
- **F3 — human IMAP fails (cause: client sent `pw` only, not `pw+totp`, R3).**
  Recovery: this is expected with 2FA; the human appends the Bitwarden TOTP to the
  stored password. If unacceptable, provision that human **without** `--with-totp`
  (posix pw only) as a documented exception.
- **F4 — Stalwart PG error / crash-loop returns (cause: a deploy re-ran
  `postgresql-setup` with the secret unreadable).** Recovery: the gen-50 fix
  (`owner = "postgres"` + guard) prevents the silent wipe; if it recurs, the role
  password was cleared — reset it from the `stalwart-pg-password` secret and ensure
  the guard/owner fix is present in the deployed config.
- **F5 — reboot reverts the test activation (R4).** Expected in `test` mode; persist
  with `switch` only after green smoke.

## Reference

- Plan index: [README.md](README.md). Needs the CLI from [02-kanidm-provision-command.md](02-kanidm-provision-command.md).
- This session's investigation: the `Invalid credentials (49)` bind failure, the
  `auth-not-allowed` SMTP rejection, the PG-password-wipe root cause + fix, and the
  gen-50 recovery. Memory: `kanidm-ldap-bind-credentials`, `canix-agenix-fido2-rekey`.
- The exact `stalwart.nix` edits were already written and then reverted this session
  (git history / working tree of `root/hosts/thething/server/stalwart.nix`).
</content>
