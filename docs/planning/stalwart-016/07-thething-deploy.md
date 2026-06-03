# Phase 07 — Staged deploy of Stalwart 0.16.7 on thething + mail smoke + rollback

> **Recommended Codex model: GPT 5.5 high**
>
> Frontier production risk in a top-level role, but executing a *now-planned* change
> (every input — package, module, provisioning, migration runbook — was built and
> rehearsed in phases 01–06), so the job is disciplined gate-enforcement under R1, not
> novel design. `5.5 high` (not `max`): the open-ended frontier work was phase 06's
> runbook; here the model follows a rehearsed recipe with hard abort points. A weaker
> model would skip a gate or misread a smoke signal and persist an outage with `switch`.

## Working tree

`/data/nvme0/can/Projects/canix`. This is the only phase that touches the live host's
boot default. **Prerequisites (all must be green):** phase 03 (the 0.16 NixOS module),
phase 04 (registry provisioning), phase 05 (the kanidm directory object), phase 06 (the
rehearsed migration runbook with a verified backup + timed rollback). Do not start until
phase 06's dry run is clean.

## Goal

`thething` runs **Stalwart 0.16.7** on the new module + registry provisioning, with the
live mailstore migrated intact, validated by mail smoke (`noreply` SMTP-AUTH, `can`
IMAP, rauthy/forgejo/vikunja service mail), persisted only after green (`switch`), with
a rehearsed rollback to gen-50 (0.15.5) if anything fails.

## Why this matters now

This realizes the migration. It is the capstone the whole set built toward, and the one
step with all-fleet-mail-down exposure. Everything before this is reversible prep; this
phase changes the live service and (on `switch`) the boot default.

## Out of scope

- Building/redesigning the module, provisioning, or migration (phases 03/04/06) — only
  execute them here. If a gate fails, roll back and fix in the owning phase, don't patch
  live.
- Any change to thething beyond the Stalwart 0.16 cutover + the kanidm directory it needs.

## Risk profile

- **R1 — Bad activation breaks Stalwart → all fleet mail down** (services + humans).
- **R2 — Migration writes 0.16 data, then a problem surfaces** → rollback requires the
  phase-06 backup restore, not a config flip.
- **R3 — `switch` persists a broken config** as the boot default → outage survives reboot.
- **R4 — kanidm directory mis-binds on 0.16** (token/`filterLogin`/`class` vs `objectClass`)
  → auth rejected even though the service is up.
- **R5 — Datastore/PG password regression** re-bricks Stalwart's DB auth (the gen-50 bug).

## Strategy (commit/deploy ladder, with revert costs)

1. **Pre-flight + final backup (revert cost: nil).** Confirm gen 50 is the boot default;
   confirm thething healthy; run phase 06's backup and verify it (the R2 floor). Confirm
   the phase 03/04/05 closure builds for aarch64.
2. **Maintenance window opens.** Announce; stop accepting new mail if required by the
   runbook.
3. **`canix rebuild test thething`** the 0.16 config in the phase-06 paused/recovery
   posture (service up but pre-migration), per the runbook. Revert cost: re-activate
   gen-50 (`test`), datastore untouched.
4. **Run the migration** (phase 06 recipe): `migrate_v016.py` → recovery →
   `stalwart-cli apply` phase-04 registryConfig → start. Revert cost: restore backup +
   redeploy gen-50 (the rehearsed < 15-min rollback).
5. **Smoke (below). Revert cost: as step 4** until green.
6. **Only if smoke is green: `canix rebuild switch thething`** to persist (new boot
   default ≥ gen 51). Revert cost: redeploy gen-50 config (and, if 0.16 wrote data,
   restore backup).

## Rollback drill (rehearse via phase 06 before opening the window; SLA: < 15 min)

- **Before migration writes:** `canix rebuild test thething` to the gen-50-equivalent
  0.15.5 config (committed `25139d9` + canix 0.15.5 cutover). Datastore untouched →
  trivial.
- **After migration writes:** restore the phase-06 verified backup into 0.15.5, redeploy
  gen-50. This is the rehearsed restore from phase 06; do not improvise it during the
  window. Never `switch-to-configuration` a generation < 50 (re-triggers the PG-password
  wipe).

## Plan

1. Establish a route to thething (`thething-healthcheck` skill) and confirm gen 50 is
   current + boot default, services healthy.
2. Build the 0.16 closure for aarch64 (emulation), `canix rebuild test thething` dry of
   the new module to confirm it activates (in the runbook's pre-migration posture).
3. Run phase 06's migration recipe step-by-step, honoring each abort branch + the timing
   budget.
4. Smoke (all gated, read-only where possible):
   - `systemctl is-active stalwart postgresql kanidm rauthy` → active; stalwart not
     crash-looping; no auth-rejection storm in `journalctl -u stalwart`.
   - `noreply` SMTP-AUTH on :587 accepted (a test submission authenticates); rauthy/
     forgejo/vikunja service mail works.
   - `can` IMAP/submission auth works (the kanidm POSIX password via search-then-bind);
     mailbox contents present (migrated).
   - The kanidm LDAP directory: a token `ldapsearch` returns persons with `mail`; a
     per-user bind authenticates (confirms R4 clear, incl. `class`/`objectClass`).
   - Listeners :25/:587/:993 listening; Brevo relay route works (outbound test).
5. Green → `canix rebuild switch thething`; record the new generation. Not green → run
   the rollback drill (step 4 or post-migration restore).

## Acceptance criteria

- [ ] After `canix rebuild test thething` + migration: `systemctl is-active stalwart
      rauthy postgresql kanidm` = active; `journalctl -u stalwart` shows no
      auth-rejection storm / crash loop.
- [ ] `noreply` SMTP-AUTH succeeds (a real test submission authenticates) and `can` IMAP
      auth succeeds with the kanidm POSIX password (search-then-bind); migrated mailbox
      contents are present.
- [ ] The deployed Stalwart is **0.16.7** running the local module (no TOML config; JSON
      bootstrap), the kanidm directory is a 0.16 registry object, and a token `ldapsearch`
      returns `mail` for a POSIX-enabled person.
- [ ] On green, `canix rebuild switch thething` persisted (boot default ≥ gen 51); the
      rollback drill (restore backup → gen-50) was rehearsed (phase 06) and the runbook
      is attached.
- [ ] The gen-50 datastore/PG-password fix pattern is preserved in the 0.16 module (no
      regression of R5).

## Files likely touched

- canix: `root/hosts/thething/server/stalwart.nix` — final switch to the phase-03 module
  + phase-04 registryConfig (the 0.16 cutover); already largely staged by phase 04.
- canix: `flake.lock` — bump nix-provenance to the rev carrying phases 01/03/04/05.
- No nix-provenance code here (it was built in 01/03/04/05); this is execution + deploy.

## Failure modes and recoveries

- **F1 — Stalwart crash-loops / mail down after activation (R1).** Recovery: `canix
  rebuild test` gen-50 (if pre-migration) or restore backup → gen-50 (if migrated); fix
  in the owning phase; do not patch live.
- **F2 — auth rejected though service is up (R4).** Cause: token bind / `filterLogin` /
  `class` vs `objectClass` mismatch on 0.16. Recovery: re-run the phase-07 ldapsearch
  smoke to localize; adjust phase 05's `classAttr`/`filterLogin`, rebuild, re-test. If
  mail must come back now, roll back.
- **F3 — migration produced missing/partial data (R2).** Recovery: restore the phase-06
  backup → gen-50 (the rehearsed restore); re-debug the migration on a copy (phase 06),
  never re-run an unproven migrate live.
- **F4 — PG password wiped / DB auth fails (R5).** Recovery: ensure the 0.16 module
  carries the owner=postgres + empty-guard fix; reset the role password from the agenix
  secret; this must have been carried forward in phase 03.
- **F5 — `switch` persisted a broken config (R3).** Recovery: redeploy gen-50 config via
  `test` then `switch`; never roll the bootloader to a generation < 50.

## Reference

- Phases 03 (module), 04 (provisioning), 05 (directory object), 06 (migration runbook +
  backup + rollback). `thething-healthcheck` skill; `canix` CLI for rebuild/deploy.
- gen-50 rollback floor; memory `stalwart-016-config-rearchitecture`,
  `kanidm-ldap-bind-credentials`, `canix-agenix-fido2-rekey`.
</content>
