# Phase 06 — thething data-migration runbook (0.15.5 → 0.16.7)

> **Recommended Codex model: GPT 5.5 max**
>
> Frontier, top-level role: a one-time, partly-irreversible data migration of the
> live fleet mailstore, where a mistake loses mail or strands accounts and the
> blast radius is all-fleet-mail-down. It needs exhaustive pre-mortem, a rehearsed
> rollback, and careful reconciliation of what auto-migrates vs what must be
> recreated. This is exactly the complexity × top-level-risk coordinate that
> warrants `max` plus a full failure-mode runbook. Mediocre work here is a silent
> data-loss event, not a build failure.

## Working tree

`/data/nvme0/can/Projects/canix`. Produces a **runbook** (a doc) and any helper
scripts, plus a **dry-run** against a *copy* of thething's data. **Prerequisites:**
phase 01 (the 0.16.7 binary + stalwart-cli 1.0.0) and phase 02 (recovery mode +
`stalwart-cli apply` mechanics). Can run in parallel with 03/04/05 (different files);
the actual execution happens in phase 07.

## Goal

A rehearsed, step-by-step runbook to migrate thething's live Stalwart datastore from
0.15.5 to 0.16.7 — `migrate_v016.py` dump → `STALWART_RECOVERY_MODE` → `stalwart-cli
apply` — with a verified backup, an explicit list of what auto-migrates vs what phase
04 must recreate, and a rehearsed rollback to gen-50 (0.15.5). The runbook is proven
by a **dry run against a copy** of thething's data, not first-run on production.

## Why this matters now

0.16 cannot read 0.15's datastore in place; migration is a forced maintenance-window
operation. Only accounts/groups/lists/tenants/domains/DKIM/TLS/datastore settings
migrate automatically — **listeners, routing, rate/connection limits, spam filter,
logging do not** (phase 04 recreates those as registry config). Account names now
require a domain (`can` → `can@tartanoglu.com`); CalDAV/CardDAV paths change. Getting
this wrong during the window means mail down + potential data loss with the team
waiting. The runbook + dry run de-risk the real cutover (phase 07).

## Out of scope

- The actual production execution (phase 07 runs this runbook on thething).
- The NixOS module / provisioning code (phases 03/04) — this phase consumes their
  output but doesn't build it.
- Schema/lib edits (phase 05).

## Risk profile

- **R1 — Data loss.** A botched dump/convert/apply loses mailboxes or account state.
- **R2 — Irreversibility window.** Once 0.16 has written to the datastore, rolling back
  to 0.15.5 means restoring the pre-migration backup — if the backup is bad, there is
  no floor.
- **R3 — Silent partial migration.** Accounts/domains migrate but a listener/route/spam
  setting is missed (doesn't auto-migrate) → mail "up" but mis-delivering or rejecting.
- **R4 — Account-naming break.** `alice` → `alice@domain` rename desyncs the kanidm LDAP
  directory's `filterLogin`/login identity or the migrated local accounts.
- **R5 — Maintenance window overrun.** The dump/convert/apply takes longer than budgeted
  on the real (larger) mailstore than on the dry-run copy → extended outage.

## Strategy (rehearse, then execute in phase 07; revert costs noted)

1. **Snapshot + back up first (revert cost: nil).** Take a consistent backup of
   thething's Stalwart datastore (PostgreSQL dump + the blob/mail store) and the
   current `services.stalwart` config. Verify the backup restores into a scratch 0.15.5
   instance. This is the R2 floor.
2. **Dry-run on a copy (revert cost: nil).** Restore the backup into a scratch host/VM,
   run the full migration there (`migrate_v016.py` → recovery → `apply`), bring up
   0.16.7, and smoke it (accounts present, a test login, mailbox contents intact).
   Time it (R5). Iterate the runbook until the dry run is clean.
3. **Reconcile auto-migrate vs recreate (revert cost: nil).** Cross-check the dry-run
   0.16 registry against thething's current `services.stalwart.settings`: confirm
   accounts/domains/DKIM/TLS came over, and that phase 04's `registryConfig` supplies
   everything that didn't (listeners, Brevo route, auto-ban, admin fallback). Produce a
   final checklist.
4. **Execution recipe for phase 07 (revert cost: restore backup + redeploy gen-50).**
   The exact ordered commands for the window: stop 0.15.5 → final backup → deploy the
   0.16.7 module (phase 03/04) in a paused/recovery state → run migrate → `apply` phase
   04's config → start → smoke. With the abort/rollback branch at each step.

## Rollback drill (rehearse before phase 07; SLA: mail restored < 15 min)

- **Pre-migration:** `canix rebuild test thething` back to the gen-50-equivalent 0.15.5
  config (the committed `25139d9` + canix 0.15.5 cutover) — known-good, datastore
  untouched. This is the trivial rollback if you abort before 0.16 writes.
- **Post-migration (0.16 has written):** restore the verified PostgreSQL + blob backup
  into 0.15.5, redeploy gen-50. Practice this restore on the dry-run copy and time it;
  it must beat the 15-min SLA. Do **not** attempt to downgrade-in-place.
- Confirm gen 50 is and stays the boot default until phase 07's `switch`.

## Plan

1. Build the backup procedure (PG dump + blob/mail store + config); script it; verify a
   restore into a scratch 0.15.5 instance.
2. Obtain `migrate_v016.py` (upstream `stalwart` repo / UPGRADING `v0_16.md`); pin its
   version against the 0.16.7 we ship. Document its inputs/outputs (dump → `export.json`).
3. Dry-run the full migration on a restored copy; bring up 0.16.7 (phase 03 module +
   phase 04 registryConfig); smoke (account list, login, mailbox read). Time each step.
4. Produce the final auto-migrate-vs-recreate checklist (R3) and confirm phase 04 covers
   the recreate set.
5. Handle the account-domain rename (R4): confirm migrated account names + the kanidm
   directory `filterLogin` still authenticate the same users; document any client-facing
   change (login string, CalDAV/CardDAV paths).
6. Write the ordered execution recipe + abort branches for phase 07.

## Acceptance criteria

- [ ] A backup script produces a datastore+blob+config backup that **verifiably restores**
      into a scratch 0.15.5 Stalwart (proven, with the restore smoke output recorded).
- [ ] A **dry run** on a restored copy completes the full `migrate_v016.py` → recovery →
      `stalwart-cli apply` flow and brings up 0.16.7 with: all accounts/domains present, a
      successful test login, and intact mailbox contents — output recorded in the runbook.
- [ ] An explicit **auto-migrate vs recreate** checklist exists, and every "recreate" item
      is confirmed present in phase 04's `registryConfig`.
- [ ] The rollback (restore backup → gen-50) is **rehearsed on the dry-run copy** and
      timed under the 15-min SLA; the runbook records the exact commands.
- [ ] The runbook gives the ordered phase-07 execution recipe with an abort branch at each
      step, and the dry-run timings (R5 budget).

## Files likely touched

- canix: `docs/...` or a runbook under the host dir — e.g.
  `root/hosts/thething/server/stalwart-016-migration-runbook.md` *(new)*.
- canix: a backup/migrate helper script (`scripts/` or the host dir) *(new)*.
- No production state changes in this phase — dry-run only, on a copy.

## Failure modes and recoveries

- **F1 — backup doesn't restore (R2).** Symptom: scratch 0.15.5 won't come up from the
  backup. Cause: inconsistent dump / missing blob store. Recovery: fix the backup
  procedure and re-verify BEFORE any production migration; a migration without a proven
  backup is forbidden.
- **F2 — `migrate_v016.py` errors or drops data (R1/R3).** Symptom: convert fails, or the
  0.16 instance is missing accounts/mail. Recovery: do not proceed to production; debug
  on the copy; if upstream migration is incomplete for our data shape, surface it — a
  manual `apply` of accounts may be needed. Never run an unproven migrate on production.
- **F3 — missed recreate item (R3).** Symptom: 0.16 up but Brevo relay/spam/auto-ban/
  listener missing → mail mis-delivered or rejected. Recovery: the checklist (step 4) is
  the guard; if found post-cutover, `stalwart-cli apply` the missing registry object live.
- **F4 — login identity break (R4).** Symptom: users can't log in after migration.
  Cause: account-domain rename desync vs the kanidm `filterLogin`. Recovery: confirm on
  the dry run that `<user>` and `<user>@domain` both resolve; adjust phase 05's
  `filterLogin` if needed before phase 07.
- **F5 — window overrun (R5).** Symptom: migration runs long on production. Recovery: the
  dry-run timing sets the budget + a hard abort point; if exceeded, abort to the rollback
  (restore backup → gen-50) rather than pressing on.

## Reference

- `notes/02-run-model.md` (recovery mode + `apply` format), phase 01 binaries, phase 04
  `registryConfig` (the recreate set), phase 05 directory object.
- Upstream `migrate_v016.py` + UPGRADING `v0_16.md`; migration spec `configBreakingNotes`.
- gen-50 rollback floor; memory `stalwart-016-config-rearchitecture`,
  `kanidm-ldap-bind-credentials`.
- Executed by: phase 07.
</content>
