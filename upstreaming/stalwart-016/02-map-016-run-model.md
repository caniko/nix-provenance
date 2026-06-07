# Phase 02 — Empirically map the Stalwart 0.16 run + provisioning model

> **Recommended Codex model: GPT 5.5 medium**
>
> Complex, partly-ambiguous research+synthesis: the goal is to turn "0.16 keeps
> config in a JMAP-managed datastore" into a precise, runnable spec (bootstrap file
> shape, listener config location, how to provision the registry non-interactively,
> `stalwart-cli apply` input format). It's sub-agent/research in role but novel
> enough that `5.5 medium` (≈ `5.4 high`, better on ambiguity) earns its keep: a
> weaker model would produce a plausible-but-wrong run model, and phases 03/04/06
> would then build a NixOS module on sand. Not `high` — it's mapping an existing
> system, not designing one.

## Working tree

`/data/nvme0/can/Projects/nix-provenance`. Output is a findings doc, not code.
**Prerequisite:** phase 01 must be done — you need the built 0.16.7 `stalwart` +
`stalwart-cli` binaries (and the `01-binary-introspection.md` note) to run things.

## Goal

A definitive, evidence-backed findings doc that lets phase 03 write a NixOS module
and phase 04/06 provision + migrate **without further reverse-engineering**. It must
answer, with command output or source citations: what the on-disk bootstrap file
contains; how/where listeners (SMTP 25, submission 587, IMAPS 993) and TLS/ACME are
configured in 0.16; how to bring up a fresh instance and provision its registry
**non-interactively**; and the exact input format `stalwart-cli apply` consumes.

## Why this matters now

The workflow established the *shape* of the change (no TOML; JSON bootstrap +
JMAP-managed datastore; REST `/api` gone; LDAP directory is a registry object) and
the **LDAP directory schema** precisely. It did **not** map the rest of the run
model: the bootstrap `config.json` contents, listener configuration, the
fresh-instance provisioning path, recovery mode mechanics, and the `stalwart-cli
apply` document format. Those are exactly what a NixOS module and a migration runbook
need. Guessing here is the single biggest risk to phases 03/04/06.

## Out of scope

- Writing the NixOS module (phase 03) or any canix wiring.
- Designing the kanidmLdap object (phase 05 owns it; the directory *schema* is
  already known from the workflow spec — don't re-derive it, just confirm how a
  directory object gets *into* the registry).
- Performing any migration of real data.

## Plan

1. Stand up a **throwaway 0.16.7 instance** locally (container/VM/tmpdir) from the
   phase-01 binary. Find the minimal `-c <config>` bootstrap file that boots it
   (start from the source: `crates/store/src/registry/local.rs` parses the file as
   `serde_json::from_str::<DataStore>`; `crates/common/src/manager/boot.rs` wires
   `CONFIG_PATH` → `RegistryStore::init` → `Bootstrap::new`). Record the **exact JSON**
   that boots against a chosen datastore backend (RocksDB/sqlite/postgres — note which
   thething uses today; thething uses PostgreSQL).
2. Determine **recovery mode**: what `STALWART_RECOVERY_MODE=1` + `STALWART_RECOVERY_ADMIN`
   do, and how they bootstrap an admin to push registry config. Capture the exact env
   + the resulting admin credential flow.
3. Map **registry provisioning non-interactively**. Determine the supported path(s):
   - `stalwart-cli apply --file <doc>` — capture the **document format** (JSON? what
     top-level keys? how are listeners / directories / accounts / domains expressed?).
     Get `stalwart-cli apply --help` and, if needed, read the CLI source
     (`stalwartlabs/cli`) for the schema it posts.
   - Whether there is a first-boot "import a config blob" path that a NixOS activation
     script could drive headlessly (vs. requiring the web UI).
4. Map **listeners + TLS** in 0.16: where SMTP/submission/IMAPS listeners and the
   ACME/cert config live now (registry objects? bootstrap?). Confirm against a running
   instance: get :25/:587/:993 listening via a pushed registry config.
5. Map what **must be recreated** post-migration (the workflow noted listeners,
   routing, rate/connection limits, spam filter, logging/telemetry don't auto-migrate)
   — enumerate each with its 0.16 registry representation so phase 04/06 can recreate
   them. Cross-check thething's current `services.stalwart.settings` (the TOML) against
   this list so nothing live is dropped.
6. Confirm the **`%{file:...}%` / `%{env:...}%` macro** question: does macro expansion
   run inside registry objects (so secrets can be referenced), or must secrets use the
   native `@type` `file`/`environmentVariable` secret variants? This decides how
   phase 04 feeds the kanidm token + Brevo key + PG password.
7. Write `upstreaming/stalwart-016/notes/02-run-model.md` capturing all of the above
   with commands/output/citations. This is the contract phases 03/04/06 consume.

## Acceptance criteria

- [ ] `notes/02-run-model.md` contains a **minimal working bootstrap `config.json`**
      that boots 0.16.7 against thething's datastore backend (PostgreSQL), proven by a
      local run (paste the boot log showing it came up).
- [ ] It documents recovery mode (`STALWART_RECOVERY_MODE`/`STALWART_RECOVERY_ADMIN`)
      with the exact mechanics and the resulting admin/credential flow.
- [ ] It documents a **non-interactive** registry-provisioning path (e.g.
      `stalwart-cli apply --file …`) with the **document format** and a worked example
      that creates a listener + a directory + an account, proven against the local
      instance (paste the apply output + a query showing it took).
- [ ] It documents how SMTP 25 / submission 587 / IMAPS 993 listeners + TLS/ACME are
      represented in 0.16, with :25/:587/:993 confirmed listening on the test instance.
- [ ] It enumerates every current thething `services.stalwart.settings` concern
      (listeners, Brevo relay/route, auto-ban limits, ACME/Cloudflare, admin fallback,
      storage roles) mapped to its 0.16 registry representation (or marked "n/a in 0.16").
- [ ] It resolves the secret-macro question (macro expansion vs `@type` file/env) with
      evidence.

## Files likely touched

- `upstreaming/stalwart-016/notes/02-run-model.md` *(new)* — the findings contract.
- Scratch only otherwise (throwaway instance dirs); no repo code changes.

## Pitfalls

- **Assuming the web UI is the only provisioning path.** A NixOS module needs a
  *headless* path. If `stalwart-cli apply` + recovery mode can't fully provision a
  fresh instance non-interactively, that is a critical finding — surface it loudly;
  phase 03/04 design depends on it.
- **Datastore backend drift.** thething uses PostgreSQL today. Validate the bootstrap
  against PostgreSQL, not just the default embedded store, or phase 03's module will
  boot in dev and fail on the real backend.
- **Macro assumptions.** Do not assume `%{file:...}%` works inside registry objects;
  the workflow flagged it unverified. Prove it or use the native `@type` secret enum.
- **Confusing "settings that migrate" with "settings to recreate".** `migrate_v016.py`
  carries accounts/domains/DKIM/TLS/datastore — NOT listeners/routing/limits/spam.
  Get the recreate-list exhaustive here so phase 06 doesn't discover a missing listener
  during the maintenance window.

## Reference

- Migration spec (`schema`, `configBreakingNotes`, `consumptionRecommendation`):
  `stalwart-016-ldap-migration` workflow output (`…/tasks/wkd5kkpy3.output`).
- Source anchors: `crates/store/src/registry/local.rs:71-88`,
  `crates/common/src/manager/boot.rs:67/124-128`,
  `crates/directory/src/core/config.rs:18-40` (directories read from the registry).
- Phase 01's `notes/01-binary-introspection.md`. Upstream `stalwartlabs/cli`,
  stalwart UPGRADING `v0_16.md`.
- Consumed by: phases 03 (module), 04 (provisioning), 06 (migration).
</content>
