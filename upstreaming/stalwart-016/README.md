# Plan: Stalwart 0.15.5 → 0.16.7 full re-architecture

> **Recommended Codex model for orchestrating this plan set: GPT 5.5 high**
>
> This set coordinates a green-field package overlay, an empirical protocol-mapping
> phase, a from-scratch NixOS module that trail-blazes an unsolved upstream problem
> (NixOS/nixpkgs#511880), a new provisioning mechanism, and a live-mail data
> migration with all-fleet-mail-down risk. The capstone phases (06, 07) are
> `max`/`high`; the orchestrator that sequences them and holds the cross-repo
> dependency graph needs `5.5 high`. Not `max` — the per-phase docs carry the
> frontier risk; the orchestrator's job is sequencing + gate enforcement.

## Scope and current state

Stalwart on `thething` (the fleet's mail host) currently runs **0.15.5** on the
nixpkgs `services.stalwart` module, which renders a **TOML** config and runs
`--config=stalwart.toml`. This plan migrates the whole stack to **Stalwart 0.16.7**.

**0.16 is not a version bump — it is a re-architecture** (verified against the
v0.16.7 source, rev `68946d4f982f60a1fa54f335547be11879ed7fea`; full migration
spec in the `stalwart-016-ldap-migration` workflow output and the
`stalwart-016-config-rearchitecture` memory):

- **No TOML config.** The 0.16 binary has *no* `toml` parser (`toml` isn't even a
  dependency). The only on-disk config file is a tiny JSON **bootstrap** that
  describes the datastore connection. Everything else — listeners, directories,
  accounts, routing — lives **in the datastore**, managed over **JMAP**.
- **No REST `/api`.** Management moved to JMAP; the CLI split to its own repo
  (`stalwartlabs/cli` v1.0.0, `stalwart-cli apply`). The current
  `canix-toolbelt.services.stalwartSeedAccounts` (drives the old REST API) is dead.
- **The nixpkgs `services.stalwart` module is incompatible** (it emits TOML).
  Upstream rewrite is tracked at **NixOS/nixpkgs#511880**; nixpkgs **PR #512341**
  packages **0.16.0** (not 0.16.7), only bumps the package, and is **blocked**
  precisely because it breaks the module. So we carry a **local** package overlay
  and a **local** NixOS module.
- **The kanidm-LDAP cutover model survives.** 0.16 `bindAuthentication = true`
  (default) is search-then-bind = our `dn=token` service token + per-user POSIX
  bind. The LDAP directory is now a **registry object** (`@type=ldap`, flat
  camelCase keys). See phase 05 + the spec for the exact schema.
- **A forced one-time data migration** is required for the live mailstore
  (`migrate_v016.py` → recovery mode → `stalwart-cli apply`). Only
  accounts/groups/lists/tenants/domains/DKIM/TLS/datastore migrate automatically;
  listeners, routing, limits, spam filter, logging are recreated by hand. Account
  names now require a domain.

**Rollback baseline:** the committed nix-provenance `25139d9` + the (uncommitted)
canix-wired **0.15.5-schema** kanidm-LDAP cutover is correct *for 0.15.5* and is
the known-good fallback. `thething` **gen 50** (0.15.5, internal directory, the
PG-password fix in place) is the rollback floor — never roll back below it.

**Modularity constraint:** keep the overlay, the NixOS module, the provisioning,
and the kanidmLdap lib clean and self-contained (housed in nix-provenance, consumed
by canix) so they can be upstreamed once stable. This work partly trail-blazes
#511880 — do not entangle it with canix-specifics that would block upstreaming.

## Phases

| Phase | File | Depends on | Repo / touches | Parallel with | Model | Blocking? |
|---|---|---|---|---|---|---|
| 01 | [01-package-overlay.md](01-package-overlay.md) | — | nix-provenance (overlay/package) | — | 5.4 medium | yes (foundation) |
| 02 | [02-map-016-run-model.md](02-map-016-run-model.md) | 01 | nix-provenance (research doc) | — | 5.5 medium | yes (gates 03–07) |
| 03 | [03-nixos-016-module.md](03-nixos-016-module.md) | 02 | nix-provenance (new NixOS module) | 05, 06 | 5.5 high | gates 04, 07 |
| 04 | [04-registry-provisioning.md](04-registry-provisioning.md) | 03, 05 | nix-provenance + canix | — | 5.5 medium | gates 07 |
| 05 | [05-kanidmldap-016-schema.md](05-kanidmldap-016-schema.md) | 02 | nix-provenance (lib/module/checks) | 03, 06 | 5.4 medium | gates 04 |
| 06 | [06-thething-migration-runbook.md](06-thething-migration-runbook.md) | 01, 02 | canix (runbook + script) | 03, 04, 05 | 5.5 max | gates 07 |
| 07 | [07-thething-deploy.md](07-thething-deploy.md) | 03, 04, 05, 06 | canix (thething deploy) | — | 5.5 high | no (capstone) |

## Parallelism layer

- **Wave 0 — 01 alone.** The 0.16.7 package overlay (recompute src+cargoHash, drop
  the 0.16.0 Duration patch, build under aarch64 emulation) unblocks everything;
  nothing can be empirically validated without a 0.16.7 binary.
- **Wave 1 — 02 alone.** Empirically map the 0.16 run/provisioning model using the
  binary from 01. Its findings doc is the ground truth every later phase builds on.
- **Wave 2 — 03, 05, 06 in parallel.** Disjoint files: 03 = the new NixOS transport
  module (nix-provenance `nix/modules/...`), 05 = the kanidmLdap lib/module + checks
  (`nix/lib/stalwart.nix`, `nix/modules/ldap/stalwart.nix`), 06 = the canix
  migration runbook/script. 06 also needs the binary (01) for dry-runs.
- **Wave 3 — 04.** Registry provisioning consumes the module (03) and the kanidmLdap
  object shape (05); it touches both the new provisioning module and canix wiring,
  so it serialises after 03 + 05.
- **Wave 4 — 07.** The capstone deploy needs the module (03), provisioning (04),
  the directory object (05), and the migration runbook (06). It is the only phase
  that touches the live host's boot default; runs last, alone.

## Whole-set acceptance criteria

- [ ] `nix build` of the overridden `stalwart` (0.16.7) and `stalwart-cli` (1.0.0)
      succeeds (aarch64), with the 0.16.0 Duration patch dropped.
- [ ] A findings doc (phase 02) authoritatively describes the 0.16 bootstrap
      `config.json`, listener config, registry-provisioning path, and
      `stalwart-cli apply` input format, with empirical evidence from the binary.
- [ ] A local NixOS module brings up Stalwart 0.16.7 in a VM/test with the JSON
      bootstrap + datastore + the three mail listeners (25/587/993), no TOML.
- [ ] The kanidm LDAP directory is provisioned as a 0.16 registry object and a
      POSIX-enabled kanidm person authenticates end-to-end (search-then-bind),
      with the service token reading `mail` — no TOML directory config anywhere.
- [ ] `thething` runs 0.16.7 (gen ≥ 51): `noreply` SMTP-AUTH accepted, `can` IMAP
      auth works, mailbox data migrated intact; rollback to gen-50 (0.15.5)
      rehearsed and documented.

## Global constraints

- **Production identity/mail is live (gen 50, 0.15.5).** Every deploy / secret-read
  / migration step is permission-gated and surfaced before running. Never roll back
  below gen 50.
- **Two-step where mail-down risk exists**: `canix rebuild test thething` and smoke
  before any `switch`; `test` activations don't change the boot default.
- **Keep secrets out of logs/transcripts**; pass by file/stdin; never echo tokens.
- **Modular, no nixpkgs upstreaming yet** — but write everything so it *could* be
  upstreamed (clean module options, no canix-only assumptions baked into the
  nix-provenance pieces).

## Reference

- Migration spec + v0.16.7 source citations: the `stalwart-016-ldap-migration`
  workflow run output (`…/tasks/wkd5kkpy3.output`).
- Memory: `stalwart-016-config-rearchitecture`, `kanidm-ldap-bind-credentials`,
  `caniko-repos-prestaged-wip`, `canix-agenix-fido2-rekey`.
- Upstream: NixOS/nixpkgs#511880 (module rewrite), NixOS/nixpkgs#512341 (0.16.0
  package, blocked), stalwart UPGRADING `v0_16.md`.
</content>
