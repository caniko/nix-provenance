# Phase 04 — Declarative registry provisioning (directories + accounts)

> **Recommended Codex model: GPT 5.5 medium**
>
> Complex orchestration in an orchestrator role: translate the declarative intent
> (the kanidm LDAP directory, the mail accounts/domains, listeners/routing) into
> `stalwart-cli apply` documents and wire them through the phase-03 provisioning hook,
> replacing BOTH the 0.15 TOML settings AND the REST-based `stalwartSeedAccounts`.
> `5.5 medium` ≈ `5.4 high` and fits a known-mechanism integration phase; it's not
> frontier (phase 02 mapped `apply`, phase 03 built the hook), but it spans two repos
> and must not silently drop a live concern, so not `5.4`.

## Working tree

Primarily `/data/nvme0/can/Projects/nix-provenance` (the provisioning module/lib),
plus `/data/nvme0/can/Projects/canix` (host wiring on `thething`). **Prerequisites:**
phase 03 (`nixosModules.stalwart016` + its `registryConfig`/provisioning hook) and
phase 05 (the kanidmLdap 0.16 registry-object emitter). Note both — this phase
serialises after 03 and 05 because it consumes both.

## Goal

A declarative path that populates Stalwart 0.16's datastore registry with everything
the live host needs — the **kanidm LDAP directory** object (from phase 05), the mail
**listeners** (25/587/993) + TLS/ACME, the **Brevo relay route**, **auto-ban** limits,
the **admin fallback**, and any **accounts/domains** not covered by the kanidm
directory — via `stalwart-cli apply` documents driven by the phase-03 hook. This
replaces the 0.15 `services.stalwart.settings` TOML **and** the REST-based
`canix-toolbelt.services.stalwartSeedAccounts`.

## Why this matters now

Phase 03 gives the *mechanism* (a headless `apply`/recovery oneshot); phase 05 gives
the kanidm *directory object*. This phase supplies the actual *content* and wires it
so a `canix rebuild` converges the 0.16 registry the way TOML+seedAccounts did for
0.15. Without it, the phase-03 module boots an empty Stalwart with no mail listeners,
no directory, no accounts.

## Out of scope

- The live `thething` data migration (phase 06) — that restores *existing* mailbox
  data + auto-migrated accounts/domains/DKIM/TLS into the datastore. This phase
  provisions the *declarative config* (directory, listeners, routes) that does NOT
  auto-migrate. Coordinate the boundary in the README, but don't do the migration here.
- The actual deploy (phase 07).
- Re-deriving the kanidm directory schema (phase 05 owns the object; here you just
  place it into a `registryConfig` entry).

## Plan

1. Inventory what must be in the registry, from `notes/02-run-model.md`'s recreate-list
   and the current canix `services.stalwart.settings` (TOML): listeners 25/587/993 + TLS
   modes; ACME letsencrypt + Cloudflare DNS-01; the Brevo relay route + `BREVO_LOGIN`;
   `server.auto-ban` rates; `authentication.fallback-admin`; storage roles
   (data/blob/fts/lookup on PostgreSQL); `session.auth` mechanisms. Map each to its 0.16
   `apply`-document representation.
2. Build a small provisioning lib/module in nix-provenance that renders these into the
   `stalwart-cli apply` document format (per phase 02), parameterised so canix supplies
   host-specifics (hostnames, secret paths). Keep secrets via `LoadCredential` + `@type`
   file/env secret variants (or `%{file}%` if phase 02 proved expansion).
3. Place the **kanidm LDAP directory object** (phase 05's emitter output) into the
   registry config, and set it as the principal directory (the 0.16 equivalent of
   `storage.directory = "kanidm"` / `session.auth.directory`).
4. **Replace `stalwartSeedAccounts`.** The REST API it used is gone. Decide the account
   model: with the kanidm directory active, human/`noreply` principals come from kanidm
   over LDAP (as in the 0.15 cutover), so accounts may not need separate seeding — but
   any Stalwart-local objects the old seed created (mailbox priming, send-only
   restrictions) must be reproduced as registry objects or documented as obsolete. Wire
   `canix-toolbelt.services.stalwartSeedAccounts.enable = false` and replace its role.
5. Wire it into canix `thething`: feed the rendered `registryConfig` into the phase-03
   module on `thething`, referencing the existing agenix secrets (Brevo key, Cloudflare
   token, admin password, the kanidm token from phase 05's reconcile) by path.
6. Idempotency: re-applying must be a no-op (the phase-03 hook + `apply` are idempotent).
   Verify in the phase-03 VM test extended with the real listener/route/directory set.

## Acceptance criteria

- [ ] A nix-provenance provisioning lib/module renders valid `stalwart-cli apply`
      documents for: the three listeners (25/587/993) + TLS, ACME/Cloudflare, the Brevo
      relay route, auto-ban limits, admin fallback, storage roles, and the kanidm LDAP
      directory as the principal directory — every current `services.stalwart.settings`
      concern accounted for (or marked obsolete with a reason).
- [ ] The phase-03 VM test (extended) boots with this full `registryConfig` and shows:
      :25/:587/:993 listening, the kanidm directory present in the registry, and the
      relay route configured — all provisioned headlessly, idempotent on re-run.
- [ ] `canix-toolbelt.services.stalwartSeedAccounts` is disabled on `thething` and its
      responsibilities are either reproduced as registry objects or explicitly retired.
- [ ] canix `thething` evaluates green consuming the phase-03 module + this provisioning
      (no TOML `settings`, no REST seed), with secrets referenced by agenix path.
- [ ] No secret values appear in the Nix store or logs (secrets via LoadCredential/@type).

## Files likely touched

- nix-provenance: `nix/lib/stalwart.nix` (or a new `nix/lib/stalwart-registry.nix`) —
  `apply`-document renderers; possibly extend `nixosModules.stalwart016` options.
- canix: `root/hosts/thething/server/stalwart.nix` — switch from `services.stalwart`
  TOML usage to the phase-03 module + `registryConfig`; disable `stalwartSeedAccounts`.
- canix: possibly `root/hosts/thething/server/kanidm-provision.nix` — if the kanidm
  token reconcile (phase 05) feeds the directory's `bindSecret`.

## Pitfalls

- **Dropping a live concern.** The current TOML carries Brevo relay, ACME/Cloudflare,
  auto-ban, admin fallback, storage roles — if any is omitted from the registry config,
  mail relay / TLS / brute-force protection silently breaks after cutover. Use phase
  02's exhaustive recreate-list as the checklist; assert each is present.
- **Assuming accounts still need REST seeding.** The REST API is gone. With the kanidm
  directory, principals come over LDAP. Don't try to resurrect `stalwartSeedAccounts`;
  reproduce only the genuinely-needed local objects as registry entries.
- **`apply` document drift.** The document format is whatever phase 02 pinned — don't
  guess keys. If `apply` rejects a document, re-read phase 02's worked example, not the
  0.15 TOML keys.
- **Secret plumbing.** The kanidm token (phase 05), Brevo key, Cloudflare token, PG
  password must reach the registry via runtime secret references, not store-baked JSON.
- **Cross-repo serialisation.** This phase edits both repos and depends on 03 + 05; if
  03's `registryConfig` option shape changes, rebase. Land 03 + 05 first.

## Reference

- Contract: `notes/02-run-model.md` (apply format, recreate-list), phase 03 module
  options, phase 05 directory-object emitter.
- Current live config to preserve: canix `root/hosts/thething/server/stalwart.nix`
  (`services.stalwart.settings`, `stalwartSeedAccounts`).
- Consumed by: phase 07 (deploy).
</content>
