# Phase 01 — Retire the inert Vikunja `vikunja_groups` SSO claim

> **Recommended Codex model: GPT 5.5 low**
>
> A trivial, mechanical edit to two Nix files: delete a no-op claim block, drop a
> scope, and rewrite a misleading comment. Leaf-node work with no design content
> and one easy-to-check trap (don't break the existing SSO eval). A smaller/faster
> tier is fine; reserve effort for the substantive phases. Routing this higher
> would be inflation.

## Working tree

`/data/nvme0/can/Projects/nix-provenance`. Independent of all other phases —
touches only the config-only SSO tenant files. Can run in parallel with Phase 02.

## Goal

The Vikunja SSO tenant no longer emits a claim that pretends team-sync works. The
`claimMaps.vikunja_groups` block — a flat string array Vikunja's team-sync cannot
consume — is removed; SSO (`openid profile email`) still emits cleanly; and the
comment correctly states that the limitation is in **kanidm core**
(kanidm#2641), not in kanidm-provision.

## Why this matters now

`nix/lib/vikunja.nix` currently emits `claimMaps.vikunja_groups = { joinType =
"array"; valuesByGroup = {…}; }` and requests a team-sync scope. Vikunja's
team-sync requires an **array of objects** (`[{name, oidcID}]`); a flat string
array is silently ignored, so the claim is a non-functional no-op that *looks*
load-bearing. Worse, the lib comment blames kanidm-provision ("accepts only string
claim-map values"), which is false — kanidm-provision accepts array claim maps;
the real limit is kanidm core's claim-value model (kanidm#2641). Leaving this in
place is misleading to the next reader and conflicts with the decision (see
[../../../upstreaming/bridges.md](../../../upstreaming/bridges.md)) to manage
Vikunja teams via the API reconciler (Phases 02–03) and keep the claim a no-op.

This is the cleanup already identified in
[../../../upstreaming/round-0-local-changes.md](../../../upstreaming/round-0-local-changes.md).

## Out of scope

- Building the reconciler crate (Phase 02) or its module (Phase 03).
- Touching `nix/lib/stalwart.nix` or any Stalwart-016-owned file.
- Adding a *real* object-array claim — kanidm core cannot emit it; do not attempt
  a workaround here.
- Removing the SSO wiring itself — SSO must keep working.

## Plan

1. In `nix/lib/vikunja.nix`:
   - **Delete** the `claimMaps.vikunja_groups` attribute (the `joinType`/
     `valuesByGroup` block) and the `groupClaimValues` parameter that feeds it.
   - **Drop** the team-sync scope from the default `scopes` so only
     `["openid" "profile" "email"]` remain (keep the `scopeMaps.<group>` SSO grant).
   - **Rewrite** the header comment (currently claims "kanidm-provision currently
     accepts only string claim-map values"): state instead that kanidm-provision
     *does* accept array claim maps, but Vikunja team-sync needs an array of
     **objects** (`[{name, oidcID}]`) which **kanidm core** cannot emit
     (kanidm#2641); teams are therefore managed out-of-band by `vikunja-provision`
     (see the plan), and this claim is intentionally omitted.
   - Optionally leave a commented-out example of the object claim for the day
     kanidm#2641 lands, clearly labelled as not-yet-supported.
2. In `nix/modules/config-only/vikunja.nix`:
   - Fix the `scope` option default to `"openid profile email"` (drop any
     `vikunja_groups`/team-sync scope reference).
   - Fix the option `description` that says the scope "must include vikunja_groups"
     — remove that claim; it is wrong on both the scope name and the implication
     that team-sync works via the claim.
3. Run `alejandra --check flake.nix nix` (or `alejandra nix/lib/vikunja.nix
   nix/modules/config-only/vikunja.nix` then `--check`) and fix formatting.
4. Build the existing SSO eval to prove nothing broke:
   `nix build .#checks.<sys>.vikunja-module-eval`.

## Acceptance criteria

- [ ] `nix/lib/vikunja.nix` no longer contains `vikunja_groups`, `claimMaps`, or
      `groupClaimValues`; `rg -n 'vikunja_groups|claimMaps|groupClaimValues'
      nix/lib/vikunja.nix nix/modules/config-only/vikunja.nix` returns nothing
      (except an optional clearly-commented example).
- [ ] The emitted `kanidmOAuth2System` still includes the
      `scopeMaps.<group> = ["openid" "profile" "email"]` SSO grant.
- [ ] `nix build .#checks.<sys>.vikunja-module-eval` still passes (the existing
      check evaluates `systemd.services.vikunja-oidc-env.serviceConfig` — unchanged
      by this phase).
- [ ] The `nix/lib/vikunja.nix` comment references kanidm#2641 and correctly
      attributes the limit to kanidm core (not kanidm-provision).
- [ ] `alejandra --check flake.nix nix` is clean.

## Files likely touched

- `nix/lib/vikunja.nix` — delete the claim block + the `groupClaimValues` param;
  trim default scopes; rewrite the comment.
- `nix/modules/config-only/vikunja.nix` — fix the `scope` default + description.

## Pitfalls

- **Breaking the SSO eval.** The existing `vikunja-module-eval` check keys off the
  `vikunja-oidc-env` systemd unit produced by the config-only module, **not** off
  the claim. Deleting the claim must not change that unit. Symptom: `vikunja-module-eval`
  fails. Cause: you removed/renamed something the SSO env unit depends on. Recovery:
  scope the edit strictly to the claim/scope/description; re-run the eval.
- **Over-deleting scopes.** Keep `openid profile email` — Vikunja needs them for
  login. Only the team-sync scope goes.
- **Leaving a stale reference elsewhere.** `rg -n vikunja_groups` across the repo
  to catch any doc/test that still mentions the dropped claim (e.g. a README table);
  fix or note. Do **not** touch `nix/modules/test/vikunja-eval.nix` if it doesn't
  reference the claim (it currently only enables SSO).

## Reference

- Decision + rationale: [../../../upstreaming/bridges.md](../../../upstreaming/bridges.md)
  ("Vikunja team-sync", "Doesn't affect us").
- Originating cleanup note: [../../../upstreaming/round-0-local-changes.md](../../../upstreaming/round-0-local-changes.md).
- Upstream limit: kanidm#2641 (richer custom claim values; kanidm core, not kanidm-provision).
