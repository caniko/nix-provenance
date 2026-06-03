# Plan: `vikunja-provision` — declarative Vikunja team/membership reconciler

> **Recommended Codex model for orchestrating this plan set: GPT 5.5 medium**
>
> Three well-scoped phases mirroring an existing in-repo template
> (`rauthy-provision` / `immich.nix`), with one substantive coding phase and a
> mechanical-but-broad Nix-integration phase. No frontier risk and nothing
> destructive — the orchestrator's job is sequencing (02 → 03) and gate
> enforcement, not novel design. `5.5 medium` holds that bar; `high`/`max` would
> be inflation against a plan whose hard parts are already pinned by the verified
> API contract and the sibling crate.

## Scope and current state

Vikunja SSO already works (`nix/modules/config-only/vikunja.nix` +
`nix/lib/vikunja.nix`). The gap is **team-sync**: Vikunja auto-assigns teams from
an OIDC claim that must be a JSON **array of objects** (`[{name, oidcID}]`), which
kanidm core cannot emit (gated on kanidm#2641, far off). The chosen bridge — and
the likely permanent answer — is **Option A** from
[../../../upstreaming/bridges.md](../../../upstreaming/bridges.md): a new
`vikunja-provision` reconciler crate that drives Vikunja's REST team/member API
from kanidm-group-derived state, leaving OIDC for login only. It's a near-exact
sibling of `rauthy-provision`.

This plan builds that tenant DRY against the workspace: reuse `provenance-core`
(http/secret/setops), mirror `rauthy-provision`'s crate shape and `immich.nix`'s
reconciler-module shape, and follow the `docs/architecture.md` "Adding a tenant"
checklist.

**Verified API contract (ground truth — do not re-derive):**
- Reconcile key = team **name** (kanidm group name → Vikunja team name). Members
  add/remove **by username** (`TeamMember.Create`/`.Delete` resolve via
  `GetUserByUsername`) → 1:1 with kanidm usernames; no numeric-ID lookup, no
  `/users` search (the `users` route group is not token-reachable).
- Endpoints (`/api/v1`, Vikunja's inverted REST): `PUT /teams` create ·
  `GET /teams` read-all (membership-scoped) · `GET /teams/{id}` observed members ·
  `POST /teams/{id}` update · `DELETE /teams/{id}`; `PUT /teams/{id}/members` add
  (`{username, admin}`) · `DELETE /teams/{id}/members/{username}` remove.
- Converge signals: tolerate code `6005` (already-member → no-op) and `1005`
  (user not yet logged in → retry next pass; users are created lazily on first
  OIDC login). The bot account that creates a team is auto-added as admin and is
  blocked from removing itself while sole member → **exclude the bot username from
  both desired and observed member sets**.
- Auth: long-lived scoped token `tk_…` as `Authorization: Bearer`; minted once
  manually (`PUT /tokens` is JWT-gated) — same shape as the Rauthy bootstrap key.

**Two load-bearing guardrails (must be encoded, not optional):**
1. **Don't hardcode the token scope set.** The CVE-2026-40103 fix (v2.3.0) pins
   scopes to path+method and Vikunja uses inverted REST — scope names are
   version-coupled. Derive/validate the required scopes from a live
   `GET /api/v1/routes` on the deployed instance at token-mint time; document the
   exact scopes (`teams` + `teams_members`).
2. **Treat a write-403 as a HARD FAIL, not a per-team skip.** A route-group rename
   on upgrade silently strips authority for one op; an additive loop would then
   converge partially and silently (adds succeed, removes 403-swallowed),
   corrupting membership. Fail loud so scope-drift surfaces immediately.

## Phases

| Phase | File | Depends on | Touches | Parallel with | Model | Blocking? |
|---|---|---|---|---|---|---|
| 01 | [01-retire-inert-claim.md](01-retire-inert-claim.md) | — | `nix/lib/vikunja.nix`, `nix/modules/config-only/vikunja.nix` | 02 | 5.5 low | no |
| 02 | [02-build-crate.md](02-build-crate.md) | — | `crates/vikunja-provision/**`, root `Cargo.toml` | 01 | 5.5 medium | yes (gates 03) |
| 03 | [03-nix-integration.md](03-nix-integration.md) | 02 | `flake.nix`, `nix/packages.nix`, `nix/checks.nix`, `nix/modules/service-oidc/vikunja.nix`, `nix/modules/test/vikunja-provision-eval.nix`, `REUSE.toml`, docs | — | 5.5 medium | no (capstone) |

## Parallelism layer

- **Wave 0 — 01 and 02 in parallel.** Disjoint files: 01 is a pure-Nix cleanup of
  the SSO tenant; 02 is a pure-Rust crate build. Neither reads the other.
- **Wave 1 — 03 alone.** Nix integration consumes the crate (02) — the module
  defaults to the package, and the checks build/lint/test it and eval the module.
  03 also references the CLI flag names fixed in 02, so it serialises after 02.
  (01 may land before, during, or after — it never blocks 03.)

Critical path is 02 → 03. 01 fans out independently and can land any time.

## Whole-set acceptance criteria

- [ ] `cargo build -p vikunja-provision` and `cargo test -p vikunja-provision`
      pass; the membership-diff unit tests cover bot-exclusion, set-match no-op,
      and add/remove deltas.
- [ ] `nix build .#vikunja-provision` succeeds; `nix flake check` passes including
      the new `vikunja-clippy`, `vikunja-test`, and `vikunja-provision-module-eval`
      checks, and the existing `tls-feature-isolation` + `license-firewall` checks
      still pass with the new crate present.
- [ ] `nix build .#checks.<sys>.vikunja-provision-module-eval` evaluates the new
      `services.vikunja.provision` reconciler to a concrete `Type=oneshot`
      `serviceConfig` with `LoadCredential` for the token (never a store path).
- [ ] The existing `vikunja-module-eval` (config-only SSO, `vikunja-oidc-env`)
      still passes — the new tenant did not clobber it.
- [ ] The inert `vikunja_groups` no-op claim is gone from `nix/lib/vikunja.nix`;
      SSO scopes (`openid profile email`) still emit; the misleading comment is
      corrected to point at kanidm#2641 (kanidm core, not kanidm-provision).
- [ ] `alejandra --check flake.nix nix` and `cargo fmt --check` clean; `REUSE.toml`
      + `docs/src/reference/licensing.md` + `README.md` + `docs/architecture.md`
      updated for the new tenant.

## Global constraints

- **Stay file-disjoint from the in-flight Stalwart 0.16 plan**
  ([../stalwart-016/](../stalwart-016/)). Phase 05 there owns `nix/lib/stalwart.nix`,
  `nix/modules/ldap/stalwart.nix`, `nix/modules/test/stalwart-eval.nix`, and the
  `stalwart-module-eval` block of `nix/checks.nix`. This plan touches none of them.
- **OIDC-sync and the API reconciler must never co-manage the same team** — OIDC
  teams are read-only to the API. We commit to API-managed local teams and keep
  the OIDC claim a no-op (Phase 01).
- **DRY is the point.** Do not duplicate plumbing `provenance-core` provides; do
  not invent a new module shape — mirror `rauthy-provision` and `immich.nix`.
- **Keep `reqwest` TLS features per-crate** (`rustls-tls-native-roots`); never
  hoist `reqwest` into `[workspace.dependencies]` (enforced by
  `tls-feature-isolation`). The crate is permissive (`MIT OR Apache-2.0`) and must
  not depend on the AGPL `immich-provision` (enforced by `license-firewall`).

## Reference

- Rationale + alternatives: [../../../upstreaming/bridges.md](../../../upstreaming/bridges.md)
  (Option A; why B/C/D were rejected; the permanent-answer reasoning).
- The cleanup in Phase 01 is also recorded in
  [../../../upstreaming/round-0-local-changes.md](../../../upstreaming/round-0-local-changes.md).
- Tenant checklist: [../../architecture.md](../../architecture.md) "Adding a tenant".
- Mirror template: `crates/rauthy-provision/`, `nix/modules/service-oidc/immich.nix`.
- Upstream exit: kanidm#2641 (richer custom claim values) — but Option A moots it.
