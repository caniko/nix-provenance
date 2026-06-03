# Temporary solutions until upstream lands (bridges)

Holistic register of every gap nix-provenance bridges until an upstream change
lands, plus the alternatives for the one genuinely-open bridge (Vikunja
team-sync). Reconciled with the in-flight [Stalwart 0.16 plan](../docs/planning/stalwart-016/).

## Executive summary

Vikunja **SSO already works today** — the gap is only **team-sync**, which needs
an array-of-objects ID-token claim kanidm core cannot emit. **Recommended bridge:
Option A, a `vikunja-provision` reconciler crate** that drives Vikunja's REST
team/member API (verified live on shipping v2.3.0) and reconciles "kanidm group
members → Vikunja team members" idempotently — a near-exact sibling of
`rauthy-provision`, working today with **zero upstream dependency**, and viable
as the *permanent* answer (it moots kanidm#2641 for us). **Fallback: keep SSO,
delete the inert no-op claim, manage teams by hand** — the lowest-risk posture if
you don't want a standing Vikunja admin token. This is a **convenience gap, not a
security boundary**: login/SSO is fully functional; only team auto-assignment is
deferred.

Avoid Options B (claim-rewriting proxy) and C (Rauthy intermediary) — verifiers
downgraded both. Option D (local kanidm fork) is a heavy last resort only if
team-sync becomes a hard, dated requirement *and* #2641 has visibly stalled.

## Vikunja team-sync

| Option | Feasibility | Effort | Fit with spine | Security footprint | Rec |
|---|---|---|---|---|---|
| **A — `vikunja-provision` API reconciler** | works-today¹ | ~2–4 days, 1 crate + 1 module | **Strong** (sibling of `rauthy-provision`) | one scoped API token (`teams`+`teams_members`); bot is a phantom member of its teams | **PRIMARY** |
| B — claim-rewriting proxy | needs-build | ~2–4 days, in-path daemon | Poor (long-running MITM) | new high-trust auth-path component that can forge team membership | **AVOID** |
| C — Rauthy intermediary IdP | **not-viable** | unbounded, zero outcome | Poor + moot | 2nd IdP in trust path, still doesn't work | **AVOID** |
| D — local kanidm fork (object claim) | heavy | 4–5 days + per-release rebase | Poor (fork-patch family) | modifies IdP token-assembly + ACP/DB migration | **last resort** |

¹ after a one-time manual token mint (`PUT /tokens` is JWT-gated) — same shape as the Rauthy bootstrap-key step the repo already tolerates.

### Recommended bridge, concretely — `vikunja-provision`

A new crate mirroring `rauthy-provision` (reuses `provenance-core` http/secret/setops):

- **Reconcile:** read a kanidm-group-derived JSON state file; reconcile each
  `{team, members[]}` against Vikunja `/api/v1`. Key = team **name**. Membership
  add/remove is **by username** (verified: `TeamMember.Create`/`.Delete` resolve
  via `GetUserByUsername`) → maps 1:1 to kanidm usernames, no numeric-ID lookup,
  no need for the token-forbidden `/users` search.
- **Endpoints (verified, Vikunja's inverted REST):** `PUT /teams` create ·
  `GET /teams` read-all (membership-scoped → a dedicated bot sees only its own
  teams) · `GET /teams/{id}` observed state · `POST /teams/{id}` update ·
  `DELETE /teams/{id}`; `PUT /teams/{id}/members` add · `DELETE /teams/{id}/members/{username}` remove.
- **Converge signals:** tolerate `6005` (already-member, no-op) and `1005` (user
  not yet logged in → retry next pass; Vikunja lazily creates the user on first
  OIDC login). New users land in teams on first login + next pass — document this.
- **Bot special-case:** the creating account is auto-added as admin; exclude the
  bot username from both desired and observed member sets. (Correction: the guard
  is last-**member**, not last-admin — exclude regardless, but don't rely on
  "permanent immovability.")
- **Plumbing:** `Type=oneshot` `RemainAfterExit` after `vikunja.service`; new
  `crates/vikunja-provision/` + `nix/modules/service-oidc/vikunja.nix` (model on
  `forgejo.nix`/`immich.nix` credential plumbing). Token from a runtime file via
  `LoadCredential` / rendered `/run` env file — never a store path or argv. Keep
  `nix/modules/config-only/vikunja.nix` (SSO) and `nix/lib/vikunja.nix` as-is;
  this is a parallel tenant, not an edit.

**Two load-bearing guardrails (verifier):**
1. **Don't hardcode the token scope set.** The CVE-2026-40103 fix (in 2.3.0) makes
   scoped tokens pin **path *and* method**, and Vikunja uses inverted REST. Derive
   the scopes from a live `GET /api/v1/routes` on the deployed instance at
   bootstrap — don't copy a guessed list.
2. **Treat a write-403 as a HARD FAIL, not a per-team skip.** A route-group rename
   on upgrade would silently strip authority for one op (e.g. member-delete); the
   additive loop would then converge partially and silently (adds succeed, removes
   swallowed), corrupting membership invisibly. Fail loud so scope-drift surfaces.

**Exit condition / permanence:** gated nominally on kanidm#2641, but **A makes
#2641 moot for us** — even if it lands, the OIDC claim path yields non-editable
"(OIDC)" teams, whereas the reconciler yields normal editable teams under
declarative control. A is fine as the permanent answer. Inviolable rule: OIDC-sync
and the API reconciler must **never co-manage the same team** (OIDC teams are
read-only to the API). Commit to API-managed local teams; leave the claim a no-op.

### Fallback

Don't want a standing admin token? Keep SSO, **delete the inert no-op
`vikunja_groups` claim**, assign teams by hand, wait on #2641. Lower capability
than A but zero added trust surface — judged lower total risk than Option B.

## Bridge register

| Gap | Current bridge | Status | Exit condition |
|---|---|---|---|
| **Vikunja team-sync** (needs array-of-object claim; kanidm emits flat strings) | SSO via `nix/lib/vikunja.nix` + `config-only/vikunja.nix`; inert no-op claim to **delete**; teams manual | running (SSO works; team-sync un-bridged) | kanidm#2641 — **or** adopt Option A (moots #2641 for us) |
| **Immich** (no auto-expiring admin credential) | local patch on Immich **v2.7.5** (`provision-token` + optional password); guarded by `checks.nix immich-patch-applies` (dry-run) | running (applies on v2.7.5) | immich#26597 (Zod) merged to main 2026-04-14 → DTO hunk needs Zod rewrite on first nixpkgs bump to a **release tag** with it. Don't pre-write. True exit: Immich ships native short-lived admin creds |
| **kanidm-provision** (no POSIX password / unix-bind toggle / SA token) | `identity-cli` + `nix/modules/kanidm/credentials.nix` (readiness-gated oneshot; self-healing token) | running | a **released** kanidm-provision tag with a POSIX-**password** field. #31 (merged) is unix-**attrs** only; v1.3.0 lacks the field. App-passwords are self-service, not a drop-in |
| **Stalwart 0.16.7** (no TOML/REST; JMAP + `stalwart-cli apply`; LDAP dir = registry object; nixpkgs module incompatible) | `docs/planning/stalwart-016/` (local overlay + JSON-bootstrap module + local `kanidmLdap` lib + `apply` provisioning + migration runbook) | planned/in-flight (deploy capstone gated; gen 50 / 0.15.5 rollback floor) | NixOS/nixpkgs#511880 (module rewrite, open) + #512341 (0.16.0 packaging, blocked). Exit: released nixpkgs `services.stalwart` rendering 0.16 |
| **Rauthy** (no declarative API-key bootstrap; bootstrap is empty-DB INSERT-only) | `rauthy-provision` continuous reconciler over `/auth/v1`; API key assembled at runtime | running (reconcile permanent; bootstrap half pending release) | sebadob/rauthy#1585 **merged 2026-06-03** but post-dates v0.35.2 → not in any release. Exit for the bootstrap half: a release **> v0.35.2**. Continuous reconcile is **never** retired |

## Doesn't affect us

- **Hydra `-`-in-claim-values (kanidm#2641, @KJTsanaktsidis):** pure charset
  problem solved by string-regex relaxation; orthogonal to our object need. No
  consumer of ours needs `-`/`:` in a claim value.
- **@bjorne's email-formatted Stalwart `groups` claim:** our Stalwart integrates
  via the **kanidm LDAP gateway** (search-then-bind, `mail` behind
  `idm_people_pii_read`), not an OIDC groups claim — group membership flows
  through LDAP attributes, never a token claim. Also a string-formatting case (#4324).
- **dvv's Mercure object claim + `${…}` interpolation:** no Mercure consumer, and
  our Vikunja object is built from values kanidm already owns — **no interpolation
  engine needed**, so the templating debate (yaleman/Firstyear) doesn't gate us.
- **Keycloak/Zitadel custom-mapper & JS/WASM scripting:** alternate IdPs we don't
  run; kanidm rejects the loadable-module route. Not a bridge option.

## Alignment with the Stalwart 0.16 plan

**Files owned by Phase 05 — do NOT touch:** `nix/lib/stalwart.nix`,
`nix/modules/ldap/stalwart.nix`, `nix/modules/test/stalwart-eval.nix`, and the
`stalwart-module-eval` block of `nix/checks.nix`. (Round-0 already records the
`stalwart.nix` `classAttr` fix as owned by that agent — not to be applied here.)

**No collision.** The Vikunja work touches only `nix/lib/vikunja.nix` +
`nix/modules/config-only/vikunja.nix` (disjoint config-only tenant), plus — for
Option A — the new `crates/vikunja-provision/` and `nix/modules/service-oidc/vikunja.nix`.

**Reusable bridge pattern (set by stalwart-016):** keep each bridge a clean,
self-contained local overlay/module/lib/crate in nix-provenance, consumed by
canix, written with no canix-only assumptions so it can be upstreamed once the
gating upstream lands. Option A fits exactly — a new tenant crate in the
`immich-provision`/`rauthy-provision` family.

## Sequencing

**Do now:**
1. **Delete the inert no-op `vikunja_groups` claimMap** (`nix/lib/vikunja.nix`) +
   the team-sync scope; keep SSO; leave a commented example; fix the misleading
   comment (limit is kanidm **core**, not kanidm-provision) and the scope
   default/description in `config-only/vikunja.nix`. Independent of Option A.
2. **Decide on Option A.** If team-sync is wanted, build `vikunja-provision` now
   (~2–4 days, no upstream dependency, also the permanent answer). Bootstrap the
   token from a live `GET /api/v1/routes`; treat write-403 as a hard fail.
3. **Keep driving kanidm#2641** (the posted comment splitting string-charset from
   structured-object) — keeps the native path open as a future simplification,
   even though Option A makes #2641 non-blocking for us.

**Defer:** Option D (only if team-sync becomes hard+dated and #2641 stalls); the
Immich Zod rewrite (armed tripwire, fires on the first release-tag bump past
#26597 — don't pre-write); the Rauthy api_keys bootstrap (wait for a release > v0.35.2).

**Dependency on stalwart-016 waves:** none — the Vikunja work is file-disjoint
from Phase 05 and lands in any order. The only shared bridge is `credentials.nix`
(kanidm posix/token), which the Stalwart LDAP cutover depends on but Vikunja does not.
