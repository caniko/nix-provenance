# Local changes before upstreaming (Round 0)

Reconcile our tree with the **current** upstream releases before sending Round 1.
Versions pinned today: Immich **v2.7.5** (nixpkgs builds this exact tag) · kanidm
**v1.10.3** · Stalwart **v0.16.7** *(but nixpkgs still builds **0.15.5**)* · Rauthy
**v0.35.2** · kanidm-provision **v1.3.0**.

> [!NOTE]
> **Status (post-review):**
> - **`nix/lib/stalwart.nix` is owned by a separate agent** — the `classAttr`
>   fix + comment are being handled there. **Do not apply them from this doc**
>   (avoid collision); the rows below are kept for the record only.
> - **The `identity-cli` `PosixExtend`/`PersonExists`/`DeletePerson` WIP is
>   intentional and stays.** Not reverted. The kanidm-provision PR draft instead
>   notes the #31 overlap and frames the PR as consolidating our local
>   posix-password path into kanidm-provision.
> - Remaining cleanups (vikunja no-op, rauthy version labels, immich patch
>   README / `checks.nix` annotations) are **recommendations**, applied only if
>   they affect active work.

## Executive summary

- **Almost nothing is runtime-broken today.** The one genuine now-broken bug is
  in [nix/lib/stalwart.nix](../nix/lib/stalwart.nix): one `classAttr` is overloaded
  for both the filter (`(class=person)` — kanidm accepts `class=` as a query
  alias, fine) and the attribute map (`attributes.class = "class"` — kanidm
  **never returns `class`, it returns `objectclass`**), so entry-type
  classification silently fails for every mailbox user on Stalwart 0.15.5.
- **The newest upstream obsoletes none of the planned upstreaming.** Immich
  `IMMICH_ALLOW_SETUP` (#24628) gates the signup endpoint, not session-minting;
  Rauthy Advanced Bootstrapping is empty-DB INSERT-only and `api_keys.json` is
  still absent in v0.35.2 (PR #1585 not redundant); kanidm-provision v1.3.0 has
  no unix/credential fields at all.
- **One pre-commit blocker (your WIP):** the uncommitted `PosixExtend` /
  `PersonExists` / `DeletePerson` subcommands in `identity-cli` have zero callers;
  `PosixExtend` duplicates kanidm-provision #31 and contradicts the
  `credentials.nix` premise. Resolve before committing — see below.
- **Two do-NOT-do-this:** don't pre-write the Immich Zod patch variant (target
  not frozen — #26597 is main-only), and don't rewrite `stalwart.nix` to the 0.16
  schema (nixpkgs still ships 0.15.5; rewriting breaks the only version that runs).

## Priority table

| File | Change | Urgency | Issue refs |
|------|--------|---------|-----------|
| [nix/lib/stalwart.nix](../nix/lib/stalwart.nix) | Split `classAttr` → `filterClassAttr ? "class"` (filters) + `attrClass ? "objectclass"` (attr map); set `attributes.class = attrClass` | **now-broken** | kanidm `ldap.md` (returns `objectclass`) |
| [nix/lib/stalwart.nix](../nix/lib/stalwart.nix) l.36 | Delete the false "kanidm exposes the object class on the `class` attribute (not objectClass)" comment | **now-broken** | — |
| `crates/identity-cli/src/{kanidm,main}.rs` (WIP) | Drop the `PosixExtend` hunk (or rewrite the module premise); decide `PersonExists`/`DeletePerson` explicitly | **pre-commit** | kanidm-provision#31 |
| [nix/lib/vikunja.nix](../nix/lib/vikunja.nix) | **Delete** the inert `claimMaps.vikunja_groups` block + team-sync scope; keep `openid profile email` SSO; leave a commented example | now-broken (misleading) | kanidm#2641, #4324 |
| [nix/lib/vikunja.nix](../nix/lib/vikunja.nix) l.3-6 + [config-only/vikunja.nix](../nix/modules/config-only/vikunja.nix) | Rewrite the comment: kanidm-provision **does** support array claim maps; the limit is kanidm **core** (flat strings, never `[{name,oidcID}]`). Fix scope default + l.52 description | now-broken (misleading) | kanidm#2641 |
| [nix/modules/ldap/stalwart.nix](../nix/modules/ldap/stalwart.nix) | Add a Stalwart-≥0.16 version-scope warning (TOML removed → whole directory attrset silently ignored); co-locate with existing warnings | before-upstream | nixpkgs#511880, stalwart#2892 |
| [patches/immich/README.md](../crates/immich-provision/patches/immich/README.md) | Compatibility note: pin **v2.7.5** baseline; DTO hunk needs Zod rewrite once nixpkgs ships a release with #26597; record the repo-method contract the runtime depends on | before-upstream | immich#26597 |
| [nix/checks.nix](../nix/checks.nix) l.151 | Annotate: tracks nixpkgs Immich v2.7.5; WILL fail on first bump past #26597; guard is `--dry-run` only (doesn't compile the patched tree) | opportunistic | immich#26597 |
| `crates/rauthy-provision/{src/client.rs,Cargo.toml}` | Bump **all three** `0.35.1` → `0.35.2` (code unchanged at v0.35.2) | opportunistic | — |
| [rauthy-provision/README.md](../crates/rauthy-provision/README.md) | Note v0.35.2 ships first-boot Advanced Bootstrapping (empty-DB INSERT only); the binary owns continuous reconcile | before-upstream | rauthy#1585 |
| [credentials.nix](../nix/modules/kanidm/credentials.nix) header | Optional one-liner: kanidm v1.10.x application passwords exist but are a user-self-service model, **not** a drop-in for declarative provisioning | opportunistic | kanidm application_passwords |
| Immich Zod variant patch | **Do NOT pre-write** (defer to a release tag) | defer | immich#26597 |
| `stalwart.nix` 0.16 schema rewrite | **Do NOT rewrite** (nixpkgs builds 0.15.5) | defer | nixpkgs#511880 |
| Retire `credentials.nix` posix-password loop | **Defer** until a *released* kanidm-provision tag carries a password field (v1.3.0/main both lack it) | defer | kanidm-provision#31, #29 |

## Per-target notes

### Stalwart — the one real bug (confidence: medium)
The fix is right; the *rationale* the research first gave (case-insensitivity /
stalwart#2363) is **wrong** — verifier corrected it. The real mechanism: Stalwart
classifies an entry by matching the **returned attribute name** against the
configured `attr_type` set; kanidm returns `objectclass`, our config says `class`,
so nothing matches and no user is classified as a person. Fix the attribute map
to `objectclass`, keep `(class=...)` in the filters (kanidm accepts it as an
alias). Cite only **nixpkgs#511880** (0.15.5→0.16 bump, open) and **stalwart#2892**
(0.16 breaking-changes, TOML removed) — other issue states were unreliable.

### Vikunja — inert no-op, not a bug (delete it)
We emit `vikunja_groups: ["vikunja-users"]` (a flat string array). Vikunja team
sync needs `[{name, oidcID}]` **objects** in the ID token, which kanidm core
cannot emit. The unlock is **kanidm#2641** ("richer custom claim values", open) —
**not** #4324: #4324 is an unmerged, not-yet-wired *string*-templating lib (its
`render` writes into a `&mut String`), so it can only ever produce strings, not
arrays of objects, and is at most contributory infra toward #2641. Unlocking
Vikunja also needs per-group object emission + a stable `oidcID` source. So the
claim is a non-functional no-op that *looks* load-bearing. Delete the claim + the
team-sync scope, keep SSO. Do **not** just rename the scope — that disguises the
no-op. The misleading comment blames kanidm-provision; the real limit is kanidm
core. Forgejo's flat `groups` claim is the easy case and is fine as-is.

### Immich — applies today, latent break on next bump (confidence: high)
Verified: all four patch anchors still exist in **v2.7.5** as class-validator with
`password!` required, so the patch applies and `immich-patch-applies` passes.
**#26597** (Zod migration) is merged to **main only**, not in any tag — that's the
future tripwire. `IMMICH_ALLOW_SETUP` (#24628) gates `/auth/admin-sign-up` only;
API keys are still non-expiring in v2.7.5, so our short-lived provision-token is
still the only auto-expiring admin credential. **Do not pre-write the Zod variant.**

### kanidm-credentials — correct against v1.10.3; the problem is the WIP tree
Runtime code is fine (client/proto pinned to v1.10.3). The issue is the
uncommitted `PosixExtend`/`PersonExists`/`DeletePerson` diff (see pre-commit
blocker). kanidm v1.10.x now has per-application LDAP "application passwords"
(`idm_application_*`) — the *eventual* upstream replacement for the unix-pw-bind +
posix-password mail path, but it's a **user-self-service** model and undocumented
on the stable LDAP page, so it is **not** a near-term migration. Keep everything;
defer retiring the posix-password loop until a released kanidm-provision tag
carries the field.

### Rauthy — correct against v0.35.2; only stale version labels
`grep 0.35.1` returns **three** hits ([client.rs:6](../crates/rauthy-provision/src/client.rs#L6), [client.rs:38](../crates/rauthy-provision/src/client.rs#L38), `Cargo.toml:35`); bump all
three (spow is still 0.6 — dependency correct, only the label is stale). Advanced
Bootstrapping in v0.35.2 is empty-DB INSERT-only (hard-gated on an empty `jwks`
table) — it cannot reconcile drift, add roles to existing users, delete, or run
the emailed-set-password flow, so the reconcile binary stays necessary and PR
#1585 is not moot.

## How this revises Round 1

- **immich-discussion.md** — change "wouldn't even apply" → "applies against
  v2.7.5 today; breaks on the first release containing **#26597**" (stronger: we
  can cite a *working* patch). **DELETE the hex-vs-Buffer caveat** — it's
  backwards: v2.7.5 `hashSha256` returns a **Buffer**, so the patch's
  `Buffer.from(...)` assertion is already correct. *(Fixed in the draft.)*
- **kanidm-provision-pr.md** — correct the base: the draft is written against
  **main** (cites #31, edits the `enable_unix` block at "~164-173"), which exists
  only on main, not the v1.3.0 tag. Add "branch from main, rebase past #31,
  re-verify line numbers." Add a forward note that application passwords may make
  a posix-password field legacy → frame as "completes the existing posix story."
  *(Fixed in the draft.)*
- **kanidm-ldap-docs.md** — vindicated against v1.10.3 (`idm_people_pii_read` and
  application passwords are still undocumented on the stable LDAP page). New
  higher-value angle: documenting **application passwords** as the per-user
  LDAP/mail alternative is less likely to be bounced than re-explaining the PII
  gate alone. *(Added to the draft.)*
- **stalwart-ldap-note.md** — keep two timelines separate: the upstream note
  targets **0.16 JMAP** (operators must **not** set `attrClass`; the 0.16 default
  `["objectClass"]` already matches kanidm's lowercase `objectclass`), while our
  local lib stays **0.15.5**. *(Reinforced in the draft.)*
- **rauthy-1585-comment.md** — no factual change; strengthen by citing the
  empty-DB `jwks` gate as proof the api_keys path is first-boot-only. *(Added.)*

## Sequencing

1. **`identity-cli` WIP stays** (decision: intentional). No revert. The
   kanidm-provision PR framing notes the #31 overlap and pitches the PR as
   consolidating our posix-password path upstream rather than running a parallel
   one. Still `cargo build --features kanidm` before committing the WIP.
2. **`stalwart.nix` classAttr fix is handled by a separate agent** — don't apply
   it here. Acting on the Round-1 Stalwart *upstream* note only needs that fix
   landed (by whoever), which is in progress; the note's content is independent.
3. **Immich / Rauthy / Vikunja edits are independent** and non-blocking; apply
   only if they affect active work.
4. **Defer** the upstream-gated retirements (Stalwart 0.16 rewrite → nixpkgs#511880;
   posix-password loop → released kanidm-provision tag).
