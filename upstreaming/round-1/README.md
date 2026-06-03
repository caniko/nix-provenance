# Upstreaming — Round 1 drafts

Review pack for the first wave of upstream contributions. Round 2 (the Immich
follow-up PR, the nixpkgs `kanidm-credentials` scoping issue) is deliberately
held until these outcomes are read in.

> [!IMPORTANT]
> **See [Round 0](../round-0-local-changes.md) for the local reconciliation
> against current upstream releases** (Immich v2.7.5, Stalwart 0.15.5-in-nixpkgs,
> kanidm-provision v1.3.0, Rauthy v0.35.2). Decisions taken:
> - `nix/lib/stalwart.nix` `classAttr` bug — **owned by a separate agent**.
> - `identity-cli` `PosixExtend`/`PersonExists`/`DeletePerson` WIP — **kept
>   intentionally**; the kanidm-provision PR draft notes the #31 overlap and
>   frames the PR as consolidating our local posix-password path upstream.
>
> The drafts below were revised per the version-skew findings (Immich Zod timing
> + the corrected Buffer assertion; kanidm-provision base = `main`/rebase past
> #31; the application-passwords angle for the kanidm docs; the Stalwart
> "don't set `attrClass`" point; the Rauthy empty-`jwks` gate).

## What's in this round

| # | File | Target | Vehicle | Blocking? |
|---|------|--------|---------|-----------|
| 1 | [kanidm-provision-pr.md](kanidm-provision-pr.md) | oddlama/kanidm-provision | Cold PR (code) | No — do first |
| 2 | [rauthy-1585-comment.md](rauthy-1585-comment.md) | sebadob/rauthy PR #1585 | Re-request-review comment | No — near-free |
| 3 | [kanidm-ldap-docs.md](kanidm-ldap-docs.md) | kanidm/kanidm book + issue #3070 | Docs PR + comment | Do before #4 |
| 4 | [stalwart-ldap-note.md](stalwart-ldap-note.md) | stalwartlabs/website | Docs PR | After #3 (cross-links it) |
| 5 | [immich-discussion.md](immich-discussion.md) | immich-app/immich | Discord + Discussion (no PR yet) | Independent track |

## Read these caveats before sending anything

1. **kanidm AI-provenance wall (#3).** kanidm's PR template has a mandatory
   "This PR contains no AI generated code" checkbox backed by a copyright/legal
   stance. The chapter draft in #3 is **reference material only** — you must
   author the prose yourself, in your own words, from the verified facts. Tested
   CLI transcripts / configs are facts (reusable); the narrative is not. Do not
   paste the draft and tick the box.

2. **What I dropped as already-documented** (so we don't get bounced):
   - kanidm `ldap.md` *already* covers `dn=token` binds and the `-D admin`
     requirement for `set-ldap-allow-unix-password-bind`. The only genuinely
     new content is the **`idm_people_pii_read` gate for reading `mail`** and
     **posix-only visibility** + a mail-server worked example.
   - Stalwart's live 0.16 page *already* covers `url`, `bindAuthentication:true`
     default, and the no-hash-comparison scenario. Our old `class` vs
     `objectClass` claim looks **stale** (kanidm's LDAP output exposes
     `objectclass` lowercase; issue #2363 closed). #4 is reduced to a small
     Kanidm note and is the **weakest** PR — expect a possible "just cross-link
     to Kanidm's docs" response.

3. **Verify-before-submit on the two docs PRs.** Re-confirm the
   `idm_people_pii_read` requirement and posix-only visibility against the
   *current* kanidm release at PR time — gateway semantics have shifted across
   versions.

4. **Strip Nix everywhere except nixpkgs.** None of these four asks should read
   as "so NixOS can do X." Frame each as real for any headless deployer; use
   "we run this in production" only as credibility.

## Sequencing recap

1 (kanidm-provision) → may obsolete part of our `identity-cli`, which changes
the Round-2 nixpkgs ask. 2 (rauthy) is independent. 3 (kanidm docs) before 4
(Stalwart note) so #4 cross-links the new chapter. 5 (Immich Discussion) is a
slow independent negotiation; its PR is Round 2.
