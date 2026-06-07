# Phase 03 — Add PR1 Generated Clients And Users

> **Recommended Codex model: GPT 5.5 medium**
>
> This is moderate coding work inside existing bootstrap flows. Medium effort is the right balance because the phase must preserve public-client semantics and insert-order safety, but the touched surface is narrow.

## Working Tree

Use `/data/nvme0/can/Projects/rauthy`. Phase 02 must be complete.

## Goal

Implement PR 1 generated secrets for bootstrap clients and users, using write-ahead encrypted-container persistence before each generated credential becomes live in the database.

## Why This Matters Now

Clients need explicit `secret: "generate"` because absent client secrets already mean public PKCE. Users need `password: "generate"` so operators can avoid committing plaintext or encrypted bootstrap passwords.

## Out Of Scope

- Do not add API-key `Generate`; that belongs to PR 2.
- Do not change day-2 bootstrap behavior.
- Do not change existing `Plain` or `Encrypted` semantics.
- Do not push or open a PR.

## Plan

1. Add `Generate` to `ClientSecret` and `UserPassword` with serde support for JSON string `"generate"`.
2. Update client bootstrap so `secret: "generate"`:
   - generates a 64-character confidential-client secret;
   - writes the plaintext to the encrypted container first;
   - inserts the DB row with encrypted secret bytes and confidential semantics.
3. Preserve absent client `secret` as public client plus forced S256.
4. Update user bootstrap so `password: "generate"`:
   - generates a high-entropy password;
   - writes the plaintext to the encrypted container first;
   - hashes the password through the existing path and inserts the user.
5. Ensure dev bootstrap paths do not accidentally emit real containers unless explicitly intended by test fixtures.
6. Add examples or tests for mixed supplied/generated client and user bootstrap data.

## Acceptance Criteria

- [ ] Existing client `secret: null` or absent secret still creates a public PKCE client.
- [ ] Client `secret: "generate"` creates a confidential client and records a retrievable container entry.
- [ ] User `password: "generate"` stores only the hashed password in DB and records the plaintext in the container.
- [ ] If container write fails, the generated client/user row is not inserted.
- [ ] Existing `Plain` and `Encrypted` test fixtures still pass.
- [ ] No branch has been pushed and no PR has been opened.

## Files Likely Touched

Rauthy:

- `src/data/src/migration/bootstrap/types.rs`
- `src/data/src/migration/bootstrap/clients.rs`
- `src/data/src/migration/bootstrap/users.rs`
- `bootstrap/clients.json`
- `bootstrap/users.json`
- Tests near bootstrap parsing or migration code

## Pitfalls

- Symptom: generated clients become public.
  Cause: treating `Generate` as `None`.
  Recovery: keep `Generate` as a present-secret branch.
- Symptom: generated user password is not retrievable.
  Cause: hashing before container write and dropping plaintext.
  Recovery: write plaintext to container before hashing/insertion.
- Symptom: day-2 restarts generate new values.
  Cause: moving bootstrap outside the existing first-boot gate.
  Recovery: keep generated paths under the current bootstrap lifecycle.

## Reference

- Phase 02: `docs/src/planning/rauthy-bootstrap-generate/02-build-pr1-container-foundation.md`
- Research evidence for client/user bootstrap paths: `/data/nvme0/can/Projects/nix-provenance/upstreaming/round-3/rauthy-bootstrap-generate-research.md`
