# Phase 06 — Build PR2 API-Key Generate Locally

> **Recommended Codex model: GPT 5.5 high**
>
> This phase changes the highest-risk credential path and depends on PR 1's write-ahead container API. High effort is justified because preserving existing supplied-secret behavior while adding generated API-key tokens requires careful ordering and test coverage.

## Working Tree

Use `/data/nvme0/can/Projects/rauthy`. Phase 05 must be complete, and the user must approve continuing beyond the PR 1 checkpoint. Ideally PR 1 is either accepted upstream or its API surface is stable enough to stack local work.

## Goal

Implement API-key `secret: "generate"` locally on top of PR 1, without publishing the PR 2 branch.

## Why This Matters Now

This is the capability that removes manual provisioner API-key secret definition. Rauthy already supports JSON-defined API keys, but those keys still require `Plain` or `Encrypted` secrets.

## Out Of Scope

- Do not push or open PR 2.
- Do not alter PR 1 behavior except where PR 2 must consume its container API.
- Do not add Kubernetes ServiceAccount Secret writing.
- Do not change existing `Plain` or `Encrypted` API-key semantics.

## Plan

1. Create a stacked local branch from the reviewed PR 1 branch.
2. Add `Generate` to `ApiKeySecret`.
3. Refactor API-key creation so generated token plaintext and hashed/encrypted verifier are prepared before DB insertion.
4. For `ApiKeySecret::Generate`, write the full `{name}${secret}` token to the encrypted container before inserting the API-key row.
5. For `Plain` and `Encrypted`, preserve current behavior: create key, discard generated token, read/decrypt supplied secret, and call `set_api_key_secret`.
6. Add tests proving:
   - generated API-key token is retrievable from the container;
   - DB validation accepts the generated token;
   - supplied-secret bootstrap behavior is unchanged;
   - container write failure prevents generated API-key insertion.
7. Extend docs and examples for `"secret": "generate"`.
8. Record local validation output for Phase 07.

## Acceptance Criteria

- [ ] `api_keys.json` accepts `"secret": "generate"`.
- [ ] Generated API-key token is stored in the encrypted container before the DB row is inserted.
- [ ] Existing `Plain` and `Encrypted` API-key fixtures still work.
- [ ] Tests cover valid generated token use and container-write failure.
- [ ] PR 2 branch is local only.
- [ ] No `git push` was run and no PR was opened.

## Files Likely Touched

Rauthy:

- `src/data/src/migration/bootstrap/types.rs`
- `src/data/src/migration/bootstrap/api_key.rs`
- `src/data/src/entity/api_keys.rs`
- `bootstrap/api_keys.json`
- `book/src/config/bootstrap.md`
- Tests near API-key entity/bootstrap logic

## Pitfalls

- Symptom: generated token cannot be validated.
  Cause: storing the wrong part of `{name}${secret}` or hashing the formatted token incorrectly.
  Recovery: mirror current `ApiKeyEntity::create` validation expectations.
- Symptom: supplied API-key secrets regress.
  Cause: over-refactoring `set_api_key_secret`.
  Recovery: keep supplied-secret path behaviorally unchanged and covered by tests.
- Symptom: live DB row exists but token is lost.
  Cause: inserting before container write.
  Recovery: generate verifier in memory, write container, then insert.

## Reference

- Phase 05: `docs/src/planning/rauthy-bootstrap-generate/05-checkpoint-pr1-before-upload.md`
- Research evidence for API-key flow: `/data/nvme0/can/Projects/nix-provenance/upstreaming/round-3/rauthy-bootstrap-generate-research.md`
