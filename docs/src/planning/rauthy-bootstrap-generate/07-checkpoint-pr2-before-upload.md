# Phase 07 — Checkpoint PR2 Before Upload

> **Recommended Codex model: GPT 5.5 low**
>
> This is a local review checkpoint. Low effort is enough because the phase verifies scope and prepares a review packet, with a hard stop before publication.

## Working Tree

Use `/data/nvme0/can/Projects/rauthy`. Phase 06 must be complete.

## Goal

Produce a local PR 2 review packet and stop before pushing or opening PR 2.

## Why This Matters Now

PR 2 carries the API-key credential path and is intentionally built locally on top of PR 1. Human review must happen before upload so the stack, diff boundaries, and generated-token semantics can be checked.

## Out Of Scope

- Do not push.
- Do not open PR 2.
- Do not change PR 1 history unless the user instructs a rebase/fixup.
- Do not start Kubernetes PR 3.

## Plan

1. Confirm branch stack:
   ```bash
   git status --short --branch
   git log --oneline --decorate --max-count=20
   ```
2. Show PR 2 diff relative to PR 1 base and relative to upstream main.
3. Re-run PR 2 validation commands from Phase 06.
4. Draft a PR 2 description locally, including:
   - relationship to PR 1;
   - API-key generated-secret behavior;
   - failure-mode guarantees;
   - tests run;
   - explicit statement that Kubernetes is out of scope.
5. Stop and request user review.

## Acceptance Criteria

- [ ] PR 2 diff contains only API-key `Generate` and related tests/docs.
- [ ] PR 1 changes are not accidentally duplicated or rewritten beyond stack mechanics.
- [ ] Validation commands and results are listed.
- [ ] A PR 2 description draft exists.
- [ ] No `git push` was run.
- [ ] No GitHub PR was opened.

## Files Likely Touched

Rauthy:

- No new source changes should be made in this checkpoint except minor review-packet notes if explicitly needed.

## Pitfalls

- Symptom: PR 2 includes PR 1 diff in an unclear way.
  Cause: comparing against `origin/main` only.
  Recovery: present both stack-relative and upstream-relative diffs.
- Symptom: accidental PR upload.
  Cause: using publishing muscle memory.
  Recovery: stop immediately and report exact remote action taken.

## Reference

- Phase 06: `docs/src/planning/rauthy-bootstrap-generate/06-build-pr2-api-key-generate-local.md`
