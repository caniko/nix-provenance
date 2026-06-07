# Phase 05 — Checkpoint PR1 Before Upload

> **Recommended Codex model: GPT 5.5 low**
>
> This is a review gate, not implementation. Low effort is sufficient because the job is to summarize local diffs, verify acceptance criteria, and stop before publication.

## Working Tree

Use `/data/nvme0/can/Projects/rauthy`. Phase 04 must be complete.

## Goal

Produce a local PR 1 review packet and stop before any branch push or PR upload, so the user can inspect the complete PR 1 diff.

## Why This Matters Now

The user explicitly requested checkpoints so PRs can be reviewed before upload. This phase enforces that PR 1 is locally complete but unpublished.

## Out Of Scope

- Do not push.
- Do not open a PR.
- Do not start PR 2 implementation.
- Do not rewrite PR 1 except for tiny review-packet fixes such as docs/test log formatting.

## Plan

1. Confirm branch and publication state:
   ```bash
   git status --short --branch
   git log --oneline --decorate --max-count=10
   ```
2. Produce a local diff summary:
   ```bash
   git diff --stat origin/main...HEAD
   git diff --name-status origin/main...HEAD
   ```
3. Re-run PR 1 validation commands from Phase 04.
4. Draft a PR 1 description locally in a temporary note or chat response, including:
   - summary;
   - behavior changes;
   - explicit non-goals;
   - tests run;
   - known risks.
5. Report that PR 1 is ready for human review and stop.

## Acceptance Criteria

- [ ] Local PR 1 branch contains only PR 1 scope: clients, users, container, CLI get/purge, docs, tests.
- [ ] API-key `Generate` is not present.
- [ ] Validation commands and results are listed.
- [ ] A PR description draft exists in the response or local notes.
- [ ] No `git push` was run.
- [ ] No GitHub PR was opened.

## Files Likely Touched

Rauthy:

- No new source files should be changed except minor review-packet notes if explicitly needed.

## Pitfalls

- Symptom: PR 2 changes sneak into PR 1.
  Cause: starting API-key work before checkpoint.
  Recovery: split the commits before review.
- Symptom: branch is accidentally pushed.
  Cause: using habitual `git push -u`.
  Recovery: stop and report immediately; do not open a PR without user approval.

## Reference

- Phase 04: `docs/src/planning/rauthy-bootstrap-generate/04-add-pr1-cli-docs-tests.md`
