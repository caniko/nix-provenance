# Phase 01 — Prepare Clean Upstream Base

> **Recommended Codex model: GPT 5.5 low**
>
> This is a bounded setup and verification phase with straightforward git and baseline checks. Low effort is sufficient because the work is mostly source hygiene and branch preparation; a larger model would not materially improve the result.

## Working Tree

Use `/data/nvme0/can/Projects/rauthy`.

## Goal

Create a clean implementation base from current upstream `origin/main`, with baseline checks recorded, so PR 1 starts from the right source and not from the stale deleted-tracking branch.

## Why This Matters Now

The research found that `feat/bootstrap-api-keys-json` tracks `caniko/feat/bootstrap-api-keys-json [gone]`. Starting there risks reintroducing stale diffs unrelated to generated bootstrap secrets.

## Out Of Scope

- Do not implement generated secrets.
- Do not push branches.
- Do not open PRs.
- Do not modify nix-provenance or canix.

## Plan

1. Check status and save any unrelated local work notes:
   ```bash
   git status --short --branch
   ```
2. Fetch upstream:
   ```bash
   git fetch origin --prune
   ```
3. Create a fresh branch or worktree from `origin/main`, for example:
   ```bash
   git switch -c feat/bootstrap-generated-secrets-pr1 origin/main
   ```
4. Inspect bootstrap source files named in the research dossier to confirm they still match the assumptions.
5. Run the smallest baseline test for existing API-key bootstrap parsing:
   ```bash
   cargo test -p rauthy-data parses_api_keys_bootstrap_example
   ```
6. Run the project's normal format/pre-PR command if available in the checkout documentation.

## Acceptance Criteria

- [ ] Active branch is based on current `origin/main`.
- [ ] `git status --short --branch` does not show the deleted upstream branch as the tracking branch.
- [ ] Existing API-key bootstrap parsing test passes or any failure is documented with exact output.
- [ ] No branch has been pushed and no PR has been opened.

## Files Likely Touched

Rauthy:

- No source files should be changed in this phase.

## Pitfalls

- Symptom: `git status` still reports `[gone]`.
  Cause: the stale local branch is still checked out.
  Recovery: create a fresh branch from `origin/main`.
- Symptom: baseline tests fail before edits.
  Cause: upstream or local environment drift.
  Recovery: stop and record the exact failing command before implementation begins.

## Reference

- Research dossier: `/data/nvme0/can/Projects/nix-provenance/upstreaming/round-3/rauthy-bootstrap-generate-research.md`
