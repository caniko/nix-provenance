# Rauthy Bootstrap Generate Plan

> **Recommended Codex model: GPT 5.5 medium**
>
> This is a top-level coordination plan over two repositories and two upstream PR boundaries. The work is moderately complex because it has security-sensitive sequencing, but each execution phase is bounded; medium effort is enough for orchestration as long as checkpoint phases stop publication until human review.

## Scope And Current State

This plan turns the research dossier at `upstreaming/round-3/rauthy-bootstrap-generate-research.md` into executable Codex phases. The immediate target is Rauthy PR 1 plus a local PR 2 branch stacked on top, with explicit human review checkpoints before any branch is pushed or PR is opened.

Current evidence says upstream `origin/main` already has `api_keys.json` bootstrap support, but generated API-key secrets are not implemented. The local Rauthy branch `feat/bootstrap-api-keys-json` tracks a deleted remote branch and must not be used as the new base.

As of June 11, 2026, the local execution layout is consolidated around one shared Git repository with role-based worktrees:

| Path | Role | Branch rule |
|---|---|---|
| `/data/nvme0/can/Projects/rauthy` | shared repo + main integration worktree | owns local integration branches; do not leave this worktree detached |
| `/data/nvme0/can/Projects/rauthy-pr1-submit` | upstream PR 1 submission worktree | owns `feat/bootstrap-generated-secrets-pr1-submit` |
| `/data/nvme0/can/Projects/rauthy-pr2` | canonical local consumer worktree for stacked PR 2 validation | stays on `local/pr2-consumer`; do not leave it detached |

`/data/nvme0/can/Projects/rauthy-pr1-check` is retired after its checkpoint role was absorbed into this canonical plan set and the named submit/consumer worktrees above.

## Phase Table

| Phase | File | Depends on | Blocking status | Safe parallelism |
|---|---|---|---|---|
| 01 | [Prepare clean upstream base](./01-prepare-upstream-base.md) | none | Blocks all implementation | none |
| 02 | [Build PR1 container foundation](./02-build-pr1-container-foundation.md) | 01 | Blocks PR1 entity integration | none |
| 03 | [Add PR1 generated clients and users](./03-add-pr1-client-user-generate.md) | 02 | Blocks PR1 checkpoint | none |
| 04 | [Add PR1 CLI docs and tests](./04-add-pr1-cli-docs-tests.md) | 03 | Blocks PR1 checkpoint | none |
| 05 | [Checkpoint PR1 before upload](./05-checkpoint-pr1-before-upload.md) | 04 | Human review gate | none |
| 06 | [Build PR2 API-key generate locally](./06-build-pr2-api-key-generate-local.md) | 05 plus PR1 review decision | Blocks PR2 checkpoint | none |
| 07 | [Checkpoint PR2 before upload](./07-checkpoint-pr2-before-upload.md) | 06 | Human review gate | none |
| 08 | [Prove nix-provenance and canix consumption](./08-prove-local-consumer-flow.md) | 07 | Optional consumer proof before upstream PR2 upload | can run after PR2 checkpoint only |

## Parallelism Layer

Wave 0: run Phase 01 only. It establishes the clean upstream base and prevents the stale local branch from contaminating the PR stack.

Wave 1: run Phases 02, 03, and 04 sequentially. They touch overlapping Rauthy bootstrap, config, CLI, and docs files, so parallel editing would create avoidable conflicts.

Wave 2: run Phase 05 and stop. This is a required human checkpoint before pushing or opening PR 1.

Wave 3: after the user approves PR 1 upload, and after PR 1 review either lands or stabilizes the API surface, run Phase 06 locally on top of the PR 1 branch. Do not publish PR 2 from this phase.

Wave 4: run Phase 07 and stop. This is the required PR 2 human checkpoint before any upload.

Wave 5: run Phase 08 only after PR 2 has a reviewed local branch. It proves the consumer flow in nix-provenance/canix and must not substitute for upstream review.

## Whole-Set Acceptance Criteria

- [ ] PR 1 is implemented on a fresh branch from current `origin/main`, not the deleted-tracking local branch.
- [ ] PR 1 has a local review checkpoint before any `git push` or GitHub PR creation.
- [ ] PR 2 is implemented locally on top of PR 1 and remains unpublished until the PR 2 checkpoint is reviewed.
- [ ] PR 1 and PR 2 both preserve Rauthy's first-boot-only bootstrap contract.
- [ ] Generated plaintext is written to the encrypted container before the corresponding live DB row is inserted.
- [ ] The CLI can decrypt locally without fetching Vault; Vault-backed operators must provide local `ENC_KEYS` and `ENC_KEY_ACTIVE`.
- [ ] Runtime purge and startup purge are both covered.

## Global Constraints

- Do not publish, push, or open a PR during phases marked as checkpoints.
- Do not add Kubernetes-native ServiceAccount Secret writing in PR 1 or PR 2.
- Do not convert bootstrap into day-2 reconciliation.
- Do not use the stale `feat/bootstrap-api-keys-json` branch as implementation base.
- Prefer small, reviewable commits inside each PR branch.

## Historical Coverage

The active execution plan is this directory only. Older Rauthy plan material remains as evidence, not as parallel instructions.

| Source | Status | Notes |
|---|---|---|
| `upstreaming/round-1/rauthy-1585-comment.md` | historical-only | records the already-merged API-key bootstrap JSON upstreaming step |
| `upstreaming/round-2/rauthy-1584-encrypted-container-rfc.md` | represented | design constraints carried into phases 02-07 |
| `upstreaming/round-2/rauthy-1584-reply-2.md` | represented | maintainer-aligned decisions folded into current phase assumptions |
| `upstreaming/round-3/rauthy-bootstrap-generate-research.md` | represented | current evidence base for the surviving implementation work |
| `upstreaming/round-0-local-changes.md` | historical-only | broader repository cleanup notes, not an execution plan for this stack |

Treat `upstreaming/round-*` as reference material only after checking whether the current phase files already represent the same intent.

## References

- Research dossier: `upstreaming/round-3/rauthy-bootstrap-generate-research.md`
- Prior upstreaming note: `upstreaming/round-2/rauthy-1584-reply-2.md`
- Rauthy upstream checkout: `/data/nvme0/can/Projects/rauthy`
