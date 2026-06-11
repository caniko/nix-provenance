# Phase 08 — Prove Local Consumer Flow

> **Recommended Codex model: GPT 5.5 medium**
>
> This phase spans Rauthy, nix-provenance, and canix evaluation, but it should remain a local proof rather than upstream implementation. Medium effort is appropriate because the work is integration-heavy but bounded by existing Nix module patterns.

## Working Tree

Use `/data/nvme0/can/Projects/nix-provenance`, `/data/nvme0/can/Projects/canix`, and `/data/nvme0/can/Projects/rauthy-pr2` on branch `local/pr2-consumer`. Phase 07 must be complete.

## Goal

Prove that a PR 2 Rauthy build can support declarative generated `rauthy-provision` API-key bootstrap for local Nix/canix consumers, without claiming day-2 migration behavior for existing live DBs.

## Why This Matters Now

The original operational pain is manual API-key provisioning for `rauthy-provision`. A local consumer proof verifies that PR 2 actually removes that manual step for fresh deployments.

## Out Of Scope

- Do not publish PR 2.
- Do not deploy to the live host unless separately requested.
- Do not claim existing Rauthy databases are migrated.
- Do not implement Kubernetes ServiceAccount behavior.

## Plan

1. Patch or override nix-provenance/canix to use the local Rauthy PR 2 build.
2. Render `api_keys.json` for `rauthy-provision` with `secret: "generate"` and required rights:
   - `Users`, `Groups`, `Roles`, `Clients`, `Scopes`, `UserAttributes`: read/create/update/delete;
   - `Secrets`: read/update.
3. Add or prototype a one-shot local extraction path using `rauthy bootstrap get --format env`.
4. Write the extracted generated token to the secret path consumed by `rauthy-provision`.
5. Validate in a fresh empty DB or VM test, not against the existing live DB.
6. Record any needed nix-provenance follow-up changes separately from upstream Rauthy PR work.

## Acceptance Criteria

- [ ] Fresh deployment/test DB can generate a `rauthy-provision` API key without manually supplying the secret.
- [ ] The generated token can be extracted locally through `rauthy bootstrap get`.
- [ ] `rauthy-provision` can authenticate with the extracted key and reconcile its configured resources.
- [ ] The proof does not require live host mutation.
- [ ] Any nix-provenance/canix changes are clearly separated from upstream Rauthy PRs.

## Files Likely Touched

nix-provenance:

- `flake.nix`
- `nix/modules/idp/rauthy.nix`
- `nix/modules/test/rauthy-eval.nix`
- `nix/checks.nix`

canix:

- `root/hosts/thething/server/rauthy.nix`
- Possibly a local test/VM module

## Pitfalls

- Symptom: proof accidentally mutates live Rauthy.
  Cause: pointing extraction/provisioning at the real service.
  Recovery: use a fresh VM/test DB and stop if no isolated environment exists.
- Symptom: existing DB still needs manual key update.
  Cause: bootstrap is first-boot-only.
  Recovery: document this as expected; do not claim day-2 migration.
- Symptom: Nix flake cannot see a local patch file.
  Cause: untracked patch path in a flake source.
  Recovery: stage or otherwise include local source inputs for evaluation.

## Reference

- Phase 07: `docs/src/planning/rauthy-bootstrap-generate/07-checkpoint-pr2-before-upload.md`
- Rauthy provisioner module: `/data/nvme0/can/Projects/nix-provenance/nix/modules/idp/rauthy.nix`
