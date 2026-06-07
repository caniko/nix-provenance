# Phase 04 — Add PR1 CLI Docs And Tests

> **Recommended Codex model: GPT 5.5 medium**
>
> This is a moderate integration phase across CLI parsing, formatting, docs, and validation. Medium effort is suitable because the implementation is not broad, but the offline/Vault behavior and env output schema need careful consistency.

## Working Tree

Use `/data/nvme0/can/Projects/rauthy`. Phase 03 must be complete.

## Goal

Finish PR 1 locally by adding `rauthy bootstrap get` and `rauthy bootstrap purge`, documenting generated clients/users, and running the PR 1 validation suite.

## Why This Matters Now

The encrypted container is only useful if operators can retrieve and purge generated values without talking to the server. The CLI must be local and explicit about Vault-backed deployments.

## Out Of Scope

- Do not implement CLI `export` unless upstream review already requested it.
- Do not add API-key `Generate`.
- Do not add Kubernetes ServiceAccount behavior.
- Do not push or open a PR.

## Plan

1. Add a `bootstrap` CLI subcommand with `get` and `purge`.
2. Implement `get --format raw|json|env`.
3. Use collision-safe env names:
   - `RAUTHY_BOOTSTRAP_CLIENT_<SANITIZED_ID>_SECRET`
   - `RAUTHY_BOOTSTRAP_USER_<SANITIZED_ID>_PASSWORD`
4. Make the CLI accept explicit local `ENC_KEY_ACTIVE` and `ENC_KEYS` via env or flags.
5. If `USE_VAULT_CONFIG=true` and local keys are absent, fail with an actionable offline-decrypt message.
6. Document generated client/user bootstrap, first-boot-only behavior, TTL/runtime purge/startup purge, env output, and Vault mode.
7. Run formatter and targeted tests.
8. Prepare a local PR 1 summary and test log for Phase 05 review.

## Acceptance Criteria

- [ ] `rauthy bootstrap get --format raw` prints only the requested secret value to stdout.
- [ ] `rauthy bootstrap get --format json` preserves `kind`, `id`, `field`, and `value`.
- [ ] `rauthy bootstrap get --format env` emits collision-safe names.
- [ ] `rauthy bootstrap purge` deletes the encrypted container and is idempotent or emits a documented not-found result.
- [ ] Docs state day-2 `"generate"` additions are ignored by the first-boot bootstrap gate.
- [ ] Formatter and targeted tests pass, or failures are recorded exactly.
- [ ] No branch has been pushed and no PR has been opened.

## Files Likely Touched

Rauthy:

- `src/bin/src/cli_args.rs`
- `src/bin/src/main.rs`
- `src/bin/src/utils/`
- `book/src/config/bootstrap.md`
- `book/src/config/cli.md`
- `bootstrap/clients.json`
- `bootstrap/users.json`
- CLI/bootstrap tests

## Pitfalls

- Symptom: CLI unexpectedly contacts Vault.
  Cause: full config loading reused in `bootstrap get`.
  Recovery: prefer explicit local keys and fail clearly in Vault mode without them.
- Symptom: env output collides.
  Cause: omitting entity kind or field.
  Recovery: include kind and secret type in every env variable name.
- Symptom: logs contain secret values.
  Cause: using tracing/debug formatting on secret payloads.
  Recovery: secrets go only to stdout for successful `get`.

## Reference

- Phase 03: `docs/src/planning/rauthy-bootstrap-generate/03-add-pr1-client-user-generate.md`
- Research design clarifications: `/data/nvme0/can/Projects/nix-provenance/upstreaming/round-3/rauthy-bootstrap-generate-research.md`
