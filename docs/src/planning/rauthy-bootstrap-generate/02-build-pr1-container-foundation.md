# Phase 02 — Build PR1 Container Foundation

> **Recommended Codex model: GPT 5.5 medium**
>
> This phase is moderate implementation work with security-sensitive file handling and configuration parsing. Medium effort is appropriate because the task is bounded to the encrypted container foundation, but smaller routing risks missing the write mode, TTL, or Vault/offline constraints.

## Working Tree

Use `/data/nvme0/can/Projects/rauthy`. Phase 01 must be complete.

## Goal

Add the reusable generated-secret container foundation for PR 1: encrypted read/write, cleartext expiry header, startup/runtime purge, config fields, and tests, without yet integrating clients or users.

## Why This Matters Now

Generated user passwords and API-key tokens cannot be reconstructed after DB insertion. The container must exist before entity integration so generated plaintext can be written ahead of live DB rows.

## Out Of Scope

- Do not add `Generate` to client, user, or API-key enums.
- Do not implement CLI commands beyond helpers needed for tests.
- Do not add Kubernetes behavior.
- Do not push or open a PR.

## Plan

1. Add a focused generated-secrets module under Rauthy's bootstrap/data area.
2. Define an encrypted container schema with:
   - cleartext magic/version/deadline header;
   - encrypted JSON payload;
   - entries keyed by `kind`, `id`, and `field`.
3. Implement atomic write with same-directory temporary file, mode `0600`, fsync, and rename.
4. Implement read/decrypt with magic/version validation before passing bytes to cryptr.
5. Add config fields under `[bootstrap]` for secrets file path and TTL seconds.
6. Resolve default path under `${data_dir}/bootstrap.secrets.enc`; make the resolution explicit in code.
7. Add startup purge of expired files using the cleartext header.
8. Add runtime Tokio purge scheduling after a container write when TTL is positive.
9. Add unit tests for roundtrip, bad magic, expired header, purge, and env-name sanitization.

## Acceptance Criteria

- [ ] Container writes are atomic and create files with `0600` permissions.
- [ ] Expired files can be purged without decrypting payload contents.
- [ ] TTL `0` disables auto-purge.
- [ ] The code path does not require Vault access for local decrypt helpers.
- [ ] Tests cover bad magic/version and expired header behavior.
- [ ] No branch has been pushed and no PR has been opened.

## Files Likely Touched

Rauthy:

- `src/data/src/migration/bootstrap/mod.rs`
- `src/data/src/migration/bootstrap/generated_secrets.rs` or similar new module
- `src/data/src/rauthy_config.rs`
- `config.toml`
- `book/src/config/bootstrap.md`
- Possibly `src/data/Cargo.toml`

## Pitfalls

- Symptom: a crash after DB insert loses generated plaintext.
  Cause: designing the container as a tail-only write.
  Recovery: keep this phase focused on write-ahead APIs that later phases can call before DB insertion.
- Symptom: CLI or tests try to fetch Vault config.
  Cause: reusing full config loading for local decrypt.
  Recovery: expose narrow local key-loading helpers.
- Symptom: file is briefly world-readable.
  Cause: write-then-chmod or plain `fs::write`.
  Recovery: create the temp file with the final mode.

## Reference

- Research dossier design clarifications: `/data/nvme0/can/Projects/nix-provenance/upstreaming/round-3/rauthy-bootstrap-generate-research.md`
