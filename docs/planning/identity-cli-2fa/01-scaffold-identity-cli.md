# Phase 01 — Scaffold the `identity-cli` crate (lib + bin, feature flags, flake, licensing)

> **Recommended Codex model: GPT 5.5 medium**
>
> Moderate-complexity foundational coding: a new workspace member, clap skeleton,
> Nix package/check wiring, and SPDX bookkeeping — mostly mechanical. The one real
> judgment call is resolving the `kanidm_client` crates.io version that speaks the
> running server's 1.10.x protocol; that needs a careful look but not frontier
> reasoning. A `low` tier would likely fumble the version-compat reasoning and the
> reqwest-feature-isolation caveat; `high`/`max` would be wasted here.

## Working tree

`/data/nvme0/can/Projects/nix-provenance` (this repo). New crate only — no other
phase has started, so the tree is clean.

## Goal

A new workspace member `crates/identity-cli` builds as both a library and a thin
binary, links `kanidm_client`/`kanidm_proto` at a version that speaks the running
kanidm **1.10.3** protocol, exposes Cargo **feature flags** (`kanidm`, `bitwarden`,
`default = ["kanidm","bitwarden"]`), is packaged in the flake (`packages.<sys>.identity-cli`)
and checked (clippy/test), and has its licensing recorded. `nix build .#identity-cli`
and `cargo build -p identity-cli` succeed; `identity-cli --help` lists
feature-gated (stub) subcommands `kanidm` and `bitwarden`.

## Why this matters now

This is the foundation for the whole `identity-cli-2fa` plan: the kanidm
provisioning (Phase 02) and Bitwarden export (Phase 03) both need the crate, its
deps, and its feature-flag layout in place. The biggest project risk —
`kanidm_client` protocol/version compatibility with the live server — is resolved
here, before any provisioning logic is written, so 02 doesn't discover a dead-end
dependency mid-flight.

## Out of scope

- Any actual kanidm provisioning logic (Phase 02) or Bitwarden logic (Phase 03) —
  this phase ships **stub** subcommands that print "not yet implemented".
- canix changes (Phase 04) or any deploy (Phase 05).
- Do not add `reqwest`, `kanidm_client`, or `spow` to the **workspace**
  `[workspace.dependencies]` — keep them member-local (see Pitfalls).

## Plan

1. **Resolve the kanidm_client version.** The server is
   `pkgs.kanidmWithSecretProvisioning_1_10` = **1.10.3**. kanidm publishes
   `kanidm_client` + `kanidm_proto` to crates.io; client/server must match the
   protocol. Find the published crate version corresponding to server 1.10.3
   (check crates.io `kanidm_client` versions and the kanidm release mapping; the
   in-tree source has `version = { workspace = true }` resolving to the kanidm
   workspace version). Record the chosen `=x.y.z` pin and a one-line note on how
   it was verified. If no published version matches, fall back to a `git`
   dependency on the kanidm repo at the `v1.10.3` tag.
2. **Create `crates/identity-cli/Cargo.toml`:**
   - `name = "identity-cli"`, `edition`/`rust-version` inherited from
     `[workspace.package]`.
   - `[lib]` + `[[bin]] name = "identity-cli"`.
   - deps (member-local): `clap.workspace = true`, `anyhow.workspace = true`,
     `serde.workspace = true`, `serde_json.workspace = true`, `tokio` (rt + macros),
     and **behind features**: `kanidm_client`/`kanidm_proto` (pinned per step 1) +
     `totp-rs` under `kanidm`; nothing extra under `bitwarden` (shells out to `bw`).
   - `[features] default = ["kanidm", "bitwarden"]`, `kanidm = ["dep:kanidm_client", "dep:kanidm_proto", "dep:totp-rs"]`, `bitwarden = []`.
3. **Create `src/lib.rs`** exposing a small public API surface (modules
   `kanidm` and `bitwarden`, each `#[cfg(feature)]`-gated, with stub public
   functions) so Phase 04 can call the library directly.
4. **Create `src/main.rs`**: a clap `derive` CLI with top-level subcommands
   `Kanidm(...)` (`#[cfg(feature = "kanidm")]`) and `Bitwarden(...)`
   (`#[cfg(feature = "bitwarden")]`), each dispatching to a stub that prints
   "not yet implemented" and exits non-zero. `tokio::main` if any feature is async.
5. **Add to the workspace:** append `"crates/identity-cli"` to `members` in the
   root `Cargo.toml`; `cargo build` to refresh `Cargo.lock`.
6. **Flake wiring:** add an `identity-cli` package to `nix/packages.nix` (mirror
   how `immich-provision`/`rauthy-provision` crates are built via `craneLib`) and a
   clippy/test check in `nix/checks.nix`. Verify the crate name maps to a
   `packages.<system>.identity-cli` output.
7. **Licensing:** pick an SPDX license for the crate (MPL-2.0 is the safe match for
   `kanidm_client`'s MPL-2.0); add the crate path to `REUSE.toml` and document it in
   `LICENSING.md`'s per-path map / permissive-core rule.
8. Verify: `cargo build -p identity-cli`, `cargo clippy -p identity-cli -- -D warnings`,
   `nix build .#identity-cli`, `./result/bin/identity-cli --help`.

## Acceptance criteria

- [ ] `cargo build -p identity-cli` and `cargo build --no-default-features -p identity-cli` both succeed (proves feature isolation).
- [ ] `cargo clippy -p identity-cli -- -D warnings` reports zero warnings.
- [ ] `nix build .#identity-cli` produces `result/bin/identity-cli`; `--help` shows `kanidm` and `bitwarden` subcommands.
- [ ] `kanidm_client`/`kanidm_proto` are pinned to a version verified against server 1.10.3, with the verification note in the Cargo.toml comment or `LICENSING.md`.
- [ ] `nix flake check --no-build` passes (the new crate's check evaluates).
- [ ] `REUSE.toml` + `LICENSING.md` cover `crates/identity-cli/`; `reuse lint` (or the repo's existing license check) passes.

## Files likely touched

- `crates/identity-cli/Cargo.toml`, `crates/identity-cli/src/lib.rs`, `crates/identity-cli/src/main.rs`
- `Cargo.toml` (workspace `members`), `Cargo.lock`
- `nix/packages.nix`, `nix/checks.nix`
- `REUSE.toml`, `LICENSING.md`

## Pitfalls

- **reqwest TLS-feature union (symptom: rauthy's root-of-trust silently changes /
  immich links spow).** The workspace `Cargo.toml` comment explicitly warns: do not
  hoist `reqwest`; immich uses `rustls-tls`, rauthy `rustls-tls-native-roots`, and a
  unified lock unions them. `kanidm_client` pulls reqwest — keep it (and any
  reqwest features) **member-local** to `identity-cli`, never in `[workspace.dependencies]`.
  Recovery: if the lock starts changing rauthy/immich features, move the dep back
  into the member manifest.
- **kanidm_client version mismatch (symptom: protocol/JSON errors at runtime in
  Phase 02, not at build).** A wrong version compiles but fails against the live
  server. Resolve and verify the version *here*, not in 02.
- **crane source filter excludes the new crate (symptom: `nix build .#identity-cli`
  can't find the crate).** Confirm `nix/packages.nix`'s `cleanCargoSource`/workspace
  set includes the new member; mirror the existing two crates exactly.
- **Feature plumbing (symptom: `--no-default-features` build fails on missing
  `kanidm_client` types).** Gate every kanidm/bitwarden `use` and module with
  `#[cfg(feature = …)]`; the stub binary must compile with any feature subset.

## Reference

- Plan index: [README.md](README.md). Next: [02-kanidm-provision-command.md](02-kanidm-provision-command.md), [03-bitwarden-export.md](03-bitwarden-export.md).
- Existing crate manifests to mirror: `crates/rauthy-provision/Cargo.toml` (has `[[bin]]` + clap), `crates/immich-provision/Cargo.toml`.
- Flake build pattern: `nix/packages.nix`, `flake.nix` (`craneLib`).
- kanidm 1.10.3 client crate (for version/API confirmation): `/nix/store/akp98h1lkc1icbq78rvkmsp9ndjd345g-source/libs/client/Cargo.toml`.
</content>
