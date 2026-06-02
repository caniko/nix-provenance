# Phase 04 — canix subsumes the `identity-cli` library

> **Recommended Codex model: GPT 5.5 medium**
>
> Moderate cross-repo coding: add a (git/path) Cargo dependency on the nix-provenance
> `identity-cli` lib and re-expose its commands under a canix subcommand, matching
> canix's existing CLI conventions. The judgment is in the dependency mechanism
> (git pin vs path) and clap wiring, not algorithms. `low` would likely mis-wire the
> cross-repo dep or the feature flags; `high`/`max` is unwarranted.

## Working tree

`/data/nvme0/can/Projects/canix` — the canix CLI crate at `cli/`. **Depends on
Phases 01–03**: the `identity-cli` library API (the public fns in `kanidm.rs` /
`bitwarden.rs`) must be stable and, for a git dependency, pushed to nix-provenance
`trunk` on codeberg (`git+ssh://git@codeberg.org/caniko/nix-provenance.git`). Runs
in parallel with Phase 05 (different repo paths). Note: canix's working tree
already carries unrelated in-flight changes — touch only `cli/` here.

## Goal

canix's CLI depends on the nix-provenance `identity-cli` **library** and exposes
its provisioning + Bitwarden-export commands under a canix subcommand (e.g.
`canix secret kanidm provision …` and `canix secret kanidm export-bitwarden …`),
selecting the features canix wants. `canix secret kanidm --help` lists the
commands; `cargo build` (in `cli/`) and `nix build .#canix` succeed; running a
command behaves identically to the standalone `identity-cli`.

## Why this matters now

The user's explicit requirement: "implement in a way that allows canix to subsume
the nix-provenance implementation." The library-first structure from Phase 01 makes
the implementation reusable; this phase realizes the subsumption so the credential
tooling is available from the canix operator CLI alongside its other secret commands.

## Out of scope

- Changing the `identity-cli` library itself — if its API is awkward to consume,
  note it for a follow-up; do not fork logic into canix.
- The Stalwart cutover / any deploy (Phase 05). canix's `root/` Nix is untouched here.
- Re-implementing kanidm/bitwarden logic in canix — canix must call the lib, not
  duplicate it.

## Plan

1. **Add the dependency.** In `cli/Cargo.toml`, add `identity-cli` as a dependency:
   - dev/iteration: a `path` dependency if a local nix-provenance checkout is
     available to the canix build;
   - release: a `git` dependency pinned to a nix-provenance `trunk` rev
     (`identity-cli = { git = "ssh://git@codeberg.org/caniko/nix-provenance.git", rev = "…", default-features = false, features = ["kanidm","bitwarden"] }`).
   Respect canix's existing admin/non-admin feature split (the `secret age` commands
   are `#[cfg(feature = "admin")]`) — gate the new commands under `admin` too.
2. **Wire the subcommand.** Following canix's command-module pattern
   (`cli/src/commands/…`, each a `<Name>Cmd` enum with `run()`), add the kanidm
   provisioning commands under the existing `secret` group (e.g.
   `cli/src/commands/repo/secrets.rs` or a new `secrets/kanidm.rs`). Each variant
   parses canix-native args (resolve host/url, idm_admin password via canix's agenix
   path helpers) and calls the `identity-cli` library fns.
3. **Feature selection.** Enable `identity-cli`'s `kanidm` + `bitwarden` features
   from canix; ensure `nix build .#canix` and the dev shell still build (mind the
   reqwest/TLS feature isolation — keep `identity-cli`/`kanidm_client` out of any
   shared workspace dep hoisting on the canix side too).
4. **Verify:** `cargo build` in `cli/` (or `nix run /…/canix#canix -- secret kanidm --help`),
   `cargo clippy`, `nix build .#canix`; run `canix secret kanidm provision --help` and
   confirm it mirrors `identity-cli kanidm provision`.

## Acceptance criteria

- [ ] `cli/Cargo.toml` depends on `identity-cli` (git-pinned for release) with the `kanidm`+`bitwarden` features; `Cargo.lock` updated.
- [ ] `cargo build` in `cli/` and `nix build .#canix` succeed; `nix flake check` (canix) does not regress.
- [ ] `canix secret kanidm --help` lists `provision` and the Bitwarden export command; `canix secret kanidm provision --help` shows the same options as the standalone tool.
- [ ] A dry `canix secret kanidm provision <throwaway> --with-totp` (gated; user go-ahead) behaves identically to `identity-cli`.
- [ ] No kanidm/bitwarden logic is duplicated in canix — it only calls the lib (grep: canix has no `idm_account_credential_update` calls of its own).

## Files likely touched

- canix `cli/Cargo.toml`, `cli/Cargo.lock`
- canix `cli/src/commands/…` (a new module + registration in `cli/src/cli.rs` / the `secret` group)

## Pitfalls

- **git-dep auth/rev churn (symptom: `nix build .#canix` can't fetch identity-cli).**
  A `git+ssh` dep needs the rev present on codeberg `trunk` and the build to have SSH
  access; pin a concrete rev and ensure Phases 01–03 are pushed first. For local
  iteration use a `path` dep, but don't commit the path dep for release.
- **Feature-flag double-vision (symptom: canix builds the CLI without admin commands,
  so `secret kanidm` is absent).** canix gates admin commands behind its `admin`
  feature (`packages.canix-admin`); register the new commands under the same gate, and
  test the build that canix actually installs.
- **reqwest TLS union on the canix side (symptom: an unrelated canix HTTP client's
  trust roots change).** Keep `identity-cli`/`kanidm_client` deps member-local in
  `cli/`, not hoisted into any canix workspace deps.

## Reference

- Plan index: [README.md](README.md). Consumes the lib from [01](01-scaffold-identity-cli.md)–[03](03-bitwarden-export.md).
- canix CLI conventions: the `canix-cli` skill; `cli/src/{cli.rs,commands/}`; the
  `secret age` admin-feature pattern in `cli/src/commands/repo/secrets.rs`.
- nix-provenance flake input already present in canix `flake.nix` as `nix-provenance`.
</content>
