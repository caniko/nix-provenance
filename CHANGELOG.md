# Changelog

## [Unreleased]

### Fixed

- Preserve host-owned Kanidm profiles, existing Tuwunel account reconciliation,
  and the Kanidm-only aarch64 identity CLI configuration when consuming trunk.
- Direnv loads the Rust tools and OpenCode LSP configuration through one shell,
  preventing repeated cache invalidation between the two shell loads.

### Added

- `github-provision` and `homeModules.github`: per-account Home Manager user
  units that reconcile a GitHub account's SSH and OpenPGP public keys, invite
  collaborators to owned or named repositories, and accept invitations only
  from trusted owners. Runs on activation, token rotation, and daily.

- A reusable treefmt module for the repository's Alejandra formatting policy.
- Host/user-scoped OpenAI ChatGPT OAuth enrollment with serialized refresh,
  rollback fencing, encrypted recovery checkpoints, and access-only adapters for
  stock OpenCode V2 and OMP. NixOS and Home Manager modules provide runtime
  enrollment and automatic compatible-consumer bindings.
