# Changelog

## [Unreleased]

### Fixed

- Compose the pinned Harbor Nix, TOML and Rust formatters through one treefmt
  wrapper shared by the development shell, flake check and Simit-generated CI.
- Load the existing lock-pinned development shell without fallback, lock updates,
  or mutable sibling LSP inputs.
- Regenerate member release workflows with credential-free signed-tag archives,
  independent environment-bound trusted publication, and distinct CI names.
- Preserve host-owned Kanidm profiles, existing Tuwunel account reconciliation,
  and the Kanidm-only aarch64 identity CLI configuration when consuming trunk.
- Direnv loads the Rust tools and OpenCode LSP configuration through one shell,
  preventing repeated cache invalidation between the two shell loads.

### Added

- A reusable treefmt module for the repository's Alejandra formatting policy.
- Host/user-scoped OpenAI ChatGPT OAuth enrollment with serialized refresh,
  rollback fencing, encrypted recovery checkpoints, and access-only adapters for
  stock OpenCode V2 and OMP. NixOS and Home Manager modules provide runtime
  enrollment and automatic compatible-consumer bindings.
