# Changelog

## [Unreleased]

### Fixed

- Preserve host-owned Kanidm profiles, existing Tuwunel account reconciliation,
  and the Kanidm-only aarch64 identity CLI configuration when consuming trunk.
- Direnv loads the Rust tools and OpenCode LSP configuration through one shell,
  preventing repeated cache invalidation between the two shell loads.

### Added

- A Home Manager rbw adapter with durable private login state, guarded legacy
  migration, shared client/agent paths, and metadata-only recovery diagnostics.
- Nullable Stalwart 0.16 listener PROXY trust overrides, with explicit set,
  replace, unmanaged, and clear semantics and isolated HAProxy/mail fixtures.
- A reusable treefmt module for the repository's Alejandra formatting policy.
- Host/user-scoped OpenAI ChatGPT OAuth enrollment with serialized refresh,
  rollback fencing, encrypted recovery checkpoints, and access-only adapters for
  stock OpenCode V2 and OMP. NixOS and Home Manager modules provide runtime
  enrollment and automatic compatible-consumer bindings.
