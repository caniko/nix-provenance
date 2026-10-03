# Changelog

## [Unreleased]

### Fixed

- Identity CLI featureless and Bitwarden-only builds no longer pull in the
  Kanidm-only generated-secret dependency and its TLS-dependent HTTP helper;
  the Forgejo OIDC secret binary correctly requires the Kanidm feature.
- Room-owner login reuses the initialized HTTP transport so construction cannot
  fail between login and the reconciliation/logout path.
- Private-room verification no longer mistakes unrelated state events for
  encryption or access policy.
- Direnv now uses the locked flake inputs without requiring a sibling
  nix-opencode-lsp checkout.
- Preserve host-owned Kanidm profiles, existing Tuwunel account reconciliation,
  and the Kanidm-only aarch64 identity CLI configuration when consuming trunk.
- Direnv loads the Rust tools and OpenCode LSP configuration through one shell,
  preventing repeated cache invalidation between the two shell loads.

### Added

- Protocol regression tests and a disposable Tuwunel VM gate cover private-room
  creation, observed-ID pinning, unsafe-state rejection and device logout.
- Tuwunel can create initially encrypted, invite-only rooms as a declared
  service account, verify live membership, and pin their observed room IDs.
  Reconciliation refuses alias drift and unsuitable existing rooms and logs
  out the room-provisioning device after either success or failure.
- A reusable treefmt module for the repository's Alejandra formatting policy.
- Host/user-scoped OpenAI ChatGPT OAuth enrollment with serialized refresh,
  rollback fencing, encrypted recovery checkpoints, and access-only adapters for
  stock OpenCode V2 and OMP. NixOS and Home Manager modules provide runtime
  enrollment and automatic compatible-consumer bindings.
