# Changelog

## [Unreleased]

### Fixed

- Tuwunel bootstrap fixtures resolve their shell from the test environment so
  lifecycle tests run in Nix sandboxes without `/usr/bin/env`.
- Tuwunel registration bootstrap tolerates delayed asynchronous config reloads
  with bounded retries of explicit registration-disabled refusals, attempts to
  restore the closed config after failures, and never retries ambiguous
  transport errors.
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

- `proton-vpn-auth enroll --stdin --stdout` validates credential documents through
  private pipes for direct vault-to-encryption imports, including base32 and
  compatible authenticator URI normalization without plaintext files.
- Official Proton VPN clients can enroll an existing account from a private
  runtime credential document through a Home Manager module and Rust adapter,
  including TOTP, session reuse, bounded retries, and redacted errors.
- `proton-vpn-auth enroll` securely prompts for existing account credentials and
  creates a private runtime document for a consumer's secret-manager import.
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
