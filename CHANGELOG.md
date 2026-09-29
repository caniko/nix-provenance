# Changelog

## [Unreleased]

### Fixed

- Direnv loads the Rust tools and OpenCode LSP configuration through one shell,
  preventing repeated cache invalidation between the two shell loads.

### Added

- A reusable treefmt module for the repository's Alejandra formatting policy.
