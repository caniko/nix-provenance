# Development

## Prerequisites

- Nix with flakes enabled
- Rust `1.82` or newer for workspace development

The development shell includes `cargo-nextest`, `rust-analyzer`, `jq`,
`alejandra`, and `mdbook`.

## Enter the dev shell

```sh
nix develop
```

## Common validation commands

From the repository root:

```sh
cargo test
nix flake check --no-build
nix build .#immich-provision
nix build .#rauthy-provision
nix build .#docs
nix build .#site
nix flake check
```

`nix build .#docs` and `nix build .#site` produce the same deployable mdBook
output.

## Local docs preview

```sh
cd docs
mdbook serve
```

## Repository structure

- `crates/provenance-core`: shared reconciler plumbing
- `crates/immich-provision`: Immich reconciler plus patch assets
- `crates/rauthy-provision`: Rauthy reconciler
- `nix/modules/`: NixOS modules grouped by tenant kind
- `nix/lib/`: shared Nix helper functions
- `docs/`: durable documentation and the mdBook source
