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

For Stalwart 0.16 module work, use the narrow Nix gates before running the full
flake:

```sh
nix build .#checks.x86_64-linux.stalwart-module-eval
nix build .#nixosTests.x86_64-linux.stalwart016-vmtest
nix build .#packages.x86_64-linux.stalwart016-provision
```

`stalwart-module-eval` validates the Kanidm LDAP registry object shape and
rejects legacy 0.15 TOML-era keys. `stalwart016-vmtest` boots the 0.16 JSON
bootstrap service, applies migration and listener registry documents through
`stalwart-cli`, verifies ports 25/587/993, and checks that registry provisioning
can rerun without replaying one-time migration inputs.

`nix flake check` builds the non-VM checks. Run VM tests on a KVM-enabled
Linux host using the exact `nixosTests` installables listed in `simit.toml`.
The generated `Nix installable builds` workflow runs all of them with one build at a time.

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
