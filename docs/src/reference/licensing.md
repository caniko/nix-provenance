# Licensing

`nix-provenance` is a **mixed-license monorepo**. Each crate and each
origin-specific file carries its own SPDX identifier; there is no single
repo-wide license. Per-path SPDX is machine-readable in `REUSE.toml` in the
repository root.

| Path | License | Origin |
|------|---------|--------|
| `crates/immich-provision/**` | `AGPL-3.0-only` | immich-provision |
| `crates/rauthy-provision/**` | `MIT OR Apache-2.0` | rauthy-provision |
| `crates/vikunja-provision/**` | `MIT OR Apache-2.0` | vikunja-provision |
| `crates/provenance-core/**` | `MIT OR Apache-2.0` | nix-provenance (shared core) |
| `nix/lib/immich.nix`, `nix/modules/service-oidc/immich.nix`, `nix/modules/test/immich-eval.nix`, `docs/rfcs/**`, `docs/kanidm-oidc-migration.md`, `docs/src/guides/kanidm-oidc-migration.md`, `docs/src/rfcs/**` | `AGPL-3.0-only` | immich-provision |
| `nix/lib/rauthy.nix`, `nix/modules/idp/rauthy.nix` | `MIT OR Apache-2.0` | rauthy-provision |
| `nix/modules/service-oidc/vikunja.nix`, `nix/modules/test/vikunja-provision-eval.nix` | `MIT OR Apache-2.0` | vikunja-provision |
| `docs/adapter-external-apps.md`, `docs/src/guides/external-apps.md` | `MIT OR Apache-2.0` | nix-provenance |
| everything else (`flake.nix`, `nix/lib/default.nix`, `nix/packages.nix`, `nix/checks.nix`, root files, `docs/book.toml`, `docs/architecture.md`, `docs/src/{SUMMARY.md,introduction.md,getting-started/**,concepts/**,reference/**}`, `.forgejo/**`) | `MIT OR Apache-2.0` | nix-provenance |

## The permissive-core rule

Any code shared by **both** the AGPL `immich-provision` crate and the
permissive `rauthy-provision` crate, namely `crates/provenance-core`, **must**
be `MIT OR Apache-2.0` or looser:

- the permissive rauthy crate cannot link AGPL code
- the AGPL immich crate can consume permissive code

The boundary is one-directional. A `license-firewall` flake check enforces that
`rauthy-provision`'s dependency closure contains no AGPL crate, and that
`provenance-core` stays `MIT OR Apache-2.0`. When extracting generic helpers
into `provenance-core`, any code that originated in the AGPL immich crate must
be clean-room reimplemented rather than copied.
