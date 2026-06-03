# Licensing

`nix-provenance` is a **mixed-license monorepo**. Each crate and each
origin-specific file carries its own SPDX identifier; there is no single
repo-wide license. Per-path SPDX is machine-readable in
[`REUSE.toml`](REUSE.toml) (REUSE 3.0).

| Path | License | Origin |
|------|---------|--------|
| `crates/immich-provision/**` | `AGPL-3.0-only` | immich-provision |
| `crates/identity-cli/**` | `MPL-2.0` | identity-cli (Kanidm client-compatible) |
| `crates/rauthy-provision/**` | `MIT OR Apache-2.0` | rauthy-provision |
| `crates/provenance-core/**` | `MIT OR Apache-2.0` | nix-provenance (shared core) |
| `nix/lib/immich.nix`, `nix/modules/service-oidc/immich.nix`, `nix/modules/test/immich-eval.nix`, `docs/kanidm-oidc-migration.md`, `docs/src/guides/kanidm-oidc-migration.md`, `docs/src/rfcs/**` | `AGPL-3.0-only` | immich-provision |
| `nix/lib/rauthy.nix`, `nix/modules/idp/rauthy.nix`, `nix/modules/test/rauthy-eval.nix` | `MIT OR Apache-2.0` | rauthy-provision |
| `docs/adapter-external-apps.md`, `docs/src/guides/external-apps.md` | `MIT OR Apache-2.0` | nix-provenance |
| everything else (`flake.nix`, `nix/lib/default.nix`, `nix/packages.nix`, `nix/checks.nix`, root files, `.gitkeep` placeholders, `docs/book.toml`, `docs/architecture.md`, `docs/planning/**`, `docs/src/{SUMMARY.md,introduction.md,getting-started/**,concepts/**,reference/**}`, `.forgejo/**`) | `MIT OR Apache-2.0` | nix-provenance |

## The permissive-core rule

Any code shared by **both** the AGPL `immich-provision` crate and the permissive
`rauthy-provision` crate — i.e. `crates/provenance-core` — **MUST** be
`MIT OR Apache-2.0` (or looser):

- the `MIT OR Apache-2.0` rauthy crate **cannot** link AGPL code;
- the `AGPL-3.0-only` immich crate **can** consume permissive code.

The boundary is therefore one-directional. A `license-firewall` flake check
enforces that `rauthy-provision`'s dependency closure contains no AGPL crate, and
that `provenance-core`'s declared license is `MIT OR Apache-2.0`. When extracting
generic helpers into `provenance-core`, any code that originated in the AGPL
immich crate must be **clean-reimplemented**, never copied, so no AGPL source
text is relicensed.
