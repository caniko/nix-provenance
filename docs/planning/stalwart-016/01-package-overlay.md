# Phase 01 — Stalwart 0.16.7 package overlay + binary introspection

> **Recommended Codex model: GPT 5.4 medium**
>
> Moderate-complexity, well-bounded build work (recompute two Nix hashes, drop a
> patch, build under emulation) plus a bounded introspection pass over the new
> binary's CLI. It's a leaf/sub-agent role with a known recipe, not a design or
> orchestration task — `5.4 medium` holds the bar. A smaller model would stumble on
> the cargo-vendor hash dance and the emulated-build feedback loop; `5.5`/`high`
> would be wasted on what is essentially packaging + `--help` reading.

## Working tree

`/data/nvme0/can/Projects/nix-provenance`. This phase adds a local overlay/package;
it does not touch canix or `thething`. The overlay lives in nix-provenance so it is
modular and consumed by canix later (canix already pins nix-provenance and applies
its overlays).

## Goal

A `nix build`-able **Stalwart 0.16.7** package (and **stalwart-cli 1.0.0**) exposed
from nix-provenance as an overlay over the pinned nixpkgs `stalwart` attr, building
cleanly for **aarch64** (thething's arch), with the 0.16.0-specific patch dropped.
Plus a short, evidence-backed note on the binary's CLI surface (recovery mode, the
bootstrap config it expects) that seeds phase 02.

## Why this matters now

Nothing downstream can be validated without a real 0.16.7 binary. nixpkgs ships
0.15.5; **PR #512341 packages 0.16.0, not 0.16.7, and is blocked** (it bumps the
package without rewriting the now-incompatible TOML-rendering NixOS module). The
PR's `src`/`cargoHash` are for v0.16.0 and its `0001-fix-missing-Duration-import.patch`
is a 0.16.0-specific compile fix that will not apply to 0.16.7. So we derive 0.16.7
ourselves. The CLI also split into its own repo at v1.0.0 — the data migration in
phase 06 uses `stalwart-cli apply`, so it must be packaged too.

## Out of scope

- Any NixOS module work (that is phase 03) — do **not** try to make `services.stalwart`
  consume this yet; the pinned module emits TOML and is incompatible.
- Deploying to `thething` or touching canix.
- Recreating the migration patch behaviour: just drop the Duration patch and verify
  0.16.7 builds without it (if 0.16.7 needs its *own* patch, document it, don't
  invent one).

## Plan

1. Read the v0.16.0 package expression for reference: `pkgs/by-name/st/stalwart/package.nix`
   (and `pkgs/by-name/st/stalwart-cli/package.nix`) from nixpkgs PR #512341
   (head `imincik:stalwart-0.16.0`) — for the build structure (`buildFeatures`,
   `fetchCargoVendor`/`cargoDeps`, the `stalwartEnterprise` override, test skips).
   Get them via `gh` / the GitHub API, or `nix-prefetch`/`builtins.fetchGit` the
   head commit `00b84fd139970c0303436a461a9bc27e584407ae`.
2. Decide the overlay shape. Two options; prefer (a):
   - **(a) `overrideAttrs` over the pinned `stalwart`** — bump `version = "0.16.7"`,
     `src = fetchFromGitHub { owner="stalwartlabs"; repo="stalwart"; tag="v0.16.7"; hash=…; }`,
     `cargoDeps = rustPlatform.fetchCargoVendor { inherit src; hash=…; }`, `patches = []`.
   - **(b) vendor `package.nix`** into nix-provenance and `callPackage` it (cleaner
     if `overrideAttrs` fights `fetchCargoVendor`/`buildFeatures`).
   Add the result to nix-provenance's overlay surface (`overlays.default` in
   `flake.nix`, or a dedicated `overlays.stalwart016`).
3. Compute the **0.16.7 src hash**: `nix-prefetch-url --unpack https://github.com/stalwartlabs/stalwart/archive/refs/tags/v0.16.7.tar.gz` (or a fake-hash build and read the "got:" line).
4. Compute the **cargo-vendor hash**: set a fake `cargoDeps` hash, build, read the
   expected hash from the failure, pin it.
5. Package **stalwart-cli 1.0.0** from `stalwartlabs/cli` tag `v1.0.0`. The PR's
   known-good hashes are reusable: src `sha256-xTxOYbPZ7zkweuuTJx3Alqig74KiD67i+TRzh1BZXa4=`,
   cargo `sha256-Z5MDM5nJvjQJ9PpS07LbUc9FjVuwhRguchakjwypSDo=` (verify they still apply).
6. Build aarch64 under emulation:
   `nix build .#packages.aarch64-linux.<attr> --extra-platforms aarch64-linux`
   (the dev host has `extra-platforms = aarch64-linux` + binfmt). Also build the
   native x86_64 for fast introspection.
7. **Introspect** the x86_64 binary (seeds phase 02; keep evidence): run
   `stalwart --help`, `stalwart server --help` (or equivalent), look for recovery-mode
   env (`STALWART_RECOVERY_MODE`, `STALWART_RECOVERY_ADMIN`), the `-c/--config` flag
   and what file it expects (the JSON `DataStore` bootstrap — confirm against the
   source `crates/store/src/registry/local.rs` and `crates/common/src/manager/boot.rs`),
   and `stalwart-cli --help` / `stalwart-cli apply --help`. Write findings to a short
   note for phase 02 (e.g. `docs/planning/stalwart-016/notes/01-binary-introspection.md`).

## Acceptance criteria

- [ ] `nix build .#packages.aarch64-linux.<stalwart-attr> --extra-platforms aarch64-linux`
      succeeds and the result reports version **0.16.7** (`<out>/bin/stalwart --version`
      under emulation, or the derivation `version`).
- [ ] `nix build` of the **stalwart-cli 1.0.0** attr succeeds (both arches).
- [ ] The derivation has **no `0001-fix-missing-Duration-import.patch`** (`patches = []`),
      and the build is clean without it (or, if 0.16.7 genuinely needs a patch, the
      replacement patch is committed with a one-line rationale).
- [ ] The overlay is exposed from nix-provenance's flake (an overlay attr) and a
      `nix flake check`-level eval of it passes.
- [ ] `docs/planning/stalwart-016/notes/01-binary-introspection.md` exists and records:
      the `--config` flag + expected bootstrap-file shape, the recovery-mode env vars,
      and the `stalwart-cli` subcommands (incl. `apply`), each with the command output
      or source citation it came from.

## Files likely touched

- `flake.nix` (nix-provenance) — add the stalwart-0.16.7 overlay attr (and stalwart-cli).
- `nix/overlays/stalwart-016.nix` *(new)* or `nix/packages.nix` — the override/package expr.
- `docs/planning/stalwart-016/notes/01-binary-introspection.md` *(new)* — introspection note.

## Pitfalls

- **Wrong/stale hashes.** The PR's v0.16.0 src+cargo hashes do NOT apply to 0.16.7 —
  you must recompute both. Symptom: hash-mismatch build error. Recovery: fake-hash →
  read expected → pin.
- **Duration patch fails to apply.** It's 0.16.0-specific. Symptom: `patch` hunk
  failure. Recovery: drop it (`patches = []`); only re-add a patch if 0.16.7 itself
  fails to compile, and document why.
- **`fetchCargoVendor` vs `overrideAttrs`.** Overriding `cargoDeps` via `overrideAttrs`
  can be finicky if the package computes it internally. Recovery: fall back to
  vendoring `package.nix` (option 2b) so you own `cargoDeps` directly.
- **Emulated build is slow / RAM-heavy.** kanidm-scale Rust trees under qemu take a
  while. Build x86_64 first for fast iteration on hashes/patch; only do the aarch64
  emulated build once x86_64 is green. Do **not** offload to thething (production
  RAM pressure).
- **`buildFeatures`/enterprise.** The package may default to non-enterprise features;
  keep parity with the PR's feature set unless you have a reason to change it.

## Reference

- Migration spec + source citations: `stalwart-016-ldap-migration` workflow output
  (`…/tasks/wkd5kkpy3.output`), `pr` + `consumptionRecommendation` sections.
- Memory: `stalwart-016-config-rearchitecture`.
- nixpkgs PR #512341 (head `imincik:stalwart-0.16.0`, commit `00b84fd1…`); upstream
  `stalwartlabs/stalwart` tag `v0.16.7`, `stalwartlabs/cli` tag `v1.0.0`.
- Next: phase 02 consumes the binary + the introspection note.
</content>
