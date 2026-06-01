# Flake checks. Per-crate build/clippy/test, plus shared nixfmt, both module-eval
# smoke tests, the Immich patch-applies guard, and the structural guards that keep
# the TLS-feature isolation and the stripped release binary honest.
{
  pkgs,
  lib,
  nixpkgs,
  craneLib,
  src,
  self,
  system,
  packages,
  args,
  cargoArtifacts,
}: let
  inherit (pkgs) runCommand;

  mkClippy = pname:
    craneLib.cargoClippy (args.${pname}
      // {
        cargoArtifacts = cargoArtifacts.${pname};
        cargoClippyExtraArgs = "--all-targets -- --deny warnings";
      });

  evalSystem = module:
    nixpkgs.lib.nixosSystem {
      inherit system;
      specialArgs = {inherit self;};
      modules = [module];
    };

  immichEval = evalSystem ./modules/test/immich-eval.nix;
  rauthyEval = evalSystem ./modules/test/rauthy-eval.nix;

  immichPatch = ../crates/immich-provision/patches/immich/0001-add-trusted-local-provision-token.patch;
in {
  # Build both crates.
  immich-provision = packages.immich-provision;
  rauthy-provision = packages.rauthy-provision;

  # Lint each crate against its isolated deps.
  immich-clippy = mkClippy "immich-provision";
  rauthy-clippy = mkClippy "rauthy-provision";

  # Tests: immich keeps cargoTest, rauthy keeps cargoNextest (preserved semantics).
  immich-test = craneLib.cargoTest (args.immich-provision // {cargoArtifacts = cargoArtifacts.immich-provision;});
  rauthy-nextest = craneLib.cargoNextest (args.rauthy-provision // {cargoArtifacts = cargoArtifacts.rauthy-provision;});

  # Workspace-wide rustfmt.
  fmt = craneLib.cargoFmt {inherit src;};

  # Nix formatting over flake.nix + nix/ (uses the raw flake source, not the
  # Cargo-cleaned src which strips .nix files).
  nixfmt = runCommand "nix-provenance-nixfmt" {nativeBuildInputs = [pkgs.alejandra];} ''
    cp -r ${self} source
    chmod -R u+w source
    cd source
    alejandra --check flake.nix nix
    touch $out
  '';

  # Both NixOS modules must evaluate to a concrete oneshot serviceConfig.
  immich-module-eval = let
    serviceConfig = builtins.toJSON immichEval.config.systemd.services.immich-provision.serviceConfig;
  in
    runCommand "immich-module-eval" {} ''
      test -n ${lib.escapeShellArg serviceConfig}
      touch $out
    '';

  rauthy-module-eval = let
    serviceConfig = builtins.toJSON rauthyEval.config.systemd.services.rauthy-provision.serviceConfig;
  in
    runCommand "rauthy-module-eval" {} ''
      test -n ${lib.escapeShellArg serviceConfig}
      touch $out
    '';

  # The Immich patch must still apply cleanly against pkgs.immich.src.
  immich-patch-applies = runCommand "immich-patch-applies" {nativeBuildInputs = [pkgs.patch];} ''
    cp -R ${pkgs.immich.src} source
    chmod -R u+w source
    patch -d source -p1 --dry-run < ${immichPatch}
    touch $out
  '';

  # Structural guard: reqwest TLS features stay per-crate (never unioned), and
  # reqwest is never hoisted into [workspace.dependencies]. This is the cheap,
  # deterministic enforcement of the no-openssl / aarch64-safe invariant.
  tls-feature-isolation = runCommand "tls-feature-isolation" {} ''
    immich='${../crates/immich-provision/Cargo.toml}'
    rauthy='${../crates/rauthy-provision/Cargo.toml}'
    root='${../Cargo.toml}'
    grep -q 'rustls-tls"' "$immich" || { echo "immich reqwest must enable rustls-tls"; exit 1; }
    if grep -q 'native-roots' "$immich"; then echo "immich reqwest must NOT enable native-roots (TLS root drift)"; exit 1; fi
    grep -q 'rustls-tls-native-roots' "$rauthy" || { echo "rauthy reqwest must enable rustls-tls-native-roots"; exit 1; }
    if grep -qE '^[[:space:]]*reqwest[[:space:]]*=' "$root"; then echo "reqwest must NOT be hoisted into [workspace.dependencies]"; exit 1; fi
    touch $out
  '';

  # The root [profile.release] strip must actually reach the release binaries
  # (member profiles are ignored by Cargo — this proves the hoist worked).
  rauthy-binary-stripped = runCommand "rauthy-binary-stripped" {nativeBuildInputs = [pkgs.file];} ''
    if file -b ${packages.rauthy-provision}/bin/rauthy-provision | grep -q 'not stripped'; then
      echo "rauthy-provision release binary is not stripped (profile.release hoist lost?)" >&2
      exit 1
    fi
    touch $out
  '';
}
