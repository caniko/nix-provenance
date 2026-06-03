# Flake checks. Per-crate build/clippy/test, plus shared nixfmt, both module-eval
# smoke tests, the Immich patch-applies guard, and the structural guards that
# keep the TLS-feature isolation and the stripped release binary honest.
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
  docs,
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
  vikunjaEval = evalSystem ./modules/test/vikunja-eval.nix;
  forgejoEval = evalSystem ./modules/test/forgejo-eval.nix;
  stalwartEval = evalSystem ./modules/test/stalwart-eval.nix;
  adapterEval = evalSystem ./modules/test/adapter-eval.nix;
  kanidmCredentialsEval = evalSystem ./modules/test/kanidm-credentials-eval.nix;

  immichPatch = ../crates/immich-provision/patches/immich/0001-add-trusted-local-provision-token.patch;
in {
  # Build all crates.
  identity-cli = packages.identity-cli;
  immich-provision = packages.immich-provision;
  rauthy-provision = packages.rauthy-provision;
  docs = docs;
  site = docs;

  # Lint each crate against its isolated deps.
  identity-clippy = mkClippy "identity-cli";
  immich-clippy = mkClippy "immich-provision";
  rauthy-clippy = mkClippy "rauthy-provision";

  # Tests: immich keeps cargoTest, rauthy keeps cargoNextest (preserved semantics).
  identity-test = craneLib.cargoTest (args.identity-cli // {cargoArtifacts = cargoArtifacts.identity-cli;});
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

  vikunja-module-eval = let
    serviceConfig = builtins.toJSON vikunjaEval.config.systemd.services.vikunja-oidc-env.serviceConfig;
  in
    runCommand "vikunja-module-eval" {} ''
      test -n ${lib.escapeShellArg serviceConfig}
      touch $out
    '';

  forgejo-module-eval = let
    serviceConfig = builtins.toJSON forgejoEval.config.systemd.services.forgejo-seed-oidc.serviceConfig;
  in
    runCommand "forgejo-module-eval" {} ''
      test -n ${lib.escapeShellArg serviceConfig}
      touch $out
    '';

  stalwart-module-eval = let
    directory = builtins.toJSON stalwartEval.config.services.stalwart.settings.directory.kanidm;
  in
    runCommand "stalwart-module-eval" {} ''
      test -n ${lib.escapeShellArg directory}
      touch $out
    '';

  # The kanidm-credentials reconcile module must evaluate to a concrete oneshot,
  # and its reconcile script must pass shellcheck (forced by depending on the
  # built ExecStart below).
  kanidm-credentials-module-eval = let
    svc = kanidmCredentialsEval.config.systemd.services.kanidm-credentials;
    serviceConfig = builtins.toJSON svc.serviceConfig;
  in
    runCommand "kanidm-credentials-module-eval" {} ''
      test -n ${lib.escapeShellArg serviceConfig}
      test -x ${svc.serviceConfig.ExecStart}
      touch $out
    '';

  # The third-party adapter must derive the pink-raven rauthy users (can keyed by
  # kanidm login, eric/caroline emailed a set-password link) and the kanidm-backend
  # OAuth2 federation client + person, all from the uniform user schema.
  adapter-module-eval = let
    rauthyUsers = builtins.toJSON adapterEval.config.services.rauthy.provision.users;
    kanidmOauth2 = builtins.toJSON adapterEval.config.services.kanidm.provision.systems.oauth2;
    kanidmPersons = builtins.toJSON adapterEval.config.services.kanidm.provision.persons;
  in
    runCommand "adapter-module-eval" {} ''
      users=${lib.escapeShellArg rauthyUsers}
      oauth2=${lib.escapeShellArg kanidmOauth2}
      persons=${lib.escapeShellArg kanidmPersons}
      for e in can@tartanoglu.com efirley@protonmail.com carolinestahl@gmx.net; do
        printf '%s' "$users" | grep -q "$e" || { echo "adapter: rauthy user $e missing" >&2; exit 1; }
      done
      # eric + caroline get an emailed set-password link; can does not.
      printf '%s' "$users" | grep -q '"sendPasswordEmail":true' \
        || { echo "adapter: no emailed (passwordInitByEmail) rauthy user rendered" >&2; exit 1; }
      # kanidm backend rendered an OAuth2 federation client + its person.
      printf '%s' "$oauth2"  | grep -q 'internal-tool'   || { echo "adapter: kanidm oauth2 system missing" >&2; exit 1; }
      printf '%s' "$persons" | grep -q 'dejana'          || { echo "adapter: kanidm person missing" >&2; exit 1; }
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

  # License firewall: the permissive dependency graph (provenance-core and the
  # MIT/Apache rauthy crate) must never pull in the AGPL immich-provision crate,
  # and provenance-core itself must stay permissive. The one-directional boundary
  # (AGPL may consume permissive, never the reverse) is enforced structurally.
  license-firewall = runCommand "license-firewall" {} ''
    core='${../crates/provenance-core/Cargo.toml}'
    rauthy='${../crates/rauthy-provision/Cargo.toml}'
    grep -q 'license = "MIT OR Apache-2.0"' "$core" || { echo "provenance-core must be MIT OR Apache-2.0"; exit 1; }
    if grep -q 'immich-provision' "$core"; then echo "provenance-core must not depend on the AGPL immich-provision crate"; exit 1; fi
    if grep -q 'immich-provision' "$rauthy"; then echo "rauthy-provision (permissive) must not depend on the AGPL immich-provision crate"; exit 1; fi
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
