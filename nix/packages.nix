# Per-crate crane builders. Each crate gets its OWN isolated cargoArtifacts built
# with `-p <crate>` — NEVER a shared workspace cargoArtifacts, which would union
# immich's `rustls-tls` with rauthy's `rustls-tls-native-roots` and change the
# TLS root of trust. `args` and `cargoArtifacts` are re-exported so the checks
# reuse the exact same isolated deps (identical derivations dedup in the store).
{
  lib,
  craneLib,
  src,
}: let
  crateVersion = pname: (craneLib.crateNameFromCargoToml {cargoToml = ../crates + "/${pname}/Cargo.toml";}).version;

  mkArgs = pname: {
    inherit src pname;
    version = crateVersion pname;
    strictDeps = true;
    cargoExtraArgs = "-p ${pname}";
    # Tests run as their own checks; keep the package build lean.
    doCheck = false;
  };

  immichArgs = mkArgs "immich-provision";
  rauthyArgs = mkArgs "rauthy-provision";
  vikunjaArgs = mkArgs "vikunja-provision";
  identityArgs = mkArgs "identity-cli";

  immichDeps = craneLib.buildDepsOnly immichArgs;
  rauthyDeps = craneLib.buildDepsOnly rauthyArgs;
  vikunjaDeps = craneLib.buildDepsOnly vikunjaArgs;
  identityDeps = craneLib.buildDepsOnly identityArgs;
in {
  args = {
    immich-provision = immichArgs;
    rauthy-provision = rauthyArgs;
    vikunja-provision = vikunjaArgs;
    identity-cli = identityArgs;
  };

  cargoArtifacts = {
    immich-provision = immichDeps;
    rauthy-provision = rauthyDeps;
    vikunja-provision = vikunjaDeps;
    identity-cli = identityDeps;
  };

  packages = {
    identity-cli = craneLib.buildPackage (identityArgs
      // {
        cargoArtifacts = identityDeps;
        meta = {
          description = "Identity administration CLI for Kanidm and Bitwarden-backed workflows";
          mainProgram = "identity-cli";
          license = [lib.licenses.mpl20];
        };
      });

    immich-provision = craneLib.buildPackage (immichArgs
      // {
        cargoArtifacts = immichDeps;
        meta = {
          description = "Declarative Immich identity provisioning for NixOS and Kanidm";
          mainProgram = "immich-provision";
          license = [lib.licenses.agpl3Only];
        };
      });

    rauthy-provision = craneLib.buildPackage (rauthyArgs
      // {
        cargoArtifacts = rauthyDeps;
        meta = {
          description = "Declarative provisioning client for Rauthy (users, groups, roles, OIDC clients)";
          mainProgram = "rauthy-provision";
          license = with lib.licenses; [mit asl20];
        };
      });

    vikunja-provision = craneLib.buildPackage (vikunjaArgs
      // {
        cargoArtifacts = vikunjaDeps;
        meta = {
          description = "Declarative provisioning client for Vikunja teams and memberships";
          mainProgram = "vikunja-provision";
          license = with lib.licenses; [mit asl20];
        };
      });
  };
}
