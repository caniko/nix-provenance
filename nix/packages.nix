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

  # Like mkArgs but with an explicit version (avoids crateNameFromCargoToml
  # path resolution issues when the Cargo.toml is not at the workspace root).
  buildArgs = pname: ver: {
    inherit src;
    pname = pname;
    version = ver;
    strictDeps = true;
    cargoExtraArgs = "-p ${pname}";
    doCheck = false;
  };

  immichArgs = mkArgs "immich-provision";
  kanidmStateRenderArgs = mkArgs "kanidm-state-render";
  rauthyArgs = mkArgs "rauthy-provision";
  rauthyStateRenderArgs = mkArgs "rauthy-state-render";
  vikunjaArgs = mkArgs "vikunja-provision";
  identityArgs = mkArgs "identity-cli";
  # stalwart016-provision uses explicit version because crateNameFromCargoToml
  # may not resolve the cargoToml path across evaluation contexts.
  stalwartProvisionArgs = buildArgs "stalwart016-provision" "0.1.0";

  immichDeps = craneLib.buildDepsOnly immichArgs;
  kanidmStateRenderDeps = craneLib.buildDepsOnly kanidmStateRenderArgs;
  rauthyDeps = craneLib.buildDepsOnly rauthyArgs;
  rauthyStateRenderDeps = craneLib.buildDepsOnly rauthyStateRenderArgs;
  vikunjaDeps = craneLib.buildDepsOnly vikunjaArgs;
  identityDeps = craneLib.buildDepsOnly identityArgs;
  stalwartProvisionDeps = craneLib.buildDepsOnly stalwartProvisionArgs;
in {
  args = {
    immich-provision = immichArgs;
    kanidm-state-render = kanidmStateRenderArgs;
    rauthy-provision = rauthyArgs;
    rauthy-state-render = rauthyStateRenderArgs;
    vikunja-provision = vikunjaArgs;
    identity-cli = identityArgs;
    stalwart016-provision = stalwartProvisionArgs;
  };

  cargoArtifacts = {
    immich-provision = immichDeps;
    kanidm-state-render = kanidmStateRenderDeps;
    rauthy-provision = rauthyDeps;
    rauthy-state-render = rauthyStateRenderDeps;
    vikunja-provision = vikunjaDeps;
    identity-cli = identityDeps;
    stalwart016-provision = stalwartProvisionDeps;
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

    kanidm-state-render = craneLib.buildPackage (kanidmStateRenderArgs
      // {
        cargoArtifacts = kanidmStateRenderDeps;
        meta = {
          description = "Offline generic renderer for kanidm-provision JSON";
          mainProgram = "kanidm-state-render";
          license = with lib.licenses; [mit asl20];
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

    rauthy-state-render = craneLib.buildPackage (rauthyStateRenderArgs
      // {
        cargoArtifacts = rauthyStateRenderDeps;
        meta = {
          description = "Offline generic renderer for rauthy-provision state JSON";
          mainProgram = "rauthy-state-render";
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

    stalwart016-provision = craneLib.buildPackage (stalwartProvisionArgs
      // {
        cargoArtifacts = stalwartProvisionDeps;
        meta = {
          description = "Recovery-mode provisioner for Stalwart Mail Server 0.16";
          mainProgram = "stalwart016-provision";
          license = with lib.licenses; [mit asl20];
        };
      });
  };
}
