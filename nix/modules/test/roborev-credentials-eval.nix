{pkgs}: let
  inherit (pkgs) lib;
  evaluate = overrides:
    (lib.evalModules {
      specialArgs = {inherit pkgs;};
      modules = [
        ../adapter/roborev-credentials.nix
        ({lib, ...}: {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.attrs;
              default = [];
            };
            systemd.services = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule {
                options.serviceConfig = lib.mkOption {
                  type = lib.types.attrsOf lib.types.anything;
                  default = {};
                };
              });
              default = {};
            };
          };
          config = {
            nix-provenance.roborev = {
              enable = lib.mkDefault true;
              controllerUnits = lib.mkDefault ["review-controller"];
              forges = {
                github = {
                  host = "github.com";
                  tokenFile = lib.mkDefault "/run/agenix/can-github-token";
                };
                codefloe = {
                  host = "codefloe.com";
                  tokenFile = "/run/agenix/can-codefloe-token";
                };
              };
            };
            systemd.services = {
              review-controller.serviceConfig.ExecStart = "/fixture/controller";
              review-worker.serviceConfig.ExecStart = "/fixture/worker";
            };
          };
        })
        overrides
      ];
    }).config;
  enabled = evaluate {};
  valid = config: lib.all (assertion: assertion.assertion) config.assertions;
  invalidPath = path: evaluate {nix-provenance.roborev.forges.github.tokenFile = lib.mkForce path;};
  disabled = evaluate {nix-provenance.roborev.enable = false;};
  duplicate = evaluate {
    nix-provenance.roborev.forges.other = {
      host = "github.com";
      tokenFile = "/run/agenix/other";
    };
  };
  missing = evaluate {nix-provenance.roborev.controllerUnits = ["missing-controller"];};
in
  assert valid enabled;
  assert enabled.systemd.services.review-controller.serviceConfig.LoadCredential == ["roborev-codefloe:/run/agenix/can-codefloe-token" "roborev-github:/run/agenix/can-github-token"];
  assert !(enabled.systemd.services.review-worker.serviceConfig ? LoadCredential);
  assert !(disabled.systemd.services.review-controller.serviceConfig ? LoadCredential);
  assert !(valid duplicate) && !(valid missing);
  assert lib.all (path: !(valid (invalidPath path))) ["/nix/store/secret" "/run/../secret" "/run/%d/token" "/run/token:other" "relative" "/run/secret\nother"];
  assert lib.hasInfix "\"codefloe.com\":\"roborev-codefloe\"" enabled.nix-provenance.roborev.credentialManifest.text;
  assert !(lib.hasInfix "/run/agenix" enabled.nix-provenance.roborev.credentialManifest.text); {
    pass = true;
    manifest = enabled.nix-provenance.roborev.credentialManifest.text;
  }
