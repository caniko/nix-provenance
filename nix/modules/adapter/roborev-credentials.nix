{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.nix-provenance.roborev;
  credentialName = name: "roborev-${name}";
  manifest = pkgs.writeText "roborev-forge-credentials.json" (builtins.toJSON {
    schemaVersion = 1;
    forges = lib.mapAttrs' (name: binding: lib.nameValuePair binding.host (credentialName name)) cfg.forges;
  });
  literalRuntimePath = value:
    lib.hasPrefix "/" value
    && value != "/nix/store"
    && !lib.hasPrefix "/nix/store/" value
    && !lib.hasInfix "//" value
    && !lib.hasInfix "/../" "${value}/"
    && !lib.hasInfix "/./" "${value}/"
    && builtins.match ".*[[:cntrl:]].*" value == null
    && !(lib.any (char: lib.hasInfix char value) [":" "%" "\\"]);
  safeName = value: builtins.match "[a-zA-Z0-9][a-zA-Z0-9_.-]*" value != null && value != "..";
  safeHost = value: lib.hasInfix "." value && lib.all safeName (lib.splitString "." value);
in {
  options.nix-provenance.roborev = {
    enable = lib.mkEnableOption "runtime forge credential bindings for an automatic advisory review controller";
    controllerUnits = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Existing NixOS controller/publisher service names, without .service. Never select a backend or worker unit.";
    };
    forges = lib.mkOption {
      default = {};
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          host = lib.mkOption {
            type = lib.types.str;
            description = "Exact approved forge host, bound to one systemd credential name.";
          };
          tokenFile = lib.mkOption {
            type = lib.types.str;
            description = "Literal absolute runtime token-file path, normally config.age.secrets.<name>.path. Token contents never enter Nix.";
          };
        };
      });
      description = "Host-scoped forge tokens for the trusted review controller only. Enrollment and encrypted-source selection belong to the consumer.";
    };
    credentialManifest = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      description = "Public JSON manifest consumed by toolbelt review automatic-scan --credentials; contains credential basenames only.";
    };
  };
  config = lib.mkMerge [
    {nix-provenance.roborev.credentialManifest = manifest;}
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = cfg.forges != {} && cfg.controllerUnits != [];
          message = "nix-provenance.roborev requires explicit forge bindings and existing controllerUnits.";
        }
        {
          assertion = lib.all safeName (builtins.attrNames cfg.forges ++ cfg.controllerUnits);
          message = "roborev credential and controller unit names must be literal safe names.";
        }
        {
          assertion = lib.all (binding: safeHost binding.host && literalRuntimePath binding.tokenFile) (builtins.attrValues cfg.forges);
          message = "roborev forge hosts must be exact names and tokenFile must be a literal absolute runtime string outside the store.";
        }
        {
          assertion = let hosts = map (binding: binding.host) (builtins.attrValues cfg.forges); in builtins.length hosts == builtins.length (lib.unique hosts);
          message = "roborev provenance bindings may not alias multiple credentials to one forge host.";
        }
        {
          assertion = lib.all (name: (config.systemd.services.${name}.serviceConfig.ExecStart or null) != null) cfg.controllerUnits;
          message = "roborev provenance must bind an existing controller execution owner.";
        }
      ];
      systemd.services = lib.genAttrs cfg.controllerUnits (_: {
        serviceConfig.LoadCredential = lib.mapAttrsToList (name: binding: "${credentialName name}:${binding.tokenFile}") cfg.forges;
      });
    })
  ];
}
