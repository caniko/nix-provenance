{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.nix-provenance.fj;
  defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.forgejo-cli;
  fjExecutable = lib.escapeShellArg (lib.getExe cfg.package);
  tokenOptions = {
    enable = mkEnableOption "automatic Forgejo application-token registration";

    host = mkOption {
      type = types.str;
      default = "codefloe.com";
      description = "Forgejo host for the application token.";
    };

    username = mkOption {
      type = types.str;
      default = "can";
      description = "Forgejo username associated with the application token.";
    };

    tokenFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Transient agenix runtime path containing the application token.";
    };
  };
  tokenSubmodule = types.submodule ({...}: {options = tokenOptions;});
  enabledTokens =
    (lib.optionalAttrs cfg.applicationToken.enable {default = cfg.applicationToken;})
    // lib.filterAttrs (_: tokenCfg: tokenCfg.enable) cfg.applicationTokens;
  tokenUnits = lib.mapAttrs' (name: tokenCfg: let
    unitName =
      if name == "default"
      then "nix-provenance-fj-application-token"
      else "nix-provenance-fj-application-token-${name}";
    tokenFile = tokenCfg.tokenFile or "";
    script = pkgs.writeShellApplication {
      name = unitName;
      runtimeInputs = [pkgs.coreutils];
      text = ''
        token_file=${lib.escapeShellArg tokenFile}
        test -s "$token_file" || {
          echo "fj: application token file is missing or empty: $token_file" >&2
          exit 1
        }

        ${fjExecutable} -H ${lib.escapeShellArg tokenCfg.host} auth logout ${lib.escapeShellArg tokenCfg.host} || true
        {
          printf '%s\n' ${lib.escapeShellArg tokenCfg.username}
          cat "$token_file"
        } | ${fjExecutable} -H ${lib.escapeShellArg tokenCfg.host} auth add-token
      '';
    };
  in
    lib.nameValuePair unitName {
      Unit = {
        Description = "Register the ${tokenCfg.host} Forgejo application token with fj";
        Wants = ["agenix.service"];
        After = ["agenix.service"];
      };
      Service = {
        Type = "oneshot";
        ExecStart = lib.getExe script;
      };
      Install.WantedBy = ["default.target"];
    }) enabledTokens;
  tokenPaths = lib.mapAttrs' (name: tokenCfg: let
    unitName =
      if name == "default"
      then "nix-provenance-fj-application-token"
      else "nix-provenance-fj-application-token-${name}";
    tokenFile = tokenCfg.tokenFile or "";
  in
    lib.nameValuePair unitName {
      Unit = {
        Description = "Watch the ${tokenCfg.host} fj application token";
        Wants = ["agenix.service"];
        After = ["agenix.service"];
      };
      Path.PathChanged = [builtins.replaceStrings ["\${XDG_RUNTIME_DIR}"] ["%t"] tokenFile];
      Install.WantedBy = ["default.target"];
    }) enabledTokens;
  tokenAssertions = lib.mapAttrsToList (name: tokenCfg: {
    assertion = tokenCfg.tokenFile != null;
    message = "nix-provenance.fj application token '${name}' requires tokenFile.";
  }) enabledTokens;
in {
  options.nix-provenance.fj = {
    enable = mkEnableOption "fj, the Forgejo command-line client";

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = lib.literalMD "nix-provenance.packages.<system>.forgejo-cli";
      description = "The Forgejo CLI package to install.";
    };

    applicationToken = mkOption {
      type = tokenSubmodule;
      default = {};
      description = "Backward-compatible single Forgejo application token.";
    };

    applicationTokens = mkOption {
      type = types.attrsOf tokenSubmodule;
      default = {};
      description = "Forgejo application tokens registered through fj, keyed by host name.";
    };
  };

  config = lib.mkMerge [
    (mkIf cfg.enable {
      home.packages = [cfg.package];
    })

    (mkIf (enabledTokens != {}) {
      assertions = tokenAssertions;
      systemd.user.services = tokenUnits;
      systemd.user.paths = tokenPaths;
    })
  ];
}
