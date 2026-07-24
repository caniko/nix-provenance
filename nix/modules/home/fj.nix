{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.nix-provenance.fj;
  tokenCfg = cfg.applicationToken;
  defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.forgejo-cli;
  fjExecutable = lib.escapeShellArg (lib.getExe cfg.package);
  tokenFile =
    if tokenCfg.tokenFile == null
    then ""
    else tokenCfg.tokenFile;
  applicationTokenScript = pkgs.writeShellApplication {
    name = "nix-provenance-fj-application-token";
    runtimeInputs = [pkgs.coreutils];
    text = ''
      token_file=${lib.escapeShellArg tokenFile}
      test -s "$token_file" || {
        echo "fj: application token file is missing or empty: $token_file" >&2
        exit 1
      }

      {
        printf '%s\n' ${lib.escapeShellArg tokenCfg.username}
        cat "$token_file"
      } | ${fjExecutable} -H ${lib.escapeShellArg tokenCfg.host} auth add-token
    '';
  };
  applicationTokenPath = builtins.replaceStrings ["\${XDG_RUNTIME_DIR}"] ["%t"] tokenFile;
in {
  options.nix-provenance.fj = {
    enable = mkEnableOption "fj, the Forgejo command-line client";

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = lib.literalMD "nix-provenance.packages.<system>.forgejo-cli";
      description = "The Forgejo CLI package to install.";
    };

    applicationToken = {
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
  };

  config = lib.mkMerge [
    (mkIf cfg.enable {
      home.packages = [cfg.package];
    })

    (mkIf tokenCfg.enable {
      assertions = [
        {
          assertion = tokenCfg.tokenFile != null;
          message = "nix-provenance.fj.applicationToken.tokenFile is required when application-token registration is enabled.";
        }
      ];

      systemd.user.services.nix-provenance-fj-application-token = {
        Unit = {
          Description = "Register the Forgejo application token with fj";
          Wants = ["agenix.service"];
          After = ["agenix.service"];
        };

        Service = {
          Type = "oneshot";
          ExecStart = lib.getExe applicationTokenScript;
        };

        Install.WantedBy = ["default.target"];
      };

      systemd.user.paths.nix-provenance-fj-application-token = {
        Unit = {
          Description = "Watch the fj application token";
          Wants = ["agenix.service"];
          After = ["agenix.service"];
        };

        Path.PathChanged = [applicationTokenPath];

        Install.WantedBy = ["default.target"];
      };
    })
  ];
}
