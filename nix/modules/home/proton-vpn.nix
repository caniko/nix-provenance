{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.nix-provenance.proton-vpn;
  unitName = "nix-provenance-proton-vpn-login";
  credentialPath =
    if cfg.login.credentialsFile == null
    then ""
    else builtins.replaceStrings ["\${XDG_RUNTIME_DIR}"] ["%t"] cfg.login.credentialsFile;
in {
  options.nix-provenance.proton-vpn = {
    enable = mkEnableOption "the official Proton VPN GUI and CLI";
    package = mkOption {
      type = types.package;
      default = pkgs.proton-vpn;
      description = "Official Proton VPN graphical client.";
    };
    cliPackage = mkOption {
      type = types.package;
      default = pkgs.proton-vpn-cli;
      description = "Official Proton VPN command-line client.";
    };
    login = {
      enable = mkEnableOption "automatic Proton account login at graphical session startup";
      credentialsFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Private runtime JSON file with username, password and optional totpSecret
          (base32 TOTP seed). Pass an agenix path, never a store file or plaintext.
          Account definitions may reuse an encrypted source across system users;
          Proton's per-user session and keyring remain independent.
        '';
      };
      package = mkOption {
        type = types.package;
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.proton-vpn-auth;
        description = "Rust runtime credential and TOTP adapter.";
      };
      keyringServiceUnit = mkOption {
        type = types.str;
        default = "dbus.service";
        description = "User service providing the unlocked Secret Service session.";
      };
      credentialServiceUnits = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "User services that materialize credentials before login, such as agenix.service.";
      };
      timeoutSeconds = mkOption {
        type = types.ints.between 1 300;
        default = 45;
        description = "Maximum duration of each official-client invocation.";
      };
    };
  };

  config = lib.mkMerge [
    (mkIf cfg.enable {
      assertions = [
        {
          assertion = pkgs.stdenv.hostPlatform.isLinux;
          message = "nix-provenance.proton-vpn requires Linux and a graphical Secret Service session.";
        }
      ];
      home.packages = [cfg.package cfg.cliPackage cfg.login.package];
    })
    (mkIf cfg.login.enable {
      assertions = [
        {
          assertion = cfg.enable;
          message = "Proton automatic login requires nix-provenance.proton-vpn.enable.";
        }
        {
          assertion =
            cfg.login.credentialsFile
            != null
            && (lib.hasPrefix "/" credentialPath || lib.hasPrefix "%t/" credentialPath)
            && !(lib.hasPrefix "/nix/store/" credentialPath);
          message = "Proton login requires credentialsFile to reference a private runtime file.";
        }
      ];
      systemd.user.services.${unitName} = {
        Unit = {
          Description = "Enroll the declared Proton VPN account session";
          Wants = [cfg.login.keyringServiceUnit] ++ cfg.login.credentialServiceUnits;
          After = ["graphical-session-pre.target" cfg.login.keyringServiceUnit] ++ cfg.login.credentialServiceUnits;
          PartOf = ["graphical-session.target"];
          StartLimitIntervalSec = 300;
          StartLimitBurst = 3;
        };
        Service = {
          Type = "oneshot";
          LoadCredential = ["account:${credentialPath}"];
          ExecStart = lib.concatStringsSep " " [
            (lib.escapeShellArg (lib.getExe cfg.login.package))
            "login"
            "--credentials-file %d/account"
            "--cli ${lib.escapeShellArg (lib.getExe cfg.cliPackage)}"
            "--setsid ${lib.escapeShellArg "${pkgs.util-linux}/bin/setsid"}"
            "--timeout-seconds ${toString cfg.login.timeoutSeconds}"
          ];
          TimeoutStartSec = cfg.login.timeoutSeconds * 3 + 10;
          Restart = "on-failure";
          RestartSec = "60s";
          RestartPreventExitStatus = 2;
          UMask = "0077";
          LimitCORE = 0;
        };
        Install.WantedBy = ["graphical-session.target"];
      };
      systemd.user.paths.${unitName} = {
        Unit = {
          Description = "Watch the Proton VPN account credential document";
          PartOf = ["graphical-session.target"];
        };
        Path.PathChanged = credentialPath;
        Install.WantedBy = ["graphical-session.target"];
      };
    })
  ];
}
