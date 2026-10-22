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
    if cfg.login.encryptedFile == null
    then ""
    else builtins.replaceStrings ["\${XDG_RUNTIME_DIR}"] ["%t"] cfg.login.encryptedFile;
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
      encryptedFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Rekeyed age ciphertext with username, password and optional totpSecret.
          Disable agenix runtime installation and pass its encrypted file instead.
          Account definitions may reuse an encrypted source across system users;
          Proton's per-user session and keyring remain independent.
        '';
      };
      identityPaths = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Private SSH or X25519 identity paths for the rekeyed home recipient. Identity contents are never rendered.";
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
            cfg.login.encryptedFile
            != null
            && (lib.hasPrefix "/" credentialPath || lib.hasPrefix "%t/" credentialPath)
            && cfg.login.identityPaths != [];
          message = "Proton login requires encryptedFile and the declared home identityPaths.";
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
          LoadCredential = ["account.age:${credentialPath}"];
          ExecStart = lib.concatStringsSep " " [
            (lib.escapeShellArg (lib.getExe cfg.login.package))
            "login"
            "--encrypted-file %d/account.age"
            (lib.concatMapStringsSep " " (path: "--identity ${lib.escapeShellArg path}") cfg.login.identityPaths)
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
          CoredumpFilter = "0x0";
          LimitMEMLOCK = "8M";
          MemorySwapMax = 0;
          KillMode = "control-group";
          TimeoutStopSec = 10;
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
