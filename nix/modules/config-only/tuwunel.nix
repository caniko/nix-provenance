{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.matrix-tuwunel;
  pcfg = cfg.provision;
  passwords = self.lib.passwords;
  system = pkgs.stdenv.hostPlatform.system;

  defaultProvisionPackage = lib.attrByPath ["packages" system "tuwunel-provision"] pkgs.tuwunel-provision self;

  userSubmodule = types.submodule {
    options = {
      passwordFile = passwords.passwordFileOption;
      admin = mkOption {
        type = types.bool;
        default = false;
        description = "Whether this user should have server admin privileges.";
      };
      displayName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional Matrix display name for the user.";
      };
    };
  };

  stateFile = pkgs.writeText "tuwunel-provision-state.json" (builtins.toJSON {
    server_name = cfg.settings.global.server_name;
    port = builtins.head cfg.settings.global.port;
    users = lib.mapAttrs (name: user: {
      inherit (user) admin;
      display_name = user.displayName;
      credential_name = passwords.credentialName name;
    }) pcfg.users;
  });
in {
  options.services.matrix-tuwunel.provision = {
    enable = mkEnableOption "declarative tuwunel user provisioning";

    provisionPackage = mkOption {
      type = types.package;
      default = defaultProvisionPackage;
      defaultText = "self.packages.\${system}.tuwunel-provision";
      description = "tuwunel-provision binary for auto-bootstrap and user provisioning.";
    };

    adminTokenFile = mkOption {
      type = types.str;
      default = "/var/lib/tuwunel/admin-token";
      description = ''
        Runtime path to a Matrix access token with admin privileges.
        On first run, the provisioner auto-bootstraps by registering the first
        admin user via open registration and writes the token to this path.
      '';
    };

    users = mkOption {
      type = types.attrsOf userSubmodule;
      default = {};
      description = ''
        Matrix users to provision, keyed by localpart
        (username without @ or server name).
      '';
    };
  };

  config = mkIf pcfg.enable {
    assertions = [
      {
        assertion = config.services.matrix-tuwunel.enable;
        message = "services.matrix-tuwunel.provision requires services.matrix-tuwunel.enable = true.";
      }
    ];

    systemd.services.tuwunel-provision = {
      description = "Declaratively provision tuwunel Matrix users";
      after = ["tuwunel.service"];
      requires = ["tuwunel.service"];
      wantedBy = ["multi-user.target"];
      restartTriggers = [stateFile];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${lib.getExe pcfg.provisionPackage} --state ${stateFile} --admin-token-file ${pcfg.adminTokenFile} --credential-dir %d --marker-dir /var/lib/tuwunel/markers --ready-timeout 30";
        LoadCredential = passwords.userPasswordCredentials "tuwunel-provision" pcfg.users;
        StateDirectory = "tuwunel";
        User = cfg.user;
        Group = cfg.group;
      };
    };
  };
}
