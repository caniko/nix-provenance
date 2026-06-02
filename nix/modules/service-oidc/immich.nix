{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption optional optionalAttrs types;
  cfg = config.services.immich.provision;

  presentOption = mkOption {
    type = types.bool;
    default = true;
    description = "Whether this user should exist.";
  };

  userSubmodule = types.submodule {
    options = {
      present = presentOption;
      email = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Primary Immich email identity. Required when present is true.";
      };
      name = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Immich display name. Required when present is true.";
      };
      isAdmin = mkOption {
        type = types.nullOr types.bool;
        default = null;
        description = "Whether the user should have Immich admin privileges.";
      };
      storageLabel = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Declared storage label. Set clearStorageLabel to clear an existing label.";
      };
      clearStorageLabel = mkOption {
        type = types.bool;
        default = false;
        description = "Set Immich storageLabel to null.";
      };
      quotaSizeInBytes = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "Declared user quota in bytes. Set clearQuota to clear an existing quota.";
      };
      clearQuota = mkOption {
        type = types.bool;
        default = false;
        description = "Set Immich quotaSizeInBytes to null.";
      };
      shouldChangePassword = mkOption {
        type = types.nullOr types.bool;
        default = null;
        description = "Whether Immich should require a password change.";
      };
      delete.force = mkOption {
        type = types.bool;
        default = false;
        description = "Second lock for user deletion. Requires allowUserDelete too.";
      };
    };
  };

  oauthSettings =
    {
      enabled = true;
      issuerUrl = cfg.oauth.issuerUrl;
      clientId = cfg.oauth.clientId;
      scope = cfg.oauth.scope;
      autoRegister = cfg.oauth.autoRegister;
      autoLaunch = cfg.oauth.autoLaunch;
      storageLabelClaim = cfg.oauth.storageLabelClaim;
      mobileOverrideEnabled = cfg.oauth.mobileOverrideEnabled;
    }
    // optionalAttrs (cfg.oauth.clientSecretFile != null) {
      clientSecret._secret = cfg.oauth.clientSecretFile;
    }
    // optionalAttrs (cfg.oauth.buttonText != null) {
      buttonText = cfg.oauth.buttonText;
    }
    // optionalAttrs (cfg.oauth.roleClaim != null) {
      roleClaim = cfg.oauth.roleClaim;
    }
    // optionalAttrs (cfg.oauth.storageQuotaClaim != null) {
      storageQuotaClaim = cfg.oauth.storageQuotaClaim;
    }
    // optionalAttrs (cfg.oauth.defaultStorageQuota != null) {
      defaultStorageQuota = cfg.oauth.defaultStorageQuota;
    }
    // optionalAttrs (cfg.oauth.mobileRedirectUri != null) {
      mobileRedirectUri = cfg.oauth.mobileRedirectUri;
    };

  userManifest = lib.mapAttrs (_: user:
    {
      inherit (user) present;
      delete.force = user.delete.force;
    }
    // optionalAttrs (user.email != null) {inherit (user) email;}
    // optionalAttrs (user.name != null) {inherit (user) name;}
    // optionalAttrs (user.isAdmin != null) {inherit (user) isAdmin;}
    // optionalAttrs (user.storageLabel != null || user.clearStorageLabel) {
      storageLabel =
        if user.clearStorageLabel
        then null
        else user.storageLabel;
    }
    // optionalAttrs (user.quotaSizeInBytes != null || user.clearQuota) {
      quotaSizeInBytes =
        if user.clearQuota
        then null
        else user.quotaSizeInBytes;
    }
    // optionalAttrs (user.shouldChangePassword != null) {inherit (user) shouldChangePassword;})
  cfg.users;

  stateFile = pkgs.writeText "immich-provision-state.json" (builtins.toJSON {users = userManifest;});

  cliArgs =
    lib.escapeShellArgs
    ([
        "--url"
        cfg.endpoint
        "--state"
        (toString stateFile)
        "--ready-timeout"
        (toString cfg.readyTimeoutSeconds)
      ]
      ++ lib.optional cfg.acceptInvalidCerts "--accept-invalid-certs"
      ++ lib.optional cfg.allowUserDelete "--allow-user-delete");

  provisionScript = pkgs.writeShellScript "immich-provision-start" ''
    set -eu
    umask 077

    token_file="$RUNTIME_DIRECTORY/provision-token"
    ${cfg.immichAdminCommand} provision-token --ttl ${toString cfg.tokenTtlSeconds} > "$token_file"
    test -s "$token_file"

    exec ${lib.escapeShellArg (lib.getExe' cfg.package "immich-provision")} ${cliArgs} --token-file "$token_file"
  '';
in {
  options.services.immich.provision = {
    enable = mkEnableOption "declarative Immich identity provisioning";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.immich-provision;
      defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.immich-provision";
      description = "immich-provision package to run.";
    };

    endpoint = mkOption {
      type = types.str;
      default = let
        # services.immich.host may be a hostname, an IPv4 literal, or a bare
        # IPv6 literal (e.g. "::1"). Node binds the string "localhost" to the
        # IPv6 loopback [::1] only, so a hardcoded 127.0.0.1 endpoint would
        # never connect and the readiness probe would time out. Follow the host
        # Immich is actually configured to listen on, bracketing bare IPv6
        # literals for use in a URL authority.
        host = config.services.immich.host;
        authority =
          if lib.hasInfix ":" host
          then "[${host}]"
          else host;
      in "http://${authority}:${toString config.services.immich.port}";
      defaultText = lib.literalExpression "\"http://\${config.services.immich.host}:\${toString config.services.immich.port}\"";
      description = "Immich base URL. The CLI appends /api if needed.";
    };

    immichAdminCommand = mkOption {
      type = types.str;
      default = "${config.services.immich.package}/bin/immich-admin";
      defaultText = lib.literalExpression ''"\${config.services.immich.package}/bin/immich-admin"'';
      description = "Patched immich-admin command that supports provision-token.";
    };

    tokenTtlSeconds = mkOption {
      type = types.ints.positive;
      default = 300;
      description = "TTL for the short-lived local provisioning token.";
    };

    readyTimeoutSeconds = mkOption {
      type = types.ints.positive;
      default = 60;
      description = "Seconds to wait for Immich before provisioning.";
    };

    acceptInvalidCerts = mkOption {
      type = types.bool;
      default = false;
      description = "Accept invalid TLS certificates when talking to Immich.";
    };

    allowUserDelete = mkOption {
      type = types.bool;
      default = false;
      description = "Global deletion lock. Per-user delete.force must also be true.";
    };

    serviceAfter = mkOption {
      type = types.listOf types.str;
      default = ["immich-server.service"];
      description = "Units that must be active before provisioning runs.";
    };

    users = mkOption {
      type = types.attrsOf userSubmodule;
      default = {};
      description = "Immich users to provision, keyed by a stable local name.";
    };

    oauth = {
      enable = mkEnableOption "declarative Immich OAuth settings";
      issuerUrl = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "OIDC issuer URL, for example https://auth.example.com/oauth2/openid/immich.";
      };
      clientId = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "OIDC client id.";
      };
      clientSecretFile = mkOption {
        type = types.nullOr (types.oneOf [types.path types.str]);
        default = null;
        description = "Path to a file containing the OIDC client secret. Rendered through services.immich.settings _secret.";
      };
      scope = mkOption {
        type = types.str;
        default = "openid profile email";
        description = "OIDC scope string requested by Immich.";
      };
      autoRegister = mkOption {
        type = types.bool;
        default = true;
        description = "Allow Immich to auto-register OAuth users.";
      };
      autoLaunch = mkOption {
        type = types.bool;
        default = false;
        description = "Automatically launch OAuth from the login page.";
      };
      buttonText = mkOption {
        type = types.nullOr types.str;
        default = "Sign in with Kanidm";
        description = "OAuth login button text.";
      };
      storageLabelClaim = mkOption {
        type = types.str;
        default = "preferred_username";
        description = "OAuth claim used for new-user storage labels.";
      };
      roleClaim = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional OAuth role claim.";
      };
      storageQuotaClaim = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional OAuth storage quota claim.";
      };
      defaultStorageQuota = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "Default storage quota in GiB for OAuth-created users.";
      };
      mobileOverrideEnabled = mkOption {
        type = types.bool;
        default = false;
        description = "Enable Immich mobile OAuth redirect override.";
      };
      mobileRedirectUri = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Immich mobile OAuth redirect override URI.";
      };
    };
  };

  config = mkIf cfg.enable {
    assertions =
      [
        {
          assertion = config.services.immich.enable;
          message = "services.immich.provision requires services.immich.enable = true.";
        }
        {
          assertion = cfg.oauth.enable -> cfg.oauth.issuerUrl != null;
          message = "services.immich.provision.oauth.issuerUrl is required when OAuth is enabled.";
        }
        {
          assertion = cfg.oauth.enable -> cfg.oauth.clientId != null;
          message = "services.immich.provision.oauth.clientId is required when OAuth is enabled.";
        }
        {
          assertion = cfg.oauth.enable -> cfg.oauth.clientSecretFile != null;
          message = "services.immich.provision.oauth.clientSecretFile is required when OAuth is enabled.";
        }
      ]
      ++ lib.flatten (lib.mapAttrsToList (name: user: [
          {
            assertion = !user.present || user.email != null;
            message = "services.immich.provision.users.${name}.email is required when present = true.";
          }
          {
            assertion = !user.present || user.name != null;
            message = "services.immich.provision.users.${name}.name is required when present = true.";
          }
          {
            assertion = !(user.storageLabel != null && user.clearStorageLabel);
            message = "services.immich.provision.users.${name} cannot set both storageLabel and clearStorageLabel.";
          }
          {
            assertion = !(user.quotaSizeInBytes != null && user.clearQuota);
            message = "services.immich.provision.users.${name} cannot set both quotaSizeInBytes and clearQuota.";
          }
        ])
        cfg.users);

    services.immich.settings.oauth = mkIf cfg.oauth.enable oauthSettings;

    systemd.services.immich-provision = {
      description = "Declaratively provision Immich users";
      after = cfg.serviceAfter;
      requires = cfg.serviceAfter;
      wantedBy = ["multi-user.target"];
      environment = config.services.immich.environment;

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = provisionScript;
        EnvironmentFile = optional (config.services.immich.secretsFile != null) config.services.immich.secretsFile;
        RuntimeDirectory = "immich-provision";
        RuntimeDirectoryMode = "0700";
        User = config.services.immich.user;
        Group = config.services.immich.group;
      };
    };
  };
}
