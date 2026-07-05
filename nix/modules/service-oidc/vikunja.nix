{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.vikunja.provision;
  webhookSecretCredential = "vikunja-webhook-secret";

  presentOption = mkOption {
    type = types.bool;
    default = true;
    description = "Whether this resource should exist.";
  };

  teamSubmodule = types.submodule {
    options = {
      present = presentOption;
      members = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Non-admin team members, by Vikunja username.";
      };
      admins = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Admin team members, by Vikunja username.";
      };
      description = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Team description.";
      };
    };
  };

  webhookSubmodule = types.submodule {
    options = {
      present = presentOption;
      url = mkOption {
        type = types.str;
        description = "Webhook target URL.";
      };
      events = mkOption {
        type = types.listOf types.str;
        default = self.lib.vikunja.webhookEvents.taskLifecycle;
        defaultText = lib.literalExpression "self.lib.vikunja.webhookEvents.taskLifecycle";
        description = "Vikunja events to subscribe to.";
      };
    };
  };

  teamManifest =
    lib.mapAttrs (_: team: {
      inherit (team) present members admins description;
    })
    cfg.teams;

  webhookManifest =
    lib.mapAttrs (_: wh: {
      inherit (wh) present url events;
    })
    cfg.webhooks;

  stateFile = pkgs.writeText "vikunja-provision-state.json" (
    builtins.toJSON {
      teams = teamManifest;
      webhooks = webhookManifest;
    }
  );

  cliArgs =
    lib.escapeShellArgs
    ([
        "--url"
        cfg.endpoint
        "--state"
        (toString stateFile)
        "--bot-username"
        cfg.botUsername
        "--ready-timeout"
        (toString cfg.readyTimeoutSeconds)
      ]
      ++ lib.optional cfg.acceptInvalidCerts "--accept-invalid-certs"
      ++ lib.optional cfg.allowTeamDelete "--allow-team-delete"
      ++ lib.optional (!cfg.autoRemove) "--no-auto-remove");

  provisionScript = pkgs.writeShellScript "vikunja-provision-start" ''
    set -eu
    test -s "$CREDENTIALS_DIRECTORY/vikunja-token"
    ${lib.optionalString (cfg.webhookSecretFile != null) ''
      test -s "$CREDENTIALS_DIRECTORY/${webhookSecretCredential}"
    ''}
    ${lib.escapeShellArg (lib.getExe cfg.package)} ${cliArgs} --token-file "$CREDENTIALS_DIRECTORY/vikunja-token" \
      ${lib.optionalString (cfg.webhookSecretFile != null) "--webhook-secret-file \"$CREDENTIALS_DIRECTORY/${webhookSecretCredential}\""}
  '';
in {
  options.services.vikunja.provision = {
    enable = mkEnableOption "declarative Vikunja team provisioning and webhook management";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.vikunja-provision;
      defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.vikunja-provision";
      description = "vikunja-provision package to run.";
    };

    endpoint = mkOption {
      type = types.str;
      default = let
        bindAddress = config.services.vikunja.address;
        host =
          if bindAddress == "" || bindAddress == "0.0.0.0" || bindAddress == "::"
          then "127.0.0.1"
          else bindAddress;
        authority =
          if lib.hasInfix ":" host
          then "[${host}]"
          else host;
      in "http://${authority}:${toString config.services.vikunja.port}";
      defaultText = lib.literalExpression "\"http://127.0.0.1:\${toString config.services.vikunja.port}\"";
      description = "Vikunja base URL. The CLI appends /api/v1.";
    };

    tokenFile = mkOption {
      type = types.nullOr (types.oneOf [types.path types.str]);
      default = null;
      description = "Runtime secret path containing the Vikunja API token.";
    };

    botUsername = mkOption {
      type = types.str;
      default = "";
      description = "Vikunja service-account username to exclude from membership reconciliation.";
    };

    webhookSecretFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Runtime secret path containing the HMAC secret for webhook signature verification.";
    };

    readyTimeoutSeconds = mkOption {
      type = types.ints.positive;
      default = 30;
      description = "Seconds to wait for Vikunja readiness before provisioning.";
    };

    acceptInvalidCerts = mkOption {
      type = types.bool;
      default = false;
      description = "Accept invalid TLS certificates when talking to Vikunja.";
    };

    allowTeamDelete = mkOption {
      type = types.bool;
      default = false;
      description = "Global deletion lock for teams declared with present = false.";
    };

    autoRemove = mkOption {
      type = types.bool;
      default = true;
      description = "Honor membership removals and team deletions. When false, the reconciler is run with --no-auto-remove.";
    };

    serviceAfter = mkOption {
      type = types.listOf types.str;
      default = ["vikunja.service"];
      description = "Units that must be active before provisioning runs.";
    };

    teams = mkOption {
      type = types.attrsOf teamSubmodule;
      default = {};
      description = "Vikunja teams to provision, keyed by team name.";
    };

    webhooks = mkOption {
      type = types.attrsOf webhookSubmodule;
      default = {};
      description = "Vikunja project webhooks to provision, keyed by project ID (as string).";
    };
  };

  config = mkIf cfg.enable {
    assertions =
      [
        {
          assertion = config.services.vikunja.enable;
          message = "services.vikunja.provision requires services.vikunja.enable = true.";
        }
        {
          assertion = cfg.tokenFile != null;
          message = "services.vikunja.provision.tokenFile is required.";
        }
        {
          assertion = cfg.botUsername != "";
          message = "services.vikunja.provision.botUsername is required.";
        }
      ]
      ++ lib.flatten (lib.mapAttrsToList (name: team: let
          usernames = team.members ++ team.admins;
        in [
          {
            assertion = !team.present || name != "";
            message = "services.vikunja.provision.teams must not contain an empty team name when present = true.";
          }
          {
            assertion = lib.all (username: username != "") usernames;
            message = "services.vikunja.provision.teams.${name} must not contain empty usernames.";
          }
          {
            assertion = lib.all (username: username != cfg.botUsername) usernames;
            message = "services.vikunja.provision.teams.${name} must not include the botUsername in members or admins.";
          }
        ])
        cfg.teams)
      ++ lib.flatten (lib.mapAttrsToList (projectId: wh: [
          {
            assertion = !wh.present || projectId != "";
            message = "services.vikunja.provision.webhooks must not contain an empty project ID when present = true.";
          }
          {
            assertion = !wh.present || wh.url != "";
            message = "services.vikunja.provision.webhooks.${projectId}.url is required when present = true.";
          }
        ])
        cfg.webhooks);

    systemd.services.vikunja-provision = {
      description = "Declaratively provision Vikunja teams and webhooks";
      after = cfg.serviceAfter;
      requires = cfg.serviceAfter;
      wantedBy = ["multi-user.target"];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        LoadCredential =
          ["vikunja-token:${cfg.tokenFile}"]
          ++ lib.optional (cfg.webhookSecretFile != null) "${webhookSecretCredential}:${cfg.webhookSecretFile}";
        ExecStart = provisionScript;
        DynamicUser = true;
        User = "vikunja";
        Group = "vikunja";
      };
    };
  };
}
