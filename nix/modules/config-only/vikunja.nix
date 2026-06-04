{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.vikunja.oidc;
  envFile = "/run/vikunja-oidc/env";
in {
  # Vikunja OIDC is config-only: Vikunja self-registers/link users through
  # OIDC, while team membership is managed out-of-band by vikunja-provision.
  # Redirect URIs are /auth/openid/<providerId>, and the rendered env var embeds
  # the upper-cased provider id. usernamefallback and emailfallback must stay
  # paired for existing local accounts to link cleanly.
  options.services.vikunja.oidc = {
    enable = mkEnableOption "declarative Vikunja kanidm OIDC wiring";

    providerId = mkOption {
      type = types.str;
      default = "kanidm";
      description = "Key under services.vikunja.settings.auth.openid.providers.*; also the redirect-URI segment.";
    };

    displayName = mkOption {
      type = types.str;
      default = "Kanidm";
      description = "OIDC provider button name shown in Vikunja.";
    };

    authUrl = mkOption {
      type = types.str;
      description = "OIDC issuer URL, for example https://auth.example.com/oauth2/openid/vikunja.";
    };

    clientId = mkOption {
      type = types.str;
      default = "vikunja";
      description = "OIDC client id.";
    };

    clientSecretFile = mkOption {
      type = types.oneOf [types.path types.str];
      description = "Runtime path to the OIDC client secret. Rendered to an env file, never a store path.";
    };

    scope = mkOption {
      type = types.str;
      default = "openid profile email";
      description = "OIDC scope string used for Vikunja login.";
    };

    usernamefallback = mkOption {
      type = types.bool;
      default = true;
      description = "Link an existing local account by username on first OIDC login. Pair with emailfallback.";
    };

    emailfallback = mkOption {
      type = types.bool;
      default = true;
      description = "Link an existing local account by email on first OIDC login. Pair with usernamefallback.";
    };

    forceUserInfo = mkOption {
      type = types.bool;
      default = false;
      description = "Force Vikunja to call the userinfo endpoint instead of trusting ID-token claims.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = config.services.vikunja.enable;
        message = "services.vikunja.oidc requires services.vikunja.enable = true.";
      }
      {
        assertion = cfg.usernamefallback == cfg.emailfallback;
        message = "services.vikunja.oidc.usernamefallback and emailfallback must be set together (Vikunja links accounts only when both are true).";
      }
    ];

    services.vikunja = {
      settings.auth = {
        local.enabled = lib.mkDefault true;
        openid = {
          enabled = true;
          providers.${cfg.providerId} = {
            name = cfg.displayName;
            authurl = cfg.authUrl;
            clientid = cfg.clientId;
            scope = cfg.scope;
            inherit (cfg) usernamefallback emailfallback;
            forceuserinfo = cfg.forceUserInfo;
          };
        };
      };

      environmentFiles = [envFile];
    };

    systemd.services.vikunja-oidc-env = {
      description = "Render Vikunja OIDC client secret to an env file";
      before = ["vikunja.service"];
      path = [pkgs.coreutils];
      script = ''
        set -eu
        umask 077

        secret="$(tr -d '\n' < ${lib.escapeShellArg (toString cfg.clientSecretFile)})"
        printf 'VIKUNJA_AUTH_OPENID_PROVIDERS_${lib.toUpper cfg.providerId}_CLIENTSECRET=%s\n' "$secret" > ${envFile}.tmp
        mv ${envFile}.tmp ${envFile}
      '';
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        RuntimeDirectory = "vikunja-oidc";
        RuntimeDirectoryMode = "0700";
      };
    };

    systemd.services.vikunja = {
      after = ["vikunja-oidc-env.service"];
      requires = ["vikunja-oidc-env.service"];
    };
  };
}
