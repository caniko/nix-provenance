# NixOS module: services.rauthy.provision
#
# Declaratively provisions a running Rauthy instance (users, groups, roles,
# OIDC clients) by rendering the option tree to a JSON state file and running
# the `rauthy-provision` reconciler as a Type=oneshot unit ordered after the
# Rauthy service. This is the analogue of `services.kanidm.provision`.
#
# Authentication uses a Rauthy API key. Prefer `apiKeyEnvironmentFile` with
# Rauthy's bootstrap `BOOTSTRAP_API_KEY_SECRET`, so the unit assembles
# `<apiKeyName>$<secret>` at runtime. `apiKeyFile` remains available for an
# already assembled key.
{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption optionalString types;
  cfg = config.services.rauthy.provision;

  presentOption = mkOption {
    type = types.bool;
    default = true;
    description = "Whether the entity should exist. Set to false to delete it (honored unless autoRemove = false).";
  };

  groupSubmodule = types.submodule {options.present = presentOption;};
  roleSubmodule = types.submodule {options.present = presentOption;};

  userSubmodule = types.submodule {
    options = {
      present = presentOption;
      givenName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Given name. Applied at creation only (not re-enforced on update, so upstream federation profile-claim sync is not fought).";
      };
      familyName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Family name. Applied at creation only.";
      };
      language = mkOption {
        type = types.enum ["de" "en" "fr" "ko" "nb" "ru" "uk" "zhhans"];
        default = "en";
        description = "Rauthy UI language for the user.";
      };
      roles = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Rauthy role names assigned to the user (reconciled on update).";
      };
      groups = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Rauthy group names assigned to the user (reconciled on update).";
      };
      sendPasswordEmail = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Email this user a set-password link on first creation (Rauthy's
          request_reset flow). No-op once the user exists, so at most one email
          is ever sent. Use for external users who must set a native Rauthy
          password. Requires passwordEmailRedirectUri.
        '';
      };
      passwordEmailRedirectUri = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Where Rauthy redirects the user after they set their password. Point
          it at the consuming app's login-initiating route (e.g.
          https://app.example.com/login), not a raw OIDC callback. Only used
          when sendPasswordEmail is true.
        '';
      };
    };
  };

  clientSubmodule = types.submodule {
    options = {
      present = presentOption;
      name = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Human-readable client name.";
      };
      confidential = mkOption {
        type = types.bool;
        default = true;
        description = "Confidential client (holds a secret). Set false for a public/PKCE-only client.";
      };
      redirectUris = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Allowed OIDC redirect URIs.";
      };
      postLogoutRedirectUris = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Allowed post-logout redirect URIs.";
      };
      allowedOrigins = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Allowed CORS origins.";
      };
      scopes = mkOption {
        type = types.listOf types.str;
        default = ["openid" "profile" "email"];
        description = "Scopes the client may request.";
      };
      defaultScopes = mkOption {
        type = types.listOf types.str;
        default = ["openid" "profile" "email"];
        description = "Scopes granted by default.";
      };
      flowsEnabled = mkOption {
        type = types.listOf types.str;
        default = ["authorization_code" "refresh_token"];
        description = "Enabled OAuth2 flows.";
      };
      enablePkce = mkOption {
        type = types.bool;
        default = true;
        description = "Enable PKCE (S256). Required for public clients.";
      };
    };
  };

  manifest = {
    groups = lib.mapAttrs (_: g: {inherit (g) present;}) cfg.groups;
    roles = lib.mapAttrs (_: r: {inherit (r) present;}) cfg.roles;
    users =
      lib.mapAttrs (_: u: {
        inherit (u) present language roles groups;
        given_name = u.givenName;
        family_name = u.familyName;
        send_password_email = u.sendPasswordEmail;
        password_email_redirect_uri = u.passwordEmailRedirectUri;
      })
      cfg.users;
    clients =
      lib.mapAttrs (_: c: {
        inherit (c) present confidential scopes;
        name = c.name;
        redirect_uris = c.redirectUris;
        post_logout_redirect_uris = c.postLogoutRedirectUris;
        allowed_origins = c.allowedOrigins;
        default_scopes = c.defaultScopes;
        flows_enabled = c.flowsEnabled;
        enable_pkce = c.enablePkce;
      })
      cfg.clients;
  };

  stateFile = pkgs.writeText "rauthy-provision-state.json" (builtins.toJSON manifest);

  cliArgs =
    lib.escapeShellArgs
    ([
        "--url"
        cfg.endpoint
        "--state"
        (toString stateFile)
      ]
      ++ lib.optionals (cfg.apiKeyFile != null) [
        "--api-key-file"
        (toString cfg.apiKeyFile)
      ]
      ++ lib.optional (!cfg.autoRemove) "--no-auto-remove"
      ++ lib.optional cfg.acceptInvalidCerts "--accept-invalid-certs");

  provisionScript = pkgs.writeShellScript "rauthy-provision-start" ''
    set -eu
    ${optionalString (cfg.apiKeyEnvironmentFile != null) ''
      if [ -z "''${BOOTSTRAP_API_KEY_SECRET:-}" ]; then
        echo "BOOTSTRAP_API_KEY_SECRET is missing from services.rauthy.provision.apiKeyEnvironmentFile" >&2
        exit 1
      fi
      if [ "''${#BOOTSTRAP_API_KEY_SECRET}" -lt 64 ]; then
        echo "BOOTSTRAP_API_KEY_SECRET must be at least 64 characters for Rauthy's bootstrap API-key flow" >&2
        exit 1
      fi
      api_key_secret="''${BOOTSTRAP_API_KEY_SECRET}"
      unset ENC_KEYS ENC_KEY_ACTIVE HQL_SECRET_RAFT HQL_SECRET_API BOOTSTRAP_ADMIN_PASSWORD_ARGON2ID BOOTSTRAP_API_KEY_SECRET
      export RAUTHY_PROVISION_API_KEY=${lib.escapeShellArg "${cfg.apiKeyName}$"}"''${api_key_secret}"
      unset api_key_secret
    ''}
    exec ${lib.escapeShellArg (lib.getExe cfg.package)} ${cliArgs}
  '';
in {
  options.services.rauthy.provision = {
    enable = mkEnableOption "declarative Rauthy provisioning (users, groups, roles, OIDC clients)";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.rauthy-provision;
      defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.rauthy-provision";
      description = "The rauthy-provision package to run.";
    };

    endpoint = mkOption {
      type = types.str;
      default = "http://127.0.0.1:8080";
      example = "https://id.example.com";
      description = "Rauthy base URL (the /auth/v1 API path is appended automatically). Prefer the local listener to avoid the reverse proxy.";
    };

    apiKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Path to a file containing the Rauthy API key (`<name>$<secret>`),
        e.g. an agenix secret path. Prefer `apiKeyEnvironmentFile` for
        bootstrap-generated keys. The key must have read+create+update+delete
        on the Users, Groups, Roles, and Clients access groups.
      '';
    };

    apiKeyEnvironmentFile = mkOption {
      type = types.nullOr (types.oneOf [types.path types.str]);
      default = null;
      description = ''
        Environment file containing `BOOTSTRAP_API_KEY_SECRET`, as used by
        Rauthy's declarative bootstrap API-key flow. When set, the unit exports
        `RAUTHY_PROVISION_API_KEY=<apiKeyName>$<BOOTSTRAP_API_KEY_SECRET>`
        before running the reconciler, keeping the secret out of argv and the
        Nix store.
      '';
    };

    apiKeyName = mkOption {
      type = types.str;
      default = "rauthy-provision";
      description = "Name of the Rauthy API key created by bootstrap and paired with `BOOTSTRAP_API_KEY_SECRET`.";
    };

    autoRemove = mkOption {
      type = types.bool;
      default = true;
      description = "Honor `present = false` deletions. When false, the reconciler is run with --no-auto-remove and never deletes.";
    };

    acceptInvalidCerts = mkOption {
      type = types.bool;
      default = false;
      description = "Accept invalid TLS certificates when talking to the endpoint.";
    };

    serviceAfter = mkOption {
      type = types.listOf types.str;
      default = ["rauthy.service"];
      description = "Units the provisioning oneshot waits for before running.";
    };

    groups = mkOption {
      type = types.attrsOf groupSubmodule;
      default = {};
      description = "Rauthy groups to provision, keyed by group name.";
    };

    roles = mkOption {
      type = types.attrsOf roleSubmodule;
      default = {};
      description = "Rauthy roles to provision, keyed by role name.";
    };

    users = mkOption {
      type = types.attrsOf userSubmodule;
      default = {};
      description = ''
        Rauthy users to provision, keyed by primary email address. Users are
        created passwordless (no email sent); with an upstream OIDC provider and
        Auto-Link enabled, a matching-email account auto-links on first login.
      '';
    };

    clients = mkOption {
      type = types.attrsOf clientSubmodule;
      default = {};
      description = "OIDC clients (relying parties) to provision, keyed by client id.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.apiKeyFile != null || cfg.apiKeyEnvironmentFile != null;
        message = "services.rauthy.provision must set apiKeyFile or apiKeyEnvironmentFile when provisioning is enabled.";
      }
      {
        assertion = !(cfg.apiKeyFile != null && cfg.apiKeyEnvironmentFile != null);
        message = "services.rauthy.provision must set only one of apiKeyFile or apiKeyEnvironmentFile.";
      }
      {
        assertion = cfg.apiKeyName != "" && !(lib.hasInfix "$" cfg.apiKeyName);
        message = "services.rauthy.provision.apiKeyName must be non-empty and must not contain '$'.";
      }
    ];

    systemd.services.rauthy-provision = {
      description = "Declaratively provision Rauthy (users, groups, roles, clients)";
      after = cfg.serviceAfter;
      requires = cfg.serviceAfter;
      wantedBy = ["multi-user.target"];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = provisionScript;
        EnvironmentFile = lib.mkIf (cfg.apiKeyEnvironmentFile != null) [(toString cfg.apiKeyEnvironmentFile)];
        # Rauthy may still be warming up when the unit first fires.
        Restart = "on-failure";
        RestartSec = "10s";
      };

      unitConfig = {
        StartLimitBurst = 6;
        StartLimitIntervalSec = 300;
      };
    };
  };
}
