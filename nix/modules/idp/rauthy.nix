# NixOS module: services.rauthy.provision
#
# Declaratively provisions a running Rauthy instance (users, groups, roles,
# OIDC clients) by rendering the option tree to a JSON state file and running
# the `rauthy-provision` reconciler as a Type=oneshot unit ordered after the
# Rauthy service. This is the analogue of `services.kanidm.provision`.
#
# Authentication uses a Rauthy API key (see `apiKeyFile`). The key must carry
# the Users/Groups/Roles/Clients access groups with read+create+update+delete
# rights. Create it once in the Rauthy Admin UI (API Keys) and store the
# `<name>$<secret>` value in the file `apiKeyFile` points at.
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
    users = lib.mapAttrs (_: u: {
      inherit (u) present language roles groups;
      given_name = u.givenName;
      family_name = u.familyName;
    }) cfg.users;
    clients = lib.mapAttrs (_: c: {
      inherit (c) present confidential scopes;
      name = c.name;
      redirect_uris = c.redirectUris;
      post_logout_redirect_uris = c.postLogoutRedirectUris;
      allowed_origins = c.allowedOrigins;
      default_scopes = c.defaultScopes;
      flows_enabled = c.flowsEnabled;
      enable_pkce = c.enablePkce;
    }) cfg.clients;
  };

  stateFile = pkgs.writeText "rauthy-provision-state.json" (builtins.toJSON manifest);
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
        e.g. an agenix secret path. The key must have read+create+update+delete
        on the Users, Groups, Roles, and Clients access groups.
      '';
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
        assertion = cfg.apiKeyFile != null;
        message = "services.rauthy.provision.apiKeyFile must be set when provisioning is enabled.";
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
        ExecStart = lib.concatStringsSep " " ([
            (lib.getExe cfg.package)
            "--url"
            cfg.endpoint
            "--state"
            stateFile
            "--api-key-file"
            (toString cfg.apiKeyFile)
          ]
          ++ lib.optional (!cfg.autoRemove) "--no-auto-remove"
          ++ lib.optional cfg.acceptInvalidCerts "--accept-invalid-certs");
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
