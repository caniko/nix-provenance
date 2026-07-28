{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.forgejo.provision;
  forgejoConfig = "${config.services.forgejo.customDir}/conf/app.ini";

  keySubmodule = types.submodule {
    options = {
      present = mkOption {
        type = types.bool;
        default = true;
        description = "Whether this SSH key should exist.";
      };
      key = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "OpenSSH public key; required when present = true.";
      };
      readOnly = mkOption {
        type = types.bool;
        default = false;
        description = "Restrict this key to read-only repository access.";
      };
    };
  };

  seedScript = pkgs.writeShellScript "forgejo-seed-oidc" ''
    set -eu
    export PATH=${lib.makeBinPath [
      config.services.forgejo.package
      pkgs.gawk
      pkgs.gnugrep
      pkgs.gnused
    ]}:$PATH

    secret="$(< "$CREDENTIALS_DIRECTORY/oidc-secret")"
    name=${lib.escapeShellArg cfg.authName}
    forgejo_cli() {
      forgejo \
        --work-path ${lib.escapeShellArg config.services.forgejo.stateDir} \
        --custom-path ${lib.escapeShellArg config.services.forgejo.customDir} \
        --config ${lib.escapeShellArg forgejoConfig} \
        "$@"
    }

    # Older Forgejo can emit vertical ID:/Name: lines; newer Forgejo emits a
    # whitespace/tab table. Missing an existing source would create duplicates.
    list="$(forgejo_cli admin auth list --vertical 2>/dev/null || forgejo_cli admin auth list 2>/dev/null || true)"
    id="$(printf '%s\n' "$list" | awk -v n="$name" '
      /^ID:/   { cur=$2 }
      /^Name:/ { if ($2 == n) { print cur; exit } }
      $2 == n { print $1; exit }
    ')"

    if [ -z "''${id:-}" ]; then
      forgejo_cli admin auth add-oauth \
        --name "$name" \
        --provider openidConnect \
        --auto-discover-url ${lib.escapeShellArg cfg.discoveryUrl} \
        --key ${lib.escapeShellArg cfg.clientId} \
        --secret "$secret" \
        --scopes ${lib.escapeShellArg cfg.scopes}
    else
      forgejo_cli admin auth update-oauth \
        --id "$id" \
        --name "$name" \
        --provider openidConnect \
        --auto-discover-url ${lib.escapeShellArg cfg.discoveryUrl} \
        --key ${lib.escapeShellArg cfg.clientId} \
        --secret "$secret" \
        --scopes ${lib.escapeShellArg cfg.scopes}
    fi
  '';

  keyManifest = lib.mapAttrs (_username: keys:
    lib.mapAttrs (_title: key: {
      inherit (key) present;
      key = key.key;
      read_only = key.readOnly;
    })
    keys)
  cfg.sshKeys;

  stateFile = pkgs.writeText "forgejo-provision-state.json" (
    builtins.toJSON {
      sshKeys = keyManifest;
    }
  );

  cliArgs = lib.escapeShellArgs ([
      "--url"
      cfg.endpoint
      "--state"
      (toString stateFile)
      "--admin-user"
      cfg.adminUser
      "--ready-timeout"
      (toString cfg.readyTimeoutSeconds)
    ]
    ++ lib.optional cfg.acceptInvalidCerts "--accept-invalid-certs"
    ++ lib.optional cfg.allowSshKeyDelete "--allow-ssh-key-delete");

  provisionScript = pkgs.writeShellScript "forgejo-provision-start" ''
    set -eu
    ${seedScript}
    ${lib.optionalString (cfg.sshKeys != {}) ''
      test -s "$CREDENTIALS_DIRECTORY/admin-password"
      ${lib.getExe cfg.package} ${cliArgs} --admin-password-file "$CREDENTIALS_DIRECTORY/admin-password"
    ''}
  '';
in {
  options.services.forgejo.provision = {
    enable = mkEnableOption "declarative Forgejo OIDC auth-source and SSH-key provisioning";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.forgejo-provision;
      defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.forgejo-provision";
      description = "forgejo-provision package to run.";
    };

    endpoint = mkOption {
      type = types.str;
      default = let
        bindAddress = config.services.forgejo.settings.server.HTTP_ADDR or "127.0.0.1";
        host =
          if bindAddress == "" || bindAddress == "0.0.0.0" || bindAddress == "::"
          then "127.0.0.1"
          else bindAddress;
        authority =
          if lib.hasInfix ":" host
          then "[${host}]"
          else host;
      in "http://${authority}:${toString (config.services.forgejo.settings.server.HTTP_PORT or 3000)}";
      defaultText = lib.literalExpression "\"http://127.0.0.1:\${toString (config.services.forgejo.settings.server.HTTP_PORT or 3000)}\"";
      description = "Forgejo base URL used by the local administrative API client.";
    };

    adminUser = mkOption {
      type = types.str;
      default = "";
      description = "Forgejo administrator used for SSH-key API requests.";
    };

    adminPasswordFile = mkOption {
      type = types.nullOr (types.oneOf [types.path types.str]);
      default = null;
      description = "Runtime file containing the Forgejo administrator password.";
    };

    readyTimeoutSeconds = mkOption {
      type = types.ints.positive;
      default = 30;
      description = "Seconds to wait for Forgejo before provisioning.";
    };

    acceptInvalidCerts = mkOption {
      type = types.bool;
      default = false;
      description = "Accept invalid TLS certificates for an explicitly configured HTTPS endpoint.";
    };

    allowSshKeyDelete = mkOption {
      type = types.bool;
      default = false;
      description = "Global deletion gate for keys declared with present = false.";
    };

    sshKeys = mkOption {
      type = types.attrsOf (types.attrsOf keySubmodule);
      default = {};
      description = "Forgejo SSH keys keyed by username and stable title.";
    };

    authName = mkOption {
      type = types.str;
      default = "kanidm";
      description = ''
        Forgejo auth-source name and callback path segment. Forgejo registers
        the redirect URI as <ROOT_URL>user/oauth2/<authName>/callback. Renaming
        it later orphans the old auth source.
      '';
    };

    clientId = mkOption {
      type = types.str;
      default = "forgejo";
      description = "OIDC client id (kanidm-provision system name).";
    };

    discoveryUrl = mkOption {
      type = types.str;
      example = "https://auth.example.com/oauth2/openid/forgejo/.well-known/openid-configuration";
      description = "OIDC discovery URL passed to forgejo admin auth add-oauth.";
    };

    clientSecretFile = mkOption {
      type = types.oneOf [types.path types.str];
      description = ''
        Path to a file containing the OIDC client secret, readable by the
        Forgejo user. Loaded through systemd LoadCredential so the secret is
        not embedded in the Nix store or unit file. Forgejo's CLI still accepts
        the secret only through --secret at runtime.
      '';
    };

    scopes = mkOption {
      type = types.str;
      default = "openid profile email groups";
      description = "Space-separated scopes registered on the auth source.";
    };

    usernameClaim = mkOption {
      type = types.str;
      default = "preferred_username";
      description = "OIDC claim that populates Forgejo's username.";
    };

    accountLinking = mkOption {
      type = types.enum ["auto" "login" "disabled"];
      default = "auto";
      description = "oauth2_client ACCOUNT_LINKING. auto links by verified email.";
    };

    autoRegister = mkOption {
      type = types.bool;
      default = true;
      description = "oauth2_client ENABLE_AUTO_REGISTRATION.";
    };

    serviceAfter = mkOption {
      type = types.listOf types.str;
      default = ["forgejo.service"];
      description = "Units the seed oneshot waits for.";
    };
  };

  config = mkIf cfg.enable {
    assertions =
      [
        {
          assertion = config.services.forgejo.enable;
          message = "services.forgejo.provision requires services.forgejo.enable = true.";
        }
        {
          assertion = cfg.sshKeys == {} || cfg.adminUser != "";
          message = "services.forgejo.provision.adminUser is required when sshKeys are declared.";
        }
        {
          assertion = cfg.sshKeys == {} || cfg.adminPasswordFile != null;
          message = "services.forgejo.provision.adminPasswordFile is required when sshKeys are declared.";
        }
      ]
      ++ lib.flatten (lib.mapAttrsToList (_username: keys:
        lib.mapAttrsToList (_title: entry: [
          {
            assertion = entry.key == null || lib.trim entry.key != "";
            message = "Forgejo SSH-key values must not be empty.";
          }
          {
            assertion = entry.key == null || (!lib.hasInfix "\n" entry.key && !lib.hasInfix "\r" entry.key);
            message = "Forgejo SSH-key values must be single-line public keys.";
          }
          {
            assertion = !entry.present || entry.key != null;
            message = "Forgejo SSH keys declared present require a public key.";
          }
        ])
        keys)
      cfg.sshKeys);

    services.forgejo.settings.oauth2_client = {
      ENABLE_AUTO_REGISTRATION = cfg.autoRegister;
      ACCOUNT_LINKING = cfg.accountLinking;
      USERNAME = cfg.usernameClaim;
      UPDATE_AVATAR = true;
    };

    systemd.services.forgejo-seed-oidc = {
      description = "Register Forgejo OIDC and reconcile declared SSH keys";
      wantedBy = ["multi-user.target"];
      after = cfg.serviceAfter;
      requires = cfg.serviceAfter;
      restartTriggers = [stateFile];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        User = config.services.forgejo.user;
        Group = config.services.forgejo.group;
        WorkingDirectory = config.services.forgejo.stateDir;
        UMask = "0077";
        StandardOutput = "journal";
        StandardError = "journal";
        LoadCredential =
          ["oidc-secret:${toString cfg.clientSecretFile}"]
          ++ lib.optional (cfg.sshKeys != {}) "admin-password:${toString cfg.adminPasswordFile}";
        ExecStart = provisionScript;
      };
    };
  };
}
