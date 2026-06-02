{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.forgejo.provision;

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

    # Older Forgejo can emit vertical ID:/Name: lines; newer Forgejo emits a
    # whitespace/tab table. Missing an existing source would create duplicates.
    list="$(forgejo admin auth list --vertical 2>/dev/null || forgejo admin auth list 2>/dev/null || true)"
    id="$(printf '%s\n' "$list" | awk -v n="$name" '
      /^ID:/   { cur=$2 }
      /^Name:/ { if ($2 == n) { print cur; exit } }
      $2 == n { print $1; exit }
    ')"

    if [ -z "''${id:-}" ]; then
      forgejo admin auth add-oauth \
        --name "$name" \
        --provider openidConnect \
        --auto-discover-url ${lib.escapeShellArg cfg.discoveryUrl} \
        --key ${lib.escapeShellArg cfg.clientId} \
        --secret "$secret" \
        --scopes ${lib.escapeShellArg cfg.scopes}
    else
      forgejo admin auth update-oauth \
        --id "$id" \
        --name "$name" \
        --provider openidConnect \
        --auto-discover-url ${lib.escapeShellArg cfg.discoveryUrl} \
        --key ${lib.escapeShellArg cfg.clientId} \
        --secret "$secret" \
        --scopes ${lib.escapeShellArg cfg.scopes}
    fi
  '';
in {
  options.services.forgejo.provision = {
    enable = mkEnableOption "declarative Forgejo OIDC auth-source registration";

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
    assertions = [
      {
        assertion = config.services.forgejo.enable;
        message = "services.forgejo.provision requires services.forgejo.enable = true.";
      }
    ];

    services.forgejo.settings.oauth2_client = {
      ENABLE_AUTO_REGISTRATION = cfg.autoRegister;
      ACCOUNT_LINKING = cfg.accountLinking;
      USERNAME = cfg.usernameClaim;
      UPDATE_AVATAR = true;
    };

    systemd.services.forgejo-seed-oidc = {
      description = "Register / update the kanidm OIDC auth source in Forgejo";
      wantedBy = ["multi-user.target"];
      after = cfg.serviceAfter;
      requires = cfg.serviceAfter;

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        User = config.services.forgejo.user;
        Group = config.services.forgejo.group;
        WorkingDirectory = config.services.forgejo.stateDir;
        UMask = "0077";
        StandardOutput = "journal";
        StandardError = "journal";
        LoadCredential = ["oidc-secret:${toString cfg.clientSecretFile}"];
        ExecStart = seedScript;
      };
    };
  };
}
