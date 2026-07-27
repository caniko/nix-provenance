{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.nix-provenance.stalwart-oauth-bootstrap;
  configuredAccounts = lib.filterAttrs (_: account: account.passwordFile != null) cfg.accounts;
  defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.stalwart-oauth-bootstrap;

  accountModule = {
    options = {
      issuer = mkOption {
        type = types.str;
        description = "Stalwart OAuth issuer URL.";
        example = "https://mail.example.com";
      };

      accountName = mkOption {
        type = types.str;
        description = "Stalwart account name or email used for bootstrap.";
      };

      passwordFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Runtime file containing the Stalwart account password.";
      };

      clientId = mkOption {
        type = types.str;
        description = "Pre-registered public OAuth client identifier.";
      };

      redirectUri = mkOption {
        type = types.str;
        description = "Exact redirect URI registered for the public OAuth client.";
      };

      scope = mkOption {
        type = types.str;
        default = "urn:ietf:params:oauth:scope:mail";
        description = "OAuth scope requested during token bootstrap.";
      };

      resource = mkOption {
        type = types.str;
        description = "RFC 8707 protected-resource URL.";
      };

      keyringService = mkOption {
        type = types.str;
        description = "Secret Service service attribute used for the refresh token.";
      };

      keyringUsername = mkOption {
        type = types.str;
        description = "Secret Service username attribute used for the refresh token.";
      };
    };
  };

  unitFor = name: account: let
    unitName = "nix-provenance-stalwart-oauth-bootstrap-${name}";
    args = lib.concatStringsSep " " (map lib.escapeShellArg [
      "--issuer"
      account.issuer
      "--account-name"
      account.accountName
      "--password-file"
      account.passwordFile
      "--client-id"
      account.clientId
      "--redirect-uri"
      account.redirectUri
      "--scope"
      account.scope
      "--resource"
      account.resource
      "--keyring-service"
      account.keyringService
      "--keyring-username"
      account.keyringUsername
    ]);
  in
    lib.nameValuePair unitName {
      Unit = {
        Description = "Bootstrap Stalwart OAuth for ${name}";
        Wants = ["agenix.service" "oo7-daemon.service"];
        After = ["agenix.service" "oo7-daemon.service"];
      };
      Service = {
        Type = "oneshot";
        ExecStart = "${lib.escapeShellArg (lib.getExe cfg.package)} ${args}";
        Restart = "on-failure";
        RestartSec = "60s";
        RestartPreventExitStatus = 2;
      };
      Install.WantedBy = ["graphical-session.target"];
    };

  pathFor = name: account: let
    unitName = "nix-provenance-stalwart-oauth-bootstrap-${name}";
  in
    lib.nameValuePair unitName {
      Unit = {
        Description = "Watch the Stalwart OAuth bootstrap password for ${name}";
        Wants = ["agenix.service"];
        After = ["agenix.service"];
      };
      # systemd path settings require an absolute path and do not expand
      # environment variables.  `%t` is the user runtime directory
      # specifier, so convert agenix's `${XDG_RUNTIME_DIR}` placeholder while
      # leaving already-absolute custom paths untouched.
      Path.PathChanged = builtins.replaceStrings ["\${XDG_RUNTIME_DIR}"] ["%t"] account.passwordFile;
      Install.WantedBy = ["graphical-session.target"];
    };
in {
  options.nix-provenance.stalwart-oauth-bootstrap = {
    enable = mkEnableOption "automatic Stalwart OAuth refresh-token bootstrap";

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = lib.literalMD "nix-provenance.packages.<system>.stalwart-oauth-bootstrap";
      description = "Rust helper used to bootstrap and refresh the OAuth token.";
    };

    accounts = mkOption {
      type = types.attrsOf (types.submodule accountModule);
      default = {};
      description = "Stalwart accounts whose OAuth refresh tokens should be maintained.";
    };
  };

  config = mkIf cfg.enable {
    assertions =
      [
        {
          assertion = cfg.accounts != {};
          message = "nix-provenance.stalwart-oauth-bootstrap.accounts must not be empty.";
        }
      ]
      ++ lib.mapAttrsToList (name: account: {
        assertion = account.passwordFile != null;
        message = "Stalwart OAuth bootstrap account '${name}' requires passwordFile.";
      })
      cfg.accounts;

    home.packages = [cfg.package];
    systemd.user.services = lib.mapAttrs' unitFor configuredAccounts;
    systemd.user.paths = lib.mapAttrs' pathFor configuredAccounts;
  };
}
