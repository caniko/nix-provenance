{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.ntfy-sh.provision;
  ntfySh = config.services.ntfy-sh;
  pw = self.lib.passwords;
  unit = "ntfy-sh-credentials";
  envFile = "/run/ntfy-sh-provision/env";
  tokenList = lib.concatLists (lib.mapAttrsToList (user: ts: lib.imap0 (i: t: t // {inherit user i;}) ts) cfg.tokens);
  secretFiles = map (u: u.passwordFile) (lib.attrValues cfg.users) ++ map (t: t.tokenFile) tokenList;
  notRuntime = f: !(lib.hasPrefix "/" f) || lib.hasPrefix builtins.storeDir f;
  tokenKey = t: "ntfy-token-${t.user}-${toString t.i}";
in {
  # Config-only: ntfy reads predefined users/tokens from NTFY_AUTH_* env vars.
  # Plaintext stays in runtime files; bcrypt hashes land in a 0600 tmpfs env
  # file that systemd (root) loads into the DynamicUser ntfy-sh service.
  options.services.ntfy-sh.provision = {
    enable = mkEnableOption "declarative ntfy users, tokens and ACLs";

    users = mkOption {
      default = {};
      description = "Predefined ntfy users.";
      type = types.attrsOf (types.submodule {
        options = {
          role = mkOption {
            type = types.enum ["admin" "user"];
            description = "ntfy role.";
          };
          passwordFile = mkOption {
            type = types.str;
            description = "Runtime file (not a store path) holding this user's password, e.g. `config.age.secrets.<name>.path`.";
          };
        };
      });
    };

    tokens = mkOption {
      default = {};
      description = "Access tokens per declared user; each file holds a `tk_` token.";
      type = types.attrsOf (types.listOf (types.submodule {
        options = {
          tokenFile = mkOption {
            type = types.str;
            description = "Runtime file (not a store path) containing a token matching `lib.ntfy.tokenPattern`.";
          };
          label = mkOption {
            type = types.nullOr (types.strMatching "[^:,]+");
            default = null;
            description = "Optional token label.";
          };
        };
      }));
    };

    access = mkOption {
      type = types.listOf types.str;
      default = [];
      example = ["publisher:alerts:wo"];
      description = "Entries merged into services.ntfy-sh.settings.auth-access (user:topic:permission).";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = ntfySh.enable;
        message = "services.ntfy-sh.provision requires services.ntfy-sh.enable = true.";
      }
      {
        assertion = ntfySh.settings ? auth-file;
        message = "services.ntfy-sh.provision requires services.ntfy-sh.settings.auth-file.";
      }
      {
        assertion = lib.all (u: cfg.users ? ${u}) (lib.attrNames cfg.tokens);
        message = "services.ntfy-sh.provision.tokens users must be declared in provision.users.";
      }
      {
        assertion = !(lib.any notRuntime secretFiles);
        message = "services.ntfy-sh.provision password/token files must be absolute runtime paths outside ${builtins.storeDir}.";
      }
      {
        assertion = ntfySh.settings.auth-default-access or null == "deny-all";
        message = "services.ntfy-sh.provision requires settings.auth-default-access = \"deny-all\" (no anonymous access).";
      }
    ];

    services.ntfy-sh.settings.auth-default-access = lib.mkDefault "deny-all";
    services.ntfy-sh.settings.auth-access = cfg.access;

    systemd.services.${unit} = {
      description = "Render ntfy users and tokens to an env file";
      requiredBy = ["ntfy-sh.service"];
      before = ["ntfy-sh.service"];
      partOf = ["ntfy-sh.service"];
      path = [pkgs.coreutils pkgs.gnugrep];
      script = self.lib.ntfy.mkEnvScript {
        ntfy = ntfySh.package;
        out = envFile;
        users =
          lib.mapAttrsToList (name: u: {
            inherit name;
            inherit (u) role;
            file = pw.userPasswordRuntimePath unit name;
          })
          cfg.users;
        tokens =
          map (t: {
            inherit (t) user label;
            file = pw.userPasswordRuntimePath unit (tokenKey t);
          })
          tokenList;
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        RuntimeDirectory = "ntfy-sh-provision";
        RuntimeDirectoryMode = "0700";
        UMask = "0077";
        LoadCredential =
          pw.userPasswordCredentials unit cfg.users
          ++ map (t: "${pw.credentialName (tokenKey t)}:${toString t.tokenFile}") tokenList;
      };
    };

    # nixpkgs sets EnvironmentFile to services.ntfy-sh.environmentFile; keep it,
    # but list ours last: with systemd the later file wins, so module credentials
    # override a pre-existing NTFY_AUTH_* there.
    systemd.services.ntfy-sh.serviceConfig.EnvironmentFile = lib.mkForce (lib.optional (ntfySh.environmentFile != null) ntfySh.environmentFile ++ [envFile]);
  };
}
