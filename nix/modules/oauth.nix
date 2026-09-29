{self}: {
  config,
  lib,
  pkgs,
  options,
  ...
}: let
  inherit (lib) mkOption types;
  cfg = config.services.provenance.oauth;
  helper = pkgs.writeShellScriptBin "provenance-oauth" ''
    export PATH=${lib.makeBinPath (cfg.recoveryPlugins ++ [pkgs.coreutils])}:"$PATH"
    exec ${lib.getExe cfg.package} "$@"
  '';
  entries = lib.concatLists (lib.mapAttrsToList (user: value:
    lib.mapAttrsToList (provider: settings: let
      name = "provenance-oauth-${user}-${provider}";
      manifest = pkgs.writeText "${name}.json" (builtins.toJSON {
        version = 1;
        target = {
          host = config.networking.hostName;
          inherit user provider;
          inherit (settings) profile account;
        };
        stateDirectory = "/var/lib/${name}";
        inherit (settings) recoveryRecipients;
      });
    in {
      inherit user provider settings name manifest;
    })
    value.providers)
  cfg.users);
  hasHomeManager = options ? home-manager;
  service = initialize: entry: {
    description = "${
      if initialize
      then "Initialize"
      else "Reconcile"
    } ${entry.user}'s shared ${entry.provider} OAuth enrollment";
    after = ["agenix.service"];
    wantedBy = lib.optionals (!initialize) ["multi-user.target"];
    restartTriggers = [entry.manifest];
    # First enrollment is explicit. A missing state file must never cause the
    # boot unit to replay a potentially rotated enrollment grant.
    unitConfig = lib.optionalAttrs (!initialize) {
      ConditionPathExists = "/var/lib/${entry.name}/state.json";
    };
    path = [pkgs.coreutils];
    serviceConfig = {
      Type = "oneshot";
      User = entry.user;
      UMask = "0077";
      StateDirectory = entry.name;
      StateDirectoryMode = "0700";
      LoadCredential = ["enrollment:${entry.settings.enrollmentFile}"];
      ExecStart = "${lib.getExe helper} --config ${entry.manifest} apply --enrollment %d/enrollment${lib.optionalString initialize " --initialize"}";
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      ProtectKernelTunables = true;
      ProtectControlGroups = true;
      RestrictAddressFamilies = ["AF_UNIX"];
    };
  };
in {
  options.services.provenance.oauth = {
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.provenance-oauth;
      description = "nix-provenance OAuth lifecycle helper.";
    };
    recoveryPlugins = mkOption {
      type = types.listOf types.package;
      default = [];
      description = "age plugins required by the public recovery recipients; encryption must be non-interactive.";
    };
    helperPackage = mkOption {
      type = types.package;
      readOnly = true;
      description = "OAuth helper with this host's recovery encryption plugins on PATH.";
    };
    users = mkOption {
      default = {};
      type = types.attrsOf (types.submodule {
        options.providers = mkOption {
          default = {};
          type = types.attrsOf (types.submodule {
            options = {
              profile = mkOption {
                type = types.enum ["chatgpt"];
                default = "chatgpt";
                description = "Compatible provider authorization profile.";
              };
              account = mkOption {
                type = types.str;
                default = "default";
                description = "Host-local enrollment account alias.";
              };
              enrollmentFile = mkOption {
                type = types.str;
                description = "Runtime agenix enrollment file, loaded through systemd credentials.";
              };
              recoveryRecipients = mkOption {
                type = types.nonEmptyListOf types.str;
                description = "Public age X25519, SSH or plugin recipients for current-state checkpoints.";
              };
            };
          });
          description = "Host-shared OAuth provider enrollments (currently openai/chatgpt).";
        };
      });
      description = "Enrollments isolated by host and local user; compatible enabled Home Manager apps bind automatically.";
    };
    manifests = mkOption {
      type = types.attrsOf (types.attrsOf types.path);
      readOnly = true;
      description = "Public per-user/provider manifests for the CLI and application adapters.";
    };
  };

  config = lib.mkMerge [
    {
      services.provenance.oauth.helperPackage = helper;
      services.provenance.oauth.manifests = lib.foldl' (result: entry:
        lib.recursiveUpdate result {${entry.user}.${entry.provider} = entry.manifest;}) {}
      entries;
      assertions =
        lib.concatMap (entry: [
          {
            assertion = entry.provider == "openai";
            message = "provenance OAuth: unsupported provider '${entry.provider}'.";
          }
          {
            assertion = builtins.match "[a-zA-Z0-9_-]+" entry.user != null && config.users.users ? ${entry.user};
            message = "provenance OAuth requires an existing local user with a simple identifier.";
          }
          {
            assertion = lib.hasPrefix "/" entry.settings.enrollmentFile && !(lib.hasPrefix "/nix/store/" entry.settings.enrollmentFile);
            message = "provenance OAuth enrollmentFile must be an absolute runtime path, never a Nix-store secret.";
          }
        ])
        entries;
      environment.systemPackages = lib.optional (entries != []) helper;
      environment.etc = builtins.listToAttrs (map (entry: lib.nameValuePair "provenance/oauth/${entry.user}-${entry.provider}.json" {source = entry.manifest;}) entries);
      systemd.services = builtins.listToAttrs (lib.concatMap (entry: [
          (lib.nameValuePair entry.name (service false entry))
          (lib.nameValuePair "${entry.name}-initialize" (service true entry))
        ])
        entries);
      systemd.paths = builtins.listToAttrs (map (entry:
        lib.nameValuePair entry.name {
          description = "Watch ${entry.user}'s shared ${entry.provider} OAuth enrollment";
          wantedBy = ["multi-user.target"];
          pathConfig = {
            PathChanged = entry.settings.enrollmentFile;
            Unit = "${entry.name}.service";
          };
        })
      entries);
    }
    (lib.optionalAttrs hasHomeManager {
      home-manager.sharedModules = [(import ./home/oauth.nix {inherit self;})];
      home-manager.users = lib.foldl' (result: entry:
        lib.recursiveUpdate result {
          ${entry.user}.nix-provenance.oauth.accounts.${entry.provider} = {
            configFile = entry.manifest;
            package = helper;
          };
        }) {}
      entries;
    })
  ];
}
