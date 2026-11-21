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
    lib.mapAttrsToList (id: settings: let
      named = value.enrollments ? ${id};
      inherit (settings) provider;
      name = "provenance-oauth-${user}-${id}";
      stateDirectory = "/var/lib/${name}";
      manifest = pkgs.writeText "${name}.json" (builtins.toJSON {
        version = 1;
        target =
          {
            host = config.networking.hostName;
            inherit user provider;
            inherit (settings) profile account;
          }
          // lib.optionalAttrs named {enrollment = id;};
        inherit stateDirectory;
        inherit (settings) recoveryRecipients;
      });
    in {
      inherit user id provider named settings name manifest stateDirectory;
    })
    ((lib.mapAttrs (provider: settings: settings // {inherit provider;}) value.providers) // value.enrollments))
  cfg.users);
  unitNames = lib.concatMap (entry: [entry.name "${entry.name}-initialize"]) entries;
  enrollmentOptions = {
    profile = mkOption {
      type = types.enum ["chatgpt" "opencode" "drive-file" "drive" "antigravity"];
      default = "chatgpt";
      description = "Compatible provider authorization profile.";
    };
    account = mkOption {
      type = types.str;
      default = "default";
      description = "Enrollment account alias; the OpenCode credential label for openai/opencode, or default or the expected Google subject for google/antigravity.";
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
      ConditionPathExists = "${entry.stateDirectory}/state.json";
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
        options = {
          providers = mkOption {
            default = {};
            type = types.attrsOf (types.submodule {options = enrollmentOptions;});
            description = "Legacy OAuth enrollments keyed by provider.";
          };
          enrollments = mkOption {
            default = {};
            type = types.attrsOf (types.submodule {
              options =
                enrollmentOptions
                // {
                  provider = mkOption {
                    type = types.enum ["google" "openai"];
                    description = "OAuth provider for this named enrollment.";
                  };
                };
            });
            description = "OAuth enrollments keyed by a simple lowercase identifier.";
          };
        };
      });
      description = "Enrollments isolated by host and local user; compatible enabled Home Manager apps bind automatically.";
    };
    manifests = mkOption {
      type = types.attrsOf (types.attrsOf types.path);
      readOnly = true;
      description = "Public per-user/enrollment manifests for the CLI and application adapters.";
    };
  };

  config = lib.mkMerge [
    {
      services.provenance.oauth.helperPackage = helper;
      services.provenance.oauth.manifests = lib.foldl' (result: entry:
        lib.recursiveUpdate result {${entry.user}.${entry.id} = entry.manifest;}) {}
      entries;
      assertions =
        [
          {
            assertion = lib.allUnique unitNames;
            message = "provenance OAuth: generated service names must be unique.";
          }
        ]
        ++ lib.mapAttrsToList (user: value: {
          assertion = lib.intersectLists (builtins.attrNames value.providers) (builtins.attrNames value.enrollments) == [];
          message = "provenance OAuth: ${user}'s providers and enrollments must not share IDs.";
        })
        cfg.users
        ++ lib.concatMap (entry: [
          {
            assertion = builtins.match "[a-z0-9][a-z0-9-]*" entry.id != null;
            message = "provenance OAuth: invalid enrollment ID '${entry.id}'.";
          }
          {
            assertion = (entry.provider == "openai" && builtins.elem entry.settings.profile ["chatgpt" "opencode"]) || (entry.provider == "google" && builtins.elem entry.settings.profile ["drive-file" "drive" "antigravity"]);
            message = "provenance OAuth: unsupported provider/profile pair '${entry.provider}/${entry.settings.profile}'.";
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
      environment.etc = builtins.listToAttrs (map (entry: lib.nameValuePair "provenance/oauth/${entry.user}-${entry.id}.json" {source = entry.manifest;}) entries);
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
      home-manager.sharedModules = [self.homeModules.oauth];
      home-manager.users =
        lib.foldl' (result: entry:
          lib.recursiveUpdate result {
            ${entry.user}.nix-provenance.oauth.accounts.${entry.id} = {
              configFile = entry.manifest;
              package = helper;
              inherit (entry) provider stateDirectory;
              inherit (entry.settings) profile;
            };
          }) {}
        # Legacy service-only Drive entries (e.g. root) must not create HM users.
        (lib.filter (entry: entry.named || entry.provider == "openai" || entry.settings.profile == "antigravity") entries);
    })
  ];
}
