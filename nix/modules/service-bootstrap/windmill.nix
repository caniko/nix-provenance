{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  wm = config.services.windmill;
  cfg = wm.provision;
  pw = self.lib.passwords;
  system = pkgs.stdenv.hostPlatform.system;
  exe = lib.getExe cfg.provisionPackage;

  stateDir = "/var/lib/windmill-provision";
  envFile = "/run/windmill-provision/env";
  superadminCredential = "superadmin";

  notRuntime = f: !(lib.hasPrefix "/" f) || lib.hasPrefix builtins.storeDir f;
  secretFiles = [cfg.superadminSecretFile] ++ map (u: toString u.passwordFile) (lib.attrValues cfg.users);

  stateFile = pkgs.writeText "windmill-provision-state.json" (builtins.toJSON {
    inherit (cfg) url;
    database = wm.database.name;
    superadmin_credential = superadminCredential;
    disable_default_admin = cfg.disableDefaultAdmin;
    workspaces = lib.mapAttrs (_: w: {inherit (w) name;}) cfg.workspaces;
    users =
      lib.mapAttrs (name: u: {
        inherit (u) email workspaces admin;
        credential_name = pw.credentialName name;
      })
      cfg.users;
    tokens =
      lib.mapAttrs (_: t: {
        inherit (t) user workspace scopes path owner group mode;
      })
      cfg.tokens;
  });
in {
  options.services.windmill.provision = {
    enable = mkEnableOption "declarative Windmill superadmin secret, operator logins, workspaces and API tokens";

    provisionPackage = mkOption {
      type = types.package;
      default = lib.attrByPath ["packages" system "windmill-provision"] pkgs.windmill-provision self;
      defaultText = "self.packages.\${system}.windmill-provision";
      description = "windmill-provision binary.";
    };

    superadminSecretFile = mkOption {
      type = types.str;
      description = ''
        Runtime file (not a store path) holding Windmill's SUPERADMIN_SECRET,
        e.g. `config.age.secrets.<name>.path`. Windmill reads this secret only
        from its environment (no `_FILE` variant), so an `ExecStartPre=+` step
        renders it into a root-owned 0600 EnvironmentFile under /run; see the
        service-root-secret exception in the architecture document.
      '';
    };

    url = mkOption {
      type = types.str;
      default = "http://127.0.0.1:${toString wm.serverPort}";
      defaultText = lib.literalExpression ''"http://127.0.0.1:''${toString config.services.windmill.serverPort}"'';
      description = "Loopback URL the reconciler uses to reach windmill-server.";
    };

    workspaces = mkOption {
      default = {};
      description = "Workspaces to ensure, keyed by workspace id (`[a-z0-9_-]+`). The open-source server allows two besides `admins`.";
      type = types.attrsOf (types.submodule {
        options.name = mkOption {
          type = types.str;
          description = "Workspace display name.";
        };
      });
    };

    users = mkOption {
      default = {};
      description = ''
        Instance users with a login. The open-source Windmill server rejects
        user creation and password changes over HTTP, so the reconciler writes
        an argon2id hash for the password file straight into the local
        `password` table (as the `postgres` superuser) and uses the HTTP API
        for workspace membership.
      '';
      type = types.attrsOf (types.submodule {
        options = {
          email = mkOption {
            type = types.str;
            description = "Login email.";
          };
          passwordFile = pw.passwordFileOption;
          workspaces = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Declared workspace ids this user belongs to.";
          };
          admin = mkOption {
            type = types.bool;
            default = false;
            description = "Instance superadmin and admin of every listed workspace.";
          };
        };
      });
    };

    disableDefaultAdmin = mkOption {
      type = types.bool;
      default = true;
      description = "Lock the stock admin@windmill.dev / changeme account (requires an admin user).";
    };

    tokens = mkOption {
      default = {};
      description = ''
        API tokens minted as `user` and stored at `path`. Token values are
        server-generated; an existing file is kept while Windmill still accepts
        it and re-minted otherwise.
      '';
      type = types.attrsOf (types.submodule ({name, ...}: {
        options = {
          user = mkOption {
            type = types.str;
            description = "Declared user the token is minted for.";
          };
          workspace = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Workspace the token is bound to.";
          };
          scopes = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Token scopes; empty means unscoped.";
          };
          path = mkOption {
            type = types.str;
            default = "${stateDir}/tokens/${name}";
            description = "File receiving the token.";
          };
          owner = mkOption {
            type = types.str;
            default = "root";
            description = "Owner (name or uid) of the token file.";
          };
          group = mkOption {
            type = types.str;
            default = "root";
            description = "Group (name or gid) of the token file.";
          };
          mode = mkOption {
            type = types.strMatching "0?[0-7]{3}";
            default = "0600";
            description = "Octal mode of the token file.";
          };
        };
      }));
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.match "https://.+|http://(127\\.0\\.0\\.1|localhost|\\[::1\\])([:/].*)?" cfg.url != null;
        message = "services.windmill.provision.url must be https:// or a loopback http:// URL: the superadmin bearer is sent over it.";
      }
      {
        assertion = wm.enable;
        message = "services.windmill.provision requires services.windmill.enable = true.";
      }
      {
        assertion = wm.database.createLocally;
        message = "services.windmill.provision writes users into the local PostgreSQL database; it requires services.windmill.database.createLocally = true.";
      }
      {
        assertion = !(lib.any notRuntime secretFiles);
        message = "services.windmill.provision secret files must be absolute runtime paths outside ${builtins.storeDir}.";
      }
      {
        assertion = !(lib.any (u: lib.toLower u.email == "admin@windmill.dev") (lib.attrValues cfg.users));
        message = "services.windmill.provision.users must not declare admin@windmill.dev: disableDefaultAdmin locks that account.";
      }
      {
        assertion = lib.length (lib.filter (id: id != "admins") (lib.attrNames cfg.workspaces)) <= 2;
        message = "services.windmill.provision.workspaces: open-source Windmill allows at most two workspaces besides `admins` (and `admins` is reserved).";
      }
      {
        assertion = !(cfg.workspaces ? admins);
        message = "services.windmill.provision.workspaces must not declare `admins`: it is reserved by Windmill.";
      }
      {
        assertion = lib.all (n: builtins.match "[A-Za-z][A-Za-z0-9_]*" n != null && lib.stringLength n <= 50) (lib.attrNames cfg.users);
        message = "services.windmill.provision.users names become Windmill usernames and must match [A-Za-z][A-Za-z0-9_]* and be at most 50 characters.";
      }
      {
        assertion = lib.all (u: u.passwordFile != null) (lib.attrValues cfg.users);
        message = "services.windmill.provision.users.*.passwordFile is required.";
      }
      {
        assertion = !cfg.disableDefaultAdmin || lib.any (u: u.admin) (lib.attrValues cfg.users);
        message = "services.windmill.provision.disableDefaultAdmin needs at least one user with admin = true.";
      }
      {
        assertion = lib.all (l: builtins.match "[A-Za-z0-9._-]+" l != null) (lib.attrNames cfg.tokens) && lib.all (t: cfg.users ? ${t.user} && (t.workspace == null || cfg.workspaces ? ${t.workspace})) (lib.attrValues cfg.tokens);
        message = "services.windmill.provision.tokens must reference declared users and workspaces.";
      }
      {
        assertion = lib.all (u: lib.all (w: cfg.workspaces ? ${w}) u.workspaces) (lib.attrValues cfg.users);
        message = "services.windmill.provision.users.*.workspaces must be declared workspaces.";
      }
    ];

    # Service-root-secret exception: Windmill takes SUPERADMIN_SECRET from its
    # environment only. Root renders it into a 0600 EnvironmentFile on tmpfs
    # at every (re)start; it never enters the store, argv or Environment=.
    systemd.services.windmill-server.serviceConfig = {
      LoadCredential = ["${superadminCredential}:${cfg.superadminSecretFile}"];
      RuntimeDirectory = "windmill-provision";
      RuntimeDirectoryMode = "0700";
      ExecStartPre = ["+${exe} env --secret-file %d/${superadminCredential} --out ${envFile}"];
      EnvironmentFile = lib.mkAfter ["-${envFile}"];
    };

    systemd.services.windmill-provision = {
      description = "Declaratively provision Windmill users, workspaces and tokens";
      after = ["windmill-server.service" "postgresql.target"];
      requires = ["windmill-server.service"];
      partOf = ["windmill-server.service"];
      wantedBy = ["multi-user.target"];
      restartTriggers = [stateFile];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StateDirectory = "windmill-provision";
        StateDirectoryMode = "0755";
        UMask = "0077";
        LoadCredential =
          ["${superadminCredential}:${cfg.superadminSecretFile}"]
          ++ pw.userPasswordCredentials "windmill-provision" cfg.users;
        ExecStart = "${exe} reconcile --state ${stateFile} --credential-dir %d --marker-dir ${stateDir}/markers --runuser ${pkgs.util-linux}/bin/runuser --psql ${config.services.postgresql.package}/bin/psql";
      };
    };
  };
}
