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
  lockOrder = lib.optional cfg.disableDefaultAdmin "windmill-lock-default-admin.service";

  # Rotation watch list: each file plus its parent directory (agenix swaps a
  # symlinked generation directory, which only the parent watch sees). Never
  # "/" or the store.
  watchPaths = files: let
    fs = map toString files;
    dirs = lib.filter (d: d != "/" && !(lib.hasPrefix builtins.storeDir d)) (map dirOf fs);
  in
    lib.unique (fs ++ dirs);

  notRuntime = f: !(lib.hasPrefix "/" f) || lib.hasPrefix builtins.storeDir f;
  secretFiles = [cfg.superadminSecretFile] ++ map (u: toString u.passwordFile) (lib.attrValues cfg.users);

  # Length-prefixed so (studio, f/a/b) and (studio-f, a/b) never share an id.
  variableCredential = ws: path:
    pw.credentialName "windmill-variable:${toString (lib.stringLength ws)}:${ws}:${toString (lib.stringLength path)}:${path}";
  declaredVariables = lib.concatLists (lib.mapAttrsToList (ws: w:
    lib.mapAttrsToList (path: v: {inherit ws path v;}) w.variables)
  cfg.workspaces);
  variableFiles = map (d: toString d.v.valueFile) declaredVariables;
  variableCredentials = map (d: "${variableCredential d.ws d.path}:${d.v.valueFile}") declaredVariables;

  stateFile = pkgs.writeText "windmill-provision-state.json" (builtins.toJSON {
    inherit (cfg) url;
    database = wm.database.name;
    superadmin_credential = superadminCredential;
    disable_default_admin = cfg.disableDefaultAdmin;
    workspaces =
      lib.mapAttrs (id: w: {
        inherit (w) name;
        scripts =
          lib.mapAttrs (_: s: {
            inherit (s) language summary;
            content_file = toString s.contentFile;
          })
          w.scripts;
        variables =
          lib.mapAttrs (path: v: {
            credential_name = variableCredential id path;
            is_secret = v.isSecret;
            inherit (v) description;
          })
          w.variables;
      })
      cfg.workspaces;
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
        options = {
          name = mkOption {
            type = types.str;
            description = "Workspace display name.";
          };

          scripts = mkOption {
            default = {};
            description = ''
              Scripts deployed into this workspace, keyed by full Windmill path.
              The reconciler deploys a new version only when the content or
              language differs from the latest deployed one; the version
              history is Windmill's.
            '';
            example = lib.literalExpression ''
              {
                "f/fleetix_hub/comfy_generate" = {
                  language = "bun";
                  contentFile = ../registry/windmill/comfy_generate.ts;
                  summary = "Submit ComfyUI prompts";
                };
              }
            '';
            type = types.attrsOf (types.submodule {
              options = {
                language = mkOption {
                  type = types.strMatching "[a-z][a-z0-9_]*";
                  description = "Windmill script language (`bun`, `python3`, `deno`, `nativets`, ...).";
                };
                contentFile = mkOption {
                  type = types.oneOf [types.path types.str];
                  description = ''
                    File holding the script content. Scripts are code, not
                    secrets, so a store path (a path literal such as
                    `./procedure.ts`, or `toString`/`"''${pkgs.writeText ...}"`)
                    is the normal choice; any readable absolute path works.
                  '';
                };
                summary = mkOption {
                  type = types.str;
                  default = "";
                  description = "Script summary shown in the Windmill UI.";
                };
              };
            });
          };

          variables = mkOption {
            default = {};
            description = ''
              Variables upserted in this workspace, keyed by full Windmill path.
              The value is read from `valueFile` at run time and never enters
              the Nix store, so `valueFile` must be a runtime path such as
              `config.age.secrets.<name>.path`.
            '';
            example = lib.literalExpression ''
              {
                "f/fleetix_hub/hub_token" = {
                  valueFile = config.age.secrets.fleetix-hub-windmill-token.path;
                  description = "Fleetix Hub receipt bearer";
                };
              }
            '';
            type = types.attrsOf (types.submodule {
              options = {
                valueFile = mkOption {
                  type = types.str;
                  description = "Runtime file (not a store path) holding the variable value.";
                };
                isSecret = mkOption {
                  type = types.bool;
                  default = true;
                  description = "Store the variable encrypted (Windmill secret).";
                };
                description = mkOption {
                  type = types.str;
                  default = "";
                  description = "Variable description shown in the Windmill UI.";
                };
              };
            });
          };
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
        assertion = builtins.match "https://[^@/?#]+/?|http://(127\\.0\\.0\\.1|localhost|[[]::1[]])(:[0-9]+)?/?" cfg.url != null;
        message = "services.windmill.provision.url must be an https:// or loopback http:// origin (no path, query or credentials): the superadmin bearer is sent over it.";
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
        assertion = lib.all (u: u.email == lib.toLower u.email) (lib.attrValues cfg.users);
        message = "services.windmill.provision.users emails must be lowercase: Windmill lowercases the email at login.";
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
        assertion = lib.all (l: l != "session" && builtins.match "[A-Za-z0-9._-]+" l != null) (lib.attrNames cfg.tokens) && lib.all (t: cfg.users ? ${t.user} && (t.workspace == null || cfg.workspaces ? ${t.workspace})) (lib.attrValues cfg.tokens);
        message = "services.windmill.provision.tokens must reference declared users and workspaces.";
      }
      {
        assertion = lib.all (t: t.workspace == null || cfg.users.${t.user}.admin || lib.elem t.workspace cfg.users.${t.user}.workspaces) (lib.filter (t: cfg.users ? ${t.user}) (lib.attrValues cfg.tokens));
        message = "services.windmill.provision.tokens bound to a workspace need an admin user or a member of that workspace.";
      }
      {
        assertion = lib.all (u: lib.all (w: cfg.workspaces ? ${w}) u.workspaces) (lib.attrValues cfg.users);
        message = "services.windmill.provision.users.*.workspaces must be declared workspaces.";
      }
      {
        assertion = lib.all (w: lib.all (p: lib.stringLength p <= 255 && builtins.match "[ufg](/[A-Za-z0-9_-]+){2,}" p != null) (lib.attrNames w.scripts ++ lib.attrNames w.variables)) (lib.attrValues cfg.workspaces);
        message = "services.windmill.provision.workspaces.*.{scripts,variables} must be keyed by a full Windmill path (`f/<folder>/<name>`, `u/<user>/<name>` or `g/<group>/<name>`; alphanumerics, `_` and `-`; at most 255 characters).";
      }
      {
        assertion = !(lib.any notRuntime variableFiles);
        message = "services.windmill.provision.workspaces.*.variables.*.valueFile must be an absolute runtime path outside ${builtins.storeDir}: the value is a secret.";
      }
    ];

    # Service-root-secret exception: Windmill takes SUPERADMIN_SECRET from its
    # environment only. Root renders it into a 0600 EnvironmentFile on tmpfs
    # at every (re)start; it never enters the store, argv or Environment=.
    systemd.services.windmill-server.serviceConfig = {
      LoadCredential = ["${superadminCredential}:${cfg.superadminSecretFile}"];
      RuntimeDirectory = "windmill-provision";
      RuntimeDirectoryMode = "0700";
      ExecStartPre = ["+${exe} env --secret-file %d/${superadminCredential} --out ${envFile} --stamp /run/windmill-provision/superadmin.sha"];
      EnvironmentFile = lib.mkAfter ["-${envFile}"];
    };

    # Locking the stock login must not depend on any secret file: systemd
    # resolves LoadCredential before ExecStart, so a missing user password
    # would fail reconcile and leave admin@windmill.dev / changeme open. This
    # unit loads no credentials at all and runs before reconcile.
    systemd.services.windmill-lock-default-admin = mkIf cfg.disableDefaultAdmin {
      description = "Lock Windmill's stock admin@windmill.dev account";
      after = ["windmill-server.service" "postgresql.target"];
      requires = ["windmill-server.service"];
      partOf = ["windmill-server.service"];
      wantedBy = ["multi-user.target"];
      restartTriggers = [stateFile];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        UMask = "0077";
        ExecStart = "${exe} lock-default-admin --state ${stateFile} --runuser ${pkgs.util-linux}/bin/runuser --psql ${config.services.postgresql.package}/bin/psql";
      };
    };

    systemd.services.windmill-provision = {
      description = "Declaratively provision Windmill users, workspaces, scripts, variables and tokens";
      after = ["windmill-server.service" "postgresql.target"] ++ lockOrder;
      requires = ["windmill-server.service"] ++ lockOrder;
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
          ++ pw.userPasswordCredentials "windmill-provision" cfg.users
          ++ variableCredentials;
        ExecStart = "${exe} reconcile --state ${stateFile} --credential-dir %d --marker-dir ${stateDir}/markers --runuser ${pkgs.util-linux}/bin/runuser --psql ${config.services.postgresql.package}/bin/psql";
      };
    };

    # Runtime secret files rotate in place, so nothing in the store changes to
    # restart on: watch them. A rotated password restarts the oneshot
    # (RemainAfterExit makes a plain start a no-op); a rotated superadmin
    # secret restarts the server (the env file is rendered at its start),
    # which re-runs provisioning through partOf.
    systemd.paths.windmill-provision-rotate = mkIf (cfg.users != {}) {
      wantedBy = ["multi-user.target"];
      pathConfig.PathChanged = watchPaths (map (u: u.passwordFile) (lib.attrValues cfg.users));
    };
    systemd.services.windmill-provision-rotate = mkIf (cfg.users != {}) {
      description = "Re-run Windmill provisioning after a password file rotates";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${config.systemd.package}/bin/systemctl restart windmill-provision.service";
      };
    };
    # Variable values are runtime secrets: an in-place rotation re-runs the
    # oneshot so Windmill picks up the new value without a full restart.
    systemd.paths.windmill-variables-rotate = mkIf (variableFiles != []) {
      wantedBy = ["multi-user.target"];
      pathConfig.PathChanged = watchPaths variableFiles;
    };
    systemd.services.windmill-variables-rotate = mkIf (variableFiles != []) {
      description = "Re-run Windmill provisioning after a variable value file rotates";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${config.systemd.package}/bin/systemctl restart windmill-provision.service";
      };
    };

    systemd.paths.windmill-superadmin-rotate = {
      wantedBy = ["multi-user.target"];
      pathConfig.PathChanged = watchPaths [cfg.superadminSecretFile];
    };
    systemd.services.windmill-superadmin-rotate = {
      description = "Restart Windmill after the superadmin secret rotates";
      serviceConfig = {
        Type = "oneshot";
        LoadCredential = ["${superadminCredential}:${cfg.superadminSecretFile}"];
        # Only a real secret change restarts the server; an agenix generation
        # switch that leaves the content alone is skipped (exit 1 = unmet).
        ExecCondition = "${exe} changed --secret-file %d/${superadminCredential} --stamp /run/windmill-provision/superadmin.sha";
        ExecStart = "${config.systemd.package}/bin/systemctl restart windmill-server.service";
      };
    };
  };
}
