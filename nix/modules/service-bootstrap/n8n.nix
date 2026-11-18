{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  n8n = config.services.n8n;
  cfg = n8n.provision;
  pw = self.lib.passwords;
  system = pkgs.stdenv.hostPlatform.system;
  exe = lib.getExe cfg.provisionPackage;
  json = pkgs.formats.json {};

  envFile = "/run/n8n-provision/owner.env";
  ownerCredential = "owner-password";
  # Length-prefixed so (foo-bar, va) and (foo, bar-va) never share an id.
  fieldCredential = name: field: pw.credentialName "n8n-credential:${toString (lib.stringLength name)}:${name}:${field}";

  # Secret-looking key anywhere in a data value (recursively): it would be
  # serialized into the store, so it belongs in dataFiles.
  looksSecret = v:
    if builtins.isAttrs v
    then lib.any (k: lib.any (s: lib.hasInfix s (lib.toLower k)) ["pass" "secret" "token" "key" "value" "auth" "cred" "bearer" "private" "cert" "jwt" "cookie" "session" "sign" "pin"] || looksSecret v.${k}) (lib.attrNames v)
    else if builtins.isList v
    then lib.any looksSecret v
    else false;

  # Rotation watch list: each file plus its parent directory (agenix swaps a
  # symlinked generation directory, which only the parent watch sees). Never
  # "/" or the store.
  watchPaths = files: let
    fs = map toString files;
    dirs = lib.filter (d: d != "/" && !(lib.hasPrefix builtins.storeDir d)) (map dirOf fs);
  in
    lib.unique (fs ++ dirs);

  notRuntime = f: !(lib.hasPrefix "/" f) || lib.hasPrefix builtins.storeDir f;
  fieldFiles = lib.concatLists (lib.mapAttrsToList (name: c: lib.mapAttrsToList (field: file: {inherit name field file;}) c.dataFiles) cfg.credentials);
  secretFiles = [cfg.owner.passwordFile] ++ map (f: toString f.file) fieldFiles;

  # Credential-carrying fields an export must never hold as data: the export is
  # copied into the store, which every process can read and every generation
  # keeps. Mirrors the reconciler's runtime lint.
  literalSecretNames = ["authorization" "api-key" "api_key" "apikey" "password" "x-api-key"];
  isLiteral = v: builtins.isString v && v != "" && !(lib.hasPrefix "=" v) && !(lib.hasInfix "{{" v);

  # The first literal credential in an export, as the field that carries it: a
  # header parameter pair (`{"name": "Authorization", "value": "Bearer ..."}`)
  # or a direct `authorization`/`apiKey`/`password` key.
  literalSecret = value:
    if builtins.isAttrs value
    then
      (
        if value ? name && isLiteral (value.value or null) && lib.elem (lib.toLower value.name) literalSecretNames
        then lib.toLower value.name
        else
          lib.findFirst (found: found != null) null (lib.mapAttrsToList (key: v:
            if lib.elem (lib.toLower key) literalSecretNames && isLiteral v
            then lib.toLower key
            else literalSecret v)
          value)
      )
    else if builtins.isList value
    then lib.findFirst (found: found != null) null (map literalSecret value)
    else null;

  # A path literal is read at evaluation: the file is already a source input, so
  # this is not IFD and the check runs before the path can enter the store. A
  # derivation output or a plain string cannot be read that way without IFD; the
  # reconciler's runtime check is what covers those.
  exportLiteral = w:
    if builtins.isPath w.file
    then literalSecret (builtins.fromJSON (builtins.readFile w.file))
    else null;
  leakedExports = lib.concatLists (lib.mapAttrsToList (name: w: let
    field = exportLiteral w;
  in
    lib.optional (field != null) {inherit name field;})
  cfg.workflows);

  ownerState = {
    inherit (cfg) url;
    owner = {
      inherit (cfg.owner) email;
      first_name = cfg.owner.firstName;
      last_name = cfg.owner.lastName;
      credential_name = ownerCredential;
    };
  };
  # the n8n-owner-env oneshot sees only the owner, so credential edits neither
  # restart n8n nor can a credential mistake stop it from starting.
  ownerStateFile = pkgs.writeText "n8n-provision-owner.json" (builtins.toJSON ownerState);

  # n8n drops an `executionTimeout` equal to the instance default from every
  # saved workflow, so the reconciler normalises a declared default away.
  executionTimeout = lib.toInt (toString (n8n.environment.EXECUTIONS_TIMEOUT or "-1"));
  # The pre-pass sees only what deactivating needs: a workflow name or a
  # credential the reconciler would reject must not keep it from unpublishing.
  inactiveWorkflows = lib.attrNames (lib.filterAttrs (_: w: !w.active) cfg.workflows);
  deactivateStateFile = pkgs.writeText "n8n-deactivate-state.json" (builtins.toJSON {
    inherit (cfg) url;
    owner = {
      inherit (cfg.owner) email;
      credential_name = ownerCredential;
    };
    inactive_workflows = inactiveWorkflows;
  });

  stateFile = pkgs.writeText "n8n-provision-state.json" (builtins.toJSON (ownerState
    // {
      execution_timeout = executionTimeout;
      credentials = lib.mapAttrs (name: c:
        {
          inherit (c) type data;
          data_files = lib.mapAttrs (field: _: fieldCredential name field) c.dataFiles;
        }
        // lib.optionalAttrs (c.dataFilePrefixes != {}) {
          data_file_prefixes = c.dataFilePrefixes;
        })
      cfg.credentials;
    }
    // lib.optionalAttrs (cfg.workflows != {}) {
      # A path literal is interpolated, not `toString`'d: the string keeps its
      # store context, so the file enters the closure and a content change
      # changes restartTriggers.
      workflows =
        lib.mapAttrs (name: w: {
          file = "${w.file}";
          inherit (w) active credentials;
        })
        cfg.workflows;
    }));
in {
  options.services.n8n.provision = {
    enable = mkEnableOption "declarative n8n owner account and credentials";

    provisionPackage = mkOption {
      type = types.package;
      default = lib.attrByPath ["packages" system "n8n-provision"] pkgs.n8n-provision self;
      defaultText = "self.packages.\${system}.n8n-provision";
      description = "n8n-provision binary.";
    };

    url = mkOption {
      type = types.str;
      default = "http://127.0.0.1:${toString n8n.environment.N8N_PORT}";
      defaultText = lib.literalExpression ''"http://127.0.0.1:''${config.services.n8n.environment.N8N_PORT}"'';
      description = "Loopback URL the reconciler uses to reach n8n.";
    };

    owner = {
      email = mkOption {
        type = types.str;
        description = "Instance owner email (the login).";
      };
      firstName = mkOption {
        type = types.str;
        default = "Instance";
        description = "Owner first name.";
      };
      lastName = mkOption {
        type = types.str;
        default = "Owner";
        description = "Owner last name.";
      };
      passwordFile = mkOption {
        type = types.str;
        description = ''
          Runtime file (not a store path) holding the owner password. When the
          root `n8n-owner-env` oneshot (required by n8n) starts or restarts it
          bcrypt-hashes it into a root-owned 0600 EnvironmentFile under /run (n8n's env-managed owner takes only a
          hash); the hash is reused while the password is unchanged.
        '';
      };
    };

    credentials = mkOption {
      default = {};
      description = ''
        n8n credentials upserted by name through the owner session. Secret
        fields come from runtime files via `dataFiles`; n8n encrypts them with
        its own encryption key.
      '';
      example = lib.literalExpression ''
        {
          studio-webhook = {
            type = "httpHeaderAuth";
            data.name = "X-Studio-Token";
            dataFiles.value = config.age.secrets.n8n-studio-webhook-token.path;
          };
        }
      '';
      type = types.attrsOf (types.submodule {
        options = {
          type = mkOption {
            type = types.str;
            description = "n8n credential type, for example `httpHeaderAuth` (fields `name`, `value`).";
          };
          data = mkOption {
            type = types.attrsOf json.type;
            default = {};
            description = "Non-secret credential fields.";
          };
          dataFiles = mkOption {
            type = types.attrsOf types.str;
            default = {};
            description = "Secret credential fields: field name to runtime file holding its value.";
          };
          dataFilePrefixes = mkOption {
            type = types.attrsOf types.str;
            default = {};
            description = ''
              Prefix prepended to a `dataFiles` value at run time, so a raw
              token file can become the field value n8n expects (a Header Auth
              `Authorization` of `value = "Bearer <token>"` uses
              `dataFilePrefixes.value = "Bearer "`). Read at run time with the
              file; the prefix itself is not secret.
            '';
            example = lib.literalExpression ''{value = "Bearer ";}'';
          };
        };
      });
    };

    workflows = mkOption {
      default = {};
      description = ''
        n8n workflows imported or updated by name from a JSON export. The
        reconciler rewrites each node's credential references to the ids of the
        declared `credentials`, then activates or deactivates the workflow to
        match `active`. An unchanged declaration writes nothing; a workflow
        edited in the UI is put back to the declared content.
      '';
      example = lib.literalExpression ''
        {
          fleetix-hub-claim = {
            file = ../n8n/workflows/fleetix-hub-claim.json;
            credentials."Fleetix Hub webhook token" = "fleetix-hub-webhook";
          };
        }
      '';
      type = types.attrsOf (types.submodule {
        options = {
          file = mkOption {
            type = types.oneOf [types.path types.str];
            description = ''
              n8n workflow JSON export (`nodes`, `connections`, optional
              `settings` and `meta`). A path literal is interpolated, so it
              stays in the closure and editing it changes the restart trigger.

              The export is copied into the Nix store, which is readable by every
              process and kept in every generation: it must be sanitized. A
              credential belongs in a declared `credentials` entry and is
              referenced from a node, and a value that must be computed uses an
              n8n expression (`=...`). A path literal is also read at evaluation,
              so an export holding a literal `Authorization`, `apiKey`/`api-key`
              or `password` value fails the build instead of reaching the store.
              That evaluation check covers path literals only: a derivation
              output or a plain string cannot be read without IFD, and for those
              the reconciler refuses the export at run time, once it is already
              in the store. Prefer a path literal for that reason.
            '';
          };
          active = mkOption {
            type = types.bool;
            default = true;
            description = ''
              Activate (publish) the imported workflow after writing it. A
              workflow declared inactive is deactivated by a separate unit that
              loads only the owner password, before the credentials are loaded,
              so a broken credential file cannot keep its webhook serving.
            '';
          };
          credentials = mkOption {
            type = types.attrsOf types.str;
            default = {};
            description = ''
              Credential reference name as written in the JSON export, mapped
              to a declared `credentials` entry. A reference with no entry here
              must itself be a declared credential name.
            '';
          };
        };
      });
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.match "https://[^@/?#]+/?|http://(127\\.0\\.0\\.1|localhost|[[]::1[]])(:[0-9]+)?/?" cfg.url != null;
        message = "services.n8n.provision.url must be an https:// or loopback http:// origin (no path, query or credentials): the owner session is sent over it.";
      }
      {
        assertion = !(lib.any (c: lib.any looksSecret [c.data]) (lib.attrValues cfg.credentials));
        message = "services.n8n.provision.credentials.*.data would land in the Nix store; put secret-looking fields (pass, secret, token, key, value, auth, cred, bearer, ...) in dataFiles.";
      }
      {
        assertion = lib.all (c: lib.all (f: !(c.data ? ${f})) (lib.attrNames c.dataFiles)) (lib.attrValues cfg.credentials);
        message = "services.n8n.provision.credentials.*: a field must not appear in both data and dataFiles.";
      }
      {
        assertion = n8n.enable;
        message = "services.n8n.provision requires services.n8n.enable = true.";
      }
      {
        assertion = !(lib.any notRuntime secretFiles);
        message = "services.n8n.provision secret files must be absolute runtime paths outside ${builtins.storeDir}.";
      }
      {
        assertion = lib.all (c: lib.all (field: c.dataFiles ? ${field}) (lib.attrNames c.dataFilePrefixes)) (lib.attrValues cfg.credentials);
        message = "services.n8n.provision.credentials.*.dataFilePrefixes must only prefix fields declared in dataFiles.";
      }
      {
        assertion = lib.all (w: lib.all (c: cfg.credentials ? ${c}) (lib.attrValues w.credentials)) (lib.attrValues cfg.workflows);
        message = "services.n8n.provision.workflows.*.credentials values must be declared credentials.";
      }
      {
        assertion = lib.all (w: lib.stringLength w != 0 && lib.stringLength w <= 128) (lib.attrNames cfg.workflows);
        message = "services.n8n.provision.workflows names must be 1-128 characters (n8n's workflow name limit).";
      }
      {
        assertion = leakedExports == [];
        message = lib.concatMapStrings (leak:
          ''
            services.n8n.provision.workflows.${leak.name}: the export holds a literal ${leak.field} value. The export is copied into the Nix store, so a header or password must be an n8n expression (`=...`) or a credential reference; move the value to a declared `credentials` entry with `dataFiles`.''
          + "\n")
        leakedExports;
      }
    ];

    # Env-managed owner: n8n reads N8N_INSTANCE_OWNER_* from its environment
    # and applies it on every start. Only the bcrypt hash is rendered, by a
    # root oneshot that holds the password as a systemd credential, so the
    # plaintext is never a credential of n8n.service itself.
    systemd.services.n8n-owner-env = {
      description = "Render the n8n owner environment from the owner password";
      before = ["n8n.service"];
      wantedBy = ["n8n.service"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        RuntimeDirectory = "n8n-provision";
        RuntimeDirectoryMode = "0700";
        RuntimeDirectoryPreserve = "yes";
        StateDirectory = "n8n-owner-env";
        StateDirectoryMode = "0700";
        LoadCredential = ["${ownerCredential}:${cfg.owner.passwordFile}"];
        ExecStart = "${exe} owner-env --state ${ownerStateFile} --password-file %d/${ownerCredential} --hash-dir /var/lib/n8n-owner-env --out ${envFile} --stamp /run/n8n-provision/owner.sha";
      };
    };
    systemd.services.n8n = {
      requires = ["n8n-owner-env.service"];
      after = ["n8n-owner-env.service"];
      serviceConfig.EnvironmentFile = lib.mkAfter ["-${envFile}"];
    };

    # Deactivation runs in its own unit that loads only the owner password.
    # systemd resolves a unit's whole LoadCredential= before ExecStart, so
    # loading the field credentials here would let one missing credential file
    # (or a corrupt credential registry) keep a webhook the declaration switched
    # off serving.
    systemd.services.n8n-deactivate = {
      description = "Deactivate n8n workflows declared active = false";
      after = ["n8n.service"];
      requires = ["n8n.service"];
      partOf = ["n8n.service"];
      wantedBy = ["multi-user.target"];
      restartTriggers = [deactivateStateFile];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        UMask = "0077";
        LoadCredential = ["${ownerCredential}:${cfg.owner.passwordFile}"];
        ExecStart = "${exe} deactivate --state ${deactivateStateFile} --credential-dir %d --ready-timeout 600";
        TimeoutStartSec = "15min";
      };
    };

    systemd.services.n8n-provision = {
      description = "Declaratively provision n8n credentials and workflows";
      # Fail closed: no workflow is written or activated unless the deactivating
      # pre-pass confirmed the declarations it had to unpublish.
      after = ["n8n.service" "n8n-deactivate.service"];
      requires = ["n8n.service" "n8n-deactivate.service"];
      partOf = ["n8n.service"];
      wantedBy = ["multi-user.target"];
      restartTriggers = [stateFile];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StateDirectory = "n8n-provision";
        StateDirectoryMode = "0700";
        UMask = "0077";
        LoadCredential =
          ["${ownerCredential}:${cfg.owner.passwordFile}"]
          ++ map (f: "${fieldCredential f.name f.field}:${f.file}") fieldFiles;
        ExecStart = "${exe} reconcile --state ${stateFile} --credential-dir %d --marker-dir /var/lib/n8n-provision/markers --ready-timeout 600";
        TimeoutStartSec = "15min";
      };
    };

    # A transient failure must not need a manual start. `Restart=` cannot do it
    # alone: a failed `Requires=` dependency cancels the provisioning job before
    # the unit runs, so no Restart= ever sees it. The timer keeps re-running the
    # pair instead (a start job pulls the failed pre-pass in again) and goes idle
    # once provisioning is active. A declaration that is genuinely broken still
    # surfaces: it stays failed between ticks, and every tick re-reports why.
    systemd.timers.n8n-provision-retry = {
      wantedBy = ["timers.target"];
      timerConfig = {
        Unit = "n8n-provision.service";
        # OnActiveSec arms the first tick (a unit that was never active has no
        # inactive timestamp to count from); OnUnitInactiveSec re-arms while the
        # unit is not active, failed included.
        OnActiveSec = "1min";
        OnUnitInactiveSec = "1min";
      };
    };

    # The owner hash is rendered by n8n-owner-env, so an in-place password
    # rotation restarts it (n8n follows via requires, n8n-provision via partOf).
    systemd.paths.n8n-provision-rotate = {
      wantedBy = ["multi-user.target"];
      pathConfig.PathChanged = watchPaths [cfg.owner.passwordFile];
    };
    systemd.services.n8n-provision-rotate = {
      description = "Restart n8n after the owner password file rotates";
      serviceConfig = {
        Type = "oneshot";
        LoadCredential = ["${ownerCredential}:${cfg.owner.passwordFile}"];
        # Only a real password change restarts n8n; an agenix generation switch
        # that leaves the content alone is skipped (exit 1 = condition unmet).
        ExecCondition = "${exe} changed --password-file %d/${ownerCredential} --stamp /run/n8n-provision/owner.sha";
        ExecStart = "${config.systemd.package}/bin/systemctl restart n8n-owner-env.service";
      };
    };

    systemd.paths.n8n-provision-credentials-rotate = mkIf (fieldFiles != []) {
      wantedBy = ["multi-user.target"];
      pathConfig.PathChanged = watchPaths (map (f: f.file) fieldFiles);
    };
    systemd.services.n8n-provision-credentials-rotate = mkIf (fieldFiles != []) {
      description = "Re-run n8n credential provisioning after a credential file rotates";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${config.systemd.package}/bin/systemctl restart n8n-provision.service";
      };
    };
  };
}
