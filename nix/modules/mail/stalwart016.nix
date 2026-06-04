{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.stalwart016;
  json = pkgs.formats.json {};
  system = pkgs.stdenv.hostPlatform.system;

  defaultPackage = lib.attrByPath ["packages" system "stalwart"] pkgs.stalwart self;
  defaultCliPackage = lib.attrByPath ["packages" system "stalwart-cli"] pkgs.stalwart-cli self;

  credentialPath = name: "/run/credentials/stalwart.service/${name}";
  postgres = cfg.datastore.postgresql;

  bootstrapConfig = json.generate "stalwart016-bootstrap.json" {
    "@type" = "PostgreSql";
    host = postgres.host;
    port = postgres.port;
    database = postgres.database;
    authUsername = postgres.username;
    authSecret =
      if postgres.passwordFile == null
      then {"@type" = "None";}
      else {
        "@type" = "File";
        filePath = credentialPath postgres.passwordCredential;
      };
    useTls = postgres.useTls;
    allowInvalidCerts = postgres.allowInvalidCerts;
    poolMaxConnections = postgres.poolMaxConnections;
  };

  enabledListeners =
    lib.filterAttrs (_: listener: listener.enable) cfg.listeners;

  listenerCreateValue =
    lib.mapAttrs (_: listener: {
      inherit (listener) name protocol useTls tlsImplicit;
      bind = lib.genAttrs listener.bind (_: true);
    })
    enabledListeners;

  listenerDestroyOps =
    lib.mapAttrsToList (_: listener: {
      "@type" = "destroy";
      object = "NetworkListener";
      value.name = listener.name;
    })
    enabledListeners;

  listenerCreateOps = lib.optional (listenerCreateValue != {}) {
    "@type" = "create";
    object = "NetworkListener";
    value = listenerCreateValue;
  };

  generatedPlan = listenerDestroyOps ++ listenerCreateOps ++ cfg.provision.registryConfig;
  generatedPlanFile =
    pkgs.writeText "stalwart016-apply.ndjson"
    (lib.concatMapStrings (op: builtins.toJSON op + "\n") generatedPlan);
  applyFiles = cfg.provision.applyFiles ++ lib.optional (generatedPlan != []) generatedPlanFile;

  # Runtime (non-store) apply inputs — e.g. a live migrate_v016.py export — must be
  # readable from inside the service sandbox. The unit runs with PrivateTmp +
  # ProtectHome + ProtectSystem=strict, which hide the host /tmp, /var/tmp and /home,
  # so their parent directories are bind-mounted read-only into the namespace. The `-`
  # prefix makes a missing source non-fatal (the provision script's pathful guard then
  # reports exactly which input is missing). Store-path inputs are already visible.
  applyInputDirs = lib.pipe cfg.provision.applyFiles [
    (map toString)
    (lib.filter (p: lib.hasPrefix "/" p && !(lib.hasPrefix builtins.storeDir p)))
    (map builtins.dirOf)
    lib.unique
  ];

  loadCredentials =
    lib.optional (postgres.passwordFile != null) "${postgres.passwordCredential}:${postgres.passwordFile}"
    ++ lib.optional cfg.provision.enable "${cfg.recoveryAdmin.passwordCredential}:${cfg.recoveryAdmin.passwordFile}"
    ++ lib.mapAttrsToList (name: path: "${name}:${path}") cfg.credentials;

  provisionScript = pkgs.writeShellApplication {
    name = "stalwart016-provision";
    runtimeInputs = [
      pkgs.coreutils
      cfg.package
      cfg.cliPackage
    ];
    text = ''
      set -euo pipefail

      marker_file=${lib.escapeShellArg cfg.provision.markerFile}
      if [ -e "$marker_file" ]; then
        echo "stalwart016: provisioning already completed ($marker_file exists); skipping recovery apply"
        exit 0
      fi

      ${lib.optionalString (cfg.provision.requireVerifiedBackupSentinel != null) ''
        # Irreversible-step gate: recovery mode is the first 0.16 touch of the datastore;
        # after it the 0.15.x binary can no longer read the DB. Refuse without a verified
        # 0.15 backup (the migration backup.sh writes this sentinel only after a passing
        # verify-restore). This makes the "R2 floor" a hard precondition, not procedural.
        if [ ! -s ${lib.escapeShellArg cfg.provision.requireVerifiedBackupSentinel} ]; then
          echo "stalwart016: REFUSING recovery-mode provisioning — no verified-backup sentinel at ${cfg.provision.requireVerifiedBackupSentinel}" >&2
          echo "stalwart016: run the migration backup.sh before the 0.16 cutover." >&2
          exit 1
        fi
      ''}
      recovery_password_file="$CREDENTIALS_DIRECTORY/${cfg.recoveryAdmin.passwordCredential}"
      if [ ! -s "$recovery_password_file" ]; then
        echo "stalwart016: recovery admin password credential is missing or empty" >&2
        exit 1
      fi

      recovery_password="$(tr -d '\n' < "$recovery_password_file")"
      export HOME=/var/lib/stalwart016
      export XDG_CONFIG_HOME=/var/lib/stalwart016/.config
      mkdir -p "$XDG_CONFIG_HOME"

      export STALWART_RECOVERY_MODE=1
      export STALWART_RECOVERY_ADMIN="${lib.escapeShellArg cfg.recoveryAdmin.username}:$recovery_password"
      export STALWART_HOSTNAME=${lib.escapeShellArg cfg.hostname}

      ${lib.getExe cfg.package} --config /etc/stalwart016/config.json &
      recovery_pid="$!"

      cleanup() {
        kill "$recovery_pid" 2>/dev/null || true
        wait "$recovery_pid" 2>/dev/null || true
      }
      trap cleanup EXIT

      ready=0
      for _ in $(seq 1 ${toString cfg.provision.startupAttempts}); do
        if timeout 1 ${pkgs.bash}/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080' >/dev/null 2>&1; then
          ready=1
          break
        fi
        sleep ${lib.escapeShellArg cfg.provision.startupInterval}
      done

      if [ "$ready" != 1 ]; then
        echo "stalwart016: recovery listener did not become ready at ${cfg.provision.recoveryUrl}" >&2
        exit 1
      fi

      ${lib.concatMapStringsSep "\n" (file: ''
          apply_file=${lib.escapeShellArg (toString file)}
          # Fail with the offending PATH (stalwart-cli's own "No such file or
          # directory (os error 2)" names no file). Runtime inputs hidden by the
          # sandbox (PrivateTmp/ProtectHome/ProtectSystem) surface here too.
          if [ ! -r "$apply_file" ]; then
            echo "stalwart016: apply input not readable inside the service sandbox: $apply_file" >&2
            echo "stalwart016: the unit runs with PrivateTmp + ProtectHome + ProtectSystem=strict, so host /tmp, /var/tmp and /home are NOT visible. Stage migration inputs under a sandbox-visible directory (e.g. /var/lib/stalwart016-migration); the module binds applyFiles' parent dirs read-only, but the dir must exist at activation." >&2
            exit 1
          fi
          STALWART_URL=${lib.escapeShellArg cfg.provision.recoveryUrl} \
          STALWART_USER=${lib.escapeShellArg cfg.recoveryAdmin.username} \
          STALWART_PASSWORD="$recovery_password" \
          ${lib.getExe cfg.cliPackage} apply --no-color ${lib.optionalString cfg.provision.continueOnError "--continue-on-error"} --file "$apply_file"
        '')
        applyFiles}

      ${lib.concatMapStringsSep "\n" (object: ''
          STALWART_URL=${lib.escapeShellArg cfg.provision.recoveryUrl} \
          STALWART_USER=${lib.escapeShellArg cfg.recoveryAdmin.username} \
          STALWART_PASSWORD="$recovery_password" \
          ${lib.getExe cfg.cliPackage} query ${lib.escapeShellArg object} --json > /var/lib/stalwart016/query-${object}.json
        '')
        cfg.provision.queryObjects}

      {
        printf 'completed_at=%s\n' "$(date -Is)"
        printf 'generated_plan=%s\n' ${lib.escapeShellArg (toString generatedPlanFile)}
      } > "$marker_file"
    '';
  };
in {
  options.services.stalwart016 = {
    enable = mkEnableOption "Stalwart 0.16 JSON-bootstrap service";

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = "self.packages.\${system}.stalwart";
      description = "Stalwart 0.16.7 package used by the service.";
    };

    cliPackage = mkOption {
      type = types.package;
      default = defaultCliPackage;
      defaultText = "self.packages.\${system}.stalwart-cli";
      description = "stalwart-cli package used for headless registry provisioning.";
    };

    hostname = mkOption {
      type = types.str;
      default = config.networking.fqdnOrHostName;
      description = "Hostname exported as STALWART_HOSTNAME during recovery and normal startup.";
    };

    credentials = mkOption {
      type = types.attrsOf types.path;
      default = {};
      example = {
        cloudflare_token = "/run/secrets/stalwart-cloudflare-token";
      };
      description = ''
        Extra systemd LoadCredential entries for registry objects. Registry
        documents should refer to them with native File secrets such as
        {"@type":"File","filePath":"/run/credentials/stalwart.service/cloudflare_token"}.
      '';
    };

    recoveryAdmin = {
      username = mkOption {
        type = types.str;
        default = "admin";
        description = "Recovery-mode Basic Auth username used by the provisioning hook.";
      };

      passwordFile = mkOption {
        type = types.path;
        description = "File containing the recovery admin password.";
      };

      passwordCredential = mkOption {
        type = types.str;
        default = "recovery_admin_password";
        description = "LoadCredential name for the recovery admin password.";
      };
    };

    datastore.postgresql = {
      host = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "PostgreSQL host for the Stalwart DataStore bootstrap JSON.";
      };

      port = mkOption {
        type = types.port;
        default = 5432;
        description = "PostgreSQL port for the Stalwart DataStore bootstrap JSON.";
      };

      database = mkOption {
        type = types.str;
        default = "stalwart";
        description = "PostgreSQL database name.";
      };

      username = mkOption {
        type = types.str;
        default = "stalwart";
        description = "PostgreSQL role name.";
      };

      passwordFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          File containing the PostgreSQL role password. When set, the service
          loads it through systemd LoadCredential and the bootstrap JSON uses a
          native File secret pointing at /run/credentials/stalwart.service.
        '';
      };

      passwordCredential = mkOption {
        type = types.str;
        default = "pg_password";
        description = "LoadCredential name for the PostgreSQL password.";
      };

      useTls = mkOption {
        type = types.bool;
        default = false;
        description = "Whether Stalwart should use TLS for the PostgreSQL connection.";
      };

      allowInvalidCerts = mkOption {
        type = types.bool;
        default = false;
        description = "Whether Stalwart should accept invalid PostgreSQL TLS certificates.";
      };

      poolMaxConnections = mkOption {
        type = types.ints.positive;
        default = 10;
        description = "Maximum PostgreSQL connection pool size.";
      };

      createLocally = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Configure the local NixOS PostgreSQL service, ensure the database and
          owner role, and set the role password in postgresql-setup with an
          empty-file guard.
        '';
      };
    };

    listeners = mkOption {
      type = types.attrsOf (types.submodule ({name, ...}: {
        options = {
          enable = mkOption {
            type = types.bool;
            default = true;
            description = "Whether to provision this NetworkListener object.";
          };

          name = mkOption {
            type = types.str;
            default = name;
            description = "Stalwart NetworkListener name.";
          };

          bind = mkOption {
            type = types.listOf types.str;
            description = "Listener bind addresses in Stalwart 0.16 registry map form.";
          };

          protocol = mkOption {
            type = types.enum ["smtp" "imap" "http"];
            description = "Stalwart listener protocol.";
          };

          useTls = mkOption {
            type = types.bool;
            default = false;
            description = "Whether TLS is enabled for the listener.";
          };

          tlsImplicit = mkOption {
            type = types.bool;
            default = false;
            description = "Whether TLS is implicit rather than STARTTLS / cleartext.";
          };
        };
      }));
      default = {
        smtp = {
          bind = ["[::]:25"];
          protocol = "smtp";
          useTls = false;
          tlsImplicit = false;
        };
        submission = {
          bind = ["[::]:587"];
          protocol = "smtp";
          useTls = true;
          tlsImplicit = false;
        };
        imaps = {
          bind = ["[::]:993"];
          protocol = "imap";
          useTls = true;
          tlsImplicit = true;
        };
      };
      description = ''
        NetworkListener registry objects. The module renders these through
        stalwart-cli apply, not through TOML or the bootstrap JSON.
      '';
    };

    provision = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Run recovery-mode stalwart-cli apply before normal service startup.";
      };

      requireVerifiedBackupSentinel = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/var/backups/stalwart-016-migration/BACKUP_VERIFIED";
        description = ''
          If set, the recovery-mode provisioning hook REFUSES to run unless a
          non-empty sentinel file exists at this path. Recovery mode is the
          irreversible first 0.16 touch of the datastore (after it, the 0.15.x
          binary can no longer read the DB), so this enforces the "a verified 0.15
          backup must exist first" floor as a hard precondition rather than a
          procedural runbook step. The migration's backup.sh writes this sentinel
          only after a passing verify-restore. Leave null for non-migration hosts.
        '';
      };

      registryConfig = mkOption {
        type = types.listOf types.attrs;
        default = [];
        description = ''
          Additional raw stalwart-cli apply operations. These are rendered as
          newline-delimited JSON, one operation per line, for stalwart-cli apply.
        '';
      };

      applyFiles = mkOption {
        type = types.listOf (types.either types.path types.str);
        default = [];
        description = ''
          Additional pre-rendered stalwart-cli apply documents. These are applied
          before the generated listener/registry plan so migration exports can
          recreate accounts/domains before the host recreate-set is applied.
          String values may name runtime paths that are created before service
          activation, for example a live migrate_v016.py export on the target host.
        '';
      };

      queryObjects = mkOption {
        type = types.listOf types.str;
        default = ["NetworkListener"];
        description = ''
          Object types queried during recovery-mode provisioning. Results are
          captured under /var/lib/stalwart016/query-<Object>.json for tests and
          operational evidence.
        '';
      };

      recoveryUrl = mkOption {
        type = types.str;
        default = "http://127.0.0.1:8080";
        description = "Recovery listener URL used by stalwart-cli.";
      };

      continueOnError = mkOption {
        type = types.bool;
        default = false;
        description = "Pass --continue-on-error to stalwart-cli apply.";
      };

      startupAttempts = mkOption {
        type = types.ints.positive;
        default = 120;
        description = "Number of readiness attempts for the recovery listener.";
      };

      startupInterval = mkOption {
        type = types.str;
        default = "0.25";
        description = "Sleep interval between recovery readiness attempts.";
      };

      markerFile = mkOption {
        type = types.str;
        default = "/var/lib/stalwart016/provisioned";
        description = ''
          Runtime marker written after recovery-mode provisioning succeeds. When
          present, subsequent service starts skip recovery provisioning.
        '';
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = !cfg.provision.enable || cfg.recoveryAdmin.passwordFile != null;
        message = "services.stalwart016.provision.enable requires services.stalwart016.recoveryAdmin.passwordFile.";
      }
      {
        assertion = postgres.passwordFile != null || !postgres.createLocally;
        message = "services.stalwart016.datastore.postgresql.createLocally requires passwordFile so the local role can use scram-sha-256 TCP auth.";
      }
    ];

    environment.etc."stalwart016/config.json".source = bootstrapConfig;

    services.postgresql = mkIf postgres.createLocally {
      enable = true;
      enableTCPIP = true;
      ensureDatabases = [postgres.database];
      ensureUsers = [
        {
          name = postgres.username;
          ensureDBOwnership = true;
        }
      ];
      authentication = lib.mkAfter ''
        host ${postgres.database} ${postgres.username} 127.0.0.1/32 scram-sha-256
        host ${postgres.database} ${postgres.username} ::1/128      scram-sha-256
      '';
    };

    systemd.services.postgresql-setup.script = mkIf (postgres.createLocally && postgres.passwordFile != null) (lib.mkAfter ''
      if [ ! -r ${postgres.passwordFile} ] || [ ! -s ${postgres.passwordFile} ]; then
        echo "postgresql-setup: ${postgres.passwordFile} unreadable/empty; refusing to clear ${postgres.username} role password" >&2
        exit 1
      fi
      printf '%s\n' \
        '\set stalwart_password `cat ${postgres.passwordFile}`' \
        "ALTER ROLE ${postgres.username} WITH PASSWORD :'stalwart_password';" \
        | psql -d postgres
    '');

    users.users.stalwart016 = {
      isSystemUser = true;
      group = "stalwart016";
    };
    users.groups.stalwart016 = {};

    systemd.services.stalwart = {
      description = "Stalwart Mail Server 0.16";
      wantedBy = ["multi-user.target"];
      after = ["network.target"] ++ lib.optional postgres.createLocally "postgresql.target";
      wants = lib.optional postgres.createLocally "postgresql.target";
      environment.STALWART_HOSTNAME = cfg.hostname;

      serviceConfig = {
        Type = "simple";
        User = "stalwart016";
        Group = "stalwart016";
        StateDirectory = "stalwart016";
        WorkingDirectory = "/var/lib/stalwart016";
        LoadCredential = loadCredentials;
        ExecStartPre = lib.optional cfg.provision.enable (lib.getExe provisionScript);
        ExecStart = "${lib.getExe cfg.package} --config /etc/stalwart016/config.json";
        Restart = "on-failure";
        RestartSec = "5s";
        AmbientCapabilities = ["CAP_NET_BIND_SERVICE"];
        CapabilityBoundingSet = ["CAP_NET_BIND_SERVICE"];
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = ["/var/lib/stalwart016"];
        # Make runtime apply inputs (e.g. the migrate_v016.py export) visible inside
        # the sandbox despite PrivateTmp/ProtectHome/ProtectSystem=strict. Without
        # this, a host path like /var/tmp/.../export.json is hidden and the recovery
        # apply dies with an unpathful "No such file or directory". `-` = optional.
        BindReadOnlyPaths = map (d: "-${d}") applyInputDirs;
      };
    };
  };
}
