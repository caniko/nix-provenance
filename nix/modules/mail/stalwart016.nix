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

  defaultPackage = pkgs.stalwart_0_16;
  defaultCliPackage = pkgs.stalwart-cli;
  defaultProvisionPackage = lib.attrByPath ["packages" system "stalwart016-provision"] pkgs.stalwart016-provision self;

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

  # JSON config for the Rust provisioner binary (generated at eval time,
  # stored in /nix/store).  Runtime credential paths are passed as separate
  # CLI args so systemd's %d specifier can resolve them.
  provisionConfig = json.generate "stalwart016-provision-config.json" {
    migration_marker_file = cfg.provision.migrationMarkerFile;
    registry_marker_file = cfg.provision.registryMarkerFile;
    legacy_marker_file = cfg.provision.markerFile;
    assume_migration_applied = cfg.provision.assumeMigrationApplied;
    generated_plan_file = toString generatedPlanFile;
    migration_apply_files = map toString migrationApplyFiles;
    stalwart_binary = lib.getExe cfg.package;
    stalwart_config = "/etc/stalwart016/config.json";
    hostname = cfg.hostname;
    stalwart_cli_binary = lib.getExe cfg.cliPackage;
    recovery_url = cfg.provision.recoveryUrl;
    recovery_admin_username = cfg.recoveryAdmin.username;
    startup_attempts = cfg.provision.startupAttempts;
    startup_interval_secs = cfg.provision.startupInterval;
    query_output_dir = "/var/lib/stalwart016";
    query_objects = cfg.provision.queryObjects;
    continue_on_error = cfg.provision.continueOnError;
    require_verified_backup_sentinel = cfg.provision.requireVerifiedBackupSentinel;
    store_health_check = cfg.provision.storeHealthCheck.enable;
    probe_table = cfg.provision.storeHealthCheck.probeTable;
    psql_binary =
      if cfg.provision.storeHealthCheck.enable
      then (lib.getExe' pkgs.postgresql "psql")
      else null;
    pg_host = postgres.host;
    pg_port = postgres.port;
    pg_user = postgres.username;
    pg_database = postgres.database;
  };

  enabledListeners =
    lib.filterAttrs (_: listener: listener.enable) cfg.listeners;

  listenerCreateValue =
    lib.mapAttrs (_: listener: {
      inherit (listener) name protocol useTls tlsImplicit;
      bind = lib.genAttrs listener.bind (_: true);
    })
    enabledListeners;

  listenerOps = lib.optional (listenerCreateValue != {}) {
    "@type" = "upsert";
    object = "NetworkListener";
    matchOn = ["name"];
    value = listenerCreateValue;
  };

  oauthClientOps = lib.optional (cfg.oidc.clients != {}) {
    "@type" = "upsert";
    object = "OAuthClient";
    matchOn = ["clientId"];
    value = lib.mapAttrs (_: client: {
      clientId = client.clientId;
      description = client.description;
      redirectUris = lib.genAttrs client.redirectUris (_: true);
      contacts = lib.genAttrs client.contacts (_: true);
    }) cfg.oidc.clients;
  };

  generatedPlan = listenerOps ++ cfg.provision.registryConfig ++ oauthClientOps;
  generatedPlanFile =
    pkgs.writeText "stalwart016-apply.ndjson"
    (lib.concatMapStrings (op: builtins.toJSON op + "\n") generatedPlan);
  migrationApplyFiles = cfg.provision.migrationApplyFiles ++ cfg.provision.applyFiles;

  # Runtime (non-store) apply inputs — e.g. a live migrate_v016.py export — must be
  # readable from inside the service sandbox. The unit runs with PrivateTmp +
  # ProtectHome + ProtectSystem=strict, which hide the host /tmp, /var/tmp and /home,
  # so their parent directories are bind-mounted read-only into the namespace. The `-`
  # prefix makes a missing source non-fatal (the provision script's pathful guard then
  # reports exactly which input is missing). Store-path inputs are already visible.
  applyInputDirs = lib.pipe migrationApplyFiles [
    (map toString)
    (lib.filter (p: lib.hasPrefix "/" p && !(lib.hasPrefix builtins.storeDir p)))
    (map builtins.dirOf)
    lib.unique
  ];

  loadCredentials =
    lib.optional (postgres.passwordFile != null) "${postgres.passwordCredential}:${postgres.passwordFile}"
    ++ lib.optional cfg.provision.enable "${cfg.recoveryAdmin.passwordCredential}:${cfg.recoveryAdmin.passwordFile}"
    ++ lib.mapAttrsToList (name: path: "${name}:${path}") cfg.credentials;
in {
  options.services.stalwart016 = {
    enable = mkEnableOption "Stalwart 0.16 JSON-bootstrap service";

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = "pkgs.stalwart_0_16";
      description = "Stalwart 0.16 package used by the service.";
    };

    cliPackage = mkOption {
      type = types.package;
      default = defaultCliPackage;
      defaultText = "pkgs.stalwart-cli";
      description = "stalwart-cli package used for headless registry provisioning.";
    };

    provisionPackage = mkOption {
      type = types.package;
      default = defaultProvisionPackage;
      defaultText = "self.packages.\${system}.stalwart016-provision";
      description = "stalwart016-provision binary for recovery-mode provisioning.";
    };

    hostname = mkOption {
      type = types.str;
      default = config.networking.fqdnOrHostName;
      description = "Hostname exported as STALWART_HOSTNAME during recovery and normal startup.";
    };

    publicUrl = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Public HTTPS URL used by OAuth clients and discovery consumers.";
    };

    oidc.clients = mkOption {
      type = types.attrsOf (types.submodule ({name, ...}: {
        options = {
          clientId = mkOption {
            type = types.str;
            default = name;
            description = "Stable OAuth client_id presented to the authorization server.";
          };
          description = mkOption {
            type = types.str;
            default = name;
            description = "Administrative description shown for the OAuth client.";
          };
          redirectUris = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Exact redirect URIs accepted for this public client.";
          };
          contacts = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Administrative contact email addresses for the client.";
          };
        };
      }));
      default = {};
      description = "Declarative Stalwart OAuth clients, reconciled by the recovery apply plan.";
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

      assumeMigrationApplied = mkOption {
        type = types.bool;
        default = false;
        description = ''
          When true, skip re-applying migrationApplyFiles and write the migration
          marker immediately. Use this on the first deploy of the stalwart016
          provisioner to a host whose database already contains the migrated data
          (e.g. a host that went through the 0.15→0.16 cutover before the
          provisioner existed). After one successful start, the marker is written
          and subsequent starts skip migration normally — set this option back to
          false (or remove it) on the next deploy.
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
          Deprecated compatibility alias for migrationApplyFiles.

          These files are treated as one-time, non-idempotent migration inputs
          and are skipped after migrationMarkerFile exists. Prefer
          migrationApplyFiles in new configurations.
        '';
      };

      migrationApplyFiles = mkOption {
        type = types.listOf (types.either types.path types.str);
        default = [];
        description = ''
          One-time pre-rendered stalwart-cli apply documents, such as a
          migrate_v016.py export. These are applied before the generated
          listener/registry plan, then skipped on later starts once
          migrationMarkerFile exists. String values may name runtime paths that
          are created before service activation, for example a live migration
          export on the target host.
        '';
      };

      queryObjects = mkOption {
        type = types.listOf types.str;
        default = ["NetworkListener" "OAuthClient"];
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

      recoveryProbeObject = mkOption {
        type = types.str;
        default = "NetworkListener";
        description = ''
          Registry object queried with authenticated stalwart-cli while waiting
          for recovery mode. This prevents treating an unrelated listener on the
          recovery port as a ready Stalwart recovery endpoint.
        '';
      };

      continueOnError = mkOption {
        type = types.bool;
        default = false;
        description = "Pass --continue-on-error to stalwart-cli apply.";
      };

      storeHealthCheck = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Before skipping recovery (both markers current), probe the PostgreSQL
            store for a core table.  If the table is missing — for example after
            a PostgreSQL data-directory reinitialisation that wiped the schema —
            force a recovery-mode re-apply that recreates all tables.
            Implies BindsTo=postgresql.service so Stalwart restarts when PG
            restarts.
          '';
        };
        probeTable = mkOption {
          type = types.str;
          default = "f";
          description = "Core table name to probe in the store health check.";
        };
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
          Legacy runtime marker used by earlier module revisions. If present, it
          is treated as proof that migration inputs already ran, but registry
          provisioning still uses registryMarkerFile and the generated plan path
          to decide whether the registry plan is current.
        '';
      };

      migrationMarkerFile = mkOption {
        type = types.str;
        default = "/var/lib/stalwart016/migration-applied";
        description = ''
          Runtime marker written after migrationApplyFiles and compatibility
          applyFiles succeed. When present, migration inputs are never re-applied.
        '';
      };

      registryMarkerFile = mkOption {
        type = types.str;
        default = "/var/lib/stalwart016/registry-applied";
        description = ''
          Runtime marker written after the generated listener/registry plan
          succeeds. The marker records the generated plan store path, so changed
          registry content re-enters recovery mode without re-applying migration
          inputs.
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
    environment.etc."stalwart016/apply.ndjson".source = generatedPlanFile;

    services.postgresql = mkIf postgres.createLocally {
      enable = true;
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
      bindsTo = lib.optional postgres.createLocally "postgresql.service";
      environment = {
        STALWART_HOSTNAME = cfg.hostname;
        HOME = "/var/lib/stalwart016";
      } // lib.optionalAttrs (cfg.publicUrl != null) {
        STALWART_PUBLIC_URL = cfg.publicUrl;
      };

      serviceConfig = {
        Type = "simple";
        User = "stalwart016";
        Group = "stalwart016";
        StateDirectory = "stalwart016";
        WorkingDirectory = "/var/lib/stalwart016";
        LoadCredential = loadCredentials;
        ExecStartPre =
          lib.optional cfg.provision.enable
          (let
            pwFlag = "--recovery-password-file %d/${cfg.recoveryAdmin.passwordCredential}";
            healthCheckFlag =
              lib.optionalString cfg.provision.storeHealthCheck.enable
              "--pg-password-file %d/${postgres.passwordCredential}";
          in "${lib.getExe cfg.provisionPackage} --config ${provisionConfig} ${pwFlag} ${healthCheckFlag}");
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
