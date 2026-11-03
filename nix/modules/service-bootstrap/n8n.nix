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
    then lib.any (k: lib.any (s: lib.hasInfix s (lib.toLower k)) ["pass" "secret" "token" "key" "value"] || looksSecret v.${k}) (lib.attrNames v)
    else if builtins.isList v
    then lib.any looksSecret v
    else false;

  notRuntime = f: !(lib.hasPrefix "/" f) || lib.hasPrefix builtins.storeDir f;
  fieldFiles = lib.concatLists (lib.mapAttrsToList (name: c: lib.mapAttrsToList (field: file: {inherit name field file;}) c.dataFiles) cfg.credentials);
  secretFiles = [cfg.owner.passwordFile] ++ map (f: toString f.file) fieldFiles;

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
  stateFile = pkgs.writeText "n8n-provision-state.json" (builtins.toJSON (ownerState
    // {
      credentials =
        lib.mapAttrs (name: c: {
          inherit (c) type data;
          data_files = lib.mapAttrs (field: _: fieldCredential name field) c.dataFiles;
        })
        cfg.credentials;
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
        message = "services.n8n.provision.credentials.*.data would land in the Nix store; put secret-looking fields (pass, secret, token, key, value) in dataFiles.";
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
        ExecStart = "${exe} owner-env --state ${ownerStateFile} --password-file %d/${ownerCredential} --hash-dir /var/lib/n8n-owner-env --out ${envFile}";
      };
    };
    systemd.services.n8n = {
      requires = ["n8n-owner-env.service"];
      after = ["n8n-owner-env.service"];
      serviceConfig.EnvironmentFile = lib.mkAfter ["-${envFile}"];
    };

    systemd.services.n8n-provision = {
      description = "Declaratively provision n8n credentials";
      after = ["n8n.service"];
      requires = ["n8n.service"];
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
        ExecStart = "${exe} reconcile --state ${stateFile} --credential-dir %d --marker-dir /var/lib/n8n-provision/markers";
      };
    };

    # The owner hash is rendered by n8n-owner-env, so an in-place password
    # rotation restarts it (n8n follows via requires, n8n-provision via partOf).
    systemd.paths.n8n-provision-rotate = {
      wantedBy = ["multi-user.target"];
      pathConfig.PathChanged = toString cfg.owner.passwordFile;
    };
    systemd.services.n8n-provision-rotate = {
      description = "Restart n8n after the owner password file rotates";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${config.systemd.package}/bin/systemctl restart n8n-owner-env.service";
      };
    };

    systemd.paths.n8n-provision-credentials-rotate = mkIf (fieldFiles != []) {
      wantedBy = ["multi-user.target"];
      pathConfig.PathChanged = map (f: toString f.file) fieldFiles;
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
