{self}: {
  config,
  lib,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.stalwart.kanidmLdap;
  ldapLib = self.lib.stalwart;
  storage = config.services.stalwart.settings.storage or {};
  storageRoles = ["data" "blob" "fts" "lookup"];
  retainedStorageRoles =
    lib.all (role: lib.hasAttr role storage && storage.${role} != cfg.directoryId) storageRoles;
in {
  options.services.stalwart.kanidmLdap = {
    enable = mkEnableOption "kanidm LDAP directory backend for Stalwart";

    directoryId = mkOption {
      type = types.str;
      default = "kanidm";
      description = "services.stalwart.settings.directory.<id> key to populate.";
    };

    address = mkOption {
      type = types.str;
      example = "ldaps://auth.tartanoglu.com:3636";
      description = "kanidm LDAP gateway URL. ldaps is recommended.";
    };

    baseDn = mkOption {
      type = types.str;
      example = "dc=auth,dc=tartanoglu,dc=com";
      description = "LDAP base DN derived from the kanidm domain.";
    };

    bindDn = mkOption {
      type = types.str;
      default = "dn=token";
      description = ''
        LDAP bind DN for a kanidm service-account API token. Kanidm documents
        API-token LDAP binds as dn=token, with the token supplied as the bind
        secret.
      '';
    };

    bindSecretMacro = mkOption {
      type = types.str;
      example = "%{file:/run/credentials/stalwart.service/kanidm_bind}%";
      description = ''
        Stalwart %{file:...}% macro resolving the bind token at config-load.
        Mirror the existing Stalwart credential pattern; the credential must be
        present in services.stalwart.credentials.
      '';
    };

    allowInvalidCerts = mkOption {
      type = types.bool;
      default = false;
      description = "Temporary escape hatch for ldaps certificate-chain debugging only.";
    };

    requireStorageRetention = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Assert the directory backend swap leaves storage.data/blob/fts/lookup
        on the mailbox store. Switching the directory must change only
        storage.directory and directory.<id>; mailbox data lives in the storage
        backend and must survive the swap.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = config.services.stalwart.enable;
        message = "services.stalwart.kanidmLdap requires services.stalwart.enable = true.";
      }
      {
        assertion =
          !cfg.requireStorageRetention
          || (storage.directory == cfg.directoryId && retainedStorageRoles);
        message = ''
          services.stalwart.kanidmLdap: storage.directory must be "${cfg.directoryId}"
          while storage.data/blob/fts/lookup stay on the mailbox store. The
          directory swap must not repoint mailbox storage.
        '';
      }
    ];

    warnings = [
      ''
        services.stalwart.kanidmLdap: kanidm LDAP only returns persons with POSIX
        attributes. Run the pre-cutover ldapsearch smoke for each mailbox user
        before switching Stalwart to this directory.
      ''
      ''
        services.stalwart.kanidmLdap: prime each primary mailbox after switching
        by querying or delivering to the primary address before relying on
        aliases. This records Stalwart's kanidm LDAP cache quirk.
      ''
    ];

    services.stalwart.settings = {
      storage.directory = cfg.directoryId;
      directory.${cfg.directoryId} = ldapLib.kanidmLdapDirectory {
        inherit (cfg) address baseDn bindDn bindSecretMacro allowInvalidCerts;
      };
    };

    systemd.services.stalwart = {
      after = lib.mkAfter ["kanidm.service"];
      wants = ["kanidm.service"];
    };
  };
}
