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

    url = mkOption {
      type = types.str;
      example = "ldaps://auth.tartanoglu.com:3636";
      description = ''
        kanidm LDAP gateway URL (Stalwart `directory.<id>.url`). ldaps is
        recommended; with an ldaps:// URL implicit TLS is used regardless of the
        StartTLS `tls.enable` flag.
      '';
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
        LDAP bind DN for the SEARCH bind. Kanidm only grants elevated read
        (e.g. to persons' mail) to a service-account API token bound as
        `dn=token` — a person/posix bind collapses to anonymous read and cannot
        see mail. So keep this `dn=token` and supply a service-account token as
        the bind secret.
      '';
    };

    authMethod = mkOption {
      type = types.enum ["template" "lookup" "default"];
      default = "template";
      description = ''
        Per-user authentication method (Stalwart `bind.auth.method`). kanidm
        requires a real LDAP *bind* to authenticate a user, so the Stalwart
        default ("default" = local password-hash comparison) does NOT work with
        kanidm. Use "template" (bind as `authTemplate`; login is the kanidm
        name/spn) or "lookup" (search via the service bind, then bind as the
        discovered DN; login may be any attribute `filter.name` matches, e.g.
        mail).
      '';
    };

    authTemplate = mkOption {
      type = types.str;
      default = "identifier=?";
      description = ''
        Bind-DN template for authMethod = "template" (Stalwart
        `bind.auth.template`). `?` is replaced with the supplied login. kanidm
        accepts `identifier=<name|spn>` as a bind DN.
      '';
    };

    authSearch = mkOption {
      type = types.bool;
      default = false;
      description = ''
        For authMethod = "template": whether the post-auth principal load reuses
        the user's connection (true) or the service bind (false). kanidm's
        attribute reads need the token service bind, so this stays false.
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
        inherit (cfg) url baseDn bindDn bindSecretMacro allowInvalidCerts;
        inherit (cfg) authMethod authTemplate authSearch;
      };
    };

    systemd.services.stalwart = {
      after = lib.mkAfter ["kanidm.service"];
      wants = ["kanidm.service"];
    };
  };
}
