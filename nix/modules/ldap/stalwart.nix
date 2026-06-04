{self}: {
  config,
  lib,
  ...
}: let
  inherit
    (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.services.stalwart.kanidmLdap;
  ldapLib = self.lib.stalwart;
  storage = config.services.stalwart.settings.storage or {};
  storageRoles = [
    "data"
    "blob"
    "fts"
    "lookup"
  ];
  retainedStorageRoles =
    lib.all (
      role: lib.hasAttr role storage && storage.${role} != cfg.directoryId
    )
    storageRoles;
  bindSecretType = types.submodule (
    {...}: {
      options = {
        type = mkOption {
          type = types.enum [
            "file"
            "environment-variable"
            "value"
          ];
          description = "Registry secret variant to render for Stalwart 0.16.";
        };

        filePath = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Runtime credential path for type = file.";
        };

        variableName = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Environment variable name for type = environment-variable.";
        };

        secret = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Literal secret for eval-only fixtures or tests.";
        };
      };
    }
  );
  renderedBindSecret =
    if cfg.bindSecret == null
    then null
    else if cfg.bindSecret.type == "file"
    then ldapLib.mkBindSecretFile cfg.bindSecret.filePath
    else if cfg.bindSecret.type == "environment-variable"
    then ldapLib.mkBindSecretEnv cfg.bindSecret.variableName
    else ldapLib.mkBindSecretValue cfg.bindSecret.secret;
  defaultFilterLogin = "(&(${cfg.classAttr}=person)(|(name=?)(spn=?)(mail=?)))";
  defaultFilterMailbox = "(&(${cfg.classAttr}=person)(mail=?))";
in {
  options.services.stalwart.kanidmLdap = {
    enable = mkEnableOption "kanidm LDAP directory backend for Stalwart";

    directoryId = mkOption {
      type = types.str;
      default = "kanidm";
      description = "Directory id phase 04 will assign to the rendered registry object.";
    };

    url = mkOption {
      type = types.str;
      example = "ldaps://auth.tartanoglu.com:3636";
      description = ''
        kanidm LDAP gateway URL for the rendered Stalwart 0.16 registry object.
        ldaps is recommended; with an ldaps:// URL implicit TLS is used regardless
        of the StartTLS `useTls` flag.
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

    bindSecret = mkOption {
      type = types.nullOr bindSecretType;
      default = null;
      description = ''
        Structured bind secret for the rendered 0.16 registry object. Use a
        runtime `file` credential for real deployments; `value` exists only for
        eval fixtures and other non-production tests.
      '';
    };

    bindAuthentication = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Render `bindAuthentication` in the 0.16 LDAP registry object. This must
        stay true for kanidm because Stalwart otherwise falls back to a local
        password-hash compare that kanidm cannot satisfy.
      '';
    };

    filterLogin = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        LDAP login filter for the rendered 0.16 directory object. When unset, it
        defaults to `(&(${cfg.classAttr}=person)(|(name=?)(spn=?)(mail=?)))`.
      '';
    };

    filterMailbox = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        LDAP mailbox lookup filter for the rendered 0.16 directory object. When
        unset, it defaults to
        `(&(${cfg.classAttr}=person)(mail=?))`.
      '';
    };

    classAttr = mkOption {
      type = types.str;
      default = "objectClass";
      description = ''
        Attribute used in the default login/mailbox filters to match person
        entries. Stalwart 0.16 defaults `attrClass` to `["objectClass"]`; phase
        07 smoke verifies whether the live kanidm LDAP gateway prefers `class`
        or `objectClass` in the filter expression.
      '';
    };

    useTls = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Enable StartTLS for the rendered 0.16 LDAP directory object. Leave false
        for ldaps:// URLs, which already use implicit TLS.
      '';
    };

    allowInvalidCerts = mkOption {
      type = types.bool;
      default = false;
      description = "Temporary escape hatch for LDAP certificate-chain debugging only.";
    };

    registryObject = mkOption {
      type = types.attrsOf types.anything;
      readOnly = true;
      description = ''
        Rendered Stalwart 0.16 LDAP Directory registry object. Phase 04 consumes
        this object and places it into the final `registryConfig`.
      '';
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
          !cfg.requireStorageRetention || (storage.directory == cfg.directoryId && retainedStorageRoles);
        message = ''
          services.stalwart.kanidmLdap: storage.directory must be "${cfg.directoryId}"
          while storage.data/blob/fts/lookup stay on the mailbox store. The
          directory swap must not repoint mailbox storage.
        '';
      }
      {
        assertion = cfg.bindSecret != null;
        message = ''
          services.stalwart.kanidmLdap.bindSecret is required. On Stalwart 0.16 a
          missing bindSecret silently degrades to anonymous LDAP reads.
        '';
      }
      {
        assertion = cfg.bindDn != "";
        message = ''
          services.stalwart.kanidmLdap.bindDn must be non-empty. The empty-string
          default would silently degrade the 0.16 LDAP registry object to
          anonymous reads.
        '';
      }
      {
        assertion = cfg.bindAuthentication;
        message = ''
          services.stalwart.kanidmLdap.bindAuthentication must remain true for
          kanidm. False makes Stalwart attempt a local password-hash compare
          that kanidm's LDAP gateway cannot satisfy.
        '';
      }
      {
        assertion =
          cfg.bindSecret
          == null
          || (
            (cfg.bindSecret.type == "file" && cfg.bindSecret.filePath != null)
            || (cfg.bindSecret.type == "environment-variable" && cfg.bindSecret.variableName != null)
            || (cfg.bindSecret.type == "value" && cfg.bindSecret.secret != null)
          );
        message = ''
          services.stalwart.kanidmLdap.bindSecret must set the field matching its
          type: `filePath`, `variableName`, or `secret`.
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

    services.stalwart.kanidmLdap.registryObject = ldapLib.kanidmLdapDirectory {
      inherit
        (cfg)
        url
        baseDn
        bindDn
        bindAuthentication
        classAttr
        useTls
        allowInvalidCerts
        ;
      bindSecret = renderedBindSecret;
      filterLogin =
        if cfg.filterLogin == null
        then defaultFilterLogin
        else cfg.filterLogin;
      filterMailbox =
        if cfg.filterMailbox == null
        then defaultFilterMailbox
        else cfg.filterMailbox;
    };

    systemd.services.stalwart = {
      after = lib.mkAfter ["kanidm.service"];
      wants = ["kanidm.service"];
    };
  };
}
