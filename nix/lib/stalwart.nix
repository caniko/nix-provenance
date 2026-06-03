{lib}: {
  # Emit a `services.stalwart.settings.directory.<id>` attrset that points
  # Stalwart at the kanidm LDAP gateway. The token bind-DN shape, query filters,
  # and attribute map are solved here once.
  #
  # Kanidm's LDAP gateway only returns persons carrying the POSIX extension
  # (uidNumber/gidNumber/loginShell/homeDirectory). Persons without posix attrs
  # are invisible over LDAP and mail delivery to them fails.
  kanidmLdapDirectory = {
    # Stalwart 0.15.5 LDAP directory keys (verified against the v0.15.5 source,
    # crates/directory/src/backend/ldap/config.rs): the connection key is `url`
    # (NOT `address`), and per-user authentication is OFF by default
    # (`bind.auth.method = "default"` → local password-hash comparison, which
    # kanidm cannot satisfy because its LDAP gateway never exposes password
    # hashes). To authenticate users we MUST set `bind.auth.method`.
    url,
    baseDn,
    bindDn,
    bindSecretMacro,
    # Per-user auth bind. kanidm only honours an LDAP *bind* (not a hash compare):
    #   * "template" — build the bind DN from `authTemplate` and bind as the user
    #     directly. kanidm accepts `identifier=<name|spn>` bind DNs, so
    #     `identifier=?` works; the login must then be the kanidm name/spn.
    #   * "lookup"   — search (via the service bind) using `filter.name`, then
    #     bind as the discovered DN. Lets users log in by any attribute the
    #     filter matches (e.g. mail). `authSearch`/`authTemplate` are ignored.
    authMethod ? "template",
    authTemplate ? "identifier=?",
    # Only meaningful for `authMethod = "template"`: whether the post-auth
    # principal load reuses the user's connection (true) or the service bind
    # (false). kanidm's search needs the token service bind, so this is false.
    authSearch ? false,
    nameAttr ? "name",
    emailAttr ? "mail",
    descriptionAttr ? "displayname",
    # kanidm exposes the object class on the `class` attribute (not objectClass).
    classAttr ? "class",
    # Match the login by kanidm name, spn, or mail so either a username or an
    # email address resolves (especially under `authMethod = "lookup"`).
    filterName ? "(&(${classAttr}=person)(|(${nameAttr}=?)(spn=?)(${emailAttr}=?)))",
    filterEmail ? "(&(${classAttr}=person)(${emailAttr}=?))",
    allowInvalidCerts ? false,
  }: {
    type = "ldap";
    inherit url;
    base-dn = baseDn;
    bind =
      {
        dn = bindDn;
        secret = bindSecretMacro;
      }
      // lib.optionalAttrs (authMethod != "default") {
        auth =
          {method = authMethod;}
          // lib.optionalAttrs (authMethod == "template") {
            template = authTemplate;
            search = authSearch;
          };
      };
    filter = {
      name = filterName;
      email = filterEmail;
    };
    attributes = {
      name = nameAttr;
      email = emailAttr;
      description = descriptionAttr;
    };
    tls."allow-invalid-certs" = allowInvalidCerts;
  };

  # Emit the read-only kanidm service-account fragment Stalwart binds as. The
  # tokenFile path must hold a kanidm service-account API token generated for
  # this account. It is consumed by the caller's kanidm-provision schema mapping
  # or fallback workflow and must resolve at runtime, not into the Nix store.
  kanidmLdapServiceAccount = {
    name ? "stalwart-ldap",
    displayName ? "Stalwart LDAP bind",
    readGroup,
    tokenFile,
  }: {
    inherit name displayName readGroup tokenFile;
  };
}
