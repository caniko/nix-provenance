{lib}: {
  # Emit a `services.stalwart.settings.directory.<id>` attrset that points
  # Stalwart at the kanidm LDAP gateway. The token bind-DN shape, query filters,
  # and attribute map are solved here once.
  #
  # Kanidm's LDAP gateway only returns persons carrying the POSIX extension
  # (uidNumber/gidNumber/loginShell/homeDirectory). Persons without posix attrs
  # are invisible over LDAP and mail delivery to them fails.
  kanidmLdapDirectory = {
    address,
    baseDn,
    bindDn,
    bindSecretMacro,
    nameAttr ? "name",
    emailAttr ? "mail",
    descriptionAttr ? "displayname",
    allowInvalidCerts ? false,
  }: {
    type = "ldap";
    inherit address;
    bind = {
      dn = bindDn;
      secret = bindSecretMacro;
    };
    base-dn = baseDn;
    filter = {
      name = "(&(class=person)(${nameAttr}=?))";
      email = "(&(class=person)(${emailAttr}=?))";
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
