{lib}: let
  # 0.16 registry SET fields serialise as objects `{ "<value>" = true; }`, not JSON
  # arrays (verified against the 0.16.7 binary in phase 06; arrays are rejected).
  toSet = xs: lib.genAttrs xs (_: true);
in {
  mkBindSecretFile = filePath: {
    "@type" = "File";
    inherit filePath;
  };

  mkBindSecretEnv = variableName: {
    "@type" = "EnvironmentVariable";
    inherit variableName;
  };

  mkBindSecretValue = secret: {
    "@type" = "Value";
    inherit secret;
  };

  # Emit the Stalwart 0.16.7 LDAP Directory registry object shape verified in
  # crates/registry/src/schema/structs.rs (LdapDirectory / SecretText) and
  # crates/registry/src/schema/structs_impl.rs (defaults). Phase 02 also proved
  # registry secrets use native File/EnvironmentVariable/Value variants.
  #
  # Kanidm's LDAP gateway only returns persons carrying the POSIX extension
  # (uidNumber/gidNumber/loginShell/homeDirectory). Persons without posix attrs
  # are invisible over LDAP and mail delivery to them fails.
  kanidmLdapDirectory = {
    url,
    baseDn,
    bindSecret,
    bindDn ? "dn=token",
    bindAuthentication ? true,
    # `description` is a required-non-empty field on the 0.16 LdapDirectory
    # (struct-level validate() flags an empty one); always emit a value.
    description ? "kanidm LDAP directory",
    # `classAttr` is the object-class attribute used ONLY in the search FILTER
    # strings below (kanidm exposes a native `class` attribute). It is distinct
    # from the registry `attrClass` field (next), which Stalwart reads to detect
    # group entries (is_group). They are independent on purpose so the filter and
    # the attribute mapping can be tuned separately.
    classAttr ? "class",
    # `attrClass` = the 0.16 registry attribute-mapping SET for the object class.
    # Default matches the schema default; set to ["class"] to mirror kanidm.
    attrClass ? ["objectClass"],
    filterLogin ? "(&(${classAttr}=person)(|(name=?)(spn=?)(mail=?)))",
    filterMailbox ? "(&(${classAttr}=person)(|(mail=?)(mailAlternateAddress=?)))",
    attrEmail ? ["mail"],
    attrEmailAlias ? ["mailAlternateAddress"],
    attrDescription ? ["displayName"],
    useTls ? false,
    allowInvalidCerts ? false,
  }: {
    # The 0.16 Directory variant discriminator is "Ldap" (capitalised); lowercase
    # "ldap" is rejected by `stalwart-cli apply` with
    # `invalidPatch | Missing or invalid '@type'` (verified vs v0.16.7 source:
    # `enum Directory { Ldap }` has no serde rename_all → variant name verbatim).
    "@type" = "Ldap";
    inherit
      url
      baseDn
      bindDn
      bindSecret
      bindAuthentication
      description
      filterLogin
      filterMailbox
      useTls
      allowInvalidCerts
      ;
    # attr* are 0.16 SET fields → objects {value:true}, not arrays
    # (crates/registry/src/types/map.rs rejects arrays).
    attrClass = toSet attrClass;
    attrEmail = toSet attrEmail;
    attrEmailAlias = toSet attrEmailAlias;
    attrDescription = toSet attrDescription;
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
    inherit
      name
      displayName
      readGroup
      tokenFile
      ;
  };
}
