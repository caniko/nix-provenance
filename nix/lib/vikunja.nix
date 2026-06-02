{lib}: {
  # Emits services.kanidm.provision.systems.oauth2.vikunja.
  # Vikunja documents a nested object-array vikunja_groups claim for team sync,
  # but kanidm-provision currently accepts only string claim-map values. Encode
  # the supported string-claim fallback once here so consumers do not rediscover
  # that constraint.
  kanidmOAuth2System = {
    frontendHostname,
    basicSecretFile,
    providerId ? "kanidm",
    group ? "vikunja-users",
    displayName ? "Vikunja",
    preferShortUsername ? true,
    scopes ? ["openid" "profile" "email" "vikunja_groups"],
    groupClaimValues ? {${group} = [group];},
  }: {
    inherit displayName basicSecretFile preferShortUsername;
    public = false;
    originUrl = "https://${frontendHostname}/auth/openid/${providerId}";
    originLanding = "https://${frontendHostname}/";
    scopeMaps.${group} = scopes;
    claimMaps.vikunja_groups = {
      joinType = "array";
      valuesByGroup = groupClaimValues;
    };
  };
}
