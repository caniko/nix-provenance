{lib}: {
  # Emits services.kanidm.provision.systems.oauth2.vikunja.
  # Vikunja team sync needs an object-array claim shaped like
  # [{name, oidcID}], and kanidm-provision can model array claim maps. The
  # missing support is in kanidm core's richer claim-value model (kanidm#2641),
  # so the inert string-array fallback is intentionally omitted. Teams are
  # managed out-of-band by vikunja-provision; see upstreaming/bridges.md.
  kanidmOAuth2System = {
    frontendHostname,
    basicSecretFile,
    providerId ? "kanidm",
    group ? "vikunja-users",
    displayName ? "Vikunja",
    preferShortUsername ? true,
    scopes ? ["openid" "profile" "email"],
  }: {
    inherit displayName basicSecretFile preferShortUsername;
    public = false;
    originUrl = "https://${frontendHostname}/auth/openid/${providerId}";
    originLanding = "https://${frontendHostname}/";
    scopeMaps.${group} = scopes;
  };
}
