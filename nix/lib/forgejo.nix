{lib}: let
  generatedBasicSecretFile = "/var/lib/forgejo-oidc-secret/oidc-secret";
in {
  inherit generatedBasicSecretFile;

  # Emits services.kanidm.provision.systems.oauth2.<name>.
  # Forgejo needs `groups` so per-org team mapping can be wired later without
  # re-provisioning the IdP side.
  kanidmOAuth2System = {
    originUrl,
    basicSecretFile ? generatedBasicSecretFile,
    originLanding ? originUrl,
    group ? "forgejo-users",
    displayName ? "Forgejo",
    preferShortUsername ? true,
    scopes ? ["openid" "profile" "email" "groups"],
  }: {
    inherit displayName originUrl originLanding basicSecretFile preferShortUsername;
    public = false;
    scopeMaps.${group} = scopes;
  };
}
