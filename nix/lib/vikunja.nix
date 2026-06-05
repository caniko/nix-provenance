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

  # Build a services.rauthy.provision.users overlay for Vikunja's OIDC team
  # sync. `users` is keyed by short Rauthy/Vikunja username and must provide
  # each user's primary `email`; `teams` is keyed by the Vikunja team slug and
  # contains `members = [ "shortname" ... ]`.
  rauthyTeamClaimUsers = {
    users,
    teams,
  }: let
    teamClaimsFor = username:
      lib.mapAttrsToList (
        teamName: team:
          if builtins.elem username (team.members or [])
          then {
            name = team.name or teamName;
            oidcID = team.oidcID or teamName;
          }
          else null
      )
      teams;
  in
    lib.mapAttrs' (
      username: user: let
        email =
          if (user.email or null) == null
          then throw "vikunja.rauthyTeamClaimUsers: user '${username}' must set `email`."
          else user.email;
        claims = lib.filter (claim: claim != null) (teamClaimsFor username);
      in
        lib.nameValuePair email {
          preferredUsername = username;
          attributes.vikunja_groups = claims;
        }
    )
    users;
}
