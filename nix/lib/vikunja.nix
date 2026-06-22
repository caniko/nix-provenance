{lib, self}: {
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

  # Produce Home Manager environment config for any Vikunja CLI client.
  # url: Vikunja API base URL, e.g. "https://vikunja.example.com/api/v1"
  # tokenFile: runtime path to an agenix-decrypted API token file (optional).
  #            When set, shell init scripts export VIKUNJA_TOKEN from the file
  #            at shell start — never baked into the Nix store.
  # Returns an attrset compatible with HM `{config, ...}:` module imports.
  mkClientEnv = {
    url,
    tokenFile ? null,
  }:
    lib.mkMerge [
      {home.sessionVariables.VIKUNJA_URL = url;}
      (lib.mkIf (tokenFile != null) {
        programs.bash.initExtra = lib.mkAfter ''
          if [ -f "${tokenFile}" ]; then
            export VIKUNJA_TOKEN="$(cat "${tokenFile}")"
          fi
        '';
        programs.nushell.envFile.text = lib.mkAfter ''
          if ($"${tokenFile}" | path exists) {
            $env.VIKUNJA_TOKEN = (open $"${tokenFile}" | str trim)
          }
        '';
      })
    ];

  # Produce a NixOS module that enables declarative Vikunja team provisioning
  # using the same API token used by vkc. Callers must provide the token path
  # (typically from agenix decryption). The token must have teams and
  # teams_members read/create/delete scopes.
  mkProvisionToken = {
    tokenFile,
    botUsername ? "vikunja-provision",
  }: {
    imports = [self.nixosModules.vikunjaProvision];
    services.vikunja.provision = {
      enable = true;
      inherit tokenFile botUsername;
    };
  };
}
