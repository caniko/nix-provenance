{
  lib,
  self,
  ...
}: {
  imports = [self.nixosModules.vikunja];

  services.vikunja = {
    enable = true;
    frontendScheme = "https";
    frontendHostname = "team.example.com";
    oidc = {
      enable = true;
      authUrl = "https://auth.example.com/oauth2/openid/vikunja";
      clientId = "vikunja";
      clientSecretFile = "/run/secrets/vikunja-oidc-client-secret";
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
