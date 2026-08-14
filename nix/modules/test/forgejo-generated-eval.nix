{
  lib,
  self,
  ...
}: {
  imports = [self.nixosModules.forgejo];

  services.forgejo = {
    enable = true;
    provision = {
      enable = true;
      discoveryUrl = "https://auth.example.com/oauth2/openid/forgejo/.well-known/openid-configuration";
      kanidmUrl = "https://auth.example.com";
      kanidmIdmAdminPasswordFile = "/run/secrets/kanidm-idm-admin";
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
