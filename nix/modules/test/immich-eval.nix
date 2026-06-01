{
  config,
  lib,
  pkgs,
  self,
  ...
}: {
  imports = [self.nixosModules.immich];

  services.immich = {
    enable = true;
    package = pkgs.immich;
    provision = {
      enable = true;
      immichAdminCommand = "${pkgs.immich}/bin/immich-admin";
      oauth = {
        enable = true;
        issuerUrl = "https://auth.example.com/oauth2/openid/immich";
        clientId = "immich";
        clientSecretFile = "/run/secrets/immich-oidc-client-secret";
      };
      users.can = {
        email = "can@example.com";
        name = "Can";
        isAdmin = true;
        storageLabel = "can";
        shouldChangePassword = false;
      };
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
