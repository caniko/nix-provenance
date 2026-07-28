{
  config,
  lib,
  pkgs,
  self,
  ...
}: {
  imports = [self.nixosModules.forgejo];

  services.forgejo = {
    enable = true;
    provision = {
      enable = true;
      discoveryUrl = "https://auth.example.com/oauth2/openid/forgejo/.well-known/openid-configuration";
      clientSecretFile = "/run/secrets/forgejo-oidc-client-secret";
      adminUser = "can";
      adminPasswordFile = "/run/secrets/forgejo-admin-password";
      sshKeys.can.laptop.key = "ssh-ed25519 AAAA";
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
