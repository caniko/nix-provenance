{
  lib,
  pkgs,
  self,
  ...
}: {
  imports = [self.nixosModules.stalwart016];

  services.stalwart016 = {
    enable = true;
    hostname = "mail.example.test";
    publicUrl = "https://mail.example.test";
    datastore.postgresql.passwordFile = pkgs.writeText "stalwart-pg-password" "password";
    recoveryAdmin.passwordFile = pkgs.writeText "stalwart-recovery-password" "password";
    oidc.clients."neverlight-mail" = {
      description = "Neverlight Mail desktop client";
      redirectUris = ["http://127.0.0.1:49152/callback"];
      contacts = ["postmaster@example.test"];
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
