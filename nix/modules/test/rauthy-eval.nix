# Module-eval smoke test for services.rauthy.provision. rauthy-provision shipped
# without one; it is authored here BEFORE any refactor so the live module stays
# eval-guarded through the migration. Mirrors immich-eval.nix.
{
  lib,
  self,
  ...
}: {
  imports = [self.nixosModules.rauthy];

  services.rauthy.provision = {
    enable = true;
    endpoint = "http://127.0.0.1:8080";
    apiKeyFile = "/run/secrets/rauthy-provision-api-key";
    groups.internal = {};
    roles.admin = {};
    users."alice@example.com" = {
      givenName = "Alice";
      familyName = "Smith";
      roles = ["admin"];
      groups = ["internal"];
    };
    clients.demo = {
      name = "Demo";
      redirectUris = ["https://demo.example.com/callback"];
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
