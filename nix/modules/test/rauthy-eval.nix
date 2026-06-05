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
    userAttributes.vikunja_groups = {
      desc = "Vikunja team sync groups";
      userEditable = false;
    };
    scopes.vikunja_groups.attrIncludeId = ["vikunja_groups"];
    users."alice@example.com" = {
      givenName = "Alice";
      familyName = "Smith";
      roles = ["admin"];
      groups = ["internal"];
      preferredUsername = "alice";
      attributes.vikunja_groups = [
        {
          name = "Operations";
          oidcID = "ops";
        }
      ];
    };
    clients.demo = {
      name = "Demo";
      redirectUris = ["https://demo.example.com/callback"];
      scopes = ["openid" "profile" "email" "vikunja_groups"];
      defaultScopes = ["openid" "profile" "email" "vikunja_groups"];
      generatedSecretFile = "/run/rauthy-clients/demo.secret";
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
