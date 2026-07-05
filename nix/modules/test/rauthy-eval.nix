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
    apiKeyEnvironmentFile = "/run/secrets/rauthy-env";
    transientApiKey.enable = true;
    groups.internal = {};
    roles.admin = {};
    userAttributes.vikunja_groups = {
      desc = "Vikunja team sync groups";
      userEditable = false;
    };
    scopes.vikunja_groups = {
      attrIncludeId = ["vikunja_groups"];
      claimsAtRoot = true;
    };
    users."alice@example.com" = {
      givenName = "Alice";
      familyName = "Smith";
      birthdate = "1984-01-02";
      timezone = "Europe/Oslo";
      street = "Example Street 1";
      zip = "12345";
      city = "Oslo";
      country = "Norway";
      phone = "+4712345678";
      userExpires = 1893456000;
      roles = ["admin"];
      groups = ["internal"];
      preferredUsername = "alice";
      attributes.vikunja_groups = [
        {
          name = "Operations";
          oidcID = "ops";
        }
      ];
      initialPasswordFile = "/run/agenix/rauthy-alice-password";
    };
    users."bob@example.com" = {
      clearFamilyName = true;
      clearBirthdate = true;
      clearTimezone = true;
      clearPreferredUsername = true;
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
