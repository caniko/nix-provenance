# Module-eval smoke test for the third-party identity adapter, and the canonical
# worked example: pink-raven (a non-OSS, outward-facing app that gets NO tenant
# here) integrated through Rauthy with can/eric/caroline, plus a kanidm-backend
# app to gate that code path too. Mirrors the other *-eval.nix modules.
{
  lib,
  self,
  ...
}: let
  adapter = self.lib.adapter;
in {
  # The adapter is a writer over the rauthy provisioner, so a rauthy-backend
  # consumer imports both modules.
  imports = [
    self.nixosModules.externalApp
    self.nixosModules.rauthy
  ];

  # Rauthy provisioning must be enabled for the adapter's clients/users to land
  # in the rendered state file. Stub the API key (eval only).
  services.rauthy.provision = {
    enable = true;
    endpoint = "http://127.0.0.1:8080";
    apiKeyFile = "/run/secrets/rauthy-provision-api-key";
  };

  services.provenance.externalApps = {
    # Outward-facing → rauthy backend. can logs in via his existing kanidm
    # identity (federated, passwordless); eric + caroline are external users who
    # get their credential by a one-time set-password email.
    pink-raven = {
      backend = "rauthy";
      displayName = "Pink Raven";
      loginUrl = "https://raven.tartanoglu.com/login";
      redirectUris = ["https://raven.tartanoglu.com/auth/callback"];
      postLogoutRedirectUris = ["https://raven.tartanoglu.com/"];
      allowedOrigins = ["https://raven.tartanoglu.com"];
      # Rauthy here relays mail through Stalwart on the host (acknowledge it).
      mailServerConfigured = true;
      users = {
        can = {
          email = "can@tartanoglu.com";
          displayName = "Can";
          credential = adapter.kanidmLogin;
        };
        eric = {
          email = "efirley@protonmail.com";
          displayName = "Eric";
          credential = adapter.passwordInitByEmail {};
        };
        caroline = {
          email = "carolinestahl@gmx.net";
          displayName = "Caroline";
          credential = adapter.passwordInitByEmail {};
        };
        bot = {
          email = "bot@example.com";
          displayName = "Bot";
          credential = adapter.passwordFromFile {
            passwordFile = "/run/agenix/pink-raven-bot-password";
          };
        };
      };
    };

    # Internal app federating directly with kanidm (confidential client). Its
    # users are kanidm persons (kanidmLogin only — emailed-init is rauthy-only).
    internal-tool = {
      backend = "kanidm";
      displayName = "Internal Tool";
      confidential = true;
      redirectUris = ["https://tool.example.com/oauth2/callback"];
      basicSecretFile = "/run/secrets/internal-tool-oauth2-basic";
      users.dejana = {
        email = "dejana@tartanoglu.com";
        displayName = "Dejana";
        credential = adapter.kanidmLogin;
      };
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
