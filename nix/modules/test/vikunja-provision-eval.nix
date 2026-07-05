{
  lib,
  self,
  ...
}: {
  imports = [self.nixosModules.vikunjaProvision];

  services.vikunja = {
    enable = true;
    frontendScheme = "https";
    frontendHostname = "team.example.com";
    provision = {
      enable = true;
      tokenFile = "/run/secrets/vikunja-provision-token";
      webhookSecretFile = "/run/secrets/vikunja-webhook-secret";
      botUsername = "vikunja-provision";
      teams.ops = {
        description = "Operations";
        members = ["alice"];
        admins = ["can"];
      };
      webhooks."10" = {
        url = "https://vikunja-bot.example.com/webhook";
      };
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
