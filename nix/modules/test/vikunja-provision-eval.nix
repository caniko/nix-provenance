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
      botUsername = "vikunja-provision";
      teams.ops = {
        description = "Operations";
        members = ["alice"];
        admins = ["can"];
      };
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
