{
  lib,
  self,
  ...
}: {
  imports = [self.nixosModules.windmillProvision];

  services.windmill = {
    enable = true;
    provision = {
      enable = true;
      superadminSecretFile = "/run/agenix/windmill-superadmin";
      workspaces.studio.name = "Studio";
      users.can = {
        email = "can@example.test";
        passwordFile = "/run/agenix/windmill-can";
        workspaces = ["studio"];
        admin = true;
      };
      tokens.paperclip-studio = {
        user = "can";
        workspace = "studio";
        group = "studio";
        mode = "0640";
      };
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
