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
      workspaces.studio = {
        name = "Studio";
        scripts."f/fleetix_hub/comfy_generate" = {
          language = "bun";
          contentFile = "/nix/store/fixture-comfy_generate.ts";
          summary = "Submit ComfyUI prompts";
        };
        variables."f/fleetix_hub/hub_token" = {
          valueFile = "/run/agenix/windmill-hub-token";
          description = "Fleetix Hub receipt bearer";
        };
      };
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
