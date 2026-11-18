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
        # A path literal, not a string: its store context must survive into the
        # state file (otherwise the file is not in the closure and editing it
        # changes no restart trigger).
        scripts."f/fleetix_hub/literal" = {
          language = "bun";
          contentFile = ./fixture-procedure.ts;
          summary = "Literal path fixture";
          tag = "hub";
        };
        variables."f/fleetix_hub/hub_token" = {
          valueFile = "/run/agenix/windmill-hub-token";
          description = "Fleetix Hub receipt bearer";
        };
      };
      # No scripts or variables: the module must omit both keys, so a host
      # still pinning an older provisioner (strict state parsing) works.
      workspaces.other = {
        name = "Other";
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
