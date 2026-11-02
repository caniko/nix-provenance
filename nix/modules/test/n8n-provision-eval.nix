{
  lib,
  self,
  ...
}: {
  imports = [self.nixosModules.n8nProvision];

  services.n8n = {
    enable = true;
    environment.N8N_ENCRYPTION_KEY_FILE = "/run/agenix/n8n-encryption-key";
    provision = {
      enable = true;
      owner = {
        email = "can@example.test";
        passwordFile = "/run/agenix/n8n-owner";
      };
      credentials.studio-webhook = {
        type = "httpHeaderAuth";
        data.name = "X-Studio-Token";
        dataFiles.value = "/run/agenix/n8n-webhook";
      };
    };
  };

  # n8n ships under the Sustainable Use License (unfree in nixpkgs).
  nixpkgs.config.allowUnfreePredicate = pkg: lib.getName pkg == "n8n";
  system.stateVersion = lib.mkDefault "25.11";
}
