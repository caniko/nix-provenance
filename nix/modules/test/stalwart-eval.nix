{
  lib,
  pkgs,
  self,
  ...
}: {
  imports = [self.nixosModules.stalwart];

  services.stalwart = {
    enable = true;
    stateVersion = "25.11";
    settings.storage = {
      directory = "kanidm";
      data = "internal";
      blob = "internal";
      fts = "internal";
      lookup = "internal";
    };
    settings.directory.internal.type = "internal";

    kanidmLdap = {
      enable = true;
      url = "ldaps://auth.example.com:3636";
      baseDn = "dc=auth,dc=example,dc=com";
      bindSecret = {
        type = "file";
        filePath = "/run/credentials/stalwart.service/kanidm_bind";
      };
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
