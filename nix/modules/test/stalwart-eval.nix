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
      data = "internal";
      blob = "internal";
      fts = "internal";
      lookup = "internal";
    };
    settings.directory.internal.type = "internal";

    kanidmLdap = {
      enable = true;
      address = "ldaps://auth.example.com:3636";
      baseDn = "dc=auth,dc=example,dc=com";
      bindSecretMacro = "%{file:/run/credentials/stalwart.service/kanidm_bind}%";
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
