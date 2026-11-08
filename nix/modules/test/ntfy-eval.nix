{
  lib,
  self,
  ...
}: {
  imports = [self.nixosModules.ntfy];

  services.ntfy-sh = {
    settings.base-url = "https://ntfy.example.test";
    enable = true;
    environmentFile = "/run/agenix/ntfy-extra";
    provision = {
      enable = true;
      users = {
        can = {
          role = "admin";
          passwordFile = "/run/agenix/ntfy-can";
        };
        admin = {
          role = "admin";
          passwordFile = "/run/agenix/ntfy-admin";
        };
        syndb-publisher = {
          role = "user";
          passwordFile = "/run/agenix/ntfy-syndb-publisher";
        };
      };
      tokens.syndb-publisher = [
        {
          tokenFile = "/run/agenix/ntfy-syndb-publisher-token";
          label = "ci";
        }
      ];
      access = ["syndb-publisher:syndb-alerts:wo"];
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
