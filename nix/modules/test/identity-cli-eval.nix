{
  lib,
  self,
  ...
}: {
  imports = [self.nixosModules.identityCli];

  services.nix-provenance.identityCli = {
    enable = true;
    rauthy = {
      url = "https://id.example.org";
      users = {
        "staff@example.org" = {
          present = true;
          givenName = "Staff";
        };
        "guest@example.org" = {
          present = true;
          givenName = "Guest";
          groups = ["guests"];
          sendPasswordEmail = true;
          passwordEmailRedirectUri = "https://app.example.org/login";
        };
      };
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
