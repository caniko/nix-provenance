{
  lib,
  self,
  ...
}: {
  imports = [self.nixosModules.wireguardStatus];

  services.nix-provenance.wireguardStatus = {
    enable = true;
    interfaces = ["wg-home"];
    listenAddress = "127.0.0.1";
    port = 19586;
  };

  system.stateVersion = lib.mkDefault "25.11";
}
