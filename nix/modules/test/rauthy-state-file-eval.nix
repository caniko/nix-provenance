{
  lib,
  pkgs,
  self,
  ...
}: let
  stateFile = pkgs.writeText "external-rauthy-state.json" (builtins.toJSON {
    groups.internal.present = true;
  });
in {
  imports = [self.nixosModules.rauthy];

  services.rauthy.provision = {
    enable = true;
    endpoint = "http://127.0.0.1:8080";
    apiKeyEnvironmentFile = "/run/secrets/rauthy-env";
    transientApiKey.enable = true;
    inherit stateFile;
  };

  system.stateVersion = lib.mkDefault "25.11";
}
