# Module-eval smoke test for the vendored services.rauthy server module.
{
  lib,
  pkgs,
  self,
  ...
}: {
  imports = [self.nixosModules.rauthyServer];

  services.rauthy = {
    enable = true;
    package = pkgs.writeShellScriptBin "rauthy" ''
      exit 0
    '';
    configurePostgres = true;
    environmentFile = "/run/secrets/rauthy-env";
    environmentFiles = ["/run/rauthy/generated.env"];
    settings = {
      server = {
        scheme = "http";
        listen_address = "127.0.0.1";
        port_http = 8080;
      };
      bootstrap.admin_email = "admin@example.com";
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
