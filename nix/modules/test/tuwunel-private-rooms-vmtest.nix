{
  pkgs,
  self,
  ...
}:
pkgs.testers.nixosTest {
  name = "tuwunel-private-rooms";

  nodes.machine = {lib, ...}: {
    imports = [self.nixosModules.tuwunel];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    services.matrix-tuwunel = {
      enable = true;
      settings.global = {
        server_name = "example.test";
        address = ["127.0.0.1"];
        port = [6167];
        allow_registration = false;
        allow_federation = false;
        trusted_servers = [];
      };
      provision = {
        enable = true;
        adminTokenUser = "matrix-admin";
        # Only synthetic disposable-VM credentials enter the fixture store.
        users = lib.genAttrs ["matrix-admin" "can" "iris" "argus"] (name: {
          admin = name == "matrix-admin";
          passwordFile = pkgs.writeText "fixture-${name}-password" "fixture-${name}-password";
        });
        rooms = lib.genAttrs ["iris" "argus"] (name: {
          alias = "#hermes-${name}:example.test";
          inherit name;
          creator = name;
          encrypted = true;
          invite = ["@can:example.test"];
        });
      };
    };
    system.stateVersion = "25.11";
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("tuwunel.service")
    machine.wait_for_unit("tuwunel-provision.service")
    machine.succeed("${pkgs.python3}/bin/python3 ${./tuwunel-private-rooms.py} ${self.packages.${pkgs.stdenv.hostPlatform.system}.tuwunel-provision}/bin/tuwunel-provision")
  '';
}
