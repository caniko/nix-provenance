{
  pkgs,
  self,
}: let
  inherit (pkgs) lib;
  evaluate = settings:
    lib.evalModules {
      specialArgs = {inherit pkgs;};
      modules = [
        ({lib, ...}: {
          options = {
            home.packages = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = [];
            };
            systemd.user.services = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
            };
            systemd.user.paths = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
            };
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.anything;
              default = [];
            };
          };
        })
        (import ../home/proton-vpn.nix {inherit self;})
        {nix-provenance.proton-vpn = settings;}
      ];
    };
  enabled =
    (evaluate {
      enable = true;
      login = {
        enable = true;
        package = pkgs.writeShellScriptBin "proton-vpn-auth" "exit 0";
        encryptedFile = "/nix/store/fixture/proton_vpn.age";
        identityPaths = ["/home/fixture user/.ssh/id_ed25519"];
        keyringServiceUnit = "oo7-daemon.service";
        credentialServiceUnits = ["agenix.service"];
      };
    }).config;
  disabled = (evaluate {}).config;
  bad =
    (evaluate {
      enable = true;
      login = {
        enable = true;
        encryptedFile = "/nix/store/invalid-account";
      };
    }).config;
  service = enabled.systemd.user.services.nix-provenance-proton-vpn-login;
in
  assert builtins.all (a: a.assertion) enabled.assertions;
  assert !(builtins.all (a: a.assertion) bad.assertions);
  assert disabled.home.packages == [] && disabled.systemd.user.services == {};
  assert service.Service.LoadCredential == ["account.age:/nix/store/fixture/proton_vpn.age"];
  assert lib.hasInfix " login --encrypted-file %d/account.age" service.Service.ExecStart;
  assert lib.hasInfix "--identity '/home/fixture user/.ssh/id_ed25519'" service.Service.ExecStart;
  assert service.Service.MemorySwapMax == 0 && service.Service.LimitMEMLOCK == "8M";
  assert enabled.systemd.user.paths.nix-provenance-proton-vpn-login.Path.PathChanged == "/nix/store/fixture/proton_vpn.age";
  assert builtins.elem "agenix.service" service.Unit.After;
  assert builtins.elem "oo7-daemon.service" service.Unit.After;
  assert service.Service.RestartPreventExitStatus == 2;
  assert builtins.length enabled.home.packages == 3;
    pkgs.runCommand "proton-vpn-module-eval" {} ''
      touch $out
    ''
