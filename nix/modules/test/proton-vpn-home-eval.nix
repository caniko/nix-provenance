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
        credentialsFile = "\${XDG_RUNTIME_DIR}/agenix/proton_vpn";
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
        credentialsFile = "/nix/store/invalid-account";
      };
    }).config;
  service = enabled.systemd.user.services.nix-provenance-proton-vpn-login;
in
  assert builtins.all (a: a.assertion) enabled.assertions;
  assert !(builtins.all (a: a.assertion) bad.assertions);
  assert disabled.home.packages == [] && disabled.systemd.user.services == {};
  assert service.Service.LoadCredential == ["account:%t/agenix/proton_vpn"];
  assert lib.hasInfix " login --credentials-file %d/account" service.Service.ExecStart;
  assert enabled.systemd.user.paths.nix-provenance-proton-vpn-login.Path.PathChanged == "%t/agenix/proton_vpn";
  assert builtins.elem "agenix.service" service.Unit.After;
  assert builtins.elem "oo7-daemon.service" service.Unit.After;
  assert service.Service.RestartPreventExitStatus == 2;
  assert builtins.length enabled.home.packages == 3;
    pkgs.runCommand "proton-vpn-module-eval" {} ''
      touch $out
    ''
