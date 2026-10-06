{
  pkgs,
  self,
}: let
  inherit (pkgs) lib;
  fakeClient = pkgs.writeShellScriptBin "rbw" ''
    if test "''${1:-}" = stop-agent; then exit 0; fi
    printf '%s\n' "$XDG_CACHE_HOME" "$XDG_DATA_HOME" "$RBW_AGENT" "$@"
  '';
  fakeRbw = pkgs.symlinkJoin {
    name = "fixture-rbw";
    paths = [fakeClient];
    postBuild = "ln -s rbw $out/bin/rbw-agent";
    meta.mainProgram = "rbw";
  };
  evaluate = enabled:
    lib.evalModules {
      specialArgs = {inherit pkgs;};
      modules = [
        (import ../home/rbw.nix {inherit self;})
        ({lib, ...}: {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.attrs;
              default = [];
            };
            home.packages = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = [];
            };
            programs.rbw.enable = lib.mkOption {
              type = lib.types.bool;
              default = false;
            };
            programs.rbw.package = lib.mkOption {
              type = lib.types.package;
              default = pkgs.rbw;
            };
            xdg.configFile = lib.mkOption {
              type = lib.types.attrs;
              default = {};
            };
            xdg.cacheHome = lib.mkOption {
              type = lib.types.str;
              default = "/build/legacy-cache";
            };
            xdg.dataHome = lib.mkOption {
              type = lib.types.str;
              default = "/build/legacy-data";
            };
            xdg.stateHome = lib.mkOption {
              type = lib.types.str;
              default = "/build/state";
            };
            systemd.user.services = lib.mkOption {
              type = lib.types.attrs;
              default = {};
            };
          };
          nix-provenance.rbw = {
            enable = enabled;
            package = fakeRbw;
          };
        })
      ];
    };
  enabled = (evaluate true).config;
  disabled = (evaluate false).config;
  manifest = enabled.nix-provenance.rbw.managedPackage.manifest;
in
  assert lib.all (item: item.assertion) enabled.assertions;
  assert enabled.programs.rbw.enable;
  assert enabled.programs.rbw.package == enabled.nix-provenance.rbw.managedPackage;
  assert enabled.systemd.user.services.nix-provenance-rbw-state.Service.UMask == "0077";
  assert enabled.nix-provenance.rbw.stateDirectory == "/build/state/nix-provenance/rbw";
  assert disabled.home.packages == [];
  assert disabled.systemd.user.services == {};
  assert disabled.xdg.configFile == {};
    pkgs.runCommand "rbw-home-module-eval" {} ''
      test -x ${enabled.programs.rbw.package}/bin/rbw
      test -x ${enabled.programs.rbw.package}/bin/rbw-agent
      mkdir -p /build/legacy-cache/rbw /build/legacy-data/rbw
      printf '{}\n' > /build/legacy-cache/rbw/fixture.json
      printf 'fixture-device\n' > /build/legacy-data/rbw/device_id
      ${enabled.programs.rbw.package}/bin/rbw fixture-argument > client-output
      ${enabled.programs.rbw.package}/bin/rbw-agent fixture-agent-argument > agent-output
      grep -Fxq /build/state/nix-provenance/rbw/cache client-output
      grep -Fxq /build/state/nix-provenance/rbw/data client-output
      grep -Fxq ${fakeRbw}/bin/rbw-agent client-output
      grep -Fxq fixture-argument client-output
      grep -Fxq /build/state/nix-provenance/rbw/cache agent-output
      grep -Fxq fixture-agent-argument agent-output
      test ! -e /build/legacy-cache/rbw
      test -f /build/state/nix-provenance/rbw/cache/rbw/fixture.json
      test -f /build/state/nix-provenance/rbw/data/rbw/device_id
      ${lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.provenance-rbw} --config ${manifest} status > status.json
      grep -Fq '"vaultDatabases": 1' status.json
      touch $out
    ''
