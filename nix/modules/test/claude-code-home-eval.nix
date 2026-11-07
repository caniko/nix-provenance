{pkgs}: let
  inherit (pkgs) lib;
  native = (pkgs.writeShellScriptBin "claude" "exit 0").overrideAttrs (_: {version = "2.1.311";});
  helper = pkgs.writeShellScriptBin "provenance-claude" "exit 0";
  self.packages.${pkgs.stdenv.hostPlatform.system}.provenance-oauth = helper;
  evaluate = tokenFile:
    (lib.evalModules {
      specialArgs = {inherit pkgs;};
      modules = [
        (import ../home/claude-code.nix {inherit self;})
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
          };
          config.nix-provenance.claudeCode = {
            inherit tokenFile;
            package = native;
          };
        })
      ];
    }).config;
  enabled = evaluate "/run/user/1000/agenix/claude-code-oauth";
  valid = c: lib.all (a: a.assertion) c.assertions;
in {
  pass = assert valid enabled;
  assert (evaluate null).home.packages == [];
  assert builtins.length enabled.home.packages == 1;
  assert lib.hasInfix (builtins.unsafeDiscardStringContext "${helper}/bin/provenance-claude") (builtins.head enabled.home.packages).buildCommand;
  assert lib.hasInfix (builtins.unsafeDiscardStringContext "${native}/bin/claude") (builtins.head enabled.home.packages).buildCommand;
  assert lib.hasInfix "/run/user/1000/agenix/claude-code-oauth" (builtins.head enabled.home.packages).buildCommand;
  assert lib.all (path: !(valid (evaluate path))) ["relative" "/nix/store/token" "/run/../token" "/run/%d/token" "/run/token\nother"]; true;
}
