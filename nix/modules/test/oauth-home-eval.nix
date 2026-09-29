{
  pkgs,
  self,
}: let
  inherit (pkgs) lib;
  evaluate = declared: enabled:
    lib.evalModules {
      specialArgs = {inherit pkgs;};
      modules = [
        (import ../home/oauth.nix {inherit self;})
        ({lib, ...}: {
          options =
            {
              assertions = lib.mkOption {type = lib.types.listOf lib.types.attrs;};
              home.packages = lib.mkOption {type = lib.types.listOf lib.types.package;};
              home.file = lib.mkOption {type = lib.types.attrs;};
            }
            // lib.optionalAttrs declared {
              programs = {
                opencode.enable = lib.mkOption {
                  type = lib.types.bool;
                  default = enabled;
                };
                opencode.settings = lib.mkOption {type = lib.types.attrs;};
                omp.enable = lib.mkOption {
                  type = lib.types.bool;
                  default = enabled;
                };
              };
            };
          config.nix-provenance.oauth.accounts.openai.configFile = "/etc/provenance/oauth/alice-openai.json";
        })
      ];
    };
  enabled = (evaluate true true).config;
  disabled = (evaluate true false).config;
  absent = (evaluate false false).config;
  plugins = enabled.nix-provenance.oauth.opencodePlugins;
  extension = enabled.home.file.".omp/agent/extensions/provenance-oauth.ts".text;
in
  assert lib.all (item: item.assertion) enabled.assertions;
  assert builtins.length plugins == 1;
  assert enabled.programs.opencode.settings.plugins == plugins;
  assert (builtins.head plugins).options.configFile == "/etc/provenance/oauth/alice-openai.json";
  assert lib.hasInfix "/bin/provenance-oauth" (builtins.head plugins).options.command;
  assert lib.hasInfix "omp.mjs" extension;
  assert lib.hasInfix "/etc/provenance/oauth/alice-openai.json" extension;
  assert disabled.nix-provenance.oauth.opencodePlugins == [];
  assert disabled.home.file == {};
  assert absent.nix-provenance.oauth.opencodePlugins == [];
  assert absent.home.file == {};
    pkgs.runCommand "oauth-home-module-eval" {} ''
      touch $out
    ''
