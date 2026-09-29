{self}: {
  config,
  lib,
  pkgs,
  options,
  ...
}: let
  cfg = config.nix-provenance.oauth;
  adapter = self.packages.${pkgs.stdenv.hostPlatform.system}.oauth-adapters;
  openCodeEnabled = lib.attrByPath ["programs" "opencode" "enable"] false config;
  ompEnabled = lib.attrByPath ["programs" "omp" "enable"] false config;
  bindings =
    lib.mapAttrsToList (_: value: {
      command = lib.getExe value.package;
      configFile = toString value.configFile;
    })
    cfg.accounts;
in {
  options.nix-provenance.oauth = {
    accounts = lib.mkOption {
      default = {};
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          configFile = lib.mkOption {
            type = lib.types.path;
            description = "Public manifest for this host/user's OAuth enrollment.";
          };
          package = lib.mkOption {
            type = lib.types.package;
            default = self.packages.${pkgs.stdenv.hostPlatform.system}.provenance-oauth;
            description = "OAuth access helper.";
          };
        };
      });
      description = "OAuth manifests supplied by the NixOS host module, or explicitly for standalone Home Manager.";
    };
    opencodePlugins = lib.mkOption {
      type = lib.types.listOf lib.types.attrs;
      readOnly = true;
      description = "Plugin entries for consumers that render their own OpenCode V2 config.";
    };
  };
  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = builtins.attrNames cfg.accounts == [] || builtins.attrNames cfg.accounts == ["openai"];
          message = "provenance OAuth currently supports one openai/chatgpt account per local user.";
        }
      ];
      nix-provenance.oauth.opencodePlugins = lib.optionals openCodeEnabled (map (binding: {
          package = "${adapter}/share/provenance-oauth";
          options = binding;
        })
        bindings);
      home.packages = map (value: value.package) (builtins.attrValues cfg.accounts);
      home.file = lib.optionalAttrs (ompEnabled && cfg.accounts != {}) {
        ".omp/agent/extensions/provenance-oauth.ts".text = ''
          import { install } from ${builtins.toJSON "${adapter}/share/provenance-oauth/omp.mjs"};
          export default function (pi) {
            install(pi, ${builtins.toJSON (builtins.head bindings)});
          }
        '';
      };
    }
    (lib.optionalAttrs (options ? programs.opencode.settings) {
      programs.opencode.settings.plugins = cfg.opencodePlugins;
    })
  ];
}
