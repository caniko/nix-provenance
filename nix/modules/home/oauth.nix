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
  openaiAccounts = lib.filterAttrs (_: account: account.provider == "openai" && account.profile == "chatgpt") cfg.accounts;
  bindings =
    lib.mapAttrsToList (_: value: {
      command = lib.getExe value.package;
      configFile = toString value.configFile;
    })
    openaiAccounts;
in {
  options.nix-provenance.oauth = {
    accounts = lib.mkOption {
      default = {};
      type = lib.types.attrsOf (lib.types.submodule ({
        name,
        config,
        ...
      }: {
        options = {
          provider = lib.mkOption {
            type = lib.types.str;
            default = name;
            description = "OAuth provider (defaults to the enrollment ID for legacy bindings).";
          };
          profile = lib.mkOption {
            type = lib.types.str;
            default =
              if config.provider == "google"
              then "antigravity"
              else "chatgpt";
            description = "OAuth profile from the public manifest.";
          };
          configFile = lib.mkOption {
            type = lib.types.path;
            description = "Public manifest for this host/user's OAuth enrollment.";
          };
          package = lib.mkOption {
            type = lib.types.package;
            default = self.packages.${pkgs.stdenv.hostPlatform.system}.provenance-oauth;
            description = "OAuth access helper.";
          };
          stateDirectory = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "Manifest's runtime state directory, used by consumers that watch for enrollment changes.";
          };
        };
      }));
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
          assertion = lib.all (id: let
            account = cfg.accounts.${id};
          in
            builtins.match "[a-z0-9][a-z0-9-]*" id
            != null
            && ((account.provider == "openai" && account.profile == "chatgpt")
              || (account.provider == "google" && builtins.elem account.profile ["antigravity" "drive" "drive-file"]))) (builtins.attrNames cfg.accounts);
          message = "provenance OAuth Home Manager bindings need a simple enrollment ID and a supported provider/profile pair.";
        }
      ];
      nix-provenance.oauth.opencodePlugins = lib.optionals openCodeEnabled (map (binding: {
          package = "${adapter}/share/provenance-oauth";
          options = binding;
        })
        bindings);
      home.packages = map (value: value.package) (builtins.attrValues openaiAccounts);
      home.file = lib.optionalAttrs (ompEnabled && openaiAccounts != {}) {
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
