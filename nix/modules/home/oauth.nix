{self}: {
  config,
  lib,
  pkgs,
  options,
  ...
}: let
  cfg = config.nix-provenance.oauth;
  chat = config.nix-provenance.opencode.chatgpt;
  adapter = self.packages.${pkgs.stdenv.hostPlatform.system}.oauth-adapters;
  openCodeEnabled = lib.attrByPath ["programs" "opencode" "enable"] false config;
  ompEnabled = lib.attrByPath ["programs" "omp" "enable"] false config;
  openaiAccounts = lib.filterAttrs (_: account: account.provider == "openai" && account.profile == "chatgpt") cfg.accounts;
  # Both legacy adapters expose a single fixed model/provider ID.
  legacy = openaiAccounts.openai or (lib.findFirst (_: true) null (builtins.attrValues openaiAccounts));
  binding = {
    command = lib.getExe legacy.package;
    configFile = toString legacy.configFile;
  };
  nativeAccounts = lib.filterAttrs (id: account:
    builtins.elem id chat.accounts && account.provider == "openai" && account.profile == "opencode")
  cfg.accounts;
  command = account: action: "${lib.getExe account.package} --config ${lib.escapeShellArg (toString account.configFile)} ${action} --opencode ${lib.getExe chat.package}";
  syncName = "nix-provenance-opencode-sync";
  sync = pkgs.writeShellApplication {
    name = syncName;
    runtimeInputs = [pkgs.coreutils];
    text = ''
      result=0
      ${lib.concatMapStringsSep "\n" (account: "${command account "opencode-sync"} || result=1") (builtins.attrValues nativeAccounts)}
      exit "$result"
    '';
  };
  installName = "nix-provenance-opencode-install";
  systemctl = "${lib.getExe' pkgs.systemd "systemctl"} --user";
  install = pkgs.writeShellApplication {
    name = installName;
    runtimeInputs = [pkgs.coreutils];
    text = ''
      case "$1" in
        ${lib.concatStringsSep "\n" (lib.mapAttrsToList (id: account: "${lib.escapeShellArg id}) exec ${command account "opencode-install"} --activate ;;")
          nativeAccounts)}
        *) echo "OpenCode: expected a declared openai/opencode enrollment" >&2; exit 1 ;;
      esac
    '';
  };
  oneshot = execStart: {
    Type = "oneshot";
    ExecStart = execStart;
    WorkingDirectory = "%h";
    UMask = "0077";
    TimeoutStartSec = "5min";
  };
  installUnit = {
    Unit.Description = "Install and activate OpenCode ChatGPT enrollment (%i)";
    Service = oneshot "${lib.getExe install} %i";
  };
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
  options.nix-provenance.opencode.chatgpt = {
    enable = lib.mkEnableOption "onboarding and backup for OpenCode's native ChatGPT credentials";
    accounts = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "IDs of openai/opencode OAuth enrollments to back up.";
    };
    active = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Enrollment to install and activate at login.";
    };
    package = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = config.programs.opencode.package or null;
      defaultText = lib.literalExpression "config.programs.opencode.package or null";
      description = "OpenCode package providing the native auth export, import, and switch commands.";
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
            && ((account.provider == "openai" && builtins.elem account.profile ["chatgpt" "opencode"])
              || (account.provider == "google" && builtins.elem account.profile ["antigravity" "drive" "drive-file"]))) (builtins.attrNames cfg.accounts);
          message = "provenance OAuth Home Manager bindings need a simple enrollment ID and a supported provider/profile pair.";
        }
      ];
      nix-provenance.oauth.opencodePlugins = lib.optional (openCodeEnabled && legacy != null) {
        package = "${adapter}/share/provenance-oauth";
        options = binding;
      };
      home.packages = lib.optional (legacy != null) legacy.package;
      home.file = lib.optionalAttrs (ompEnabled && legacy != null) {
        ".omp/agent/extensions/provenance-oauth.ts".text = ''
          import { install } from ${builtins.toJSON "${adapter}/share/provenance-oauth/omp.mjs"};
          export default function (pi) {
            install(pi, ${builtins.toJSON binding});
          }
        '';
      };
    }
    (lib.optionalAttrs (options ? programs.opencode.settings) {
      programs.opencode.settings.plugins = cfg.opencodePlugins;
    })
    (lib.mkIf chat.enable {
      assertions = [
        {
          assertion = chat.package != null;
          message = "nix-provenance.opencode.chatgpt requires an OpenCode package.";
        }
        {
          assertion = lib.allUnique chat.accounts && lib.all (id: nativeAccounts ? ${id}) chat.accounts;
          message = "nix-provenance.opencode.chatgpt.accounts must list distinct openai/opencode enrollment IDs.";
        }
        {
          assertion = chat.active != null && nativeAccounts ? ${chat.active};
          message = "nix-provenance.opencode.chatgpt.active must be a listed openai/opencode enrollment ID.";
        }
      ];
    })
    (lib.mkIf (chat.enable && chat.package != null) {
      systemd.user.services =
        {
          ${syncName} = {
            Unit.Description = "Back up OpenCode's native ChatGPT credentials";
            Service = oneshot (lib.getExe sync);
          };
          "${installName}@" = installUnit;
        }
        // lib.optionalAttrs (chat.active != null && nativeAccounts ? ${chat.active}) {
          "${installName}@${chat.active}" = installUnit // {Install.WantedBy = ["default.target"];};
        };
      systemd.user.timers.${syncName} = {
        Unit.Description = "Back up OpenCode's native ChatGPT credentials hourly";
        Timer = {
          OnCalendar = "hourly";
          Persistent = true;
        };
        Install.WantedBy = ["timers.target"];
      };
    })
    (lib.optionalAttrs (options ? home.activation) {
      home.activation.provenanceOpenCode =
        lib.mkIf
        (chat.enable && chat.package != null && chat.active != null && nativeAccounts ? ${chat.active} && (config.systemd.user.startServices or true))
        (lib.hm.dag.entryAfter ["reloadSystemd"] ''
          if ${systemctl} --quiet is-active default.target; then
            run ${systemctl} --no-block start ${lib.escapeShellArg "${installName}@${chat.active}.service"}
          fi
        '');
    })
  ];
}
