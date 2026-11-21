{
  pkgs,
  self,
}: let
  inherit (pkgs) lib;
  native = pkgs.writeShellScriptBin "opencode" "exit 0";
  helper = pkgs.writeShellScriptBin "provenance-oauth" ''
    printf '%s\n' "$@" >> "$CAPTURE"
  '';
  evaluate = declared: enabled: accounts: chatgpt:
    lib.evalModules {
      specialArgs = {
        inherit pkgs;
        lib = lib // {hm.dag.entryAfter = after: data: {inherit after data;};};
      };
      modules = [
        (import ../home/oauth.nix {inherit self;})
        ({lib, ...}: {
          options =
            {
              assertions = lib.mkOption {type = lib.types.listOf lib.types.attrs;};
              home.packages = lib.mkOption {type = lib.types.listOf lib.types.package;};
              home.file = lib.mkOption {type = lib.types.attrs;};
              home.activation = lib.mkOption {
                type = lib.types.attrsOf lib.types.anything;
                default = {};
              };
              systemd.user.services = lib.mkOption {
                type = lib.types.attrs;
                default = {};
              };
              systemd.user.timers = lib.mkOption {
                type = lib.types.attrs;
                default = {};
              };
            }
            // lib.optionalAttrs declared {
              programs = {
                opencode.enable = lib.mkOption {
                  type = lib.types.bool;
                  default = enabled;
                };
                opencode.settings = lib.mkOption {type = lib.types.attrs;};
                opencode.package = lib.mkOption {
                  type = lib.types.package;
                  default = native;
                };
                omp.enable = lib.mkOption {
                  type = lib.types.bool;
                  default = enabled;
                };
              };
            };
          config.nix-provenance = {
            oauth = {inherit accounts;};
            opencode = {inherit chatgpt;};
          };
        })
      ];
    };
  openai.openai.configFile = "/etc/provenance/oauth/alice-openai.json";
  google.google = {
    configFile = "/etc/provenance/oauth/alice-google.json";
    stateDirectory = "/var/lib/provenance-oauth-alice-google";
  };
  nativeAccounts = lib.genAttrs ["chat-personal" "chat-work"] (id: {
    provider = "openai";
    profile = "opencode";
    configFile = "/etc/provenance/oauth/alice-${id}.json";
    package = helper;
  });
  chat = {
    enable = true;
    accounts = ["chat-personal" "chat-work"];
    active = "chat-work";
  };
  enabled = (evaluate true true (openai // google // nativeAccounts) chat).config;
  googleOnly = (evaluate true true google {}).config;
  namedChatgpt = {
    provider = "openai";
    inherit (openai.openai) configFile;
  };
  namedOnly = (evaluate true true {chat = namedChatgpt;} {}).config;
  maxLengthId = lib.fixedWidthString 48 "a" "";
  maxLength = (evaluate true true {${maxLengthId} = namedChatgpt;} {}).config;
  overlong = (evaluate true true {${maxLengthId + "a"} = namedChatgpt;} {}).config;
  disabled = (evaluate true false openai {}).config;
  absent = (evaluate false false openai {}).config;
  invalid = (evaluate true true (openai // nativeAccounts) (chat // {active = "openai";})).config;
  services = enabled.systemd.user.services;
  install = services."nix-provenance-opencode-install@".Service.ExecStart;
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
  assert lib.all (item: item.assertion) googleOnly.assertions;
  assert googleOnly.programs.opencode.settings.plugins == [];
  assert googleOnly.home.file == {};
  assert namedOnly.programs.opencode.settings.plugins == [];
  assert namedOnly.home.file == {};
  assert lib.all (item: item.assertion) maxLength.assertions;
  assert !(lib.all (item: item.assertion) overlong.assertions);
  assert disabled.nix-provenance.oauth.opencodePlugins == [];
  assert disabled.home.file == {};
  assert absent.nix-provenance.oauth.opencodePlugins == [];
  assert absent.home.file == {};
  assert !(lib.all (item: item.assertion) invalid.assertions);
  assert enabled.nix-provenance.opencode.chatgpt.package == native;
  assert services."nix-provenance-opencode-install@chat-work".Install.WantedBy == ["default.target"];
  assert enabled.home.activation.provenanceOpenCode.after == ["reloadSystemd"];
  assert lib.hasInfix "nix-provenance-opencode-install@chat-work.service" enabled.home.activation.provenanceOpenCode.data;
  assert !(services ? "nix-provenance-opencode-install@chat-personal");
  assert enabled.systemd.user.timers.nix-provenance-opencode-sync.Timer.OnCalendar == "hourly";
  assert lib.hasSuffix " %i" install;
    pkgs.runCommand "oauth-home-module-eval" {} ''
      export CAPTURE="$TMPDIR/args"
      ${services.nix-provenance-opencode-sync.Service.ExecStart}
      grep -Fx /etc/provenance/oauth/alice-chat-personal.json "$CAPTURE"
      grep -Fx /etc/provenance/oauth/alice-chat-work.json "$CAPTURE"
      test "$(grep -Fxc opencode-sync "$CAPTURE")" = 2
      : > "$CAPTURE"
      ${lib.removeSuffix " %i" install} chat-personal
      grep -Fx /etc/provenance/oauth/alice-chat-personal.json "$CAPTURE"
      grep -Fx opencode-install "$CAPTURE"
      grep -Fx -- --activate "$CAPTURE"
      if ${lib.removeSuffix " %i" install} openai; then
        echo 'native ChatGPT unit accepted a chatgpt plugin enrollment' >&2
        exit 1
      fi
      touch $out
    ''
