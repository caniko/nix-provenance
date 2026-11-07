{pkgs}: let
  inherit (pkgs) lib;
  system = pkgs.stdenv.hostPlatform.system;
  fakePackage = pkgs.writeShellScriptBin "provenance-oauth" "exit 0";
  fakeSelf = {packages.${system}.provenance-oauth = fakePackage;};
  manifest = pkgs.writeText "fixture-openai-manifest.json" "{}";
  mkEvaluate = withMaterialization: overrides:
    (lib.evalModules {
      specialArgs = {inherit pkgs;};
      modules = [
        (import ../adapter/t3code-credentials.nix {self = fakeSelf;})
        ({lib, ...}: {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.attrs;
              default = [];
            };
            users.users = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule {
                options.isNormalUser = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                };
              });
              default = {};
            };
            systemd.services = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule {
                options = {
                  serviceConfig = lib.mkOption {
                    type = lib.types.attrsOf lib.types.anything;
                    default = {};
                  };
                  environment = lib.mkOption {
                    type = lib.types.attrsOf (lib.types.nullOr (lib.types.either lib.types.str (lib.types.listOf lib.types.str)));
                    default = {};
                  };
                  after = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    default = [];
                  };
                  wants = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    default = [];
                  };
                  requires = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    default = [];
                  };
                };
              });
              default = {};
            };
          };
          config = {
            users.users = {
              alice.isNormalUser = true;
              bob.isNormalUser = true;
              dana.isNormalUser = true;
            };
            systemd.services =
              {
                "t3-runner@" = {
                  serviceConfig = {
                    ExecStart = "/fixture/t3 runner";
                    User = "%i";
                  };
                };
                "t3-runner@alice".serviceConfig.ExecStart = ["" "/fixture/t3 runner --allow-root /home/alice"];
                "t3-runner@bob".serviceConfig.ExecStart = ["" "/fixture/t3 runner --allow-root /home/bob"];
                "t3-runner@dana".serviceConfig.ExecStart = ["" "/fixture/t3 runner --allow-root /home/dana"];
                provenance-oauth-alice-openai.serviceConfig.ExecStart = "/fixture/oauth --config /fixture/manifest.json";
                provenance-oauth-alice-openai-initialize.serviceConfig.ExecStart = "/fixture/oauth --initialize";
                t3code.serviceConfig = {
                  ExecStart = "/fixture/t3 serve";
                  User = "t3code";
                };
              }
              // lib.optionalAttrs withMaterialization {
                "agenix-install-secrets".serviceConfig.ExecStart = "/fixture/agenix-install";
                "agenix-chown".serviceConfig.ExecStart = "/fixture/agenix-chown";
              };
          };
        })
        overrides
      ];
    }).config;
  evaluate = mkEvaluate true;
  withoutMaterialization = mkEvaluate false {
    nix-provenance.t3code.users.alice = {
      claudeTokenFile = "/run/agenix/t3code-claude-alice";
      openaiConfigFile = "/etc/t3code/openai-alice.json";
    };
  };
  enabled = evaluate {
    nix-provenance.t3code.users = {
      alice = {
        claudeTokenFile = "/run/agenix/t3code-claude-alice";
        openaiConfigFile = "/etc/t3code/openai-alice.json";
        openaiPackage = fakePackage;
      };
      bob.claudeTokenFile = "/run/agenix/t3code-claude-bob";
      dana.openaiConfigFile = "/etc/t3code/openai-dana.json";
      carol = {};
    };
  };
  openaiOnly = evaluate {
    nix-provenance.t3code.users.alice.openaiConfigFile = "/etc/t3code/openai.json";
  };
  storeManifest = evaluate {
    nix-provenance.t3code.users.alice.openaiConfigFile = manifest;
  };
  empty = evaluate {nix-provenance.t3code.users = {};};
  valid = config: lib.all (assertion: assertion.assertion) config.assertions;
  invalid = overrides: !(valid (evaluate overrides));
  invalidClaude = path: invalid {nix-provenance.t3code.users.alice.claudeTokenFile = path;};
  invalidOpenai = path: invalid {nix-provenance.t3code.users.alice.openaiConfigFile = path;};
in
  assert valid enabled;
  assert enabled.systemd.services."t3-runner@".serviceConfig.User == "%i";
  assert enabled.systemd.services."t3-runner@".requires == [];
  assert enabled.systemd.services."t3-runner@alice".serviceConfig.LoadCredential == ["claude-oauth:/run/agenix/t3code-claude-alice"];
  assert enabled.systemd.services."t3-runner@alice".environment
  == {
    T3CODE_CLAUDE_OAUTH_TOKEN_FILE = "%d/claude-oauth";
    T3CODE_OPENAI_OAUTH_COMMAND = lib.getExe fakePackage;
    T3CODE_OPENAI_OAUTH_CONFIG_FILE = "/etc/t3code/openai-alice.json";
  };
  assert enabled.systemd.services."t3-runner@alice".after == ["agenix-install-secrets.service" "agenix-chown.service" "provenance-oauth-alice-openai.service"];
  assert enabled.systemd.services."t3-runner@alice".wants == ["provenance-oauth-alice-openai.service"];
  assert enabled.systemd.services."t3-runner@alice".requires == ["agenix-install-secrets.service" "agenix-chown.service"];
  assert enabled.systemd.services."t3-runner@bob".serviceConfig.LoadCredential == ["claude-oauth:/run/agenix/t3code-claude-bob"];
  assert enabled.systemd.services."t3-runner@bob".environment == {T3CODE_CLAUDE_OAUTH_TOKEN_FILE = "%d/claude-oauth";};
  assert enabled.systemd.services."t3-runner@bob".after == ["agenix-install-secrets.service" "agenix-chown.service"];
  assert enabled.systemd.services."t3-runner@bob".wants == [];
  assert enabled.systemd.services."t3-runner@bob".requires == ["agenix-install-secrets.service" "agenix-chown.service"];
  assert enabled.systemd.services."t3-runner@dana".environment
  == {
    T3CODE_OPENAI_OAUTH_COMMAND = lib.getExe fakePackage;
    T3CODE_OPENAI_OAUTH_CONFIG_FILE = "/etc/t3code/openai-dana.json";
  };
  assert !(enabled.systemd.services."t3-runner@dana".serviceConfig ? LoadCredential);
  assert !(enabled.systemd.services."t3-runner@dana".environment ? T3CODE_CLAUDE_OAUTH_TOKEN_FILE);
  assert enabled.systemd.services."t3-runner@dana".after == [];
  assert enabled.systemd.services."t3-runner@dana".wants == [];
  assert enabled.systemd.services."t3-runner@dana".requires == [];
  assert !(enabled.systemd.services ? "t3-runner@carol");
  assert !(enabled.systemd.services.t3code.serviceConfig ? LoadCredential);
  assert enabled.systemd.services.t3code.environment == {};
  assert enabled.systemd.services.t3code.after == [];
  assert enabled.systemd.services.t3code.wants == [];
  assert enabled.systemd.services.t3code.requires == [];
  assert lib.all (unit: !(lib.hasInfix "-initialize" unit)) (
    enabled.systemd.services."t3-runner@alice".after
    ++ enabled.systemd.services."t3-runner@alice".wants
    ++ enabled.systemd.services."t3-runner@alice".requires
  );
  assert lib.all (unit: unit != "agenix.service") (
    enabled.systemd.services."t3-runner@alice".after
    ++ enabled.systemd.services."t3-runner@alice".requires
    ++ enabled.systemd.services."t3-runner@bob".after
    ++ enabled.systemd.services."t3-runner@bob".requires
  );
  assert withoutMaterialization.systemd.services."t3-runner@alice".after == ["provenance-oauth-alice-openai.service"];
  assert withoutMaterialization.systemd.services."t3-runner@alice".wants == ["provenance-oauth-alice-openai.service"];
  assert withoutMaterialization.systemd.services."t3-runner@alice".requires == [];
  assert openaiOnly.systemd.services."t3-runner@alice".environment.T3CODE_OPENAI_OAUTH_COMMAND == lib.getExe fakePackage;
  assert !(openaiOnly.systemd.services."t3-runner@alice".serviceConfig ? LoadCredential);
  assert !(openaiOnly.systemd.services."t3-runner@alice".environment ? T3CODE_CLAUDE_OAUTH_TOKEN_FILE);
  assert storeManifest.systemd.services."t3-runner@alice".environment.T3CODE_OPENAI_OAUTH_CONFIG_FILE == toString manifest;
  assert valid empty;
  assert empty.systemd.services."t3-runner@alice".environment == {};
  assert !(empty.systemd.services."t3-runner@alice".serviceConfig ? LoadCredential);
  assert empty.systemd.services."t3-runner@alice".after == [];
  assert empty.systemd.services."t3-runner@alice".requires == [];
  assert lib.all (path: invalidClaude path) [
    "/nix/store/secret"
    "/nix/store/secret/token"
    "/run/../secret"
    "/run/./secret"
    "/run//token"
    "/run/%d/token"
    "/run/token:other"
    "relative"
    "/run/secret\nother"
  ];
  assert lib.all (path: invalidOpenai path) [
    "relative.json"
    "/etc//openai.json"
    "/etc/../openai.json"
    "/etc/./openai.json"
    "/etc/%d/openai.json"
    "/etc/openai:alice.json"
    "/etc/openai\n.json"
  ];
  assert invalid {nix-provenance.t3code.users.ghost.claudeTokenFile = "/run/agenix/ghost";};
  assert invalid {nix-provenance.t3code.users."alice@evil".claudeTokenFile = "/run/agenix/evil";};
  assert lib.all (user: invalid {nix-provenance.t3code.users.${user} = {};}) ["Alice" "0alice" "alice.work"];
  assert invalid {
    users.users.dave.isNormalUser = true;
    nix-provenance.t3code.users.dave.claudeTokenFile = "/run/agenix/dave";
  };
  assert invalid {
    systemd.services."t3-runner@alice".serviceConfig.User = "bob";
    nix-provenance.t3code.users.alice.claudeTokenFile = "/run/agenix/alice";
  };
  assert invalid {
    systemd.services."t3-runner@".serviceConfig = lib.mkForce {
      ExecStart = "/fixture/t3 runner";
      User = "root";
    };
    nix-provenance.t3code.users.alice.claudeTokenFile = "/run/agenix/alice";
  };
  assert invalid {
    systemd.services."t3-runner@".serviceConfig = lib.mkForce {User = "%i";};
    nix-provenance.t3code.users.alice.claudeTokenFile = "/run/agenix/alice";
  }; {
    pass = true;
    manifest = builtins.toJSON {
      users = ["alice" "bob" "dana"];
      claudeCredential = "claude-oauth";
      openaiCommand = lib.getExe fakePackage;
    };
  }
