# Bind per-user OAuth credentials into existing T3 Code runner instances.
# The shared t3code server never receives provider credentials; each
# `t3-runner@<user>` instance keeps only its own user's paths.
{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.nix-provenance.t3code;
  # An entry with no credential source must not create or modify any unit.
  active = lib.filterAttrs (_: settings: settings.claudeTokenFile != null || settings.openaiConfigFile != null) cfg.users;
  activeUsers = builtins.attrNames active;
  safeUser = value: builtins.match "[a-z_][a-z0-9_-]{0,31}" value != null;
  # Secret sources stay literal runtime paths: no store copy, traversal,
  # systemd specifier, credential separator or control characters.
  literalRuntimePath = value:
    lib.hasPrefix "/" value
    && value != "/nix/store"
    && !lib.hasPrefix "/nix/store/" value
    && !lib.hasInfix "//" value
    && !lib.hasInfix "/../" "${value}/"
    && !lib.hasInfix "/./" "${value}/"
    && builtins.match ".*[[:cntrl:]].*" value == null
    && !(lib.any (char: lib.hasInfix char value) [":" "%" "\\"]);
  # OpenAI manifests are public, so store paths are allowed; the string form
  # still has to be a literal absolute path safe to place in Environment=.
  publicManifestPath = value: let
    path = toString value;
  in
    lib.hasPrefix "/" path
    && !lib.hasInfix "//" path
    && !lib.hasInfix "/../" "${path}/"
    && !lib.hasInfix "/./" "${path}/"
    && builtins.match ".*[[:cntrl:]].*" path == null
    && !(lib.any (char: lib.hasInfix char path) [":" "%" "\\"]);
  service = name: config.systemd.services.${name} or {};
  hasService = name: builtins.hasAttr name (config.systemd.services or {});
  templateOwned = let
    unit = service "t3-runner@";
  in
    (unit.serviceConfig.ExecStart or null)
    != null
    && (unit.serviceConfig.User or null) == "%i";
  instanceOwned = user: let
    unit = service "t3-runner@${user}";
    owner = unit.serviceConfig.User or "%i";
  in
    (unit.serviceConfig.ExecStart or null)
    != null
    && (owner == "%i" || owner == user);
  oauthName = user: "provenance-oauth-${user}-openai";
  oauthUnit = user: "${oauthName user}.service";
  # Only order against the normal OAuth reconciliation unit. The -initialize
  # unit stays explicit and must never be pulled in by a boot-time runner.
  oauthReady = user: settings: settings.openaiConfigFile != null && hasService (oauthName user);
  # agenix has no `agenix.service`; secret materialization is either the
  # sysusers units below or the activation script (nothing to order against).
  materializationUnits =
    map (name: "${name}.service")
    (builtins.filter hasService ["agenix-install-secrets" "agenix-chown"]);
  claudeMaterialization = settings: lib.optionals (settings.claudeTokenFile != null) materializationUnits;
  settingsEnv = settings:
    lib.optionalAttrs (settings.claudeTokenFile != null) {
      T3CODE_CLAUDE_OAUTH_TOKEN_FILE = "%d/claude-oauth";
    }
    // lib.optionalAttrs (settings.openaiConfigFile != null) {
      T3CODE_OPENAI_OAUTH_COMMAND = lib.getExe settings.openaiPackage;
      T3CODE_OPENAI_OAUTH_CONFIG_FILE = toString settings.openaiConfigFile;
    };
  unitDeps = user: settings: {
    after =
      claudeMaterialization settings
      ++ lib.optional (oauthReady user settings) (oauthUnit user);
    wants = lib.optional (oauthReady user settings) (oauthUnit user);
    requires = claudeMaterialization settings;
  };
in {
  options.nix-provenance.t3code.users = lib.mkOption {
    default = {};
    type = lib.types.attrsOf (lib.types.submodule {
      options = {
        claudeTokenFile = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Literal absolute runtime Claude token file, normally config.age.secrets.<name>.path. Loaded as the claude-oauth systemd credential; its contents never enter Nix.";
        };
        openaiConfigFile = lib.mkOption {
          type = lib.types.nullOr (lib.types.either lib.types.path lib.types.str);
          default = null;
          description = "Public OpenAI OAuth helper manifest path (store path or literal absolute runtime string). Never a secret.";
        };
        openaiPackage = lib.mkOption {
          type = lib.types.package;
          default = self.packages.${pkgs.stdenv.hostPlatform.system}.provenance-oauth;
          defaultText = lib.literalMD "`self.packages.<system>.provenance-oauth`";
          description = "OAuth helper executable handed to the runner through T3CODE_OPENAI_OAUTH_COMMAND.";
        };
      };
    });
    description = "Per-Linux-user T3 Code runner credential bindings. Only an existing systemd.services.\"t3-runner@<user>\" instance is modified.";
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = lib.all safeUser (builtins.attrNames cfg.users);
          message = "nix-provenance.t3code user keys must be literal Linux usernames.";
        }
        {
          assertion = lib.all (user: builtins.hasAttr user (config.users.users or {})) activeUsers;
          message = "nix-provenance.t3code may only bind existing Linux users.";
        }
        {
          assertion = active == {} || templateOwned;
          message = "nix-provenance.t3code requires the existing t3-runner@ template with User=%i and an ExecStart.";
        }
        {
          assertion = lib.all instanceOwned activeUsers;
          message = "nix-provenance.t3code must bind an existing t3-runner@<user> instance that owns the runner ExecStart.";
        }
        {
          assertion = lib.all (settings:
            (settings.claudeTokenFile == null || literalRuntimePath settings.claudeTokenFile)
            && (settings.openaiConfigFile == null || publicManifestPath settings.openaiConfigFile))
          (builtins.attrValues active);
          message = "nix-provenance.t3code sources must be literal paths: Claude tokens are runtime files outside the store; OpenAI manifests are public paths without specifiers.";
        }
      ];
    }
    (lib.mkIf (active != {}) {
      systemd.services = lib.mapAttrs' (user: settings:
        lib.nameValuePair "t3-runner@${user}" (lib.mkMerge [
          (lib.optionalAttrs (settings.claudeTokenFile != null) {
            serviceConfig.LoadCredential = ["claude-oauth:${settings.claudeTokenFile}"];
          })
          (unitDeps user settings)
          {environment = settingsEnv settings;}
        ]))
      active;
    })
  ];
}
