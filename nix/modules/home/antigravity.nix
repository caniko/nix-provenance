# Register an Antigravity Google sign-in from a shared agy token file, so each
# profile starts signed in without a browser. agy refreshes its own access
# tokens from this file and rewrites it on every launch, so each profile gets a
# private writable copy; the agenix source stays the single grant.
_: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.nix-provenance.antigravity.googleAuth;
  unitName = "nix-provenance-antigravity-google-auth";
  # Runtime paths only: the token never enters the store, and `${XDG_RUNTIME_DIR}`
  # expands at run time as it does for the fj tokens.
  runtimePrefix = "\${XDG_RUNTIME_DIR}";
  shellPath = value:
    if lib.hasPrefix runtimePrefix value
    then "\"$XDG_RUNTIME_DIR\"${lib.escapeShellArg (lib.removePrefix runtimePrefix value)}"
    else lib.escapeShellArg value;
  literalPath = value:
    (lib.hasPrefix "/" value || lib.hasPrefix "${runtimePrefix}/" value)
    && !lib.hasPrefix "/nix/store/" value
    && !lib.hasInfix "/../" "${value}/"
    && builtins.match ".*[[:cntrl:]].*" value == null;
  script = pkgs.writeShellApplication {
    name = unitName;
    runtimeInputs = [pkgs.coreutils pkgs.diffutils pkgs.jq];
    text = ''
      token=${shellPath (toString cfg.tokenFile)}
      # A token without a refresh grant would leave agy asking for a browser.
      jq -e 'type == "object" and all(.client_id, .client_secret, .refresh_token; type == "string" and length > 0)' \
        "$token" >/dev/null || {
        echo "antigravity: $token is not an agy Google token file" >&2
        exit 1
      }
      # An array: a one-word literal list fails shellcheck (SC2043).
      profiles=(${lib.escapeShellArgs cfg.profileDirectories})
      for profile in "''${profiles[@]}"; do
        target="$profile/antigravity-acp/acp_token.json"
        install -d -m 700 "$profile/antigravity-acp"
        cmp -s "$token" "$target" && continue
        install -m 600 "$token" "$target.tmp"
        mv -f "$target.tmp" "$target"
      done
    '';
  };
in {
  options.nix-provenance.antigravity.googleAuth = {
    enable = mkEnableOption "automatic Antigravity Google sign-in from a shared agy token";

    tokenFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Runtime agenix path holding agy's acp_token.json from one Google sign-in (client_id, client_secret, refresh_token, project_id). Its contents never enter Nix.";
    };

    profileDirectories = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "agy profile directories (GEMINI_HOME), such as a T3 Code Antigravity instance's profile, that receive antigravity-acp/acp_token.json.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.tokenFile != null && literalPath cfg.tokenFile;
        message = "nix-provenance.antigravity.googleAuth.tokenFile must be a literal runtime path outside the Nix store.";
      }
      {
        assertion = cfg.profileDirectories != [] && lib.all literalPath cfg.profileDirectories;
        message = "nix-provenance.antigravity.googleAuth.profileDirectories must list absolute directories.";
      }
    ];
    systemd.user.services.${unitName} = {
      Unit = {
        Description = "Register the shared Antigravity Google sign-in";
        Wants = ["agenix.service"];
        After = ["agenix.service"];
      };
      Service = {
        Type = "oneshot";
        ExecStart = lib.getExe script;
      };
      Install.WantedBy = ["default.target"];
    };
    systemd.user.paths.${unitName} = {
      Unit.Description = "Watch the shared Antigravity Google token";
      Path.PathChanged = builtins.replaceStrings [runtimePrefix] ["%t"] (toString cfg.tokenFile);
      Install.WantedBy = ["default.target"];
    };
  };
}
