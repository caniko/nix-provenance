# Register an Antigravity Google sign-in from a shared grant, so each
# profile starts signed in without a browser. agy refreshes its own access
# tokens from this file and rewrites it on every launch, so each profile gets a
# private writable copy.
_: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.nix-provenance.antigravity.googleAuth;
  account = config.nix-provenance.oauth.accounts.google or null;
  stateDirectory = account.stateDirectory or null;
  stateFile = "${toString stateDirectory}/state.json";
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
    runtimeInputs = [pkgs.coreutils pkgs.jq];
    text = ''
      umask 077
      work=$(mktemp -d -p "''${XDG_RUNTIME_DIR:-''${TMPDIR:-/tmp}}")
      staged=
      trap 'if [ -n "$staged" ]; then rm -f -- "$staged"; fi; rm -f -- "$work/token"; rmdir -- "$work"' EXIT
      token="$work/token"
      ${
        if account != null
        then let
          helper = "${lib.getExe account.package} --config ${lib.escapeShellArg (toString account.configFile)}";
        in ''
          if ! ${helper} agy-token > "$token"; then
            # A removed enrollment stops new exports; existing copies stay until deleted.
            ${helper} status | jq -e '.state == "removed"' >/dev/null && exit 0
            exit 1
          fi''
        else ''cat -- ${shellPath (toString cfg.tokenFile)} > "$token"''
      }
      # A token without a refresh grant would leave agy asking for a browser.
      jq -e 'type == "object" and all(.client_id, .client_secret, .refresh_token; type == "string" and length > 0)' \
        "$token" >/dev/null 2>&1 || {
        echo "antigravity: source is not an agy Google token file" >&2
        exit 1
      }
      # agy rewrites its copy with fresh access tokens, so compare only the grant.
      grant='[.client_id, .client_secret, .refresh_token, .project_id]'
      # An array: a one-word literal list fails shellcheck (SC2043).
      profiles=(${lib.escapeShellArgs cfg.profileDirectories})
      for profile in "''${profiles[@]}"; do
        dir="$profile/antigravity-acp"
        target="$dir/acp_token.json"
        install -d -m 700 "$dir"
        if [ -f "$target" ] && [ ! -L "$target" ] && [ "$(stat -c %a -- "$target")" = 600 ] \
          && jq -e --slurpfile source "$token" "$grant == (\$source[0] | $grant)" "$target" >/dev/null 2>&1; then
          continue
        fi
        staged=$(mktemp "$dir/.provenance-token.XXXXXXXX")
        install -m 600 "$token" "$staged"
        mv -fT -- "$staged" "$target"
        staged=
      done
    '';
  };
in {
  options.nix-provenance.antigravity.googleAuth = {
    enable = mkEnableOption "automatic Antigravity Google sign-in from a shared agy token";

    tokenFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Legacy runtime agenix path holding agy's acp_token.json. Use instead of a google/antigravity enrollment, never alongside one. Its contents never enter Nix.";
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
        assertion = (cfg.tokenFile != null) != (account != null);
        message = "nix-provenance.antigravity.googleAuth requires exactly one source: tokenFile or a google/antigravity enrollment.";
      }
      {
        assertion = cfg.tokenFile == null || literalPath cfg.tokenFile;
        message = "nix-provenance.antigravity.googleAuth.tokenFile must be a literal runtime path outside the Nix store.";
      }
      {
        assertion = account == null || (stateDirectory != null && lib.hasPrefix "/" stateDirectory && literalPath stateDirectory);
        message = "The google/antigravity enrollment needs an absolute runtime stateDirectory outside the Nix store.";
      }
      {
        assertion = cfg.profileDirectories != [] && lib.all literalPath cfg.profileDirectories;
        message = "nix-provenance.antigravity.googleAuth.profileDirectories must list absolute directories.";
      }
    ];
    systemd.user.services.${unitName} = {
      Unit =
        {
          Description = "Register the shared Antigravity Google sign-in";
        }
        // (
          if account != null
          then {
            ConditionPathExists = stateFile;
          }
          else {
            Wants = ["agenix.service"];
            After = ["agenix.service"];
          }
        );
      Service = {
        Type = "oneshot";
        ExecStart = lib.getExe script;
      };
      Install.WantedBy = ["default.target"];
    };
    systemd.user.paths.${unitName} = {
      Unit.Description = "Watch the shared Antigravity Google token";
      Path.PathChanged =
        if account != null
        then stateFile
        else builtins.replaceStrings [runtimePrefix] ["%t"] (toString cfg.tokenFile);
      Install.WantedBy = ["default.target"];
    };
  };
}
