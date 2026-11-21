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
  enrollmentIdPattern = import ../../lib/oauth-enrollment-id-pattern.nix;
  accounts = lib.filterAttrs (_: value: value.provider == "google" && value.profile == "antigravity") (config.nix-provenance.oauth.accounts or {});
  account = accounts.${cfg.enrollment} or null;
  stateDirectory = account.stateDirectory or null;
  stateFile = "${toString stateDirectory}/state.json";
  unitName = "nix-provenance-antigravity-google-auth";
  systemctl = "${lib.getExe' pkgs.systemd "systemctl"} --user";
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
    runtimeInputs = [pkgs.coreutils pkgs.jq pkgs.util-linux];
    text = ''
      umask 077
      if [ -n "''${XDG_RUNTIME_DIR:-}" ]; then
        exec 9>"$XDG_RUNTIME_DIR/${unitName}.lock"
        flock 9
      fi
      work=$(mktemp -d -p "''${XDG_RUNTIME_DIR:-''${TMPDIR:-/tmp}}")
      staged=
      trap 'if [ -n "$staged" ]; then rm -f -- "$staged"; fi; rm -f -- "$work/token"; rmdir -- "$work"' EXIT
      token="$work/token"
      ${
        if cfg.tokenFile != null
        then ''if [ "$#" -eq 0 ]; then cat -- ${shellPath cfg.tokenFile} > "$token"; else''
        else ''if [ "$#" -eq 0 ]; then set -- ${lib.escapeShellArg cfg.enrollment}; fi''
      }
      case "$1" in
        ${lib.concatStringsSep "\n" (lib.mapAttrsToList (id: value: let
          helper = "${lib.getExe value.package} --config ${lib.escapeShellArg (toString value.configFile)}";
        in ''
          ${lib.escapeShellArg id})
            if ! ${helper} agy-token > "$token"; then
              # A removed enrollment stops new exports; existing copies stay until deleted.
              ${helper} status | jq -e '.state == "removed"' >/dev/null && exit 0
              exit 1
            fi ;;
        '')
        accounts)}
        *) echo "antigravity: expected a declared google/antigravity enrollment" >&2; exit 1 ;;
      esac
      ${lib.optionalString (cfg.tokenFile != null) "fi"}
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

    enrollment = mkOption {
      type = types.strMatching enrollmentIdPattern;
      default = "google";
      description = "OAuth account ID with the google/antigravity profile to install on activation.";
    };

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
    systemd.user.services."${unitName}@" = {
      Unit.Description = "Register an Antigravity Google enrollment (%i)";
      Service = {
        Type = "oneshot";
        ExecStart = "${lib.getExe script} %i";
      };
    };
    systemd.user.paths.${unitName} = {
      Unit.Description = "Watch the shared Antigravity Google token";
      Path.PathChanged =
        if account != null
        then stateFile
        else builtins.replaceStrings [runtimePrefix] ["%t"] (toString cfg.tokenFile);
      Install.WantedBy = ["default.target"];
    };
    # HM only starts new/changed units. Restore the declared enrollment on
    # reactivation even if a live switch did not change any unit files.
    home.activation.provenanceAntigravity = mkIf (account != null && (config.systemd.user.startServices or true)) (lib.hm.dag.entryAfter ["reloadSystemd"] ''
      if ${systemctl} --quiet is-active default.target; then
        run ${systemctl} --no-block start ${unitName}.service
      fi
    '');
  };
}
