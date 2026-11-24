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
  # Every enrollment can be the live pick, so each one's refresh re-syncs it.
  stateFiles = lib.unique (lib.mapAttrsToList (_: value: "${toString value.stateDirectory}/state.json") accounts);
  declared = lib.escapeShellArg cfg.enrollment;
  unitName = "nix-provenance-antigravity-google-auth";
  systemctl = "${lib.getExe' pkgs.systemd "systemctl"} --user";
  agyKeyring = pkgs.oo7.overrideAttrs (old: {
    patches = (old.patches or []) ++ [./oo7-agy.patch];
  });
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
      trap 'if [ -n "$staged" ]; then rm -f -- "$staged"; fi; rm -f -- "$work/token" "$work/native"; rmdir -- "$work"' EXIT
      token="$work/token"
      ${
        if cfg.tokenFile != null
        then ''if [ "$#" -eq 0 ]; then cat -- ${shellPath cfg.tokenFile} > "$token"; else''
        else ''
          selection="''${XDG_STATE_HOME:-$HOME/.local/state}/nix-provenance/antigravity-selection"
          remember=1
          if [ "$#" -eq 0 ]; then
            remember=
            set -- ${declared}
            # A live pick (the @ID unit) holds until the declared enrollment changes.
            picked=$(jq -r --arg declared ${declared} 'select(.declared == $declared) | .enrollment' "$selection" 2>/dev/null) || picked=
            case "$picked" in
              ${lib.concatMapStringsSep "|" lib.escapeShellArg (builtins.attrNames accounts)}) set -- "$picked" ;;
            esac
          fi
        ''
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
            fi
            ${lib.optionalString cfg.keyring.enable "keyring_helper=(${helper})"}
            ;;
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
      # agy 1.5 reads the native file instead of acp_token.json in file-storage mode.
      jq -ce '{auth_method:"consumer", token:{token_type:"Bearer", refresh_token}}' "$token" > "$work/native"
      install_grant() {
        local source=$1 target=$2 grant=$3
        # Keep access tokens agy cached for the same grant.
        if [ -f "$target" ] && [ ! -L "$target" ] && [ "$(stat -c %a -- "$target")" = 600 ] \
          && jq -e --slurpfile source "$source" "$grant == (\$source[0] | $grant)" "$target" >/dev/null 2>&1; then
          return
        fi
        staged=$(mktemp "''${target%/*}/.provenance-token.XXXXXXXX")
        install -m 600 "$source" "$staged"
        mv -fT -- "$staged" "$target"
        staged=
      }
      # An array: a one-word literal list fails shellcheck (SC2043).
      profiles=(${lib.escapeShellArgs cfg.profileDirectories})
      for profile in "''${profiles[@]}"; do
        dir="$profile/antigravity-acp"
        install -d -m 700 "$dir"
        install_grant "$token" "$dir/acp_token.json" '[.client_id, .client_secret, .refresh_token, .project_id]'
        install_grant "$work/native" "$dir/antigravity-oauth-token" '[.auth_method, .token.token_type, .token.refresh_token]'
      done
      ${lib.optionalString (cfg.tokenFile == null) ''
        if [ -n "$remember" ]; then
          install -d -m 700 "$(dirname -- "$selection")"
          jq -n --arg enrollment "$1" --arg declared ${declared} '{$enrollment, $declared}' > "$selection.tmp"
          mv -fT -- "$selection.tmp" "$selection"
        fi
      ''}
      ${lib.optionalString cfg.keyring.enable ''
        # agy checks the actual collection path, not the "login" alias.
        keyring=(timeout --kill-after=1s 5s ${lib.getExe' cfg.keyring.package "oo7-cli"}
          --prefer-collection-path /org/freedesktop/secrets/collection/login)
        attributes=(service=gemini username=antigravity)
        same_refresh=".token.refresh_token == \$source[0].refresh_token"
        if "''${keyring[@]}" search --all --json "''${attributes[@]}" 2>/dev/null \
          | jq -e --slurpfile source "$token" "length == 1 and (.[0].secret | fromjson? | $same_refresh)" >/dev/null 2>&1; then
          exit 0
        else
          lookup_status="''${PIPESTATUS[0]}"
        fi
        if [ "$lookup_status" -ne 0 ]; then
          echo "antigravity: ACP profiles installed, but Secret Service keyring lookup failed (unlock it and retry)" >&2
          # The ordinary unit also runs before graphical login. Keep explicit @ID switches strict.
          if [ -z "$remember" ]; then
            exit 0
          fi
          exit 1
        fi
        # Keep the same refresh grant as the ACP copies if the enrollment
        # changed during installation. Never call store on empty input.
        unset entry
        if ! {
          entry=$(timeout --kill-after=1s 15s "''${keyring_helper[@]}" agy-keyring-entry \
            | jq -cse --slurpfile source "$token" "select(length == 1) | .[0] | select($same_refresh)" 2>/dev/null) &&
            builtin printf '%s' "$entry" |
            "''${keyring[@]}" store --replace-all "Password for 'antigravity' on 'gemini'" "''${attributes[@]}" >/dev/null 2>&1
        }; then
          echo "antigravity: ACP profiles installed, but the CLI keyring entry could not be updated (check Google access and unlock the keyring, then retry)" >&2
          exit 1
        fi
      ''}
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
      description = "agy profile directories (GEMINI_HOME), such as a T3 Code Antigravity instance's profile, that receive both native and legacy credentials in antigravity-acp.";
    };

    keyring = {
      enable = mkEnableOption "install the selected Antigravity enrollment into the interactive agy CLI's Secret Service keyring";
      package = mkOption {
        type = types.package;
        default = agyKeyring;
        defaultText = lib.literalMD "`pkgs.oo7` with agy keyring support";
        description = "Package providing oo7-cli with --prefer-collection-path and store --replace-all support.";
      };
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
        assertion = !cfg.keyring.enable || cfg.tokenFile == null;
        message = "nix-provenance.antigravity.googleAuth.keyring requires an OAuth enrollment and cannot be used with tokenFile.";
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
            # Any enrollment's state: the live pick need not be the declared one.
            ConditionPathExists = map (file: "|${file}") stateFiles;
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
        then stateFiles
        else builtins.replaceStrings [runtimePrefix] ["%t"] (toString cfg.tokenFile);
      Install.WantedBy = ["default.target"];
    };
    # HM only starts new/changed units. Re-sync on reactivation even if no unit
    # file changed: the live pick, or the declared enrollment once it changes.
    home.activation.provenanceAntigravity = mkIf (account != null && (config.systemd.user.startServices or true)) (lib.hm.dag.entryAfter ["reloadSystemd"] ''
      if ${systemctl} --quiet is-active default.target; then
        run ${systemctl} --no-block start ${unitName}.service
      fi
    '');
  };
}
