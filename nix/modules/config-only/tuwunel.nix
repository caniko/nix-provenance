{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.matrix-tuwunel;
  pcfg = cfg.provision;
  passwords = self.lib.passwords;

  userSubmodule = types.submodule {
    options = {
      passwordFile = passwords.passwordFileOption;
      admin = mkOption {
        type = types.bool;
        default = false;
        description = "Whether this user should have server admin privileges.";
      };
      displayName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional Matrix display name for the user.";
      };
    };
  };

  stateFile = pkgs.writeText "tuwunel-provision-state.json" (builtins.toJSON {
    server_name = cfg.settings.global.server_name;
    port = builtins.head cfg.settings.global.port;
    users = lib.mapAttrs (name: user: {
      inherit (user) admin;
      display_name = user.displayName;
      credential_name = passwords.credentialName name;
    }) pcfg.users;
  });
in {
  options.services.matrix-tuwunel.provision = {
    enable = mkEnableOption "declarative tuwunel user provisioning";

    adminTokenFile = mkOption {
      type = types.path;
      description = ''
        Runtime path to a Matrix access token with admin privileges.
        Bootstrap: register the first user (admin) via Element, extract token,
        store in agenix, then enable the provisioner.
      '';
    };

    users = mkOption {
      type = types.attrsOf userSubmodule;
      default = {};
      description = ''
        Matrix users to provision, keyed by localpart
        (username without @ or server name).
      '';
    };
  };

  config = mkIf pcfg.enable {
    assertions = [
      {
        assertion = config.services.matrix-tuwunel.enable;
        message = "services.matrix-tuwunel.provision requires services.matrix-tuwunel.enable = true.";
      }
    ];

    systemd.services.tuwunel-provision = {
      description = "Declaratively provision tuwunel Matrix users";
      after = ["tuwunel.service"];
      requires = ["tuwunel.service"];
      wantedBy = ["multi-user.target"];
      restartTriggers = [stateFile];

      script = let
        stateFileAbs = toString stateFile;
        tokenFileAbs = toString pcfg.adminTokenFile;
      in ''
        set -eu
        umask 077

        token=$(tr -d '\n' < ${lib.escapeShellArg tokenFileAbs})
        test -n "$token"

        state=${lib.escapeShellArg stateFileAbs}
        server_name=$(jq -r '.server_name' "$state")
        port=$(jq -r '.port' "$state")
        base_url="http://127.0.0.1:''${port}"

        jq -c '.users | to_entries[]' "$state" | while IFS= read -r entry; do
          username=$(echo "$entry" | jq -r '.key')
          is_admin=$(echo "$entry" | jq -r '.value.admin // false')
          display_name=$(echo "$entry" | jq -r '.value.display_name // ""')
          cred_name=$(echo "$entry" | jq -r '.value.credential_name')
          user_id="@''${username}:''${server_name}"

          cred_path="/run/credentials/tuwunel-provision.service/''${cred_name}"
          if [ ! -f "$cred_path" ]; then
            echo "tuwunel-provision: credential ''${cred_name} not found — skipping ''${user_id}" >&2
            continue
          fi
          password=$(tr -d '\n' < "$cred_path")

          payload=$(jq -n \
            --arg pw "$password" \
            --argjson admin "$is_admin" \
            --arg display "$display_name" \
            '{password: $pw, admin: $admin, displayname: $display}')

          http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST "''${base_url}/_synapse/admin/v2/users/''${user_id}" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$payload" 2>/dev/null || echo "000")

          case "$http_code" in
            200|201)
              echo "tuwunel-provision: created/updated ''${user_id}"
              ;;
            404|405)
              echo "tuwunel-provision: admin API unsupported, trying register endpoint for ''${user_id}"
              curl -s -o /dev/null \
                -X POST "''${base_url}/_matrix/client/v3/register" \
                -H "Authorization: Bearer $token" \
                -H "Content-Type: application/json" \
                -d "$(jq -n \
                  --arg user "$username" \
                  --arg pw "$password" \
                  --argjson admin "$is_admin" \
                  '{username: $user, password: $pw, admin: $admin}')" \
                && echo "tuwunel-provision: registered ''${user_id} via fallback" \
                || echo "tuwunel-provision: fallback also failed for ''${user_id}" >&2
              ;;
            000)
              echo "tuwunel-provision: tuwunel not reachable at ''${base_url}" >&2
              exit 1
              ;;
            *)
              echo "tuwunel-provision: admin API returned HTTP $http_code for ''${user_id}" >&2
              ;;
          esac
        done
      '';

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        LoadCredential = passwords.userPasswordCredentials "tuwunel-provision" pcfg.users;
        User = cfg.user;
        Group = cfg.group;
      };
    };
  };
}
