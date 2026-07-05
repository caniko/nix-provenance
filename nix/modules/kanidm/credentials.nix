# Declarative reconciliation of the kanidm credential state that
# `services.kanidm.provision` cannot express. kanidm-provision's state covers
# only {groups, persons, systems}; it has no way to set POSIX passwords, toggle
# the domain `ldap_allow_unix_pw_bind` flag, or mint a service-account API
# token. All three are required for an LDAP consumer (e.g. Stalwart) to both
# search the directory and authenticate users — see the verified facts:
#
#   * Only a service-account token bound as `dn=token` gets elevated LDAP read
#     (a person/posix bind is anonymous-read-only and cannot see `mail`); the
#     service account must be a member of `idm_people_pii_read` to read mail.
#   * Per-user auth uses `ldap_allow_unix_pw_bind = true` + a POSIX password
#     (single factor; not MFA-gated, unlike the primary credential).
#   * The unix-pw-bind toggle requires the `admin` account; everything else is
#     `idm_admin`. Setting a POSIX password requires the person to be
#     posix-enabled first (done declaratively by kanidm-provision).
#
# This module runs a kanidm-readiness-gated oneshot that drives `identity-cli`
# to reconcile that state on every activation, idempotently. The minted token is
# self-healing: it is persisted under StateDirectory and re-minted only if it is
# missing or no longer binds (e.g. after a kanidm DB restore).
{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.kanidm-credentials;

  identityCli = self.packages.${pkgs.stdenv.hostPlatform.system}.identity-cli;

  sa = cfg.serviceAccount;
  posixNames = lib.attrNames cfg.posixAccounts;
  validSshTag = tag: builtins.match "[A-Za-z0-9_.@:-]+" tag != null;
  invalidSshTags =
    lib.concatLists (
      lib.mapAttrsToList (
        name: acct:
          map (tag: "${name}.${tag}") (
            lib.filter (tag: !(validSshTag tag)) (lib.attrNames acct.sshPublicKeys)
          )
      )
      cfg.posixAccounts
    );

  desiredSshTagsFile = name: acct:
    pkgs.writeText "kanidm-${name}-ssh-tags" (
      lib.concatStringsSep "\n" (lib.attrNames acct.sshPublicKeys)
      + lib.optionalString (acct.sshPublicKeys != {}) "\n"
    );

  # systemd LoadCredential entries: idm_admin always; admin when the domain
  # toggle is managed; one per posix account.
  loadCredentials =
    ["idm-admin:${cfg.idmAdminPasswordFile}"]
    ++ lib.optional (cfg.adminPasswordFile != null) "admin:${cfg.adminPasswordFile}"
    ++ lib.mapAttrsToList (name: acct: "posix-${name}:${acct.passwordFile}") cfg.posixAccounts
    ++ lib.mapAttrsToList (name: acct: "initial-${name}:${acct.initialPasswordFile}") (lib.filterAttrs (_: acct: acct.initialPasswordFile != null) cfg.posixAccounts);

  reconcile = pkgs.writeShellApplication {
    name = "kanidm-credentials-reconcile";
    runtimeInputs = [pkgs.coreutils pkgs.curl pkgs.gnugrep pkgs.openldap cfg.package];
    text = ''
      cred="$CREDENTIALS_DIRECTORY"
      url=${lib.escapeShellArg cfg.instanceUrl}

      # Wait for the kanidm HTTPS API to accept connections before driving it.
      ready=
      for _ in $(seq 1 ${toString (cfg.readyTimeoutSeconds / 2)}); do
        if curl -fsS --max-time 5 "$url/status" >/dev/null 2>&1; then ready=1; break; fi
        sleep 2
      done
      if [ -z "$ready" ]; then
        echo "kanidm-credentials: kanidm API at $url not ready after ~${toString cfg.readyTimeoutSeconds}s" >&2
        exit 1
      fi

      idm() { identity-cli kanidm --url "$url" --idm-admin-password-file "$cred/idm-admin" "$@"; }

      ${lib.optionalString (cfg.ldapUnixBind != null) ''
        # Domain-level toggle — requires the admin account (idm_admin 404s).
        identity-cli kanidm --url "$url" \
          --idm-admin-password-file "$cred/idm-admin" \
          --admin-password-file "$cred/admin" \
          set-ldap-unix-bind ${lib.boolToString cfg.ldapUnixBind}
      ''}

      ${lib.optionalString (sa != null) ''
        # LDAP search-bind service account + read grants + a self-healing token.
        idm service-account create ${lib.escapeShellArg sa.name} \
          --display-name ${lib.escapeShellArg sa.displayName} >/dev/null
        ${lib.concatMapStringsSep "\n" (g: ''
            idm group-add-members ${lib.escapeShellArg g} ${lib.escapeShellArg sa.name} >/dev/null
          '')
          sa.readGroups}

        token=${lib.escapeShellArg sa.tokenPath}
        install -d -m 0700 -- "$(dirname -- "$token")"
        if [ ! -s "$token" ] \
           || ! ldapwhoami -H ${lib.escapeShellArg cfg.ldapUrl} -x -D "dn=token" -y "$token" >/dev/null 2>&1; then
          idm service-account api-token ${lib.escapeShellArg sa.name} \
            --label ${lib.escapeShellArg sa.tokenLabel} --out "$token"
        fi
      ''}

      # POSIX passwords (best-effort per account so one failure — e.g. an
      # account that kanidm-provision has not posix-enabled yet — does not block
      # the others). The reconcile still exits non-zero if any failed.
      rc=0
      marker_dir="$STATE_DIRECTORY/password-markers"
      ssh_marker_dir="$STATE_DIRECTORY/ssh-key-tags"
      mkdir -p "$marker_dir"
      mkdir -p "$ssh_marker_dir"
      ${lib.concatMapStringsSep "\n" (name: ''
          ${lib.optionalString (cfg.posixAccounts.${name}.initialPasswordFile != null) ''
            initial_hash="$(sha256sum "$cred/initial-${name}" | cut -d ' ' -f1)"
            initial_marker="$marker_dir/initial-${builtins.substring 0 16 (builtins.hashString "sha256" name)}.sha256"
            if [ ! -s "$initial_marker" ] || [ "$(cat "$initial_marker")" != "$initial_hash" ]; then
              if initial_output="$(idm set-initial-primary-password ${lib.escapeShellArg name} --primary-from "$cred/initial-${name}" 2>&1)"; then
                if printf '%s\n' "$initial_output" | grep -q '^initial_primary_password_present='; then
                  if [ ! -s "$initial_marker" ]; then
                    echo "kanidm-credentials: warning: ${name} already has a primary credential; adopting initialPasswordFile marker without changing Kanidm credentials" >&2
                  else
                    echo "kanidm-credentials: warning: initialPasswordFile changed for ${name}; existing Kanidm primary credentials cannot be changed declaratively" >&2
                  fi
                fi
                printf '%s\n' "$initial_hash" > "$initial_marker"
              else
                printf '%s\n' "$initial_output" >&2
                echo "kanidm-credentials: failed to set/adopt initial primary credential for ${name}" >&2
                rc=1
              fi
            fi
          ''}
          if ! idm set-posix-password ${lib.escapeShellArg name} --posix-from "$cred/posix-${name}" >/dev/null; then
            echo "kanidm-credentials: failed to set POSIX password for ${name}" >&2
            rc=1
          fi

          desired_tags=${lib.escapeShellArg (desiredSshTagsFile name cfg.posixAccounts.${name})}
          owned_tags="$ssh_marker_dir/${builtins.substring 0 16 (builtins.hashString "sha256" name)}.tags"
          touch "$owned_tags"
          ssh_ok=1
          ${lib.concatStringsSep "\n" (lib.mapAttrsToList (tag: publicKey: ''
            if ! idm ssh-public-key ensure ${lib.escapeShellArg name} ${lib.escapeShellArg tag} ${lib.escapeShellArg publicKey} >/dev/null; then
              echo "kanidm-credentials: failed to ensure SSH public key ${tag} for ${name}" >&2
              rc=1
              ssh_ok=0
            fi
          '')
          cfg.posixAccounts.${name}.sshPublicKeys)}
          while IFS= read -r old_tag; do
            [ -n "$old_tag" ] || continue
            if ! grep -Fxq -- "$old_tag" "$desired_tags"; then
              if ! idm ssh-public-key delete ${lib.escapeShellArg name} "$old_tag" >/dev/null; then
                echo "kanidm-credentials: failed to delete previously owned SSH public key $old_tag for ${name}" >&2
                rc=1
                ssh_ok=0
              fi
            fi
          done < "$owned_tags"
          if [ "$ssh_ok" = 1 ]; then
            cp "$desired_tags" "$owned_tags"
          fi
        '')
        posixNames}
      exit "$rc"
    '';
  };
in {
  options.services.kanidm-credentials = {
    enable = mkEnableOption ''
      reconciliation of kanidm credential state that kanidm-provision cannot
      express: POSIX passwords, the LDAP unix-pw-bind domain toggle, and an LDAP
      search service account with a self-healing API token
    '';

    instanceUrl = mkOption {
      type = types.str;
      example = "https://auth.tartanoglu.com:8443";
      description = "kanidm HTTPS API base URL the CLI authenticates against.";
    };

    ldapUrl = mkOption {
      type = types.str;
      default = "";
      example = "ldaps://auth.tartanoglu.com:3636";
      description = ''
        kanidm LDAP gateway URL, used to self-test the service-account token
        (re-mint if it no longer binds). Required when serviceAccount is set.
      '';
    };

    idmAdminPasswordFile = mkOption {
      type = types.path;
      description = "Path to the idm_admin password (used for all non-domain operations).";
    };

    adminPasswordFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Path to the admin password. Required when ldapUnixBind is set — the
        domain toggle is hidden from idm_admin and needs the admin account.
      '';
    };

    package = mkOption {
      type = types.package;
      default = identityCli;
      defaultText = lib.literalExpression "nix-provenance identity-cli";
      description = "identity-cli package providing the kanidm subcommands.";
    };

    readyTimeoutSeconds = mkOption {
      type = types.ints.positive;
      default = 120;
      description = "How long to wait for the kanidm API to become ready before failing.";
    };

    ldapUnixBind = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = ''
        When non-null, set the domain `ldap_allow_unix_pw_bind` flag to this
        value. Required for per-user LDAP password authentication. Needs
        adminPasswordFile.
      '';
    };

    posixAccounts = mkOption {
      default = {};
      description = ''
        Persons to set a POSIX/LDAP password on. Each must already be
        posix-enabled by kanidm-provision (`enableUnix`); the password is
        re-asserted idempotently on every reconcile.
      '';
      type = types.attrsOf (types.submodule {
        options.passwordFile = mkOption {
          type = types.path;
          description = "File whose contents become the account's POSIX password.";
        };
        options.initialPasswordFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            Optional file whose contents become the account's primary Kanidm
            password only when the account has no primary credential yet. For
            existing credentialed users, the service records the declared hash
            and warns instead of changing Kanidm credentials.
          '';
        };
        options.sshPublicKeys = mkOption {
          type = types.attrsOf types.str;
          default = {};
          description = ''
            Tagged OpenSSH public keys to register on the Kanidm person. This
            module owns only tags it has previously declared, preserving manual
            or unrelated Kanidm SSH keys.
          '';
        };
      });
    };

    serviceAccount = mkOption {
      default = null;
      description = ''
        Optional LDAP search-bind service account to ensure, grant read groups
        to, and mint a persisted (self-healing) API token for.
      '';
      type = types.nullOr (types.submodule ({config, ...}: {
        options = {
          name = mkOption {
            type = types.str;
            description = "Service account name (the LDAP search-bind identity).";
          };
          displayName = mkOption {
            type = types.str;
            default = "LDAP search bind";
            description = "Service account display name.";
          };
          readGroups = mkOption {
            type = types.listOf types.str;
            default = ["idm_people_pii_read"];
            description = ''
              Groups the service account joins so its token can read the needed
              attributes. `mail` lives behind `idm_people_pii_read`.
            '';
          };
          tokenPath = mkOption {
            type = types.str;
            default = "/var/lib/kanidm-credentials/${config.name}.token";
            defaultText = lib.literalExpression ''"/var/lib/kanidm-credentials/''${name}.token"'';
            description = "Persistent path the minted API token is written to (mode 0600).";
          };
          tokenLabel = mkOption {
            type = types.str;
            default = "ldap-search";
            description = "Label for the minted API token.";
          };
        };
      }));
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = (cfg.ldapUnixBind != null) -> (cfg.adminPasswordFile != null);
        message = "services.kanidm-credentials.ldapUnixBind requires adminPasswordFile (the domain toggle needs the kanidm admin account).";
      }
      {
        assertion = (cfg.serviceAccount != null) -> (cfg.ldapUrl != "");
        message = "services.kanidm-credentials.serviceAccount requires ldapUrl (used to self-test the minted token).";
      }
      {
        assertion = invalidSshTags == [];
        message = "services.kanidm-credentials.posixAccounts.*.sshPublicKeys tags must match [A-Za-z0-9_.@:-]+; invalid tags: ${lib.concatStringsSep ", " invalidSshTags}";
      }
    ];

    systemd.services.kanidm-credentials = {
      description = "Reconcile kanidm credentials (POSIX passwords, unix-pw-bind, LDAP search service account + token)";
      after = ["kanidm.service"];
      wants = ["kanidm.service"];
      wantedBy = ["multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StateDirectory = "kanidm-credentials";
        StateDirectoryMode = "0700";
        LoadCredential = loadCredentials;
        ExecStart = lib.getExe reconcile;
      };
    };
  };
}
