{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.nix-provenance.github;
  defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.github-provision;
  unitName = name: "nix-provenance-github-${name}";
  # systemd expands `%t`, not agenix's literal `${XDG_RUNTIME_DIR}` placeholder.
  runtimePath = builtins.replaceStrings ["\${XDG_RUNTIME_DIR}"] ["%t"];

  keyModule = extra: {
    options =
      {
        present = mkOption {
          type = types.bool;
          default = true;
          description = "Whether the key should be registered. Removal also needs allowDelete.";
        };
        key = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Public key text. Required when present.";
        };
      }
      // extra;
  };

  accountModule = {name, ...}: {
    options = {
      login = mkOption {
        type = types.str;
        default = name;
        description = "GitHub login the token must authenticate as; a mismatch fails closed.";
      };
      tokenFile = mkOption {
        type = types.str;
        description = "Runtime file (outside the Nix store) holding the account's personal access token.";
        example = "\${XDG_RUNTIME_DIR}/agenix/github_token";
      };
      gpgKeys = mkOption {
        type = types.attrsOf (types.submodule (keyModule {
          fingerprint = mkOption {
            type = types.str;
            description = "Full primary-key fingerprint, used to match GitHub's long key id.";
          };
        }));
        default = {};
        description = "ASCII-armored OpenPGP public keys by name.";
      };
      sshKeys = mkOption {
        type = types.attrsOf (types.submodule (keyModule {}));
        default = {};
        description = "SSH authentication public keys by title.";
      };
      collaborators = mkOption {
        type = types.attrsOf (types.submodule {
          options = {
            permission = mkOption {
              type = types.enum ["pull" "triage" "push" "maintain" "admin"];
              default = "push";
              description = "Permission requested in each invitation.";
            };
            repositories = mkOption {
              type = types.either (types.enum ["owned"]) (types.listOf types.str);
              description = ''`"owned"` for every non-archived repository this account owns, or `owner/name` entries.'';
            };
          };
        });
        default = {};
        description = "Users to invite as collaborators. Existing collaborators are never changed or removed.";
      };
      acceptInvitationsFrom = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Accept repository invitations only when both the inviter and the repository owner are listed.";
      };
      allowDelete = mkOption {
        type = types.bool;
        default = false;
        description = "Permit deleting keys declared with present = false.";
      };
      after = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Other accounts to reconcile first, for example the inviting owner before the invitee accepts.";
      };
    };
  };

  stateFor = name: account:
    pkgs.writeText "github-provision-${name}.json" (builtins.toJSON {
      inherit (account) login acceptInvitationsFrom;
      gpgKeys = lib.mapAttrs (_: key: {inherit (key) present key fingerprint;}) account.gpgKeys;
      sshKeys = lib.mapAttrs (_: key: {inherit (key) present key;}) account.sshKeys;
      inherit (account) collaborators;
    });

  serviceFor = name: account:
    lib.nameValuePair (unitName name) {
      Unit = {
        Description = "Reconcile GitHub account ${account.login}";
        Wants = ["agenix.service"] ++ map (other: "${unitName other}.service") account.after;
        After = ["agenix.service"] ++ map (other: "${unitName other}.service") account.after;
      };
      Service = {
        Type = "oneshot";
        ExecStart = lib.concatStringsSep " " (
          [(lib.escapeShellArg (lib.getExe cfg.package)) "--state" (stateFor name account) "--token-file" (lib.escapeShellArg (runtimePath account.tokenFile))]
          ++ lib.optional account.allowDelete "--allow-delete"
        );
        Restart = "on-failure";
        RestartSec = "5min";
        RestartPreventExitStatus = 2;
      };
      Install.WantedBy = ["default.target"];
    };

  pathFor = name: account:
    lib.nameValuePair (unitName name) {
      Unit.Description = "Watch the GitHub token for ${account.login}";
      Path.PathChanged = runtimePath account.tokenFile;
      Install.WantedBy = ["default.target"];
    };

  # New repositories need invitations and pending invitations need accepting.
  timerFor = name: account:
    lib.nameValuePair (unitName name) {
      Unit.Description = "Periodically reconcile GitHub account ${account.login}";
      Timer = {
        OnCalendar = "daily";
        Persistent = true;
        RandomizedDelaySec = "1h";
      };
      Install.WantedBy = ["timers.target"];
    };
in {
  options.nix-provenance.github = {
    enable = mkEnableOption "declarative GitHub account keys and collaborator reconciliation";

    package = mkOption {
      type = types.package;
      default = defaultPackage;
      defaultText = lib.literalMD "nix-provenance.packages.<system>.github-provision";
      description = "Reconciler used by the per-account user units.";
    };

    accounts = mkOption {
      type = types.attrsOf (types.submodule accountModule);
      default = {};
      description = "GitHub accounts reconciled with their own tokens.";
    };
  };

  config = mkIf cfg.enable {
    assertions = lib.concatLists (lib.mapAttrsToList (name: account:
      [
        {
          assertion = !(lib.hasPrefix builtins.storeDir account.tokenFile) && (lib.hasPrefix "/" account.tokenFile || lib.hasPrefix "\${XDG_RUNTIME_DIR}/" account.tokenFile);
          message = "nix-provenance.github.accounts.${name}.tokenFile must be an absolute runtime path outside the Nix store.";
        }
        {
          assertion = lib.all (other: cfg.accounts ? ${other}) account.after;
          message = "nix-provenance.github.accounts.${name}.after names an undeclared account.";
        }
      ]
      ++ lib.mapAttrsToList (title: key: {
        assertion = !key.present || key.key != null;
        message = "nix-provenance.github.accounts.${name}: key ${title} is present but has no public key.";
      }) (account.gpgKeys // account.sshKeys))
    cfg.accounts);

    systemd.user.services = lib.mapAttrs' serviceFor cfg.accounts;
    systemd.user.paths = lib.mapAttrs' pathFor cfg.accounts;
    systemd.user.timers = lib.mapAttrs' timerFor cfg.accounts;
  };
}
