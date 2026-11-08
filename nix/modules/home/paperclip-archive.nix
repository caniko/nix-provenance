# Immortalize Paperclip companies: export them on a timer into a git-LFS
# repository, and restore declared companies from a pinned copy of that
# repository only when they do not exist yet. Live edits are never overwritten.
{
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.nix-provenance.paperclip-archive;
  q = lib.escapeShellArg;
  paperclip = lib.getExe' cfg.package "paperclip";
  # Same slug the export writes to COMPANY.md.
  slugOf = ''ascii_downcase | gsub("[^a-z0-9]+"; "-") | gsub("^-+|-+$"; "")'';
  apiEnv = ''
    export PAPERCLIP_API_URL=${q cfg.apiUrl}
    export PAPERCLIP_API_KEY_FILE=${q cfg.apiKeyFile}
  '';
  runtimeInputs = [pkgs.coreutils pkgs.git pkgs.git-lfs pkgs.gnugrep pkgs.gnused pkgs.jq pkgs.openssh];

  # Reads the token at runtime; only its path ever reaches git config.
  credentialHelper = pkgs.writeShellScript "paperclip-archive-credential" ''
    test "$1" = get || exit 0
    echo username=${q cfg.username}
    echo "password=$(${pkgs.coreutils}/bin/cat ${q cfg.tokenFile})"
  '';

  gitattributes = lib.concatMapStrings (p: "${p} filter=lfs diff=lfs merge=lfs -text\n") cfg.lfsPatterns;

  exportScript = pkgs.writeShellApplication {
    name = "paperclip-archive-export";
    inherit runtimeInputs;
    text = ''
      ${apiEnv}
      dir=${q cfg.checkoutDir}
      mkdir -p "$(dirname "$dir")"
      if test ! -d "$dir/.git"; then
        git -c credential.helper="${credentialHelper}" clone ${q cfg.repository} "$dir"
      fi
      cd "$dir"
      git config credential.helper "${credentialHelper}"
      # Machine-owned clone: a private hooks dir keeps global hooks out; only LFS's run.
      # Commits use the user's own git identity.
      mkdir -p .git/lfs-hooks
      git config core.hooksPath "$PWD/.git/lfs-hooks"
      git lfs install --local
      # The checkout is machine-owned: drop leftovers of an interrupted run.
      if git rev-parse -q --verify HEAD >/dev/null; then
        git reset --hard -q HEAD
        git clean -fdq
        git pull --ff-only origin main
      else
        git symbolic-ref HEAD refs/heads/main
      fi

      tmp="$(mktemp -d)"
      trap 'rm -rf "$tmp"' EXIT
      mkdir "$tmp/companies"
      ids="$(${paperclip} company list --json | jq -r '.[].id')"
      # ponytail: refuse an empty list so an API glitch cannot wipe the archive.
      test -n "$ids" || { echo "paperclip-archive: no companies listed; refusing to prune" >&2; exit 1; }
      for id in $ids; do
        ${paperclip} company export "$id" --out "$tmp/raw-$id" --force \
          --include ${q (lib.concatStringsSep "," cfg.include)} >/dev/null
        slug="$(sed -n 's/^slug: "\(.*\)"$/\1/p' "$tmp/raw-$id/COMPANY.md" | head -n1)"
        test -n "$slug" || { echo "paperclip-archive: no slug in export of $id" >&2; exit 1; }
        mv "$tmp/raw-$id" "$tmp/companies/$slug"
      done

      # Every export succeeded: swap the tree in, which also prunes deleted companies.
      rm -rf companies
      mv "$tmp/companies" companies
      printf '%s' ${q gitattributes} > .gitattributes
      git add -A
      if git diff --cached --quiet; then
        echo "paperclip-archive: no changes"
        exit 0
      fi
      git commit -q -m "archive: paperclip $(${paperclip} --version)"
      git push origin HEAD:refs/heads/main
    '';
  };

  restoreScript = pkgs.writeShellApplication {
    name = "paperclip-archive-restore";
    inherit runtimeInputs;
    text = ''
      ${apiEnv}
      live="$(${paperclip} company list --json | jq -r '.[].name | ${slugOf}')"
      ${lib.concatStrings (lib.mapAttrsToList (slug: entry: ''
          if printf '%s\n' "$live" | grep -Fxq ${q slug}; then
            echo "paperclip-archive: ${slug} exists, skipping restore"
          else
            echo "paperclip-archive: restoring ${slug}"
            ${paperclip} company import ${q entry.source} --target new --collision skip --yes
          fi
        '')
        cfg.restore)}
    '';
  };
in {
  options.nix-provenance.paperclip-archive = {
    enable = mkEnableOption "timed Paperclip company export into a git-LFS repository, with restore-if-missing";

    package = mkOption {
      type = types.package;
      description = "Package providing the `paperclip` CLI.";
    };

    apiUrl = mkOption {
      type = types.str;
      description = "Paperclip API base URL.";
    };

    apiKeyFile = mkOption {
      type = types.str;
      description = "Runtime path of the Paperclip Bearer key (read by the CLI, never in argv).";
    };

    repository = mkOption {
      type = types.str;
      description = "HTTPS URL of the archive repository (without credentials).";
    };

    username = mkOption {
      type = types.str;
      default = "caniko";
      description = "Forgejo login paired with the token.";
    };

    tokenFile = mkOption {
      type = types.str;
      description = "Runtime path of the Forgejo token; read on demand by a git credential helper.";
    };

    checkoutDir = mkOption {
      type = types.str;
      default = "${config.xdg.stateHome}/paperclip-archive";
      defaultText = lib.literalExpression ''"''${config.xdg.stateHome}/paperclip-archive"'';
      description = "Local clone used for export commits.";
    };

    include = mkOption {
      type = types.listOf (types.enum ["company" "agents" "projects" "issues" "tasks" "skills"]);
      default = ["company" "agents" "projects" "issues" "tasks" "skills"];
      description = "Parts of each company to export.";
    };

    schedule = mkOption {
      type = types.str;
      default = "daily";
      description = "systemd OnCalendar expression for the export.";
    };

    lfsPatterns = mkOption {
      type = types.listOf types.str;
      default =
        ["**/assets/**" "**/images/**"]
        ++ map (e: "*.${e}") ["png" "jpg" "jpeg" "gif" "webp" "pdf" "zip" "mp4" "webm" "glb"];
      description = "`.gitattributes` patterns stored in git-LFS.";
    };

    paperclipUnit = mkOption {
      type = types.str;
      default = "paperclip-operations.service";
      description = "Unit the restore service orders itself after.";
    };

    restore = mkOption {
      type = types.attrsOf (types.submodule {
        options.source = mkOption {
          type = types.path;
          description = "Pinned exported company package (a `companies/<slug>` directory).";
        };
      });
      default = {};
      description = "Companies to import when no company with that slug exists, keyed by slug.";
    };
  };

  config = mkIf cfg.enable (lib.mkMerge [
    {
      systemd.user.services.paperclip-archive-export = {
        Unit = {
          Description = "Export Paperclip companies into the git-LFS archive";
          After = [cfg.paperclipUnit];
        };
        Service = {
          Type = "oneshot";
          ExecStart = lib.getExe exportScript;
        };
      };
      systemd.user.timers.paperclip-archive-export = {
        Unit.Description = "Periodic Paperclip company export";
        Timer = {
          OnCalendar = cfg.schedule;
          Persistent = true;
          RandomizedDelaySec = "10m";
        };
        Install.WantedBy = ["timers.target"];
      };
    }
    (mkIf (cfg.restore != {}) {
      systemd.user.services.paperclip-archive-restore = {
        Unit = {
          Description = "Restore missing Paperclip companies from the pinned archive";
          After = [cfg.paperclipUnit];
        };
        Service = {
          Type = "oneshot";
          ExecStartPre = "${lib.getExe pkgs.curl} -fsS --retry 30 --retry-delay 2 --retry-connrefused -o /dev/null ${q cfg.apiUrl}/api/health";
          ExecStart = lib.getExe restoreScript;
        };
        Install.WantedBy = ["default.target"];
      };
    })
  ]);
}
