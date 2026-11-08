# Runs the real export/restore scripts against a fake `paperclip` CLI and a
# local bare repository: LFS tracking, pruning, idempotence, restore-if-missing.
{pkgs}: let
  inherit (pkgs) lib;
  fake = pkgs.writeShellScriptBin "paperclip" ''
    case "$*" in
      --version) echo 9.9.9 ;;
      "company list --json") cat "$FAKE_STATE/companies" ;;
      "company export"*)
        id=$3; out=$5
        mkdir -p "$out/images"
        printf -- '---\nname: "%s"\nslug: "%s"\n---\n' "$id" "$id" > "$out/COMPANY.md"
        printf '\x89PNG%s' "$id" > "$out/images/org-chart.png"
        ;;
      "company import"*) echo "$*" >> "$FAKE_STATE/imports" ;;
      *) echo "unexpected: $*" >&2; exit 1 ;;
    esac
  '';
  evaluated = lib.evalModules {
    specialArgs = {inherit pkgs;};
    modules = [
      ../home/paperclip-archive.nix
      ({lib, ...}: {
        options = {
          assertions = lib.mkOption {
            type = lib.types.listOf lib.types.attrs;
            default = [];
          };
          xdg.stateHome = lib.mkOption {
            type = lib.types.str;
            default = "/build/state";
          };
          systemd.user.services = lib.mkOption {
            type = lib.types.attrs;
            default = {};
          };
          systemd.user.timers = lib.mkOption {
            type = lib.types.attrs;
            default = {};
          };
        };
        config.nix-provenance.paperclip-archive = {
          enable = true;
          package = fake;
          apiUrl = "http://127.0.0.1:3117";
          apiKeyFile = "/run/secrets/paperclip-key";
          repository = "/build/remote.git";
          tokenFile = "/run/secrets/codefloe-token";
          checkoutDir = "/build/checkout";
          restore.beta.source = "/build/pinned/beta";
          restore.alpha.source = "/build/pinned/alpha";
        };
      })
    ];
  };
  svc = evaluated.config.systemd.user.services;
in
  pkgs.runCommand "paperclip-archive-module-eval" {nativeBuildInputs = [pkgs.git pkgs.git-lfs pkgs.jq];} ''
    export HOME=$TMPDIR/home FAKE_STATE=$TMPDIR/state
    mkdir -p $HOME $FAKE_STATE
    git config --global init.defaultBranch main
    git config --global user.name test
    git config --global user.email test@example.com
    git init -q --bare /build/remote.git
    git -C /build/remote.git config lfs.allowincompletepush true
    export PATH=${fake}/bin:$PATH
    export_bin=${svc.paperclip-archive-export.Service.ExecStart}

    echo '[{"id":"alpha","name":"Alpha"},{"id":"beta","name":"Beta"}]' > $FAKE_STATE/companies
    $export_bin
    $export_bin # idempotent: no second commit
    test "$(git -C /build/remote.git rev-list --count main)" = 1
    git -C /build/checkout lfs ls-files | tee $TMPDIR/lfs
    grep -q 'companies/alpha/images/org-chart.png' $TMPDIR/lfs
    git -C /build/checkout log -1 --format=%s | grep -Fq 'paperclip 9.9.9'

    # A deleted company is pruned from the archive.
    echo '[{"id":"alpha","name":"Alpha"}]' > $FAKE_STATE/companies
    $export_bin
    test ! -e /build/checkout/companies/beta
    test "$(git -C /build/remote.git rev-list --count main)" = 2

    # An empty listing must fail and leave the archive alone.
    echo '[]' > $FAKE_STATE/companies
    if $export_bin; then echo "empty list must fail" >&2; exit 1; fi
    test "$(git -C /build/remote.git rev-list --count main)" = 2

    # Restore imports only the company whose slug is absent.
    echo '[{"id":"alpha","name":"Alpha"}]' > $FAKE_STATE/companies
    ${svc.paperclip-archive-restore.Service.ExecStart}
    test "$(wc -l < $FAKE_STATE/imports)" = 1
    grep -q '/build/pinned/beta --target new --collision skip --yes' $FAKE_STATE/imports

    # The token path, never its contents, is what git config records.
    grep -q credential /build/checkout/.git/config
    touch $out
  ''
