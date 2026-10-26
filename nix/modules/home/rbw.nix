{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.nix-provenance.rbw;
  manifest = pkgs.writeText "provenance-rbw.json" (builtins.toJSON {
    inherit (cfg) stateDirectory;
    legacyCacheDirectory = config.xdg.cacheHome;
    legacyDataDirectory = config.xdg.dataHome;
    rbwBinary = lib.getExe cfg.package;
    agentBinary = lib.getExe' cfg.package "rbw-agent";
  });
  managedPackage =
    pkgs.runCommand "rbw-provenance-${cfg.package.version or "unversioned"}" {
      nativeBuildInputs = [pkgs.makeBinaryWrapper];
      meta = (cfg.package.meta or {}) // {mainProgram = "rbw";};
      passthru = {
        inherit manifest;
        unwrapped = cfg.package;
      };
    } ''
      mkdir -p $out/bin
      makeBinaryWrapper ${lib.getExe cfg.helperPackage} $out/bin/rbw \
        --add-flags '--config ${manifest} exec --program rbw --'
      makeBinaryWrapper ${lib.getExe cfg.helperPackage} $out/bin/rbw-agent \
        --add-flags '--config ${manifest} exec --program agent --'
      if test -d ${cfg.package}/share; then
        ln -s ${cfg.package}/share $out/share
      fi
    '';
in {
  options.nix-provenance.rbw = {
    enable = mkEnableOption "durable rbw login state managed by nix-provenance";
    package = mkOption {
      type = types.package;
      default = pkgs.rbw;
      defaultText = lib.literalMD "pkgs.rbw";
      description = "Unwrapped rbw package. rbw continues to own authentication and refresh.";
    };
    helperPackage = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.provenance-rbw;
      description = "The durable-state migration helper.";
    };
    stateDirectory = mkOption {
      type = types.str;
      default = "${config.xdg.stateHome}/nix-provenance/rbw";
      defaultText = lib.literalMD ''"''${config.xdg.stateHome}/nix-provenance/rbw"'';
      description = "Private durable client-state directory, on the same filesystem as legacy rbw state. Include this directory in credential-state backups.";
    };
    managedPackage = mkOption {
      type = types.package;
      readOnly = true;
      default = managedPackage;
      description = "Client and agent wrappers bound to the public state manifest.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = pkgs.stdenv.hostPlatform.isLinux;
        message = "nix-provenance.rbw currently supports Linux only.";
      }
      {
        assertion = lib.hasPrefix "/" cfg.stateDirectory && !(lib.hasPrefix "/nix/store/" cfg.stateDirectory);
        message = "nix-provenance.rbw.stateDirectory must be an absolute mutable path outside the Nix store.";
      }
    ];
    programs.rbw = {
      enable = lib.mkDefault true;
      package = managedPackage;
    };
    home.packages = [cfg.helperPackage];
    xdg.configFile."nix-provenance/rbw.json".source = manifest;
    systemd.user.services.nix-provenance-rbw-state = {
      Unit.Description = "Preserve rbw login state in durable private storage";
      Service = {
        Type = "oneshot";
        ExecStart = "${lib.getExe cfg.helperPackage} --config ${manifest} prepare";
        TimeoutStartSec = "20s";
        UMask = "0077";
      };
      Install.WantedBy = ["default.target"];
    };
  };
}
