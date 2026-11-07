{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.nix-provenance.claudeCode;
  helper = self.packages.${pkgs.stdenv.hostPlatform.system}.provenance-oauth;
  wrapped = pkgs.symlinkJoin {
    name = "claude-code-with-credential";
    inherit (cfg.package) version;
    paths = [cfg.package];
    nativeBuildInputs = [pkgs.makeBinaryWrapper];
    postBuild = ''
      rm "$out/bin/claude"
      makeBinaryWrapper ${helper}/bin/provenance-claude "$out/bin/claude" \
        --add-flag ${lib.escapeShellArg cfg.tokenFile} \
        --add-flag ${lib.escapeShellArg (lib.getExe cfg.package)}
    '';
    meta.mainProgram = "claude";
  };
in {
  options.nix-provenance.claudeCode = {
    tokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Private runtime file containing a native claude setup-token token. Null leaves native login unchanged.";
    };
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.claude-code;
      description = "Native Claude Code package, before credential wrapping.";
    };
  };
  config = lib.mkIf (cfg.tokenFile != null) {
    assertions = [
      {
        assertion =
          lib.hasPrefix "/" cfg.tokenFile
          && !lib.hasPrefix "/nix/store/" cfg.tokenFile
          && cfg.tokenFile != "/nix/store"
          && !lib.hasInfix "/../" "${cfg.tokenFile}/"
          && !lib.hasInfix "/./" "${cfg.tokenFile}/"
          && !lib.hasInfix "%" cfg.tokenFile
          && builtins.match ".*[[:cntrl:]].*" cfg.tokenFile == null;
        message = "nix-provenance.claudeCode.tokenFile must be a literal absolute runtime path outside the Nix store.";
      }
      {
        assertion = lib.versionAtLeast (cfg.package.version or "0") "2.1.311";
        message = "Managed Claude credentials require the verified native descriptor interface in Claude Code 2.1.311 or later.";
      }
    ];
    home.packages = [wrapped];
  };
}
