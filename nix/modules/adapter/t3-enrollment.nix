{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.nix-provenance.t3Enrollment;

  # Secret files stay in private runtime storage. Paths may be declared here;
  # their contents never enter the Nix store or this manifest.
  privatePath = value:
    lib.isString value
    && lib.hasPrefix "/" value
    && value != "/"
    && !(value == "/nix/store" || lib.hasPrefix "/nix/store/" value)
    && !lib.hasInfix "//" value
    && !lib.hasInfix "/./" value
    && !lib.hasInfix "/../" value
    && !(lib.hasSuffix "/." value)
    && !(lib.hasSuffix "/.." value)
    && builtins.match ".*[[:cntrl:]].*" value == null
    && !(lib.any (char: lib.hasInfix char value) ["%" ":" "\\"]);

  absolutePath = value:
    lib.isString value
    && lib.hasPrefix "/" value
    && value != "/"
    && !lib.hasInfix "//" value
    && !lib.hasInfix "/./" value
    && !lib.hasInfix "/../" value
    && !(lib.hasSuffix "/." value)
    && !(lib.hasSuffix "/.." value)
    && builtins.match ".*[[:cntrl:]].*" value == null;

  inNixStore = value:
    value == "/nix/store" || lib.hasPrefix "/nix/store/" value;

  commandPath = value:
    lib.isString value
    && value != ""
    && builtins.match ".*[[:cntrl:]].*" value == null
    && (
      if lib.hasInfix "/" value
      then
        lib.hasPrefix "/" value
        && !lib.hasInfix "//" value
        && !lib.hasInfix "/./" value
        && !lib.hasInfix "/../" value
        && !(lib.hasSuffix "/." value)
        && !(lib.hasSuffix "/.." value)
      else builtins.match "[A-Za-z0-9._+-]+" value != null
    );

  accessType = lib.types.enum [
    "read-only"
    "approval-required"
    "auto-accept-edits"
    "auto"
    "full-access"
  ];

  bearerType = lib.types.submodule {
    options = {
      httpBaseUrl = lib.mkOption {
        type = lib.types.str;
        description = "T3-normalized http(s) endpoint, for example `https://atlas.example.ts.net/`.";
      };
      wsBaseUrl = lib.mkOption {
        type = lib.types.str;
        description = "Matching ws(s) endpoint, for example `wss://atlas.example.ts.net/`.";
      };
      credentialFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Manual-mode private runtime bearer-token file. Forbidden with an owner executor.";
      };
    };
  };

  sshType = lib.types.submodule {
    options = {
      alias = lib.mkOption {
        type = lib.types.str;
        description = "SSH alias stored in the native desktop connection.";
      };
      hostname = lib.mkOption {
        type = lib.types.str;
        description = "SSH host stored in the native desktop connection.";
      };
      username = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "SSH username, or null for the OpenSSH default.";
      };
      port = lib.mkOption {
        type = lib.types.nullOr lib.types.port;
        default = null;
        description = "SSH port, or null for the OpenSSH default.";
      };
      credentialFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Manual-mode private runtime bearer credential. Forbidden with an owner executor.";
      };
    };
  };

  desktopType = lib.types.submodule {
    options = {
      bearer = lib.mkOption {
        type = lib.types.nullOr bearerType;
        default = null;
        description = "Direct bearer connection imported into the desktop keyring.";
      };
      ssh = lib.mkOption {
        type = lib.types.nullOr sshType;
        default = null;
        description = "SSH connection imported into the desktop keyring; OpenSSH owns host-key trust.";
      };
    };
  };

  ownerType = lib.types.submodule {
    options = {
      host = lib.mkOption {
        type = lib.types.str;
        description = "Local hostname/loopback or an already-trusted SSH alias; OpenSSH owns host-key trust.";
      };
      t3 = lib.mkOption {
        type = lib.types.str;
        description = "Explicit absolute T3 CLI path on the target.";
      };
      baseDir = lib.mkOption {
        type = lib.types.str;
        description = "Explicit absolute T3 data directory on the target.";
      };
    };
  };

  peerType = lib.types.submodule {
    options = {
      environmentId = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Expected T3 environment id. Optional with an owner executor; a declared value is cross-checked.";
      };
      access = lib.mkOption {
        type = accessType;
        description = "Explicit T3 MCP client access granted to this environment.";
      };
      urls = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Peer origins tried in order. Plain http is accepted only for loopback or Tailscale.";
      };
      owner = lib.mkOption {
        type = lib.types.nullOr ownerType;
        default = null;
        description = "Optional same-owner executor. When set, pairing codes and desktop tokens are minted natively.";
      };
      pairingCodeFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Private one-time `t3 pair` code file, read once only when a link must be made.";
      };
      desktop = lib.mkOption {
        type = lib.types.nullOr desktopType;
        default = null;
        description = "Native desktop connections to import for this verified peer.";
      };
    };
  };

  secretPaths =
    lib.concatMap (
      peer:
        lib.optional (peer.pairingCodeFile != null) peer.pairingCodeFile
        ++ lib.optionals (peer.desktop != null) (
          lib.optional (peer.desktop.bearer != null && peer.desktop.bearer.credentialFile != null) peer.desktop.bearer.credentialFile
          ++ lib.optional (peer.desktop.ssh != null && peer.desktop.ssh.credentialFile != null) peer.desktop.ssh.credentialFile
        )
    )
    cfg.peers;

  desktopUsed = lib.any (peer: peer.desktop != null) cfg.peers;

  manifest = {
    user = cfg.user;
    inherit (cfg) baseDir t3 desktop;
    peers =
      map (peer: {
        inherit (peer) environmentId access urls pairingCodeFile;
        owner =
          if peer.owner == null
          then null
          else {
            inherit (peer.owner) host t3 baseDir;
          };
        desktop =
          if peer.desktop == null
          then null
          else {
            bearer =
              if peer.desktop.bearer == null
              then null
              else {
                inherit (peer.desktop.bearer) httpBaseUrl wsBaseUrl credentialFile;
              };
            ssh =
              if peer.desktop.ssh == null
              then null
              else {
                inherit (peer.desktop.ssh) alias hostname username port credentialFile;
              };
          };
      })
      cfg.peers;
  };
in {
  options.services.nix-provenance.t3Enrollment = {
    enable = lib.mkEnableOption "native T3 Code environment enrollment";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.provenance-t3-enroll;
      defaultText = lib.literalMD "`self.packages.<system>.provenance-t3-enroll`";
      description = "Native enrollment helper.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      description = "Existing Unix user whose own T3 environments are enrolled.";
    };

    baseDir = lib.mkOption {
      type = lib.types.str;
      description = "Explicit local T3 data directory used for every list/link. Must already exist, owned by user, not group/other-writable.";
    };

    t3 = lib.mkOption {
      type = lib.types.str;
      default = "t3";
      description = "T3 CLI command or absolute path, normally the pinned T3 build with native environment commands.";
    };

    desktop = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "T3 Code desktop command or absolute path; required when a peer declares desktop routes.";
    };

    peers = lib.mkOption {
      type = lib.types.listOf peerType;
      default = [];
      description = "Own-user T3 environments to enroll. Scheduling and service ownership remain consumer policy.";
    };

    manifest = lib.mkOption {
      type = lib.types.attrs;
      readOnly = true;
      description = "Rendered non-secret enrollment manifest.";
    };

    manifestFile = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      description = "Rendered non-secret enrollment manifest. Pass it to `provenance-t3-enroll --manifest`.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.hasAttr cfg.user (config.users.users or {});
        message = "nix-provenance.t3Enrollment may only enroll an existing Unix user.";
      }
      {
        assertion = absolutePath cfg.baseDir && !(inNixStore cfg.baseDir);
        message = "nix-provenance.t3Enrollment.baseDir must be an explicit absolute runtime path outside the Nix store.";
      }
      {
        assertion =
          lib.all (
            peer:
              peer.owner
              == null
              || (absolutePath peer.owner.t3 && absolutePath peer.owner.baseDir && !(inNixStore peer.owner.baseDir))
          )
          cfg.peers;
        message = "nix-provenance.t3Enrollment owner t3/baseDir must be explicit absolute paths; baseDir must stay outside the Nix store.";
      }
      {
        assertion = commandPath cfg.t3;
        message = "nix-provenance.t3Enrollment.t3 must be an absolute path or a bare command name.";
      }
      {
        assertion = cfg.desktop == null || commandPath cfg.desktop;
        message = "nix-provenance.t3Enrollment.desktop must be null, an absolute path, or a bare command name.";
      }
      {
        assertion = lib.all privatePath secretPaths;
        message = "nix-provenance.t3Enrollment secret files must be literal private runtime paths, never the Nix store.";
      }
      {
        assertion = !desktopUsed || cfg.desktop != null;
        message = "nix-provenance.t3Enrollment.desktop is required when a peer declares desktop routes.";
      }
      {
        assertion = lib.all (peer: peer.urls != []) cfg.peers;
        message = "nix-provenance.t3Enrollment peers must declare at least one URL.";
      }
      {
        assertion = lib.all (peer: peer.desktop == null || peer.desktop.bearer != null || peer.desktop.ssh != null) cfg.peers;
        message = "nix-provenance.t3Enrollment desktop routes must declare a bearer or SSH connection.";
      }
      {
        assertion = lib.all (peer: peer.desktop == null || peer.desktop.ssh == null || peer.desktop.ssh.username == null || peer.desktop.ssh.username == cfg.user) cfg.peers;
        message = "nix-provenance.t3Enrollment SSH usernames must be the enrollment user or null.";
      }
      {
        assertion = lib.all (peer: peer.owner != null || peer.environmentId != null) cfg.peers;
        message = "nix-provenance.t3Enrollment peers without an owner executor must declare environmentId.";
      }
      {
        assertion = lib.all (peer: peer.owner == null || peer.pairingCodeFile == null) cfg.peers;
        message = "nix-provenance.t3Enrollment cannot combine an owner executor with a pairing code file.";
      }
      {
        assertion =
          lib.all (
            peer:
              peer.owner
              == null
              || peer.desktop == null
              || (
                (peer.desktop.bearer == null || peer.desktop.bearer.credentialFile == null)
                && (peer.desktop.ssh == null || peer.desktop.ssh.credentialFile == null)
              )
          )
          cfg.peers;
        message = "nix-provenance.t3Enrollment cannot combine an owner executor with desktop credential files.";
      }
      {
        assertion =
          lib.all (
            peer:
              peer.owner
              != null
              || peer.desktop == null
              || (
                (peer.desktop.bearer == null || peer.desktop.bearer.credentialFile != null)
                && (peer.desktop.ssh == null || peer.desktop.ssh.credentialFile != null)
              )
          )
          cfg.peers;
        message = "nix-provenance.t3Enrollment manual desktop routes require credentialFile.";
      }
      {
        assertion = let
          ids = builtins.filter (id: id != null) (map (peer: peer.environmentId) cfg.peers);
        in
          builtins.length ids == builtins.length (lib.unique ids);
        message = "nix-provenance.t3Enrollment environment ids must be unique.";
      }
    ];

    environment.systemPackages = [cfg.package];

    services.nix-provenance.t3Enrollment.manifest = manifest;

    services.nix-provenance.t3Enrollment.manifestFile =
      pkgs.writeText "nix-provenance-t3-enrollment.json" (builtins.toJSON manifest);
  };
}
