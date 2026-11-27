{pkgs}: let
  inherit (pkgs) lib;

  self = {
    packages.${pkgs.stdenv.hostPlatform.system}.provenance-t3-enroll = pkgs.hello;
  };

  peer = {
    environmentId = "env_atlas";
    access = "approval-required";
    urls = ["https://atlas.example.ts.net"];
    pairingCodeFile = "/run/credentials/provenance-t3-enroll.service/atlas-code";
    desktop = {
      bearer = {
        httpBaseUrl = "https://atlas.example.ts.net/";
        wsBaseUrl = "wss://atlas.example.ts.net/";
        credentialFile = "/run/credentials/provenance-t3-enroll.service/atlas-token";
      };
      ssh = {
        alias = "atlas";
        hostname = "atlas.example";
        username = "alice";
        port = 22;
        credentialFile = "/run/credentials/provenance-t3-enroll.service/atlas-ssh-token";
      };
    };
  };

  base = overrides:
    (lib.evalModules {
      specialArgs = {inherit pkgs;};
      modules = [
        (import ../adapter/t3-enrollment.nix {inherit self;})
        ({lib, ...}: {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.attrs;
              default = [];
            };
            users.users = lib.mkOption {
              type = lib.types.attrsOf lib.types.attrs;
              default = {};
            };
            environment.systemPackages = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = [];
            };
          };
          config = {
            users.users.alice = {isNormalUser = true;};
            services.nix-provenance.t3Enrollment = {
              enable = true;
              user = "alice";
              baseDir = "/var/lib/t3-enroll";
              t3 = "/run/current-system/sw/bin/t3";
              desktop = "/run/current-system/sw/bin/t3-code";
              peers = [peer];
            };
          };
        })
        overrides
      ];
    }).config;

  ownerPeer = {
    environmentId = "env_atlas";
    access = "approval-required";
    urls = ["https://atlas.example.ts.net"];
    owner = {
      host = "atlas";
      t3 = "/run/current-system/sw/bin/t3";
      baseDir = "/var/lib/t3-owner";
    };
    desktop = {
      bearer = {
        httpBaseUrl = "https://atlas.example.ts.net/";
        wsBaseUrl = "wss://atlas.example.ts.net/";
      };
    };
  };

  enabled = base {};
  valid = config: lib.all (assertion: assertion.assertion) config.assertions;
  bad = base ({lib, ...}: {
    services.nix-provenance.t3Enrollment.peers = lib.mkForce [
      (peer
        // {
          pairingCodeFile = "/nix/store/not-a-secret";
        })
    ];
  });
  badUsername = base ({lib, ...}: {
    services.nix-provenance.t3Enrollment.peers = lib.mkForce [
      (peer
        // {
          desktop =
            peer.desktop
            // {
              ssh = peer.desktop.ssh // {username = "mallory";};
            };
        })
    ];
  });
  ownerEnabled = base ({lib, ...}: {
    services.nix-provenance.t3Enrollment.peers = lib.mkForce [ownerPeer];
  });
  badBase = base ({lib, ...}: {
    services.nix-provenance.t3Enrollment.baseDir = lib.mkForce "/nix/store/t3-state";
  });
  badOwnerT3 = base ({lib, ...}: {
    services.nix-provenance.t3Enrollment.peers = lib.mkForce [
      (ownerPeer
        // {
          owner = ownerPeer.owner // {t3 = "relative/t3";};
        })
    ];
  });
  badOwnerBase = base ({lib, ...}: {
    services.nix-provenance.t3Enrollment.peers = lib.mkForce [
      (ownerPeer
        // {
          owner = ownerPeer.owner // {baseDir = "/nix/store/t3-owner";};
        })
    ];
  });
  badTrailingBase = base ({lib, ...}: {
    services.nix-provenance.t3Enrollment.baseDir = lib.mkForce "/var/lib/t3-enroll/.";
  });
  badTrailingOwner = base ({lib, ...}: {
    services.nix-provenance.t3Enrollment.peers = lib.mkForce [
      (ownerPeer
        // {
          owner = ownerPeer.owner // {baseDir = "/var/lib/t3-owner/..";};
        })
    ];
  });
in
  assert valid enabled;
  assert !(valid bad);
  assert !(valid badUsername);
  assert valid ownerEnabled;
  assert !(valid badBase) && !(valid badOwnerT3) && !(valid badOwnerBase);
  assert !(valid badTrailingBase) && !(valid badTrailingOwner);
  assert builtins.elem enabled.services.nix-provenance.t3Enrollment.package enabled.environment.systemPackages;
  assert enabled.services.nix-provenance.t3Enrollment.manifest.user == "alice";
  assert enabled.services.nix-provenance.t3Enrollment.manifest.baseDir == "/var/lib/t3-enroll";
  assert builtins.length enabled.services.nix-provenance.t3Enrollment.manifest.peers == 1;
  assert builtins.length ownerEnabled.services.nix-provenance.t3Enrollment.manifest.peers == 1; {
    pass = true;
    manifest = builtins.toJSON enabled.services.nix-provenance.t3Enrollment.manifest;
    ownerManifest = builtins.toJSON ownerEnabled.services.nix-provenance.t3Enrollment.manifest;
    manifestFile = enabled.services.nix-provenance.t3Enrollment.manifestFile;
  }
