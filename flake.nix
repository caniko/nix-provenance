{
  description = "Declarative identity & OIDC provisioning for NixOS, Kanidm, and Rauthy (monorepo)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    rauthy-src = {
      # Canonical local consumer worktree for stacked PR2 validation. Keep this
      # path on the consumer-ready branch rather than a detached HEAD.
      url = "path:/data/nvme0/can/Projects/rauthy-pr2";
      flake = false;
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
    crane,
    rauthy-src,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        stalwartOverlay = import ./nix/overlays/stalwart-016.nix;
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (import rust-overlay)
            stalwartOverlay
          ];
        };
        inherit (pkgs) lib;
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = ["rustfmt" "clippy"];
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
        src = craneLib.cleanCargoSource ./.;

        crates = import ./nix/packages.nix {
          inherit lib;
          inherit craneLib src;
        };
        packages =
          crates.packages
          // {
            docs = docsPackage;
            site = docsPackage;
            rauthy-vikunja-groups = pkgs.rauthy.overrideAttrs (old: {
              src = rauthy-src;
              cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
                src = rauthy-src;
                hash = "sha256-wNLKdfFVfXUc5BhX9McitliEnc1WKytgo53LiAQHlqA=";
              };
              npmDeps = pkgs.fetchNpmDeps {
                src = "${rauthy-src}/frontend";
                hash = "sha256-w3x+dUfmJ4H82wX87C3UHEJ5Ls4v6lsn7kKOxvRJY8g=";
              };
              nativeBuildInputs =
                (builtins.filter
                  (input: !(lib.hasPrefix "wasm-bindgen-cli-" (input.name or "")))
                  (old.nativeBuildInputs or []))
                ++ [pkgs.wasm-bindgen-cli];
              preBuild = ''
                pushd src/wasm-modules
                wasm-pack build -d ../../frontend/src/wasm/spow --no-pack --mode no-install --out-name spow --features spow
                wasm-pack build -d ../../frontend/src/wasm/md --no-pack --mode no-install --out-name md --features md
                popd
                pushd "$npmRoot"
                npm run build
                popd
              '';
            });
            inherit (pkgs) stalwart stalwart-cli;
          };

        docsPackage = pkgs.stdenv.mkDerivation {
          pname = "nix-provenance-docs";
          version = "unstable";
          src = builtins.path {
            name = "nix-provenance-docs-src";
            path = ./docs;
          };
          nativeBuildInputs = [pkgs.mdbook];
          phases = ["buildPhase" "installPhase"];
          buildPhase = ''
            cp -r --no-preserve=mode "$src" docs
            chmod -R u+w docs
            mdbook build docs
          '';
          installPhase = ''
            cp -r docs/book "$out"
          '';
        };
      in {
        inherit packages;

        checks = import ./nix/checks.nix {
          inherit pkgs nixpkgs craneLib src self system;
          inherit lib;
          inherit packages;
          inherit (crates) args cargoArtifacts;
          docs = docsPackage;
        };

        devShells.default = craneLib.devShell {
          packages = [pkgs.cargo-nextest pkgs.rust-analyzer pkgs.jq pkgs.alejandra pkgs.mdbook];
        };

        formatter = pkgs.alejandra;
      }
    )
    // {
      # System-independent pure-Nix helpers (see nix/lib/default.nix).
      lib = import ./nix/lib/default.nix {inherit (nixpkgs) lib;};

      # One named NixOS module per tenant. Rauthy consumers should import both
      # `rauthyServer` (the server service) and `rauthy` (the provisioner)
      # until nixpkgs ships `services.rauthy` on the supported branch.
      nixosModules = {
        immich = import ./nix/modules/service-oidc/immich.nix {inherit self;};
        rauthyServer = import ./nix/modules/idp/rauthy-server.nix;
        rauthy = import ./nix/modules/idp/rauthy.nix {inherit self;};
        vikunja = import ./nix/modules/config-only/vikunja.nix {inherit self;};
        vikunjaProvision = import ./nix/modules/service-oidc/vikunja.nix {inherit self;};
        forgejo = import ./nix/modules/service-oidc/forgejo.nix {inherit self;};
        stalwart = import ./nix/modules/ldap/stalwart.nix {inherit self;};
        stalwart016 = import ./nix/modules/mail/stalwart016.nix {inherit self;};
        kanidmCredentials = import ./nix/modules/kanidm/credentials.nix {inherit self;};
        externalApp = import ./nix/modules/adapter/external-app.nix {inherit self;};
        default = {imports = [self.nixosModules.rauthy];};
      };

      overlays.default = final: _prev: let
        craneLib = crane.mkLib final;
        src = craneLib.cleanCargoSource ./.;
        crates = import ./nix/packages.nix {
          inherit (final) lib;
          inherit craneLib src;
        };
        nativeWasmToolPath = final.lib.makeBinPath [
          final.pkgsBuildBuild.cargo
          final.pkgsBuildBuild.rustc
          final.pkgsBuildBuild.wasm-bindgen-cli
          final.pkgsBuildBuild.wasm-pack
        ];
        rauthyVikunjaGroups = final.rauthy.overrideAttrs (old: {
          src = rauthy-src;
          cargoDeps = final.rustPlatform.fetchCargoVendor {
            src = rauthy-src;
            hash = "sha256-wNLKdfFVfXUc5BhX9McitliEnc1WKytgo53LiAQHlqA=";
          };
          npmDeps = final.fetchNpmDeps {
            src = "${rauthy-src}/frontend";
            hash = "sha256-w3x+dUfmJ4H82wX87C3UHEJ5Ls4v6lsn7kKOxvRJY8g=";
          };
          nativeBuildInputs =
            (builtins.filter
              (input: !(final.lib.hasPrefix "wasm-bindgen-cli-" (input.name or "")))
              (old.nativeBuildInputs or []))
            ++ [final.wasm-bindgen-cli];
          preBuild = ''
            pushd src/wasm-modules
            (
              export PATH=${nativeWasmToolPath}:$PATH
              export CARGO=${final.pkgsBuildBuild.cargo}/bin/cargo
              export RUSTC=${final.pkgsBuildBuild.rustc}/bin/rustc
              unset CARGO_BUILD_TARGET
              wasm-pack build -d ../../frontend/src/wasm/spow --no-pack --mode no-install --out-name spow --features spow
              wasm-pack build -d ../../frontend/src/wasm/md --no-pack --mode no-install --out-name md --features md
            )
            popd
            pushd "$npmRoot"
            npm run build
            popd
          '';
        });
      in
        {
          inherit (crates.packages) identity-cli immich-provision rauthy-provision rauthy-state-render vikunja-provision;
          rauthy-vikunja-groups = rauthyVikunjaGroups;
        }
        // (import ./nix/overlays/stalwart-016.nix final _prev);

      overlays.stalwart016 = import ./nix/overlays/stalwart-016.nix;
    };
}
