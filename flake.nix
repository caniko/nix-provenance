{
  description = "Declarative identity & OIDC provisioning for NixOS, Kanidm, and Rauthy (monorepo)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rs-harbor = {
      url = "git+https://codeberg.org/caniko/rs-harbor.git?ref=trunk&rev=9bfa8bdb0ecb22d7bc11448665f7fbaebae7a759";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # rust-overlay and crane are re-exported by rs-harbor; follow them through.
    rust-overlay.follows = "rs-harbor/rust-overlay";
    crane.follows = "rs-harbor/crane";
    rauthy-src = {
      # PR2 review-fix source: feat(bootstrap) generated API key tokens.
      # Keep this commit-pinned because the original branch was deleted.
      url = "git+https://github.com/caniko/rauthy?rev=bdcabc50862c73f215506805980d486889a3f3d3";
      flake = false;
    };
    plinth = {
      url = "git+https://codeberg.org/caniko/plinth.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    forgejo-cli = {
      # Keep the CLI as a separate capability owner; nix-provenance only
      # exposes its package and Home Manager integration.
      url = "git+https://codeberg.org/caniko/forgejo-cli.git?ref=main";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rs-harbor,
    rust-overlay,
    crane,
    rauthy-src,
    plinth,
    forgejo-cli,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (import rust-overlay)
          ];
        };
        inherit (pkgs) lib;
        toolchain = rs-harbor.lib.mkToolchain {
          inherit pkgs;
          channel = "stable";
          extensions = ["rustfmt" "clippy"];
          crossTargets = [];
        };
        inherit (toolchain) rustToolchain craneLib;
        cross = rs-harbor.lib.mkCross {inherit pkgs system;};
        src = craneLib.cleanCargoSource ./.;

        crates = import ./nix/packages.nix {
          inherit pkgs;
          inherit lib;
          inherit craneLib src;
        };
        identityCrossPackageSet =
          if system == "x86_64-linux"
          then
            rs-harbor.lib.mkCrossPackages {
              inherit pkgs craneLib cross;
              pname = "identity-cli";
              commonArgs = crates.args.identity-cli;
              targets = ["aarch64-linux"];
              toolchainArgs = {
                channel = "stable";
                extensions = ["rust-src" "rustfmt" "clippy"];
              };
            }
          else {};
        packages =
          crates.packages
          // lib.optionalAttrs (system == "x86_64-linux") {
            "identity-cli-aarch64-linux" = identityCrossPackageSet."identity-cli-aarch64-linux";
          }
          // {
            docs = docsPackage;
            site = pkgs.runCommand "nix-provenance-site" {} ''
              mkdir -p $out
              cp -rL --no-preserve=mode ${docsPackage}/. $out/
              printf '%s\n' "nix-provenance.tartanoglu.com" > $out/.domains
            '';
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
            forgejo-cli = forgejo-cli.packages.${system}.forgejo-cli;
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

        atticAdapter = rs-harbor.lib.mkAdapter {
          attic = {
            endpoint = "https://attic.candee.baby";
            cache = "canix";
          };
        };
      in {
        inherit packages;

        checks = import ./nix/checks.nix {
          inherit pkgs nixpkgs craneLib src self system;
          inherit lib;
          inherit packages;
          inherit (crates) args cargoArtifacts;
          inherit identityCrossPackageSet;
          docs = docsPackage;
        };

        devShells.default = rs-harbor.lib.mkDevShell {
          inherit pkgs craneLib cross;
          packages = [pkgs.cargo-nextest pkgs.rust-analyzer pkgs.jq pkgs.alejandra pkgs.mdbook];
          cargoConfig = rs-harbor.lib.mkCargoConfig {
            inherit pkgs;
            channel = "stable";
          };
          enableOsxcrossEnv = false;
          enableWindowsEnv = false;
        };

        apps.push-cache = rs-harbor.lib.mkAtticPush {
          inherit pkgs;
          adapter = atticAdapter;
          paths = builtins.attrValues packages;
        };

        apps.deploy-pages = plinth.lib.${system}.mkDeployPagesApp {
          domain = "nix-provenance.tartanoglu.com";
        };

        formatter = pkgs.alejandra;
      }
    )
    // {
      # System-independent pure-Nix helpers (see nix/lib/default.nix).
      lib = import ./nix/lib/default.nix {
        lib = nixpkgs.lib;
        inherit self;
      };

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
        wireguardStatus = import ./nix/modules/adapter/wireguard-status.nix;
        tuwunel = import ./nix/modules/config-only/tuwunel.nix {inherit self;};
        default = {imports = [self.nixosModules.rauthy];};
      };

      homeModules = {
        rustdesk-client = import ./nix/modules/home/rustdesk-client.nix;
        fj = import ./nix/modules/home/fj.nix {inherit self;};
        stalwart-oauth-bootstrap = import ./nix/modules/home/stalwart-oauth-bootstrap.nix {inherit self;};
      };

      # Crossbow consumers build this package on Atlas and select it through
      # the namespaced crossPackages interface rather than falling back to a
      # native package derivation with a target linker.
      crossPackages.x86_64-linux.aarch64-linux.identity-cli =
        self.packages.x86_64-linux."identity-cli-aarch64-linux";

      overlays.default = final: _prev: let
        craneLib = crane.mkLib final;
        src = craneLib.cleanCargoSource ./.;
        crates = import ./nix/packages.nix {
          pkgs = final;
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
      in {
        inherit (crates.packages) identity-cli immich-provision kanidm-state-render rauthy-provision rauthy-state-render vikunja-provision forgejo-provision stalwart016-provision tuwunel-provision;
        forgejo-cli = forgejo-cli.packages.${final.stdenv.hostPlatform.system}.forgejo-cli;
        rauthy-vikunja-groups = rauthyVikunjaGroups;
      };
    };
}
