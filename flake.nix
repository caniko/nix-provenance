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
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
    crane,
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

      # One named NixOS module per tenant. `default` is a back-compat alias for
      # the live canix consumer (rauthy); it is dropped once canix imports
      # `nixosModules.rauthy` explicitly.
      nixosModules = {
        immich = import ./nix/modules/service-oidc/immich.nix {inherit self;};
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

      overlays.default = final: _prev:
        {
          identity-cli = self.packages.${final.stdenv.hostPlatform.system}.identity-cli;
          immich-provision = self.packages.${final.stdenv.hostPlatform.system}.immich-provision;
          rauthy-provision = self.packages.${final.stdenv.hostPlatform.system}.rauthy-provision;
          vikunja-provision = self.packages.${final.stdenv.hostPlatform.system}.vikunja-provision;
        }
        // (import ./nix/overlays/stalwart-016.nix final _prev);

      overlays.stalwart016 = import ./nix/overlays/stalwart-016.nix;
    };
}
