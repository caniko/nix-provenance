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
        pkgs = import nixpkgs {
          inherit system;
          overlays = [(import rust-overlay)];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = ["rustfmt" "clippy"];
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
        src = craneLib.cleanCargoSource ./.;

        crates = import ./nix/packages.nix {
          inherit (pkgs) lib;
          inherit craneLib src;
        };
      in {
        packages = crates.packages;

        checks = import ./nix/checks.nix {
          inherit pkgs nixpkgs craneLib src self system;
          inherit (pkgs) lib;
          inherit (crates) packages args cargoArtifacts;
        };

        devShells.default = craneLib.devShell {
          packages = [pkgs.cargo-nextest pkgs.rust-analyzer pkgs.jq pkgs.alejandra];
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
        default = {imports = [self.nixosModules.rauthy];};
      };

      overlays.default = final: _prev: {
        immich-provision = self.packages.${final.stdenv.hostPlatform.system}.immich-provision;
        rauthy-provision = self.packages.${final.stdenv.hostPlatform.system}.rauthy-provision;
      };
    };
}
