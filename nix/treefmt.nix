{rustfmtPackage}: {...}: {
  projectRootFile = "flake.nix";
  programs.alejandra.enable = true;
  programs.rustfmt = {
    enable = true;
    edition = "2024";
    package = rustfmtPackage;
  };
}
