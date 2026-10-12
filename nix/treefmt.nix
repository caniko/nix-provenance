{
  harbor-rs,
  rustfmtPackage,
}: {...}: {
  imports = [
    harbor-rs.inputs.harbor-meta.treefmtModules.nix
    harbor-rs.inputs.harbor-meta.treefmtModules.toml
    harbor-rs.treefmtModules.rust
  ];
  projectRootFile = "flake.nix";
  programs.rustfmt = {
    edition = "2024";
    package = rustfmtPackage;
  };
}
