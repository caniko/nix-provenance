{
  pkgs,
  self,
}: let
  evaluation = import "${pkgs.path}/nixos/lib/eval-config.nix" {
    system = pkgs.stdenv.hostPlatform.system;
    specialArgs = {inherit self;};
    modules = [
      ./stalwart016-eval.nix
      {
        services.stalwart016.datastore.postgresql = {
          host = "/run/postgresql";
          passwordFile = pkgs.lib.mkForce null;
        };
      }
    ];
  };
  inherit (evaluation.config) systemd;
  execStartPre = builtins.concatStringsSep " " systemd.services.stalwart.serviceConfig.ExecStartPre;
  bootstrap = evaluation.config.environment.etc."stalwart016/config.json".source;
in
  assert !(pkgs.lib.hasInfix "--pg-password-file" execStartPre);
  assert pkgs.lib.hasInfix "--recovery-password-file" execStartPre;
    pkgs.runCommand "stalwart016-peer-eval" {nativeBuildInputs = [pkgs.jq];} ''
      jq -e '.authSecret == {"@type":"None"} and .host == "/run/postgresql"' ${bootstrap}
      touch "$out"
    ''
