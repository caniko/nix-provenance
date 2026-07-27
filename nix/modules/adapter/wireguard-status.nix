{
  config,
  lib,
  ...
}: let
  cfg = config.services.nix-provenance.wireguardStatus;
in {
  options.services.nix-provenance.wireguardStatus = {
    enable = lib.mkEnableOption "the declarative WireGuard status exporter";

    interfaces = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "WireGuard interfaces to expose; an empty list exposes all interfaces.";
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Address on which the local status metrics endpoint listens.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 9586;
      description = "Port for the local WireGuard status metrics endpoint.";
    };

    withRemoteIp = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Expose each peer's remote endpoint in the metrics.";
    };
  };

  config = lib.mkIf cfg.enable {
    services.prometheus.exporters.wireguard = {
      enable = true;
      inherit (cfg) interfaces listenAddress port withRemoteIp;
    };

    environment.etc."nix-provenance/wireguard-status.json".text = builtins.toJSON {
      schemaVersion = 1;
      metricsUrl = "http://${cfg.listenAddress}:${toString cfg.port}/metrics";
      inherit (cfg) interfaces;
    };
  };
}
