# Module-eval smoke test for Rauthy's generated bootstrap API-key flow.
{
  lib,
  pkgs,
  self,
  ...
}: {
  imports = [
    self.nixosModules.rauthyServer
    self.nixosModules.rauthy
  ];

  config = {
    services.rauthy = {
      enable = true;
      package = pkgs.writeShellScriptBin "rauthy" ''
        exit 0
      '';
      settings.server = {
        scheme = "http";
        listen_address = "127.0.0.1";
        port_http = 8080;
      };
    };

    services.rauthy.provision = {
      enable = true;
      package = pkgs.writeShellScriptBin "rauthy-provision" ''
        exit 0
      '';
      endpoint = "http://127.0.0.1:8080";
      apiKeyName = "rauthy-provision";
      transientApiKey.enable = true;
      generatedApiKey = {
        enable = true;
        configFile = "/etc/rauthy/config.toml";
        environmentFile = "/run/secrets/rauthy-env";
        file = "/run/rauthy-provision/api-key";
        generatedSecretsFile = "/var/lib/rauthy/bootstrap.secrets.enc";
        generatedSecretsTtl = 0;
      };

      groups.internal = {};
      roles.admin = {};
      userAttributes.vikunja_groups.desc = "Vikunja team sync groups";
      scopes.vikunja_groups.attrIncludeId = ["vikunja_groups"];
      clients.demo = {
        name = "Demo";
        redirectUris = ["https://demo.example.com/callback"];
        generatedSecretFile = "/run/rauthy-clients/demo.secret";
      };
    };

    system.stateVersion = lib.mkDefault "25.11";
  };
}
