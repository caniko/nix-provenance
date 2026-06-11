# Module-eval smoke test for Rauthy's generated bootstrap API-key flow.
{
  lib,
  pkgs,
  self,
  ...
}: {
  imports = [
    {
      options.services.rauthy = {
        package = lib.mkOption {
          type = lib.types.package;
          default = pkgs.writeShellScriptBin "rauthy" ''
            exit 0
          '';
          description = "Stub Rauthy package for generated API-key module evaluation.";
        };
        settings = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = {};
          description = "Stub Rauthy settings option for generated API-key module evaluation.";
        };
        environmentFiles = lib.mkOption {
          type = lib.types.listOf (lib.types.oneOf [lib.types.path lib.types.str]);
          default = [];
          description = "Stub Rauthy environmentFiles option for generated API-key module evaluation.";
        };
      };
    }
    self.nixosModules.rauthy
  ];

  config = {
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
