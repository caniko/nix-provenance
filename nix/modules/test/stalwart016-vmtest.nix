{
  pkgs,
  self,
  ...
}:
pkgs.testers.nixosTest {
  name = "stalwart016";

  nodes.machine = {
    config,
    lib,
    pkgs,
    ...
  }: {
    imports = [self.nixosModules.stalwart016];

    services.stalwart016 = {
      enable = true;
      hostname = "mail.example.test";

      datastore.postgresql.passwordFile = pkgs.writeText "stalwart-pg-password" "phase03-postgres-password";
      recoveryAdmin.passwordFile = pkgs.writeText "stalwart-recovery-admin" "phase03-recovery-password";

      provision = {
        queryObjects = ["NetworkListener" "Domain"];
        registryConfig = [
          {
            "@type" = "destroy";
            object = "Domain";
            value.name = "example.test";
          }
          {
            "@type" = "create";
            object = "Domain";
            value."example.test" = {
              name = "example.test";
            };
          }
        ];
      };
    };

    networking.firewall.allowedTCPPorts = [25 587 993];
    system.stateVersion = lib.mkDefault "25.11";
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("postgresql.service")
    machine.wait_for_unit("stalwart.service")
    machine.succeed("systemctl is-active --quiet stalwart.service")

    machine.succeed("systemctl cat stalwart.service | grep -- '--config /etc/stalwart016/config.json'")
    machine.fail("systemctl cat stalwart.service | grep -F 'stalwart.toml'")
    machine.succeed("test -s /etc/stalwart016/config.json")
    machine.succeed("grep -F '\"@type\"' /etc/stalwart016/config.json")
    machine.succeed("grep -F '\"PostgreSql\"' /etc/stalwart016/config.json")

    machine.wait_until_succeeds("ss -ltn | grep -E ':(25|587|993)[[:space:]]'")
    machine.succeed("ss -ltn | grep -E ':(25)[[:space:]]'")
    machine.succeed("ss -ltn | grep -E ':(587)[[:space:]]'")
    machine.succeed("ss -ltn | grep -E ':(993)[[:space:]]'")

    machine.succeed("grep -F 'smtp' /var/lib/stalwart016/query-NetworkListener.json")
    machine.succeed("grep -F 'submission' /var/lib/stalwart016/query-NetworkListener.json")
    machine.succeed("grep -F 'imaps' /var/lib/stalwart016/query-NetworkListener.json")
    machine.succeed("grep -F 'example.test' /var/lib/stalwart016/query-Domain.json")

    machine.succeed("systemctl restart stalwart.service")
    machine.wait_for_unit("stalwart.service")
    machine.succeed("systemctl is-active --quiet stalwart.service")
    machine.wait_until_succeeds("ss -ltn | grep -E ':(25|587|993)[[:space:]]'")
    machine.succeed("grep -F 'example.test' /var/lib/stalwart016/query-Domain.json")
  '';
}
