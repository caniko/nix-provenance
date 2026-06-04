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
  }: let
    migrationExport = pkgs.writeText "stalwart016-migration.ndjson" ''
      {"@type":"create","object":"Domain","value":{"migrated.test":{"name":"migrated.test"}}}
    '';
  in {
    imports = [self.nixosModules.stalwart016];

    services.stalwart016 = {
      enable = true;
      hostname = "mail.example.test";

      datastore.postgresql.passwordFile = pkgs.writeText "stalwart-pg-password" "phase03-postgres-password";
      recoveryAdmin.passwordFile = pkgs.writeText "stalwart-recovery-admin" "phase03-recovery-password";

      provision = {
        migrationApplyFiles = [migrationExport];
        queryObjects = ["NetworkListener" "Domain"];
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
    machine.succeed("grep -F 'migrated.test' /var/lib/stalwart016/query-Domain.json")
    machine.succeed("test -s /var/lib/stalwart016/migration-applied")
    machine.succeed("grep -F 'migration_files=' /var/lib/stalwart016/migration-applied")
    machine.succeed("test -s /var/lib/stalwart016/registry-applied")
    machine.succeed("grep -F 'generated_plan=' /var/lib/stalwart016/registry-applied")

    machine.succeed("systemctl restart stalwart.service")
    machine.wait_for_unit("stalwart.service")
    machine.succeed("systemctl is-active --quiet stalwart.service")
    machine.wait_until_succeeds("ss -ltn | grep -E ':(25|587|993)[[:space:]]'")
    machine.succeed("grep -F 'migrated.test' /var/lib/stalwart016/query-Domain.json")

    # Force only the registry phase to rerun. The migration document is a bare
    # create and would fail on duplicate Domain if migrationApplyFiles replayed.
    machine.succeed("rm /var/lib/stalwart016/registry-applied")
    machine.succeed("systemctl restart stalwart.service")
    machine.wait_for_unit("stalwart.service")
    machine.succeed("systemctl is-active --quiet stalwart.service")
    machine.succeed("grep -F 'migrated.test' /var/lib/stalwart016/query-Domain.json")
  '';
}
