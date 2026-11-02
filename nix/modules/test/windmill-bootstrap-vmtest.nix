{
  pkgs,
  self,
  windmillPackage ? null,
  nameSuffix ? "",
  ...
}:
pkgs.testers.nixosTest {
  name = "windmill-bootstrap${nameSuffix}";

  nodes.machine = {lib, ...}: {
    imports = [self.nixosModules.windmillProvision];
    virtualisation.memorySize = 3072;
    virtualisation.cores = 2;
    environment.systemPackages = [pkgs.curl pkgs.jq];
    users.groups.studio = {};

    # Synthetic disposable-VM secrets, created at runtime so the module's
    # "no store path" assertion holds.
    systemd.tmpfiles.settings."10-fixture" = {
      "/var/lib/fixture/superadmin".f = {
        mode = "0600";
        argument = "fixture-superadmin-secret-with space";
      };
      "/var/lib/fixture/can".f = {
        mode = "0600";
        argument = "fixture-can-password";
      };
    };

    services.windmill = {
      enable = true;
      package = lib.mkIf (windmillPackage != null) windmillPackage;
      baseUrl = "http://localhost:8001";
      provision = {
        enable = true;
        superadminSecretFile = "/var/lib/fixture/superadmin";
        workspaces.studio.name = "Studio";
        users.can = {
          email = "can@example.test";
          passwordFile = "/var/lib/fixture/can";
          workspaces = ["studio"];
          admin = true;
        };
        tokens.paperclip-studio = {
          user = "can";
          workspace = "studio";
          group = "studio";
          mode = "0640";
        };
      };
    };
    # Jobs are out of scope; keep the VM small.
    systemd.services.windmill-worker.enable = lib.mkForce false;
    systemd.services.windmill-worker-native.enable = lib.mkForce false;
    system.stateVersion = "25.11";
  };

  testScript = ''
    api = "http://127.0.0.1:8001/api"

    def login_code(email, password):
        return machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' -X POST {api}/auth/login "
            f"-H 'content-type: application/json' "
            f"-d '{{\"email\":\"{email}\",\"password\":\"{password}\"}}'"
        ).strip()

    machine.start()
    machine.wait_for_unit("windmill-server.service")
    machine.wait_for_unit("windmill-provision.service")

    with subtest("generated password logs in, stock admin is locked"):
        assert login_code("can@example.test", "fixture-can-password") == "200"
        assert login_code("admin@windmill.dev", "changeme") != "200"
        assert login_code("can@example.test", "wrong") != "200"

    with subtest("superadmin secret reaches the server only through the env file"):
        machine.succeed("test \"$(stat -c %a /run/windmill-provision/env)\" = 600")
        machine.succeed(f"curl -sf -H 'Authorization: Bearer fixture-superadmin-secret-with space' {api}/users/whoami")
        machine.fail("grep -r fixture-superadmin /nix/store/*windmill-provision-state.json")

    with subtest("minted token authenticates with declared ownership"):
        machine.succeed("test \"$(stat -c '%a %G' /var/lib/windmill-provision/tokens/paperclip-studio)\" = '640 studio'")
        out = machine.succeed(f"curl -sf -H \"Authorization: Bearer $(cat /var/lib/windmill-provision/tokens/paperclip-studio)\" {api}/w/studio/users/whoami")
        assert "can@example.test" in out, out

    with subtest("second reconcile is a no-op"):
        before = machine.succeed("cat /var/lib/windmill-provision/tokens/paperclip-studio")
        machine.succeed("systemctl restart windmill-provision.service")
        inv = machine.succeed("systemctl show -p InvocationID --value windmill-provision.service").strip()
        journal = machine.succeed(f"journalctl -o cat _SYSTEMD_INVOCATION_ID={inv}")
        for word in ("minted", "created", "applied", "added"):
            assert word not in journal, journal
        assert machine.succeed("cat /var/lib/windmill-provision/tokens/paperclip-studio") == before
  '';
}
