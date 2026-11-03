{
  pkgs,
  self,
  ...
}: let
  # n8n ships under the Sustainable Use License (unfree in nixpkgs); the
  # externally created instance cannot take `nixpkgs.config` from the node.
  upkgs = import pkgs.path {
    inherit (pkgs.stdenv.hostPlatform) system;
    config.allowUnfreePredicate = pkg: pkgs.lib.getName pkg == "n8n";
  };
in
  upkgs.testers.nixosTest {
    name = "n8n-bootstrap";

    nodes.machine = {lib, ...}: {
      imports = [self.nixosModules.n8nProvision];
      virtualisation.memorySize = 3072;
      virtualisation.cores = 2;
      environment.systemPackages = [pkgs.curl pkgs.jq];

      # Synthetic disposable-VM secrets, created at runtime so the module's
      # "no store path" assertion holds.
      systemd.tmpfiles.settings."10-fixture" = {
        "/var/lib/fixture/key".f = {
          mode = "0600";
          argument = "fixture-n8n-encryption-key";
        };
        "/var/lib/fixture/owner".f = {
          mode = "0600";
          argument = "Fixture-owner-pw-1";
        };
        "/var/lib/fixture/webhook".f = {
          mode = "0600";
          argument = "fixture-webhook-token";
        };
      };

      services.n8n = {
        enable = true;
        environment.N8N_ENCRYPTION_KEY_FILE = "/var/lib/fixture/key";
        provision = {
          enable = true;
          owner = {
            email = "can@example.test";
            firstName = "Can";
            lastName = "Owner";
            passwordFile = "/var/lib/fixture/owner";
          };
          credentials.studio-webhook = {
            type = "httpHeaderAuth";
            data.name = "X-Studio-Token";
            dataFiles.value = "/var/lib/fixture/webhook";
          };
        };
      };
      # Removal: the declared credential goes away, so n8n must drop it.
      specialisation.nocreds.configuration.services.n8n.provision.credentials = lib.mkForce {};
      system.stateVersion = "25.11";
    };

    testScript = ''
      base = "http://127.0.0.1:5678"

      def login_code(password):
          return machine.succeed(
              f"curl -s -o /dev/null -w '%{{http_code}}' -X POST {base}/rest/login "
              f"-H 'content-type: application/json' "
              f"-d '{{\"emailOrLdapLoginId\":\"can@example.test\",\"password\":\"{password}\"}}'"
          ).strip()

      machine.start()
      machine.wait_for_unit("n8n.service")
      machine.wait_for_unit("n8n-provision.service")

      with subtest("generated owner password logs in"):
          assert login_code("Fixture-owner-pw-1") == "200"
          assert login_code("wrong-password") != "200"

      with subtest("env file holds a hash, never the password"):
          machine.succeed("test \"$(stat -c %a /run/n8n-provision/owner.env)\" = 600")
          machine.succeed("grep -q 'PASSWORD_HASH=\"\\$2' /run/n8n-provision/owner.env")
          machine.fail("grep -q Fixture-owner-pw-1 /run/n8n-provision/owner.env")

      with subtest("credential exists"):
          machine.succeed(f"curl -sf -c /tmp/jar -X POST {base}/rest/login -H 'content-type: application/json' -d '{{\"emailOrLdapLoginId\":\"can@example.test\",\"password\":\"Fixture-owner-pw-1\"}}'")
          out = machine.succeed(f"curl -sf -b /tmp/jar {base}/rest/credentials")
          assert "studio-webhook" in out, out

      with subtest("second reconcile and restart are no-ops"):
          hash_before = machine.succeed("cat /var/lib/n8n-owner-env/owner.bcrypt")
          machine.succeed("systemctl restart n8n.service")
          machine.wait_for_unit("n8n.service")
          machine.succeed("systemctl restart n8n-provision.service")
          assert machine.succeed("cat /var/lib/n8n-owner-env/owner.bcrypt") == hash_before
          inv = machine.succeed("systemctl show -p InvocationID --value n8n-provision.service").strip()
          journal = machine.succeed(f"journalctl -o cat _SYSTEMD_INVOCATION_ID={inv}")
          for word in ("created", "updated"):
              assert word not in journal, journal
          assert login_code("Fixture-owner-pw-1") == "200"

      with subtest("a rotated credential file is re-applied by the path unit"):
          machine.succeed("printf 'rotated-webhook-token' > /var/lib/fixture/webhook")
          machine.wait_until_succeeds(
              "journalctl -u n8n-provision.service -o cat | grep -q 'credential studio-webhook: updated'"
          )

      with subtest("a rotated owner password restarts n8n and takes effect"):
          machine.succeed("printf 'Rotated-owner-pw-2' > /var/lib/fixture/owner")
          machine.wait_until_succeeds(
              f"curl -sf -X POST {base}/rest/login -H 'content-type: application/json' "
              "-d '{\"emailOrLdapLoginId\":\"can@example.test\",\"password\":\"Rotated-owner-pw-2\"}'"
          )
          assert login_code("Fixture-owner-pw-1") != "200"
          machine.wait_for_unit("n8n-provision.service")

      with subtest("removing a credential declaration deletes it from n8n"):
          machine.succeed("/run/current-system/specialisation/nocreds/bin/switch-to-configuration test")
          machine.wait_for_unit("n8n-provision.service")
          machine.succeed(
              f"curl -sf -c /tmp/jar2 -X POST {base}/rest/login -H 'content-type: application/json' "
              "-d '{\"emailOrLdapLoginId\":\"can@example.test\",\"password\":\"Rotated-owner-pw-2\"}'"
          )
          out = machine.succeed(f"curl -sf -b /tmp/jar2 {base}/rest/credentials")
          assert "studio-webhook" not in out, out
    '';
  }
