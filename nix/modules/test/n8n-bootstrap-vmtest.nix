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

    nodes.machine = {lib, ...}: let
      # A one-node webhook workflow: the cheapest end-to-end proof that the
      # import, the credential id binding and the activation all took.
      workflow = pkgs.writeText "fleetix-hub-fixture.json" (builtins.toJSON {
        name = "exported fixture name";
        nodes = [
          {
            parameters = {
              path = "fleetix-hub-fixture";
              httpMethod = "POST";
              authentication = "headerAuth";
              responseMode = "onReceived";
              options = {};
            };
            id = "fixture-webhook";
            name = "Webhook";
            type = "n8n-nodes-base.webhook";
            typeVersion = 2;
            position = [0 0];
            credentials.httpHeaderAuth.name = "Fleetix Hub webhook token";
          }
        ];
        connections = {};
        settings.executionOrder = "v1";
        active = false;
      });
    in {
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
            data.name = "Authorization";
            dataFiles.value = "/var/lib/fixture/webhook";
            # The Header Auth value the hub sends: "Bearer <token>".
            dataFilePrefixes.value = "Bearer ";
          };
          workflows.fixture-workflow = {
            file = "${workflow}";
            credentials."Fleetix Hub webhook token" = "studio-webhook";
          };
        };
      };
      # Removal: the declared credential goes away, so n8n must drop it (the
      # workflow goes with it: its reference would point at no credential).
      specialisation.nocreds.configuration.services.n8n.provision = {
        credentials = lib.mkForce {};
        workflows = lib.mkForce {};
      };
      # Deactivation: the workflow stays, but stops serving its webhook.
      specialisation.workflowoff.configuration.services.n8n.provision.workflows.fixture-workflow.active = lib.mkForce false;
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
      # Activating a specialisation replaces /run/current-system, so the sibling
      # specialisations must be addressed through the base build.
      system = machine.succeed("readlink -f /run/current-system").strip()

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

      def hook(authorization):
          return machine.succeed(
              f"curl -s -o /dev/null -w '%{{http_code}}' -X POST {base}/webhook/fleetix-hub-fixture "
              f"-H 'Authorization: {authorization}'"
          ).strip()

      with subtest("the declared workflow is imported, activated and bound to the credential"):
          # The prefix template turns the raw token file into "Bearer <token>",
          # and the node's credential reference resolves to the provisioned id:
          # only then does the webhook accept the token and reject every other.
          assert hook("Bearer fixture-webhook-token") == "200", hook("Bearer fixture-webhook-token")
          assert hook("Bearer wrong-token") == "403", hook("Bearer wrong-token")
          assert hook("") == "403", hook("")
          machine.succeed(f"curl -sf -c /tmp/jar3 -X POST {base}/rest/login -H 'content-type: application/json' -d '{{\"emailOrLdapLoginId\":\"can@example.test\",\"password\":\"Fixture-owner-pw-1\"}}'")
          workflows = machine.succeed(
              f"curl -sf -b /tmp/jar3 {base}/rest/workflows "
              "| jq -r '.data[] | select(.name == \"fixture-workflow\") | [.active, .id] | @tsv'"
          ).strip()
          assert workflows, "workflow fixture-workflow is not in n8n"
          rows = workflows.split("\n")
          assert len(rows) == 1, rows
          active, workflow_id = rows[0].split("\t")
          assert active == "true", active
          assert workflow_id, rows
          # The file's own name never wins over the declared one.
          exported = machine.succeed(
              f"curl -sf -b /tmp/jar3 {base}/rest/workflows "
              "| jq -r '.data[] | select(.name == \"exported fixture name\") | .id'"
          ).strip()
          assert not exported, exported

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

      with subtest("deactivating the workflow stops its webhook"):
          machine.succeed(f"{system}/specialisation/workflowoff/bin/switch-to-configuration test")
          machine.wait_for_unit("n8n-provision.service")
          machine.wait_until_succeeds(
              "journalctl -u n8n-provision.service -o cat | grep -q 'workflow fixture-workflow: deactivated'"
          )
          assert hook("Bearer fixture-webhook-token") != "200", hook("Bearer fixture-webhook-token")

      with subtest("removing a credential declaration deletes it from n8n"):
          machine.succeed(f"{system}/specialisation/nocreds/bin/switch-to-configuration test")
          machine.wait_for_unit("n8n-provision.service")
          machine.succeed(
              f"curl -sf -c /tmp/jar2 -X POST {base}/rest/login -H 'content-type: application/json' "
              "-d '{\"emailOrLdapLoginId\":\"can@example.test\",\"password\":\"Rotated-owner-pw-2\"}'"
          )
          out = machine.succeed(f"curl -sf -b /tmp/jar2 {base}/rest/credentials")
          assert "studio-webhook" not in out, out
    '';
  }
