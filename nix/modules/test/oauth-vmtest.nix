{
  pkgs,
  self,
}:
pkgs.testers.runNixOSTest {
  name = "provenance-oauth-runtime";
  nodes.machine = {pkgs, ...}: {
    imports = [self.nixosModules.oauth];
    networking.hostName = "oauth-runtime";
    users.users.alice.isNormalUser = true;
    users.users.bob.isNormalUser = true;
    environment.systemPackages = [pkgs.python3];
    services.provenance.oauth.users.alice.providers.openai = {
      # Test-only runtime artifact generated inside the VM. Nothing here is a
      # provider grant, and no token value is rendered into the Nix store.
      enrollmentFile = "/var/lib/oauth-runtime-enrollment.json";
      recoveryRecipients = ["age1luyy6j8g4689rqj2qwlu4znr3zjael48pq8tlgl5fu7l2l8r7qvqdfxaa5"];
    };
    system.stateVersion = "26.05";
    virtualisation.memorySize = 1024;
  };
  testScript = {nodes, ...}: ''
    import json

    start_all()
    machine.wait_for_unit("multi-user.target")
    state = "/var/lib/provenance-oauth-alice-openai"
    manifest = "/etc/provenance/oauth/alice-openai.json"
    helper = "provenance-oauth --config " + manifest
    normal = "provenance-oauth-alice-openai.service"
    initial = "provenance-oauth-alice-openai-initialize.service"

    with subtest("evaluated unit texts match the loaded systemd contract"):
        units = ${builtins.toJSON {
      "provenance-oauth-alice-openai.service" = nodes.machine.systemd.units."provenance-oauth-alice-openai.service".text;
      "provenance-oauth-alice-openai-initialize.service" = nodes.machine.systemd.units."provenance-oauth-alice-openai-initialize.service".text;
    }}
        def content(text):
            return [line.strip() for line in text.splitlines()
                    if line.strip() and not line.strip().startswith("#")]
        for unit, expected in units.items():
            actual = machine.succeed("systemctl --no-pager cat -- " + unit)
            assert content(actual) == content(expected)
            assert machine.succeed("systemctl show --value --property NeedDaemonReload -- " + unit).strip() == "no"

    with subtest("normal boot never initializes absent state"):
        machine.fail("test -e " + state + "/state.json")
        machine.succeed("systemctl start " + normal)
        machine.fail("test -e " + state + "/state.json")

    with subtest("runtime enrollment is loaded through systemd credentials"):
        machine.succeed("python3 - <<'PY'\n"
            "import json, os, secrets, time\n"
            "target = json.load(open('/etc/provenance/oauth/alice-openai.json'))['target']\n"
            "os.umask(0o077)\n"
            "with open('/var/lib/oauth-runtime-enrollment.json', 'w') as f:\n"
            " json.dump({'version': 1, 'target': target, 'generation': 100, 'grant': "
            "{'accessToken': secrets.token_urlsafe(), 'refreshToken': secrets.token_urlsafe(), "
            "'expiresAt': int(time.time()*1000)+3600000, 'accountId': 'runtime-fixture'}}, f)\n"
            "PY")
        machine.succeed("systemctl start " + initial)
        status = json.loads(machine.succeed("su -s /bin/sh alice -c '" + helper + " status'"))
        assert status["generation"] == 100 and status["state"] == "enrolled"
        machine.succeed("test $(stat -c '%U:%a' " + state + ") = alice:700")
        for name in ["state.json", "checkpoint.age", "lock"]:
            machine.succeed("test $(stat -c '%U:%a' " + state + "/" + name + ") = alice:600")
        machine.succeed("install -m600 /dev/null /run/access.json")
        machine.succeed("su -s /bin/sh alice -c '" + helper + " access' >/run/access.json")
        machine.succeed("python3 - <<'PY'\nimport json\na=json.load(open('/run/access.json'))\n"
            "assert set(a) == {'accessToken', 'expiresAt', 'accountId'}\nPY")

    with subtest("another UID cannot read or consume credentials"):
        machine.fail("su -s /bin/sh bob -c 'test -r " + state + "/state.json'")
        machine.fail("su -s /bin/sh bob -c '" + helper + " access >/dev/null'")
        machine.fail("su -s /bin/sh alice -c 'test -r /var/lib/oauth-runtime-enrollment.json'")

    with subtest("reboot reconciliation preserves established generation"):
        machine.reboot()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("systemctl start " + normal)
        status = json.loads(machine.succeed("su -s /bin/sh alice -c '" + helper + " status'"))
        assert status["generation"] == 100 and status["revision"] == 0

    with subtest("removal tombstone survives enrollment replay and reboot"):
        machine.succeed("su -s /bin/sh alice -c '" + helper + " remove'")
        machine.succeed("systemctl start " + normal)
        machine.reboot()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("systemctl start " + normal)
        status = json.loads(machine.succeed("su -s /bin/sh alice -c '" + helper + " status'"))
        assert status["state"] == "removed" and status["generation"] == 100
        machine.fail("su -s /bin/sh alice -c '" + helper + " access >/dev/null'")

    with subtest("state loss cannot trigger automatic bootstrap replay"):
        machine.succeed("rm " + state + "/state.json")
        machine.reboot()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("systemctl start " + normal)
        machine.fail("test -e " + state + "/state.json")
  '';
}
