{
  pkgs,
  self,
  windmillPackage ? null,
  nameSuffix ? "",
  ...
}:
pkgs.testers.nixosTest {
  name = "windmill-bootstrap${nameSuffix}";

  nodes.machine = {lib, ...}: let
    canUser = {
      email = "can@example.test";
      passwordFile = "/var/lib/fixture/can";
      workspaces = ["studio"];
      admin = true;
    };
    opsUser = {
      email = "ops@example.test";
      passwordFile = "/var/lib/fixture/ops";
      workspaces = ["studio"];
      admin = true;
    };
    studioToken = {
      user = "can";
      workspace = "studio";
      group = "studio";
      mode = "0640";
    };
    opsToken = {
      user = "ops";
      workspace = "studio";
    };
  in {
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
      "/var/lib/fixture/ops".f = {
        mode = "0600";
        argument = "fixture-ops-password";
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
        users.can = canUser;
        users.ops = opsUser;
        tokens.paperclip-studio = studioToken;
        tokens.ops-token = opsToken;
      };
    };
    # Declared-token spec change (token rebound to a second workspace).
    specialisation.rebound.configuration.services.windmill.provision = {
      workspaces.other.name = "Other";
      users.can.workspaces = ["studio" "other"];
      tokens.paperclip-studio.workspace = lib.mkForce "other";
    };
    # Role change: ops loses instance admin, so its token must be re-minted.
    specialisation.demoted.configuration.services.windmill.provision.users.ops.admin = lib.mkForce false;
    # Removal: ops and its token are no longer declared.
    specialisation.pruned.configuration.services.windmill.provision = {
      users = lib.mkForce {can = canUser;};
      tokens = lib.mkForce {paperclip-studio = studioToken;};
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

    base = machine.succeed("readlink -f /run/current-system").strip()
    spec = {n: machine.succeed(f"readlink -f /run/current-system/specialisation/{n}").strip() for n in ("rebound", "demoted", "pruned")}
    tok = "/var/lib/windmill-provision/tokens"

    def read_token(name):
        return machine.succeed(f"cat {tok}/{name}").strip()

    def code(token, ws="studio"):
        return machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' -H 'Authorization: Bearer {token}' {api}/w/{ws}/users/whoami"
        ).strip()

    def switch(system):
        machine.succeed(f"{system}/bin/switch-to-configuration test")
        machine.wait_for_unit("windmill-provision.service")
        # Windmill caches authenticated tokens for up to two minutes; a restart
        # flushes that cache so a revocation is observable immediately.
        machine.succeed("systemctl restart windmill-server.service")
        machine.wait_for_unit("windmill-provision.service")
        machine.wait_until_succeeds(f"curl -sf {api}/version")

    with subtest("a token spec change re-mints and revokes the old token"):
        old = read_token("paperclip-studio")
        switch(spec["rebound"])
        new = read_token("paperclip-studio")
        assert new != old
        assert code(old, "other") == "401", code(old, "other")
        assert code(new, "other") == "200", code(new, "other")
        machine.succeed(f"test \"$(stat -c '%a %G' {tok}/paperclip-studio)\" = '640 studio'")
        switch(base)

    with subtest("demoting a user re-mints and revokes its admin token"):
        old = read_token("ops-token")
        assert code(old) == "200", code(old)
        switch(spec["demoted"])
        new = read_token("ops-token")
        assert new != old
        assert code(old) == "401", code(old)
        assert code(new) == "200", code(new)
        switch(base)

    with subtest("removing a user and a token entry revokes both"):
        ops_token = read_token("ops-token")
        assert login_code("ops@example.test", "fixture-ops-password") == "200"
        switch(spec["pruned"])
        assert code(ops_token) == "401", code(ops_token)
        machine.fail(f"test -e {tok}/ops-token")
        assert login_code("ops@example.test", "fixture-ops-password") != "200"
        # The remaining declared user and token are untouched.
        assert login_code("can@example.test", "fixture-can-password") == "200"
        assert code(read_token("paperclip-studio")) == "200"
  '';
}
