{
  pkgs,
  self,
  windmillPackage ? null,
  # Scripts whose language needs a lock generation job (bun, deno, python3, ...)
  # push a dependency job on deploy, and Windmill 1.601.1's push violates its own
  # v2_job_queue NOT NULL on `__job_kind` under PostgreSQL 17. The default
  # (1.601.1) variant therefore deploys a bash script (no lock job), while the
  # Atlas variant (1.839.0) covers the language the consumer really uses.
  scriptLanguage ? "bash",
  # Worker tag declared on the fixture script (null keeps it untagged).
  scriptTag ? null,
  # Run a worker, so a dependency job is picked up and the deployed version
  # really gets its lock (only the bun/Atlas variant needs one).
  runWorker ? false,
  nameSuffix ? "",
  ...
}:
pkgs.testers.nixosTest {
  name = "windmill-bootstrap${nameSuffix}";

  nodes.machine = {
    lib,
    pkgs,
    ...
  }: let
    # Code, not secrets: store paths, so the state file changes with the content.
    scriptCode = version:
      if scriptLanguage == "bash"
      then "echo ${version}"
      else ''export async function main() { return "${version}"; }'';
    scriptV1 = pkgs.writeText "fixture-script" (scriptCode "v1");
    scriptV2 = pkgs.writeText "fixture-script" (scriptCode "v2");
    studio = {
      name = "Studio";
      scripts."f/fixture/hello" = {
        language = scriptLanguage;
        contentFile = "${scriptV1}";
        summary = "fixture procedure";
        tag = scriptTag;
      };
      variables."f/fixture/hub_token" = {
        valueFile = "/var/lib/fixture/hub-token";
        description = "fixture bearer";
      };
    };
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
    # A worker adds a second windmill process to the VM.
    virtualisation.memorySize =
      if runWorker
      then 4096
      else 3072;
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
      "/var/lib/fixture/hub-token".f = {
        mode = "0600";
        argument = "fixture-hub-token";
      };
    };

    services.windmill = {
      enable = true;
      package = lib.mkIf (windmillPackage != null) windmillPackage;
      baseUrl = "http://localhost:8001";
      provision = {
        enable = true;
        superadminSecretFile = "/var/lib/fixture/superadmin";
        workspaces.studio = studio;
        users.can = canUser;
        users.ops = opsUser;
        tokens.paperclip-studio = studioToken;
        tokens.ops-token = opsToken;
      };
    };
    # Changed script content: a new version is deployed, the path stays.
    specialisation.scriptv2.configuration.services.windmill.provision.workspaces.studio.scripts."f/fixture/hello".contentFile = lib.mkForce "${scriptV2}";
    # Variable secrecy flip forces an update of the same path.
    specialisation.variablepublic.configuration.services.windmill.provision.workspaces.studio.variables."f/fixture/hub_token".isSecret = lib.mkForce false;
    # Declared-token spec change (token rebound to a second workspace).
    specialisation.rebound.configuration.services.windmill.provision = {
      workspaces.other.name = "Other";
      users.can.workspaces = ["studio" "other"];
      tokens.paperclip-studio.workspace = lib.mkForce "other";
    };
    # Role change: ops loses instance admin, so its token must be re-minted.
    specialisation.demoted.configuration.services.windmill.provision.users.ops.admin = lib.mkForce false;
    # Email change: the old login must die and the new one take over.
    specialisation.emailchanged.configuration.services.windmill.provision.users.ops.email = lib.mkForce "ops2@example.test";
    # Removal: ops and its token are no longer declared.
    specialisation.pruned.configuration.services.windmill.provision = {
      users = lib.mkForce {can = canUser;};
      tokens = lib.mkForce {paperclip-studio = studioToken;};
    };
    # The bun variant deploys a script whose version is only runnable once its
    # dependency job has written the lock, so it runs a worker; the bash variant
    # needs none and keeps the VM small.
    systemd.services.windmill-worker = {
      enable = lib.mkForce runWorker;
      # A tagged script's dependency job is queued on that tag (the default
      # worker tags are replaced), so the worker must listen for it.
      environment = lib.mkIf (scriptTag != null) {WORKER_TAGS = lib.mkForce scriptTag;};
    };
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

    superadmin = "-H 'Authorization: Bearer fixture-superadmin-secret-with space'"

    def script_field(field, path="f/fixture/hello"):
        return machine.succeed(
            f"curl -sf {superadmin} {api}/w/studio/scripts/get/p/{path} | jq -r '{field}'"
        ).strip()

    def script_hash(path="f/fixture/hello"):
        return machine.succeed(f"curl -sf {superadmin} {api}/w/studio/scripts/get_latest_version/{path} | jq -r .script_hash")

    def script_tag(path="f/fixture/hello"):
        return machine.succeed(
            f"curl -sf {superadmin} {api}/w/studio/scripts/get/p/{path} | jq -r '.tag // \"\"'"
        ).strip()

    def variable_field(field, path="f/fixture/hub_token"):
        return machine.succeed(
            f"curl -sf {superadmin} {api}/w/studio/variables/get/{path} | jq -r '{field}'"
        ).strip()

    with subtest("the declared script is deployed with its language, content and tag"):
        document = machine.succeed(f"curl -sf {superadmin} {api}/w/studio/scripts/get/p/f/fixture/hello")
        assert script_field(".language") == "${scriptLanguage}", document
        assert script_field(".summary") == "fixture procedure", document
        content = script_field(".content")
        assert "v1" in content, document
        assert script_tag() == "${
      if scriptTag == null
      then ""
      else scriptTag
    }", document
        # Windmill queues a dependency job for a bun script and only a version
        # whose lock that job wrote is runnable: the reconciler waited for it.
        assert script_field(".lock") != "null", document

    with subtest("the declared variable holds the runtime credential value, as a secret"):
        document = machine.succeed(f"curl -sf {superadmin} {api}/w/studio/variables/get/f/fixture/hub_token")
        assert variable_field(".value") == "fixture-hub-token", document
        assert variable_field(".is_secret") == "true", document
        assert variable_field(".description") == "fixture bearer", document
        # The value lives in Windmill, never in the rendered state.
        machine.fail("grep -r fixture-hub-token /nix/store/*windmill-provision-state.json")
        machine.fail("grep -r fixture-hub-token /run/windmill-provision/env")

    with subtest("second reconcile is a no-op"):
        before = machine.succeed("cat /var/lib/windmill-provision/tokens/paperclip-studio")
        script_before = script_hash()
        machine.succeed("systemctl restart windmill-provision.service")
        inv = machine.succeed("systemctl show -p InvocationID --value windmill-provision.service").strip()
        journal = machine.succeed(f"journalctl -o cat _SYSTEMD_INVOCATION_ID={inv}")
        for word in ("minted", "created", "applied", "added", "deployed", "updated"):
            assert word not in journal, journal
        assert machine.succeed("cat /var/lib/windmill-provision/tokens/paperclip-studio") == before
        assert script_hash() == script_before

    base = machine.succeed("readlink -f /run/current-system").strip()
    spec = {n: machine.succeed(f"readlink -f /run/current-system/specialisation/{n}").strip() for n in ("scriptv2", "variablepublic", "rebound", "demoted", "emailchanged", "pruned")}
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

    with subtest("a changed script content deploys a new version at the same path"):
        before = script_hash()
        switch(spec["scriptv2"])
        content = script_field(".content")
        assert "v2" in content, content
        assert script_hash() != before
        # A new version does not inherit its parent's tag: the reconciler sends
        # the deployed one back when the declaration does not change it.
        assert script_tag() == "${
      if scriptTag == null
      then ""
      else scriptTag
    }"
        switch(base)
        content = script_field(".content")
        assert "v1" in content, content
        assert script_hash() != before
        assert script_tag() == "${
      if scriptTag == null
      then ""
      else scriptTag
    }"

    with subtest("flipping a variable's secrecy updates it in place"):
        switch(spec["variablepublic"])
        assert variable_field(".is_secret") == "false"
        assert variable_field(".value") == "fixture-hub-token"
        switch(base)
        assert variable_field(".is_secret") == "true"

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

    with subtest("changing a user's email locks the old login and rolls the token over"):
        old = read_token("ops-token")
        assert login_code("ops@example.test", "fixture-ops-password") == "200"
        switch(spec["emailchanged"])
        new = read_token("ops-token")
        assert new != old
        assert login_code("ops@example.test", "fixture-ops-password") != "200"
        assert login_code("ops2@example.test", "fixture-ops-password") == "200"
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

    with subtest("an in-place password rotation is applied by the path unit"):
        switch(base)
        machine.succeed("printf 'rotated-can-password' > /var/lib/fixture/can")
        machine.wait_until_succeeds(
            f"curl -sf -X POST {api}/auth/login -H 'content-type: application/json' "
            "-d '{\"email\":\"can@example.test\",\"password\":\"rotated-can-password\"}'"
        )
        assert login_code("can@example.test", "fixture-can-password") != "200"

    with subtest("an in-place variable value rotation is applied by the path unit"):
        switch(base)
        machine.succeed("printf 'rotated-hub-token' > /var/lib/fixture/hub-token")
        machine.wait_until_succeeds(
            f"curl -sf {superadmin} {api}/w/studio/variables/get/f/fixture/hub_token "
            "| jq -e '.value == \"rotated-hub-token\"'"
        )

    with subtest("an in-place superadmin secret rotation restarts the server and provisioning"):
        machine.succeed("printf 'rotated-superadmin-secret' > /var/lib/fixture/superadmin")
        machine.wait_until_succeeds(
            f"curl -sf -H 'Authorization: Bearer rotated-superadmin-secret' {api}/users/whoami"
        )
        machine.wait_for_unit("windmill-provision.service")
  '';
}
