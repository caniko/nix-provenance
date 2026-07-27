# Flake checks. Per-crate build/clippy/test, plus shared nixfmt, both module-eval
# smoke tests, the Immich patch-applies guard, and the structural guards that
# keep the TLS-feature isolation and the stripped release binary honest.
{
  pkgs,
  lib,
  nixpkgs,
  craneLib,
  src,
  self,
  system,
  packages,
  args,
  cargoArtifacts,
  identityCrossPackageSet,
  docs,
}: let
  inherit (pkgs) runCommand;

  mkClippy = pname:
    craneLib.cargoClippy (
      args.${pname}
      // {
        cargoArtifacts = cargoArtifacts.${pname};
        cargoClippyExtraArgs = "--all-targets -- --deny warnings";
      }
    );

  evalSystem = module:
    nixpkgs.lib.nixosSystem {
      inherit system;
      specialArgs = {inherit self;};
      modules = [module];
    };

  immichEval = evalSystem ./modules/test/immich-eval.nix;
  rauthyServerEval = evalSystem ./modules/test/rauthy-server-eval.nix;
  rauthyEval = evalSystem ./modules/test/rauthy-eval.nix;
  rauthyStateFileEval = evalSystem ./modules/test/rauthy-state-file-eval.nix;
  rauthyGeneratedEval = evalSystem ./modules/test/rauthy-generated-api-key-eval.nix;
  vikunjaEval = evalSystem ./modules/test/vikunja-eval.nix;
  vikunjaProvisionEval = evalSystem ./modules/test/vikunja-provision-eval.nix;
  forgejoEval = evalSystem ./modules/test/forgejo-eval.nix;
  stalwartEval = evalSystem ./modules/test/stalwart-eval.nix;
  stalwart016Eval = evalSystem ./modules/test/stalwart016-eval.nix;
  stalwart016VmTest = import ./modules/test/stalwart016-vmtest.nix {inherit pkgs self system;};
  adapterEval = evalSystem ./modules/test/adapter-eval.nix;
  kanidmCredentialsEval = evalSystem ./modules/test/kanidm-credentials-eval.nix;
  tuwunelEval = evalSystem ./modules/test/tuwunel-eval.nix;
  wireguardStatusEval = evalSystem ./modules/test/wireguard-status-eval.nix;

  immichPatch = ../crates/immich-provision/patches/immich/0001-add-trusted-local-provision-token.patch;
in
  {
    # Build all crates.
    identity-cli = packages.identity-cli;
    immich-provision = packages.immich-provision;
    kanidm-state-render = packages.kanidm-state-render;
    rauthy-provision = packages.rauthy-provision;
    rauthy-state-render = packages.rauthy-state-render;
    vikunja-provision = packages.vikunja-provision;
    stalwart016-provision = packages.stalwart016-provision;
    tuwunel-provision = packages.tuwunel-provision;
    docs = docs;
    site = docs;
    forgejo-cli = packages.forgejo-cli;

    # The fj application-token path must consume the token through stdin only.
    fj-module-eval = let
      tokenFile = "/tmp/nix-provenance-fj-application-token";
      codebergTokenFile = "/tmp/nix-provenance-fj-codeberg-token";
      fakeFj = pkgs.writeShellScriptBin "fj" ''
        printf '%s\n' "$@" > "$FJ_TEST_ARGS"
        cat > "$FJ_TEST_STDIN"
      '';
      evaluated = lib.evalModules {
        modules = [
          ({lib, ...}: {
            options.home.packages = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = [];
            };
            options.systemd.user.services = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
            };
            options.systemd.user.paths = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
            };
            options.assertions = lib.mkOption {
              type = lib.types.listOf lib.types.anything;
              default = [];
            };
          })
          (import ./modules/home/fj.nix {inherit self;})
          {
            nix-provenance.fj = {
              enable = true;
              package = fakeFj;
              applicationToken = {
                enable = true;
                host = "codefloe.com";
                username = "can";
                tokenFile = tokenFile;
              };
              applicationTokens.codeberg = {
                enable = true;
                host = "codeberg.org";
                username = "can";
                tokenFile = codebergTokenFile;
              };
            };
          }
        ];
        specialArgs = {inherit pkgs;};
      };
      service = evaluated.config.systemd.user.services.nix-provenance-fj-application-token;
      path = evaluated.config.systemd.user.paths.nix-provenance-fj-application-token;
      codebergService = evaluated.config.systemd.user.services.nix-provenance-fj-application-token-codeberg;
      codebergPath = evaluated.config.systemd.user.paths.nix-provenance-fj-application-token-codeberg;
    in
      assert service.Service.Type == "oneshot";
      assert builtins.elem "agenix.service" service.Unit.Wants;
      assert builtins.elem "agenix.service" service.Unit.After;
      assert path.Path.PathChanged == tokenFile;
      assert codebergService.Service.Type == "oneshot";
      assert builtins.elem "agenix.service" codebergService.Unit.Wants;
      assert codebergPath.Path.PathChanged == codebergTokenFile;
      assert builtins.elem fakeFj evaluated.config.home.packages;
        runCommand "fj-module-eval" {} ''
          grep -Fq ${lib.escapeShellArg tokenFile} ${service.Service.ExecStart}
          grep -Fq 'auth logout codefloe.com' ${service.Service.ExecStart}
          grep -Fq ${lib.escapeShellArg codebergTokenFile} ${codebergService.Service.ExecStart}
          grep -Fq 'auth logout codeberg.org' ${codebergService.Service.ExecStart}
          if grep -Fq 'test-application-token' ${service.Service.ExecStart}; then
            echo "fj: token leaked into the generated command" >&2
            exit 1
          fi
          printf 'test-application-token\n' > ${lib.escapeShellArg tokenFile}
          FJ_TEST_ARGS="$TMPDIR/args" \
            FJ_TEST_STDIN="$TMPDIR/stdin" \
            ${service.Service.ExecStart}

          test "$(sed -n '1p' "$TMPDIR/args")" = "-H"
          test "$(sed -n '2p' "$TMPDIR/args")" = "codefloe.com"
          test "$(sed -n '3p' "$TMPDIR/args")" = "auth"
          test "$(sed -n '4p' "$TMPDIR/args")" = "add-token"
          if grep -Fq 'test-application-token' "$TMPDIR/args"; then
            echo "fj: token leaked into argv" >&2
            exit 1
          fi
          printf 'can\ntest-application-token\n' > "$TMPDIR/expected"
          cmp -s "$TMPDIR/expected" "$TMPDIR/stdin"
          printf 'test-codeberg-token\n' > ${lib.escapeShellArg codebergTokenFile}
          FJ_TEST_ARGS="$TMPDIR/codeberg-args" \
            FJ_TEST_STDIN="$TMPDIR/codeberg-stdin" \
            ${codebergService.Service.ExecStart}
          test "$(sed -n '2p' "$TMPDIR/codeberg-args")" = "codeberg.org"
          printf 'can\ntest-codeberg-token\n' > "$TMPDIR/codeberg-expected"
          cmp -s "$TMPDIR/codeberg-expected" "$TMPDIR/codeberg-stdin"
          touch $out
        '';

    # Lint each crate against its isolated deps.
    identity-clippy = mkClippy "identity-cli";
    immich-clippy = mkClippy "immich-provision";
    kanidm-state-render-clippy = mkClippy "kanidm-state-render";
    rauthy-state-render-clippy = mkClippy "rauthy-state-render";
    rauthy-clippy = mkClippy "rauthy-provision";
    vikunja-clippy = mkClippy "vikunja-provision";
    stalwart016-provision-clippy = mkClippy "stalwart016-provision";
    tuwunel-provision-clippy = mkClippy "tuwunel-provision";

    # Tests: immich keeps cargoTest, rauthy keeps cargoNextest (preserved semantics).
    identity-test = craneLib.cargoTest (
      args.identity-cli // {cargoArtifacts = cargoArtifacts.identity-cli;}
    );
    immich-test = craneLib.cargoTest (
      args.immich-provision // {cargoArtifacts = cargoArtifacts.immich-provision;}
    );
    kanidm-state-render-test = craneLib.cargoTest (
      args.kanidm-state-render // {cargoArtifacts = cargoArtifacts.kanidm-state-render;}
    );
    rauthy-nextest = craneLib.cargoNextest (
      args.rauthy-provision // {cargoArtifacts = cargoArtifacts.rauthy-provision;}
    );
    rauthy-state-render-test = craneLib.cargoTest (
      args.rauthy-state-render // {cargoArtifacts = cargoArtifacts.rauthy-state-render;}
    );
    vikunja-test = craneLib.cargoTest (
      args.vikunja-provision
      // {
        cargoArtifacts = cargoArtifacts.vikunja-provision;
        doCheck = true;
      }
    );

    stalwart016-provision-test = craneLib.cargoTest (
      args.stalwart016-provision
      // {
        cargoArtifacts = cargoArtifacts.stalwart016-provision;
        doCheck = true;
      }
    );

    tuwunel-provision-test = craneLib.cargoTest (
      args.tuwunel-provision
      // {
        cargoArtifacts = cargoArtifacts.tuwunel-provision;
        doCheck = true;
      }
    );

    # Workspace-wide rustfmt.
    fmt = craneLib.cargoFmt {inherit src;};

    # Nix formatting over flake.nix + nix/ (uses the raw flake source, not the
    # Cargo-cleaned src which strips .nix files).
    nixfmt = runCommand "nix-provenance-nixfmt" {nativeBuildInputs = [pkgs.alejandra];} ''
      cp -r ${self} source
      chmod -R u+w source
      cd source
      alejandra --check flake.nix nix
      touch $out
    '';

    # Both NixOS modules must evaluate to a concrete oneshot serviceConfig.
    immich-module-eval = let
      svc = immichEval.config.systemd.services.immich-provision;
      serviceConfig = builtins.toJSON svc.serviceConfig;
    in
      runCommand "immich-module-eval" {} ''
        test -n ${lib.escapeShellArg serviceConfig}
        service=${lib.escapeShellArg serviceConfig}
        state_file=$(grep -o '/nix/store/[^ ]*immich-provision-state.json' ${svc.serviceConfig.ExecStart})
        state=$(cat "$state_file")
        printf '%s' "$service" | grep -q '/run/agenix/immich-eric-password' \
          || { echo "immich: password LoadCredential source missing" >&2; exit 1; }
        printf '%s' "$state" | grep -q '/run/credentials/immich-provision.service/password-eric' \
          || { echo "immich: rendered state must reference runtime credential path" >&2; exit 1; }
        if printf '%s' "$state" | grep -q 'immich-eric-password'; then
          echo "immich: rendered state must not contain agenix source path" >&2
          exit 1
        fi
        touch $out
      '';

    rauthy-server-module-eval = let
      svc = rauthyServerEval.config.systemd.services.rauthy;
      serviceConfig = builtins.toJSON svc.serviceConfig;
      environment = builtins.toJSON svc.environment;
    in
      assert svc.serviceConfig.DynamicUser == false;
      assert svc.serviceConfig.User == "rauthy";
        runCommand "rauthy-server-module-eval" {} ''
          test -n ${lib.escapeShellArg serviceConfig}
          env=${lib.escapeShellArg environment}
          exec_start=${lib.escapeShellArg svc.serviceConfig.ExecStart}
          printf '%s' "$exec_start" | grep -q -- 'serve --config-file' \
            || { echo "rauthy server: ExecStart must run the Rauthy server with generated config" >&2; exit 1; }
          test -f ${rauthyServerEval.config.services.rauthy.configFile} \
            || { echo "rauthy server: generated configFile option must point to a TOML file" >&2; exit 1; }
          printf '%s' "$env" | grep -q 'PG_HOST' \
            || { echo "rauthy server: PostgreSQL environment missing when configurePostgres is enabled" >&2; exit 1; }
          printf '%s' ${lib.escapeShellArg (builtins.toJSON svc.serviceConfig.EnvironmentFile)} | grep -q '/run/secrets/rauthy-env' \
            || { echo "rauthy server: primary environmentFile missing" >&2; exit 1; }
          printf '%s' ${lib.escapeShellArg (builtins.toJSON svc.serviceConfig.EnvironmentFile)} | grep -q '/run/rauthy/generated.env' \
            || { echo "rauthy server: extra environmentFiles missing" >&2; exit 1; }
          touch $out
        '';

    rauthy-module-eval = let
      svc = rauthyEval.config.systemd.services.rauthy-provision;
      serviceConfig = builtins.toJSON rauthyEval.config.systemd.services.rauthy-provision.serviceConfig;
      restartTriggers = builtins.toJSON svc.restartTriggers;
      clients = builtins.toJSON rauthyEval.config.services.rauthy.provision.clients;
      users = builtins.toJSON rauthyEval.config.services.rauthy.provision.users;
      renderedStateFile = toString (builtins.head svc.restartTriggers);
      scopes = builtins.toJSON rauthyEval.config.services.rauthy.provision.scopes;
      userAttrs = builtins.toJSON rauthyEval.config.services.rauthy.provision.userAttributes;
    in
      runCommand "rauthy-module-eval" {} ''
        test -n ${lib.escapeShellArg serviceConfig}
        clients=${lib.escapeShellArg clients}
        users=${lib.escapeShellArg users}
        rendered_state=$(cat ${lib.escapeShellArg renderedStateFile})
        scopes=${lib.escapeShellArg scopes}
        attrs=${lib.escapeShellArg userAttrs}
        triggers=${lib.escapeShellArg restartTriggers}
        grep -q -- '--transient-api-key' ${svc.serviceConfig.ExecStart} \
          || { echo "rauthy: transient API-key CLI flag missing from provisioner script" >&2; exit 1; }
        printf '%s' "$triggers" | grep -q 'rauthy-provision-state.json' \
          || { echo "rauthy: provisioner restartTriggers must include rendered state" >&2; exit 1; }
        printf '%s' "$clients" | grep -q '/run/rauthy-clients/demo.secret' \
          || { echo "rauthy: generatedSecretFile path missing from rendered client state" >&2; exit 1; }
        printf '%s' "$clients" | grep -q 'vikunja_groups' \
          || { echo "rauthy: custom Vikunja scope missing from client state" >&2; exit 1; }
        printf '%s' "$users" | grep -q 'preferredUsername' \
          || { echo "rauthy: preferredUsername missing from rendered user state" >&2; exit 1; }
        printf '%s' "$users" | grep -q 'Europe/Oslo' \
          || { echo "rauthy: timezone missing from rendered user state" >&2; exit 1; }
        printf '%s' "$users" | grep -q '12345' \
          || { echo "rauthy: ZIP/postal code missing from rendered user state" >&2; exit 1; }
        printf '%s' "$users" | grep -q '+4712345678' \
          || { echo "rauthy: phone missing from rendered user state" >&2; exit 1; }
        printf '%s' "$users" | grep -q 'vikunja_groups' \
          || { echo "rauthy: custom Vikunja user attribute value missing" >&2; exit 1; }
        printf '%s' "$rendered_state" | grep -q '/run/credentials/rauthy-provision.service/password-alice' \
          || { echo "rauthy: rendered users must reference runtime password credential" >&2; exit 1; }
        printf '%s' ${lib.escapeShellArg serviceConfig} | grep -q '/run/agenix/rauthy-alice-password' \
          || { echo "rauthy: password LoadCredential source missing" >&2; exit 1; }
        if printf '%s' "$rendered_state" | grep -q 'rauthy-alice-password'; then
          echo "rauthy: rendered state must not contain agenix source path" >&2
          exit 1
        fi
        printf '%s' "$scopes" | grep -q 'attrIncludeId' \
          || { echo "rauthy: custom scope attrIncludeId missing" >&2; exit 1; }
        printf '%s' "$scopes" | grep -q 'claimsAtRoot' \
          || { echo "rauthy: custom scope claimsAtRoot missing" >&2; exit 1; }
        printf '%s' "$attrs" | grep -q 'vikunja_groups' \
          || { echo "rauthy: userAttributes missing vikunja_groups" >&2; exit 1; }
        if printf '%s' "$clients" | grep -q 'clientsecret'; then
          echo "rauthy: rendered state must contain only secret paths, never client secret values" >&2
          exit 1
        fi
        touch $out
      '';

    rauthy-state-file-module-eval = let
      svc = rauthyStateFileEval.config.systemd.services.rauthy-provision;
      stateFile = toString rauthyStateFileEval.config.services.rauthy.provision.stateFile;
      restartTriggers = builtins.toJSON svc.restartTriggers;
    in
      runCommand "rauthy-state-file-module-eval" {} ''
        grep -q -- ${lib.escapeShellArg "--state ${stateFile}"} ${lib.escapeShellArg svc.serviceConfig.ExecStart} \
          || { echo "rauthy: provisioner must pass the configured services.rauthy.provision.stateFile path" >&2; exit 1; }
        triggers=${lib.escapeShellArg restartTriggers}
        printf '%s' "$triggers" | grep -q ${lib.escapeShellArg stateFile} \
          || { echo "rauthy: provisioner restartTriggers must include services.rauthy.provision.stateFile" >&2; exit 1; }
        touch $out
      '';

    rauthy-generated-api-key-module-eval = let
      bootstrapSvc = rauthyGeneratedEval.config.systemd.services.rauthy-bootstrap-api-key;
      provisionSvc = rauthyGeneratedEval.config.systemd.services.rauthy-provision;
      bootstrapSettings = builtins.toJSON rauthyGeneratedEval.config.services.rauthy.settings.bootstrap;
      bootstrapDir = rauthyGeneratedEval.config.services.rauthy.settings.bootstrap.bootstrap_dir;
    in
      runCommand "rauthy-generated-api-key-module-eval" {} ''
        test -x ${bootstrapSvc.serviceConfig.ExecStart}
        grep -q -- 'bootstrap get' ${bootstrapSvc.serviceConfig.ExecStart} \
          || { echo "rauthy generated API key: bootstrap extraction command missing" >&2; exit 1; }
        grep -q -- '--config-file /etc/rauthy/config.toml' ${bootstrapSvc.serviceConfig.ExecStart} \
          || { echo "rauthy generated API key: extraction must use --config-file" >&2; exit 1; }
        grep -q -- '--kind api-key' ${bootstrapSvc.serviceConfig.ExecStart} \
          || { echo "rauthy generated API key: extraction must request api-key kind" >&2; exit 1; }
        grep -q -- '--field token' ${bootstrapSvc.serviceConfig.ExecStart} \
          || { echo "rauthy generated API key: extraction must request token field" >&2; exit 1; }
        grep -q -- 'Rauthy generated bootstrap API key was not available' ${bootstrapSvc.serviceConfig.ExecStart} \
          || { echo "rauthy generated API key: extraction must have a bounded retry diagnostic" >&2; exit 1; }
        test ${lib.escapeShellArg bootstrapSvc.serviceConfig.Restart} = on-failure \
          || { echo "rauthy generated API key: extraction unit must restart on failure" >&2; exit 1; }
        test ${lib.escapeShellArg bootstrapSvc.serviceConfig.RestartSec} = 10s \
          || { echo "rauthy generated API key: extraction unit restart delay must be 10s" >&2; exit 1; }
        test ${lib.escapeShellArg (toString bootstrapSvc.unitConfig.StartLimitBurst)} = 6 \
          || { echo "rauthy generated API key: extraction unit start limit burst must be set" >&2; exit 1; }
        grep -q -- '--key-manager-api-key-file /run/rauthy-provision/api-key' ${provisionSvc.serviceConfig.ExecStart} \
          || { echo "rauthy generated API key: transient mode must use generated key as manager key" >&2; exit 1; }
        grep -q -- '--transient-api-key' ${provisionSvc.serviceConfig.ExecStart} \
          || { echo "rauthy generated API key: transient flag missing from provisioner script" >&2; exit 1; }
        settings=${lib.escapeShellArg bootstrapSettings}
        printf '%s' "$settings" | grep -q 'bootstrap.secrets.enc' \
          || { echo "rauthy generated API key: generated_secrets_file missing from Rauthy bootstrap settings" >&2; exit 1; }
        grep -q 'AuthProviders' ${bootstrapDir}/api_keys.json \
          || { echo "rauthy generated API key: AuthProviders access group missing" >&2; exit 1; }
        grep -q 'ApiKeys' ${bootstrapDir}/api_keys.json \
          || { echo "rauthy generated API key: manager key must include ApiKeys access for transient mode" >&2; exit 1; }
        touch $out
      '';

    vikunja-module-eval = let
      serviceConfig = builtins.toJSON vikunjaEval.config.systemd.services.vikunja-oidc-env.serviceConfig;
    in
      runCommand "vikunja-module-eval" {} ''
        test -n ${lib.escapeShellArg serviceConfig}
        touch $out
      '';

    vikunja-provision-module-eval = let
      svc = vikunjaProvisionEval.config.systemd.services.vikunja-provision;
      serviceConfig = builtins.toJSON svc.serviceConfig;
      defaultWebhookEvents = builtins.toJSON vikunjaProvisionEval.config.services.vikunja.provision.webhooks."10".events;
    in
      runCommand "vikunja-provision-module-eval" {} ''
        test -n ${lib.escapeShellArg serviceConfig}
        test ${lib.escapeShellArg svc.serviceConfig.Type} = oneshot
        test ${lib.escapeShellArg (toString svc.serviceConfig.RemainAfterExit)} = 1
        printf '%s\n' ${lib.escapeShellArg (builtins.toJSON svc.serviceConfig.LoadCredential)} | grep -q 'vikunja-token:/run/secrets/vikunja-provision-token'
        printf '%s\n' ${lib.escapeShellArg (builtins.toJSON svc.serviceConfig.LoadCredential)} | grep -q 'vikunja-webhook-secret:/run/secrets/vikunja-webhook-secret'
        printf '%s\n' ${lib.escapeShellArg (builtins.toJSON svc.after)} | grep -q 'vikunja.service'
        test -x ${svc.serviceConfig.ExecStart}
        grep -q -- '--webhook-secret-file "$CREDENTIALS_DIRECTORY/vikunja-webhook-secret"' ${svc.serviceConfig.ExecStart}
        test ${lib.escapeShellArg defaultWebhookEvents} = ${lib.escapeShellArg (builtins.toJSON self.lib.vikunja.webhookEvents.taskLifecycle)}
        printf '%s\n' ${lib.escapeShellArg defaultWebhookEvents} | grep -q 'task.assignee.created'
        ! printf '%s\n' ${lib.escapeShellArg defaultWebhookEvents} | grep -q 'task.assigned'
        touch $out
      '';

    forgejo-module-eval = let
      svc = forgejoEval.config.systemd.services.forgejo-seed-oidc;
      serviceConfig = builtins.toJSON svc.serviceConfig;
    in
      runCommand "forgejo-module-eval" {} ''
        test -n ${lib.escapeShellArg serviceConfig}
        test -x ${svc.serviceConfig.ExecStart}
        grep -q -- '--config' ${svc.serviceConfig.ExecStart}
        grep -q -- '/custom/conf/app.ini' ${svc.serviceConfig.ExecStart}
        touch $out
      '';

    stalwart-module-eval = let
      directory = builtins.toJSON stalwartEval.config.services.stalwart.kanidmLdap.registryObject;
    in
      runCommand "stalwart-module-eval" {} ''
        directory=${lib.escapeShellArg directory}
        test -n "$directory"
        printf '%s' "$directory" | grep -Fq '"@type":"Ldap"' || { echo "stalwart: missing @type=Ldap (0.16 Directory discriminator is PascalCase; lowercase is rejected by stalwart-cli apply)" >&2; exit 1; }
        printf '%s' "$directory" | grep -Fq '"bindAuthentication":true' || { echo "stalwart: missing bindAuthentication=true" >&2; exit 1; }
        printf '%s' "$directory" | grep -Fq '"filterLogin":' || { echo "stalwart: missing filterLogin" >&2; exit 1; }
        printf '%s' "$directory" | grep -Fq '"filterMailbox":' || { echo "stalwart: missing filterMailbox" >&2; exit 1; }
        printf '%s' "$directory" | grep -Fq '"bindDn":"dn=token"' || { echo "stalwart: missing bindDn=dn=token" >&2; exit 1; }
        printf '%s' "$directory" | grep -Fq '"baseDn":"dc=auth,dc=example,dc=com"' || { echo "stalwart: missing baseDn" >&2; exit 1; }
        printf '%s' "$directory" | grep -Fq '"bindSecret":' || { echo "stalwart: missing bindSecret" >&2; exit 1; }
        printf '%s' "$directory" | grep -Fq '"filePath":"/run/credentials/stalwart.service/kanidm_bind"' || { echo "stalwart: missing bindSecret.filePath" >&2; exit 1; }
        printf '%s' "$directory" | grep -Fq '"@type":"File"' || { echo "stalwart: missing bindSecret @type=File (0.16 SecretKey variant is PascalCase)" >&2; exit 1; }
        printf '%s' "$directory" | grep -Fq '"attrEmail":{"mail":true}' || { echo "stalwart: attrEmail must be a 0.16 SET object {value:true}, not an array (Map<T> rejects arrays)" >&2; exit 1; }
        printf '%s' "$directory" | grep -Fq '"description":' || { echo "stalwart: missing LdapDirectory description (required-non-empty in 0.16)" >&2; exit 1; }
        if printf '%s' "$directory" | grep -Fq '"bind":{'; then echo "stalwart: found legacy bind object" >&2; exit 1; fi
        if printf '%s' "$directory" | grep -Fq '"filter":{'; then echo "stalwart: found legacy filter object" >&2; exit 1; fi
        if printf '%s' "$directory" | grep -Fq '"attributes":'; then echo "stalwart: found legacy attributes map" >&2; exit 1; fi
        if printf '%s' "$directory" | grep -Fq '"base-dn"'; then echo "stalwart: found legacy base-dn key" >&2; exit 1; fi
        if printf '%s' "$directory" | grep -Fq '"allow-invalid-certs"'; then echo "stalwart: found legacy allow-invalid-certs key" >&2; exit 1; fi
        touch $out
      '';

    stalwart016-module-eval = let
      cfg = stalwart016Eval.config.services.stalwart016;
      clients = builtins.toJSON cfg.oidc.clients;
      plan = stalwart016Eval.config.environment.etc."stalwart016/apply.ndjson".source;
      serviceEnvironment = builtins.toJSON stalwart016Eval.config.systemd.services.stalwart.environment;
    in
      runCommand "stalwart016-module-eval" {} ''
        printf '%s' ${lib.escapeShellArg clients} | grep -Fq '"neverlight-mail"'
        printf '%s' ${lib.escapeShellArg clients} | grep -Fq '"redirectUris":["http://127.0.0.1:49152/callback"]'
        grep -Fq '"@type":"upsert","matchOn":["name"],"object":"NetworkListener"' ${plan}
        printf '%s' ${lib.escapeShellArg serviceEnvironment} | grep -Fq 'STALWART_PUBLIC_URL'
        test ${lib.escapeShellArg cfg.publicUrl} = 'https://mail.example.test'
        touch $out
      '';

    stalwart016-vmtest = stalwart016VmTest;

    wireguard-status-module-eval = let
      exporter = wireguardStatusEval.config.services.prometheus.exporters.wireguard;
      artifact = wireguardStatusEval.config.environment.etc."nix-provenance/wireguard-status.json".text;
    in
      runCommand "wireguard-status-module-eval" {} ''
        test ${lib.escapeShellArg (toString exporter.enable)} = 1
        test ${lib.escapeShellArg exporter.listenAddress} = 127.0.0.1
        test ${lib.escapeShellArg (toString exporter.port)} = 19586
        test ${lib.escapeShellArg (builtins.toJSON exporter.interfaces)} = '["wg-home"]'
        printf '%s' ${lib.escapeShellArg artifact} | grep -q '"schemaVersion":1'
        printf '%s' ${lib.escapeShellArg artifact} | grep -q '127.0.0.1:19586/metrics'
        touch $out
      '';

    # The kanidm-credentials reconcile module must evaluate to a concrete oneshot,
    # and its reconcile script must pass shellcheck (forced by depending on the
    # built ExecStart below).
    kanidm-credentials-module-eval = let
      svc = kanidmCredentialsEval.config.systemd.services.kanidm-credentials;
      serviceConfig = builtins.toJSON svc.serviceConfig;
    in
      runCommand "kanidm-credentials-module-eval" {} ''
        test -n ${lib.escapeShellArg serviceConfig}
        test -x ${svc.serviceConfig.ExecStart}
        script=$(cat ${svc.serviceConfig.ExecStart})
        printf '%s' "$script" | grep -q 'set-ldap-unix-bind true'
        printf '%s' "$script" | grep -q 'set-initial-primary-password can --primary-from'
        printf '%s' "$script" | grep -q 'ssh-public-key ensure can hm-identity'
        printf '%s' "$script" | grep -q 'set-posix-password noreply'
        printf '%s' ${lib.escapeShellArg serviceConfig} | grep -q '/run/agenix/primary-can' \
          || { echo "kanidm-credentials: initial primary password LoadCredential missing" >&2; exit 1; }
        printf '%s' "$script" | grep -q 'service-account create stalwart-ldap'
        printf '%s' "$script" | grep -q 'group-add-members idm_people_pii_read stalwart-ldap'
        printf '%s' "$script" | grep -q '/var/lib/kanidm-credentials/stalwart-ldap.token'
        touch $out
      '';

    tuwunel-module-eval = let
      svc = tuwunelEval.config.systemd.services.tuwunel;
      provisionSvc = tuwunelEval.config.systemd.services.tuwunel-provision;
      serviceConfig = builtins.toJSON svc.serviceConfig;
      settings = builtins.toJSON tuwunelEval.config.services.matrix-tuwunel.settings.global.identity_provider.kanidm;
      provisionConfig = builtins.toJSON provisionSvc.serviceConfig;
    in
      runCommand "tuwunel-module-eval" {} ''
        settings=${lib.escapeShellArg settings}
        service=${lib.escapeShellArg serviceConfig}
        provision=${lib.escapeShellArg provisionConfig}
        printf '%s' "$settings" | grep -q '"client_id":"matrix"' \
          || { echo "tuwunel: OIDC client_id missing" >&2; exit 1; }
        printf '%s' "$settings" | grep -q '"issuer_url":"https://auth.example.com/oauth2/openid/matrix"' \
          || { echo "tuwunel: OIDC issuer_url missing" >&2; exit 1; }
        printf '%s' "$settings" | grep -q '"callback_url":"https://matrix.example.com/_matrix/client/unstable/login/sso/callback/matrix"' \
          || { echo "tuwunel: OIDC callback_url missing" >&2; exit 1; }
        printf '%s' "$settings" | grep -q '"userid_claims":\["preferred_username"\]' \
          || { echo "tuwunel: OIDC userid_claims missing" >&2; exit 1; }
        printf '%s' "$settings" | grep -q '"unique_id_fallbacks":false' \
          || { echo "tuwunel: unique_id_fallbacks false missing" >&2; exit 1; }
        printf '%s' "$settings" | grep -q '/run/credentials/tuwunel.service/password-oidc-kanidm-' \
          || { echo "tuwunel: OIDC client_secret_file must point at runtime credential" >&2; exit 1; }
        printf '%s' "$service" | grep -q '/run/agenix/matrix-oidc-client-secret' \
          || { echo "tuwunel: OIDC LoadCredential source missing" >&2; exit 1; }
        if printf '%s' "$settings" | grep -q '/run/agenix/matrix-oidc-client-secret'; then
          echo "tuwunel: rendered settings must not contain agenix source path" >&2
          exit 1
        fi
        printf '%s' "$provision" | grep -q '/run/agenix/matrix-admin-password' \
          || { echo "tuwunel: matrix-admin password LoadCredential missing" >&2; exit 1; }
        state_file=$(printf '%s' ${lib.escapeShellArg provisionSvc.serviceConfig.ExecStart} | grep -o '/nix/store/[^ ]*tuwunel-provision-state.json')
        grep -q '"admin_token_user":"matrix-admin"' "$state_file" \
          || { echo "tuwunel: admin_token_user missing from provision state" >&2; exit 1; }
        grep -q '"alias":"#canix-alerts:matrix.example.com"' "$state_file" \
          || { echo "tuwunel: Matrix alert room missing from provision state" >&2; exit 1; }
        grep -q '"@matrix-alerts:matrix.example.com"' "$state_file" \
          || { echo "tuwunel: Matrix alert room invite missing from provision state" >&2; exit 1; }
        touch $out
      '';

    # The third-party adapter must derive the pink-raven rauthy users (can keyed by
    # kanidm login, eric/caroline emailed a set-password link) and the kanidm-backend
    # OAuth2 federation client + person, all from the uniform user schema.
    adapter-module-eval = let
      svc = adapterEval.config.systemd.services.rauthy-provision;
      serviceConfig = builtins.toJSON svc.serviceConfig;
      renderedStateFile = toString (builtins.head svc.restartTriggers);
      rauthyUsers = builtins.toJSON adapterEval.config.services.rauthy.provision.users;
      kanidmOauth2 = builtins.toJSON adapterEval.config.services.kanidm.provision.systems.oauth2;
      kanidmPersons = builtins.toJSON adapterEval.config.services.kanidm.provision.persons;
    in
      runCommand "adapter-module-eval" {} ''
        users=${lib.escapeShellArg rauthyUsers}
        rendered_state=$(cat ${lib.escapeShellArg renderedStateFile})
        oauth2=${lib.escapeShellArg kanidmOauth2}
        persons=${lib.escapeShellArg kanidmPersons}
        service=${lib.escapeShellArg serviceConfig}
        for e in can@tartanoglu.com efirley@protonmail.com carolinestahl@gmx.net bot@example.com; do
          printf '%s' "$users" | grep -q "$e" || { echo "adapter: rauthy user $e missing" >&2; exit 1; }
        done
        # eric + caroline get an emailed set-password link; can does not.
        printf '%s' "$users" | grep -q '"sendPasswordEmail":true' \
          || { echo "adapter: no emailed (passwordInitByEmail) rauthy user rendered" >&2; exit 1; }
        printf '%s' "$users" | grep -q '"requiredAuthProvider":"kanidm"' \
          || { echo "adapter: kanidmLogin user missing requiredAuthProvider marker" >&2; exit 1; }
        ! printf '%s' "$users" | grep -oE '"efirley@protonmail.com":\{[^}]*\}' | grep -q 'requiredAuthProvider' \
          || { echo "adapter: passwordInitByEmail user must not carry requiredAuthProvider" >&2; exit 1; }
        printf '%s' "$rendered_state" | grep -q '"required_auth_provider":"kanidm"' \
          || { echo "adapter: requiredAuthProvider did not render into provision state" >&2; exit 1; }
        printf '%s' "$rendered_state" | grep -q '/run/credentials/rauthy-provision.service/password-bot' \
          || { echo "adapter: passwordFromFile did not render runtime password path" >&2; exit 1; }
        printf '%s' "$rendered_state" | grep -q '"initial_password_file"' \
          || { echo "adapter: passwordFromFile did not render initial_password_file" >&2; exit 1; }
        ! printf '%s' "$rendered_state" | grep -q '"password_file"' \
          || { echo "adapter: passwordFromFile rendered obsolete password_file" >&2; exit 1; }
        printf '%s' "$service" | grep -q '/run/agenix/pink-raven-bot-password' \
          || { echo "adapter: passwordFromFile LoadCredential source missing" >&2; exit 1; }
        printf '%s' "$rendered_state" | grep -q '"post_logout_redirect_uris":\["https://raven.tartanoglu.com/"\]' \
          || { echo "adapter: pink-raven post-logout redirect missing" >&2; exit 1; }
        printf '%s' "$rendered_state" | grep -q '"allowed_origins":\["https://raven.tartanoglu.com"\]' \
          || { echo "adapter: pink-raven allowed origin missing" >&2; exit 1; }
        # kanidm backend rendered an OAuth2 federation client + its person.
        printf '%s' "$oauth2"  | grep -q 'internal-tool'   || { echo "adapter: kanidm oauth2 system missing" >&2; exit 1; }
        printf '%s' "$persons" | grep -q 'dejana'          || { echo "adapter: kanidm person missing" >&2; exit 1; }
        touch $out
      '';

    # The Immich patch must still apply cleanly against pkgs.immich.src.
    immich-patch-applies = runCommand "immich-patch-applies" {nativeBuildInputs = [pkgs.patch];} ''
      cp -R ${pkgs.immich.src} source
      chmod -R u+w source
      patch -d source -p1 --dry-run < ${immichPatch}
      touch $out
    '';

    # Structural guard: reqwest TLS features stay per-crate (never unioned), and
    # reqwest is never hoisted into [workspace.dependencies]. This is the cheap,
    # deterministic enforcement of the no-openssl / aarch64-safe invariant.
    tls-feature-isolation = runCommand "tls-feature-isolation" {} ''
      immich='${../crates/immich-provision/Cargo.toml}'
      rauthy='${../crates/rauthy-provision/Cargo.toml}'
      vikunja='${../crates/vikunja-provision/Cargo.toml}'
      root='${../Cargo.toml}'
      grep -q 'rustls-tls"' "$immich" || { echo "immich reqwest must enable rustls-tls"; exit 1; }
      if grep -q 'native-roots' "$immich"; then echo "immich reqwest must NOT enable native-roots (TLS root drift)"; exit 1; fi
      grep -q 'rustls-tls-native-roots' "$rauthy" || { echo "rauthy reqwest must enable rustls-tls-native-roots"; exit 1; }
      grep -q 'rustls-tls-native-roots' "$vikunja" || { echo "vikunja reqwest must enable rustls-tls-native-roots"; exit 1; }
      if grep -qE '^[[:space:]]*reqwest[[:space:]]*=' "$root"; then echo "reqwest must NOT be hoisted into [workspace.dependencies]"; exit 1; fi
      touch $out
    '';

    # License firewall: the permissive dependency graph (provenance-core and the
    # MIT/Apache rauthy crate) must never pull in the AGPL immich-provision crate,
    # and provenance-core itself must stay permissive. The one-directional boundary
    # (AGPL may consume permissive, never the reverse) is enforced structurally.
    license-firewall = runCommand "license-firewall" {} ''
      core='${../crates/provenance-core/Cargo.toml}'
      rauthy='${../crates/rauthy-provision/Cargo.toml}'
      vikunja='${../crates/vikunja-provision/Cargo.toml}'
      grep -q 'license = "MIT OR Apache-2.0"' "$core" || { echo "provenance-core must be MIT OR Apache-2.0"; exit 1; }
      if grep -q 'immich-provision' "$core"; then echo "provenance-core must not depend on the AGPL immich-provision crate"; exit 1; fi
      if grep -q 'immich-provision' "$rauthy"; then echo "rauthy-provision (permissive) must not depend on the AGPL immich-provision crate"; exit 1; fi
      if grep -q 'immich-provision' "$vikunja"; then echo "vikunja-provision (permissive) must not depend on the AGPL immich-provision crate"; exit 1; fi
      touch $out
    '';

    # The root [profile.release] strip must actually reach the release binaries
    # (member profiles are ignored by Cargo — this proves the hoist worked).
    rauthy-binary-stripped =
      runCommand "rauthy-binary-stripped" {nativeBuildInputs = [pkgs.file];}
      ''
        if file -b ${packages.rauthy-provision}/bin/rauthy-provision | grep -q 'not stripped'; then
          echo "rauthy-provision release binary is not stripped (profile.release hoist lost?)" >&2
          exit 1
        fi
        touch $out
      '';
  }
  // lib.optionalAttrs (system == "x86_64-linux") {
    # Keep the target package in the ordinary flake check graph so a future
    # change cannot silently reintroduce host objects into the target linker.
    identity-cli-aarch64-linux = identityCrossPackageSet."identity-cli-aarch64-linux";
  }
