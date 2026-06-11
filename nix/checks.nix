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
  stalwart016VmTest = import ./modules/test/stalwart016-vmtest.nix {inherit pkgs self system;};
  adapterEval = evalSystem ./modules/test/adapter-eval.nix;
  kanidmCredentialsEval = evalSystem ./modules/test/kanidm-credentials-eval.nix;

  immichPatch = ../crates/immich-provision/patches/immich/0001-add-trusted-local-provision-token.patch;
in {
  # Build all crates.
  identity-cli = packages.identity-cli;
  immich-provision = packages.immich-provision;
  rauthy-provision = packages.rauthy-provision;
  rauthy-state-render = packages.rauthy-state-render;
  vikunja-provision = packages.vikunja-provision;
  stalwart = packages.stalwart;
  stalwart-cli = packages.stalwart-cli;
  docs = docs;
  site = docs;

  # Lint each crate against its isolated deps.
  identity-clippy = mkClippy "identity-cli";
  immich-clippy = mkClippy "immich-provision";
  rauthy-state-render-clippy = mkClippy "rauthy-state-render";
  rauthy-clippy = mkClippy "rauthy-provision";
  vikunja-clippy = mkClippy "vikunja-provision";

  # Tests: immich keeps cargoTest, rauthy keeps cargoNextest (preserved semantics).
  identity-test = craneLib.cargoTest (
    args.identity-cli // {cargoArtifacts = cargoArtifacts.identity-cli;}
  );
  immich-test = craneLib.cargoTest (
    args.immich-provision // {cargoArtifacts = cargoArtifacts.immich-provision;}
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
    serviceConfig = builtins.toJSON immichEval.config.systemd.services.immich-provision.serviceConfig;
  in
    runCommand "immich-module-eval" {} ''
      test -n ${lib.escapeShellArg serviceConfig}
      touch $out
    '';

  rauthy-server-module-eval = let
    svc = rauthyServerEval.config.systemd.services.rauthy;
    serviceConfig = builtins.toJSON svc.serviceConfig;
    environment = builtins.toJSON svc.environment;
  in
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
    scopes = builtins.toJSON rauthyEval.config.services.rauthy.provision.scopes;
    userAttrs = builtins.toJSON rauthyEval.config.services.rauthy.provision.userAttributes;
  in
    runCommand "rauthy-module-eval" {} ''
      test -n ${lib.escapeShellArg serviceConfig}
      clients=${lib.escapeShellArg clients}
      users=${lib.escapeShellArg users}
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
  in
    runCommand "vikunja-provision-module-eval" {} ''
      test -n ${lib.escapeShellArg serviceConfig}
      test ${lib.escapeShellArg svc.serviceConfig.Type} = oneshot
      test ${lib.escapeShellArg (toString svc.serviceConfig.RemainAfterExit)} = 1
      printf '%s\n' ${lib.escapeShellArg (builtins.toJSON svc.serviceConfig.LoadCredential)} | grep -q 'vikunja-token:/run/secrets/vikunja-provision-token'
      printf '%s\n' ${lib.escapeShellArg (builtins.toJSON svc.after)} | grep -q 'vikunja.service'
      test -x ${svc.serviceConfig.ExecStart}
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

  stalwart016-vmtest = stalwart016VmTest;

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
      touch $out
    '';

  # The third-party adapter must derive the pink-raven rauthy users (can keyed by
  # kanidm login, eric/caroline emailed a set-password link) and the kanidm-backend
  # OAuth2 federation client + person, all from the uniform user schema.
  adapter-module-eval = let
    rauthyUsers = builtins.toJSON adapterEval.config.services.rauthy.provision.users;
    kanidmOauth2 = builtins.toJSON adapterEval.config.services.kanidm.provision.systems.oauth2;
    kanidmPersons = builtins.toJSON adapterEval.config.services.kanidm.provision.persons;
  in
    runCommand "adapter-module-eval" {} ''
      users=${lib.escapeShellArg rauthyUsers}
      oauth2=${lib.escapeShellArg kanidmOauth2}
      persons=${lib.escapeShellArg kanidmPersons}
      for e in can@tartanoglu.com efirley@protonmail.com carolinestahl@gmx.net; do
        printf '%s' "$users" | grep -q "$e" || { echo "adapter: rauthy user $e missing" >&2; exit 1; }
      done
      # eric + caroline get an emailed set-password link; can does not.
      printf '%s' "$users" | grep -q '"sendPasswordEmail":true' \
        || { echo "adapter: no emailed (passwordInitByEmail) rauthy user rendered" >&2; exit 1; }
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
