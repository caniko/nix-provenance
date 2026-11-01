{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.matrix-tuwunel;
  pcfg = cfg.provision;
  passwords = self.lib.passwords;
  system = pkgs.stdenv.hostPlatform.system;

  defaultProvisionPackage = lib.attrByPath ["packages" system "tuwunel-provision"] pkgs.tuwunel-provision self;
  oidcCredentialName = name: passwords.credentialName "oidc-${name}";
  toml = pkgs.formats.toml {};
  registrationBootstrapRuntimeConfig = "/var/lib/tuwunel/provision-registration.toml";
  registrationBootstrapReloadCommand = "server reload-config ${registrationBootstrapRuntimeConfig}";

  matches = pattern: value: builtins.match pattern value != null;
  validIpv4 = host: matches "[0-9]{1,3}([.][0-9]{1,3}){3}" host && lib.all (part: lib.strings.toIntBase10 part <= 255) (lib.splitString "." host);
  validIpv6 = host: let
    # nixpkgs' IPv6 parser does not handle an embedded IPv4 tail; convert it to
    # two hextets, then reuse the parser for compression and group-count checks.
    mixed = builtins.match "(.*:)([0-9]+([.][0-9]+){3})" host;
    octets =
      if mixed == null
      then []
      else map lib.strings.toIntBase10 (lib.splitString "." (builtins.elemAt mixed 1));
    expanded =
      if mixed == null
      then host
      else "${builtins.head mixed}${lib.toHexString ((builtins.elemAt octets 0) * 256 + builtins.elemAt octets 1)}:${lib.toHexString ((builtins.elemAt octets 2) * 256 + builtins.elemAt octets 3)}";
  in
    (mixed == null || (validIpv4 (builtins.elemAt mixed 1) && lib.all (part: part == "0" || !lib.hasPrefix "0" part) (lib.splitString "." (builtins.elemAt mixed 1))))
    && lib.all (part: part == "" || matches "[0-9A-Fa-f]{1,4}" part) (lib.splitString ":" expanded)
    && (builtins.tryEval (lib.network.ipv6.fromString expanded).address).success;
  validServerName = server: let
    ipv6 = builtins.match "[[]([0-9A-Fa-f:.]+)[]](:[0-9]{1,5})?" server;
    dns = builtins.match "([A-Za-z0-9.-]{1,255})(:[0-9]{1,5})?" server;
    host =
      if dns == null
      then ""
      else builtins.head dns;
  in
    if ipv6 != null
    then validIpv6 (builtins.head ipv6)
    else dns != null && (!matches "[0-9]+([.][0-9]+){3}" host || validIpv4 host);
  validRoomId = id: let
    legacy = builtins.match "!([^:]+):(.+)" id;
  in
    builtins.stringLength id
    <= 255
    && (
      if legacy != null
      then validServerName (builtins.elemAt legacy 1)
      # A 32-byte hash leaves two zero padding bits in the final sextet.
      else matches "![A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]" id
    );

  userSubmodule = types.submodule {
    options = {
      passwordFile = passwords.passwordFileOption;
      admin = mkOption {
        type = types.bool;
        default = false;
        description = "Whether this user should have server admin privileges.";
      };
      displayName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional Matrix display name for the user.";
      };
    };
  };

  roomSubmodule = types.submodule {
    options = {
      alias = mkOption {
        type = types.str;
        description = "Canonical Matrix room alias, for example #canix-alerts:matrix.example.com.";
      };
      name = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional human-readable Matrix room name.";
      };
      topic = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional Matrix room topic.";
      };
      invite = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Matrix user IDs to invite to the room.";
      };
      creator = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Localpart of a provisioned user that creates and reconciles the room.
          Use this for private rooms whose membership must exclude the provisioning admin.
        '';
      };
      encrypted = mkOption {
        type = types.bool;
        default = false;
        description = "Require encryption in the initial room state and verify it on reconciliation.";
      };
      expectedRoomId = mkOption {
        type = types.nullOr (types.addCheck types.str validRoomId);
        default = null;
        description = "Live room ID (legacy domain-qualified or v12 hash-based) pinned after bootstrap; fail if this alias resolves elsewhere.";
      };
    };
  };

  oidcProviderSubmodule = types.submodule {
    options = {
      brand = mkOption {
        type = types.str;
        description = "OIDC provider brand/software name used by Tuwunel.";
      };
      clientId = mkOption {
        type = types.str;
        description = "OIDC client_id registered with the provider.";
      };
      clientSecretFile = mkOption {
        type = types.oneOf [types.path types.str];
        description = "Runtime file containing the OIDC client secret.";
      };
      issuerUrl = mkOption {
        type = types.str;
        description = "OIDC issuer URL published by the provider.";
      };
      callbackUrl = mkOption {
        type = types.str;
        description = "Tuwunel SSO callback URL registered with the provider.";
      };
      scope = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "OIDC scopes requested from the provider.";
      };
      useridClaims = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Claims Tuwunel may use to derive Matrix user IDs.";
      };
      trusted = mkOption {
        type = types.bool;
        default = false;
        description = "Whether this self-hosted provider may attach to matching Matrix users.";
      };
      registration = mkOption {
        type = types.bool;
        default = true;
        description = "Whether this provider may create Matrix users.";
      };
      uniqueIdFallbacks = mkOption {
        type = types.bool;
        default = true;
        description = "Whether Tuwunel may generate random fallback user IDs.";
      };
      default = mkOption {
        type = types.bool;
        default = false;
        description = "Whether this provider is the default SSO provider.";
      };
      displayName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional provider display name shown to users.";
      };
    };
  };

  stateFile = pkgs.writeText "tuwunel-provision-state.json" (builtins.toJSON {
    server_name = cfg.settings.global.server_name;
    port = builtins.head cfg.settings.global.port;
    admin_token_user = pcfg.adminTokenUser;
    users =
      lib.mapAttrs (name: user: {
        inherit (user) admin;
        display_name = user.displayName;
        credential_name = passwords.credentialName name;
      })
      pcfg.users;
    inherit (pcfg) rooms;
  });
  registrationBootstrapClosedConfig = toml.generate "tuwunel-provision-registration-closed.toml" {
    global = cfg.settings.global;
  };
  registrationBootstrapOpenConfig = toml.generate "tuwunel-provision-registration-open.toml" {
    global =
      cfg.settings.global
      // {
        allow_registration = true;
        yes_i_am_very_very_sure_i_want_an_open_registration_server_prone_to_abuse = true;
      };
  };
in {
  options.services.matrix-tuwunel.provision = {
    enable = mkEnableOption "declarative tuwunel user provisioning";

    provisionPackage = mkOption {
      type = types.package;
      default = defaultProvisionPackage;
      defaultText = "self.packages.\${system}.tuwunel-provision";
      description = "tuwunel-provision binary for auto-bootstrap and user provisioning.";
    };

    adminTokenFile = mkOption {
      type = types.str;
      default = "/var/lib/tuwunel/admin-token";
      description = ''
        Runtime path to a Matrix access token with admin privileges.
        On first run, the provisioner auto-bootstraps by registering the first
        admin user via open registration and writes the token to this path.
      '';
    };

    users = mkOption {
      type = types.attrsOf userSubmodule;
      default = {};
      description = ''
        Matrix users to provision, keyed by localpart
        (username without @ or server name).
      '';
    };

    rooms = mkOption {
      type = types.attrsOf roomSubmodule;
      default = {};
      description = "Matrix rooms to create and invite service accounts into.";
    };

    adminTokenUser = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Optional provisioned localpart whose password login should refresh
        adminTokenFile after reconciliation. Use this when migrating the
        bootstrap admin token away from a human account.
      '';
    };

    registrationBootstrap = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether the provisioner may temporarily reload Tuwunel with public
          registration enabled when it must create a missing local account and
          the Synapse admin user API is unavailable.
        '';
      };
    };

    oidcProviders = mkOption {
      type = types.attrsOf oidcProviderSubmodule;
      default = {};
      description = "OIDC identity providers to render into Tuwunel configuration.";
    };
  };

  config = mkIf pcfg.enable {
    assertions = [
      {
        assertion = config.services.matrix-tuwunel.enable;
        message = "services.matrix-tuwunel.provision requires services.matrix-tuwunel.enable = true.";
      }
    ];

    services.matrix-tuwunel.settings.global = {
      admin_signal_execute = lib.mkIf pcfg.registrationBootstrap.enable [
        registrationBootstrapReloadCommand
      ];
      identity_provider = lib.mapAttrs (name: provider:
        {
          inherit (provider) brand;
          client_id = provider.clientId;
          client_secret_file = "/run/credentials/tuwunel.service/${oidcCredentialName name}";
          issuer_url = provider.issuerUrl;
          callback_url = provider.callbackUrl;
          inherit (provider) scope trusted registration default;
          userid_claims = provider.useridClaims;
          unique_id_fallbacks = provider.uniqueIdFallbacks;
        }
        // lib.optionalAttrs (provider.displayName != null) {
          name = provider.displayName;
        })
      pcfg.oidcProviders;
    };

    systemd.services.tuwunel.serviceConfig.LoadCredential = lib.mkAfter (
      lib.mapAttrsToList (
        name: provider: "${oidcCredentialName name}:${toString provider.clientSecretFile}"
      )
      pcfg.oidcProviders
    );

    systemd.services.tuwunel-provision = {
      description = "Declaratively provision tuwunel Matrix users";
      after = ["tuwunel.service"];
      requires = ["tuwunel.service"];
      wantedBy = ["multi-user.target"];
      restartTriggers = [stateFile];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${lib.getExe pcfg.provisionPackage} --state ${stateFile} --admin-token-file ${pcfg.adminTokenFile} --credential-dir %d --marker-dir /var/lib/tuwunel/markers${lib.optionalString pcfg.registrationBootstrap.enable " --registration-bootstrap-open-config ${registrationBootstrapOpenConfig} --registration-bootstrap-closed-config ${registrationBootstrapClosedConfig} --registration-bootstrap-runtime-config ${registrationBootstrapRuntimeConfig} --systemctl ${pkgs.systemd}/bin/systemctl --tuwunel-service tuwunel.service"} --ready-timeout 30";
        LoadCredential = passwords.userPasswordCredentials "tuwunel-provision" pcfg.users;
      };
    };
  };
}
