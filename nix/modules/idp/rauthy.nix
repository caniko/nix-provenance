# NixOS module: services.rauthy.provision
#
# Declaratively provisions a running Rauthy instance (users, groups, roles,
# OIDC clients) by rendering the option tree to a JSON state file and running
# the `rauthy-provision` reconciler as a Type=oneshot unit ordered after the
# Rauthy service. This is the analogue of `services.kanidm.provision`.
#
# Authentication uses a Rauthy API key. Prefer `apiKeyEnvironmentFile` with
# Rauthy's bootstrap `BOOTSTRAP_API_KEY_SECRET`, so the unit assembles
# `<apiKeyName>$<secret>` at runtime. `apiKeyFile` remains available for an
# already assembled key.
{self}: {
  config,
  lib,
  options,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption optionalAttrs optionalString types;
  cfg = config.services.rauthy.provision;
  passwords = self.lib.passwords;
  generatedApiKeyUnit = "rauthy-bootstrap-api-key";

  presentOption = mkOption {
    type = types.bool;
    default = true;
    description = "Whether the entity should exist. Set to false to delete it (honored unless autoRemove = false).";
  };

  groupSubmodule = types.submodule {options.present = presentOption;};
  roleSubmodule = types.submodule {options.present = presentOption;};
  scopeSubmodule = types.submodule {
    options = {
      present = presentOption;
      attrIncludeAccess = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Custom user attributes to include in access tokens when this custom scope is granted.";
      };
      attrIncludeId = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Custom user attributes to include in ID tokens when this custom scope is granted.";
      };
      claimsAtRoot = mkOption {
        type = types.bool;
        default = false;
        description = "Whether included custom attributes should be emitted as root JWT claims instead of under the custom claim.";
      };
    };
  };
  userAttributeSubmodule = types.submodule {
    options = {
      present = presentOption;
      desc = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional custom user attribute description.";
      };
      defaultValue = mkOption {
        type = types.nullOr types.anything;
        default = null;
        description = "Optional JSON default value for the custom user attribute.";
      };
      userEditable = mkOption {
        type = types.bool;
        default = false;
        description = "Whether users may edit this custom attribute themselves.";
      };
    };
  };

  userSubmodule = types.submodule {
    options = {
      present = presentOption;
      givenName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Given name. Reconciled only when set; null leaves the field unmanaged.";
      };
      clearGivenName = mkOption {
        type = types.bool;
        default = false;
        description = "Clear Rauthy given_name. Use only when the Rauthy user-values policy permits it.";
      };
      familyName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Family name. Reconciled only when set; null leaves the field unmanaged.";
      };
      clearFamilyName = mkOption {
        type = types.bool;
        default = false;
        description = "Clear Rauthy family_name.";
      };
      birthdate = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Birthdate in YYYY-MM-DD form. Reconciled only when set.";
      };
      clearBirthdate = mkOption {
        type = types.bool;
        default = false;
        description = "Clear Rauthy birthdate.";
      };
      timezone = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Rauthy user timezone, for example Europe/Oslo. Reconciled only when set.";
      };
      clearTimezone = mkOption {
        type = types.bool;
        default = false;
        description = "Clear Rauthy timezone.";
      };
      street = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Street address. Reconciled only when set.";
      };
      clearStreet = mkOption {
        type = types.bool;
        default = false;
        description = "Clear Rauthy street address.";
      };
      zip = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "ZIP/postal code. Reconciled only when set.";
      };
      clearZip = mkOption {
        type = types.bool;
        default = false;
        description = "Clear Rauthy ZIP/postal code.";
      };
      city = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "City. Reconciled only when set.";
      };
      clearCity = mkOption {
        type = types.bool;
        default = false;
        description = "Clear Rauthy city.";
      };
      country = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Country. Reconciled only when set.";
      };
      clearCountry = mkOption {
        type = types.bool;
        default = false;
        description = "Clear Rauthy country.";
      };
      phone = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Phone number. Reconciled only when set.";
      };
      clearPhone = mkOption {
        type = types.bool;
        default = false;
        description = "Clear Rauthy phone number.";
      };
      language = mkOption {
        type = types.enum ["de" "en" "fr" "ko" "nb" "ru" "uk" "zhhans"];
        default = "en";
        description = "Rauthy UI language for the user.";
      };
      userExpires = mkOption {
        type = types.nullOr types.int;
        default = null;
        description = "Optional Unix timestamp in seconds after which the Rauthy user expires.";
      };
      roles = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Rauthy role names assigned to the user (reconciled on update).";
      };
      groups = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Rauthy group names assigned to the user (reconciled on update).";
      };
      preferredUsername = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Rauthy preferred_username to set through the admin API.";
      };
      clearPreferredUsername = mkOption {
        type = types.bool;
        default = false;
        description = "Clear Rauthy preferred_username.";
      };
      attributes = mkOption {
        type = types.attrsOf types.anything;
        default = {};
        description = "Custom Rauthy user attribute values, rendered as JSON.";
      };
      requiredAuthProvider = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Reconciliation-time assertion that this user must authenticate
          through the named Rauthy upstream provider. This does not change
          Rauthy's runtime login policy; it rejects local credential drift.
        '';
      };
      sendPasswordEmail = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Email this user a set-password link on first creation (Rauthy's
          request_reset flow). No-op once the user exists, so at most one email
          is ever sent. Use for external users who must set a native Rauthy
          password. Requires passwordEmailRedirectUri.
        '';
      };
      passwordEmailRedirectUri = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Where Rauthy redirects the user after they set their password. Point
          it at the consuming app's login-initiating route (e.g.
          https://app.example.com/login), not a raw OIDC callback. Only used
          when sendPasswordEmail is true.
        '';
      };
      initialPasswordFile = passwords.passwordFileOption;
    };
  };

  clientSubmodule = types.submodule {
    options = {
      present = presentOption;
      name = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Human-readable client name.";
      };
      confidential = mkOption {
        type = types.bool;
        default = true;
        description = "Confidential client (holds a secret). Set false for a public/PKCE-only client.";
      };
      redirectUris = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Allowed OIDC redirect URIs.";
      };
      postLogoutRedirectUris = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Allowed post-logout redirect URIs.";
      };
      allowedOrigins = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Allowed CORS origins.";
      };
      scopes = mkOption {
        type = types.listOf types.str;
        default = ["openid" "profile" "email"];
        description = "Scopes the client may request.";
      };
      defaultScopes = mkOption {
        type = types.listOf types.str;
        default = ["openid" "profile" "email"];
        description = "Scopes granted by default.";
      };
      flowsEnabled = mkOption {
        type = types.listOf types.str;
        default = ["authorization_code" "refresh_token"];
        description = "Enabled OAuth2 flows.";
      };
      enablePkce = mkOption {
        type = types.bool;
        default = true;
        description = "Enable PKCE (S256). Required for public clients.";
      };
      generatedSecretFile = mkOption {
        type = types.nullOr (types.oneOf [types.path types.str]);
        default = null;
        description = ''
          Runtime path where rauthy-provision writes this confidential client's
          generated secret if the file is missing. The path is rendered into the
          state file, but the secret value is generated at activation time and
          never enters the Nix store.
        '';
      };
    };
  };

  providerSubmodule = types.submodule {
    options = {
      present = presentOption;
      name = mkOption {
        type = types.str;
        description = "Display name for the upstream auth provider.";
      };
      typ = mkOption {
        type = types.enum ["oidc" "github" "google" "custom"];
        default = "oidc";
        description = "Rauthy upstream auth provider type.";
      };
      enabled = mkOption {
        type = types.bool;
        default = true;
        description = "Whether this upstream provider is enabled.";
      };
      issuer = mkOption {
        type = types.str;
        description = "Provider issuer URL.";
      };
      authorizationEndpoint = mkOption {
        type = types.str;
        description = "Provider authorization endpoint.";
      };
      tokenEndpoint = mkOption {
        type = types.str;
        description = "Provider token endpoint.";
      };
      userinfoEndpoint = mkOption {
        type = types.str;
        description = "Provider userinfo endpoint.";
      };
      jwksEndpoint = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional provider JWKS endpoint.";
      };
      clientId = mkOption {
        type = types.str;
        description = "Client id Rauthy uses with the upstream provider.";
      };
      clientSecretFile = mkOption {
        type = types.nullOr (types.oneOf [types.path types.str]);
        default = null;
        description = "Runtime file containing the upstream provider client secret.";
      };
      scope = mkOption {
        type = types.str;
        default = "openid email profile";
        description = "Scope string requested from the upstream provider.";
      };
      usePkce = mkOption {
        type = types.bool;
        default = true;
        description = "Use PKCE for upstream provider login.";
      };
      clientSecretBasic = mkOption {
        type = types.bool;
        default = true;
        description = "Authenticate to the upstream token endpoint with client_secret_basic.";
      };
      clientSecretPost = mkOption {
        type = types.bool;
        default = false;
        description = "Authenticate to the upstream token endpoint with client_secret_post.";
      };
      autoOnboarding = mkOption {
        type = types.bool;
        default = false;
        description = "Allow this provider to create new Rauthy users automatically.";
      };
      autoLink = mkOption {
        type = types.bool;
        default = false;
        description = "Link matching-email local users to this provider on first login.";
      };
      adminClaimPath = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional admin-claim path.";
      };
      adminClaimValue = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional admin-claim value.";
      };
      mfaClaimPath = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional MFA-claim path.";
      };
      mfaClaimValue = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional MFA-claim value.";
      };
    };
  };

  generatedApiKeySubmodule = types.submodule {
    options = {
      enable = mkEnableOption "extract a generated first-boot Rauthy API key for rauthy-provision";
      file = mkOption {
        type = types.str;
        default = "/var/lib/rauthy-provision/api-key";
        description = "Runtime path where the full generated `<name>$<secret>` API key is stored.";
      };
      generatedSecretsFile = mkOption {
        type = types.str;
        default = "/var/lib/rauthy/bootstrap.secrets.enc";
        description = "Runtime path to Rauthy's encrypted generated bootstrap secret container.";
      };
      generatedSecretsTtl = mkOption {
        type = types.int;
        default = 0;
        description = "TTL in seconds for the generated bootstrap secret container. 0 disables automatic expiry.";
      };
      configFile = mkOption {
        type = types.nullOr (types.oneOf [types.path types.str]);
        default = null;
        description = ''
          Runtime Rauthy config file passed to `rauthy bootstrap get`. The
          command reads `bootstrap.generated_secrets_file` from this config and
          uses the normal Rauthy config parser, so any environment referenced by
          the config must be available to the extraction unit.
        '';
      };
      environmentFile = mkOption {
        type = types.nullOr (types.oneOf [types.path types.str]);
        default = null;
        description = ''
          Optional environment file loaded before `rauthy bootstrap get`
          parses the Rauthy config. Use this when the config references runtime
          secrets such as ENC_KEY_ACTIVE or ENC_KEYS.
        '';
      };
    };
  };

  transientApiKeySubmodule = types.submodule {
    options = {
      enable = mkEnableOption "mint a short-lived Rauthy API key for each provisioning run";
      name = mkOption {
        type = types.str;
        default = "rauthy-prov-transient";
        description = ''
          Name of the transient API key. Rauthy API-key names are limited to
          24 characters, so this intentionally does not default to
          `${cfg.apiKeyName}-transient` when apiKeyName is the module default.
        '';
      };
      ttl = mkOption {
        type = types.ints.positive;
        default = 600;
        description = "Transient API-key lifetime in seconds.";
      };
    };
  };

  bootstrapApiKeyAccess =
    map
    (group: {
      inherit group;
      access_rights = ["read" "create" "update" "delete"];
    })
    ["Users" "Groups" "Roles" "Clients" "Scopes" "UserAttributes" "AuthProviders"]
    ++ [
      {
        group = "Secrets";
        access_rights = ["read" "update"];
      }
    ]
    ++ lib.optional cfg.transientApiKey.enable {
      group = "ApiKeys";
      access_rights = ["read" "create" "update" "delete"];
    };

  bootstrapApiKeyRequest = {
    name = cfg.apiKeyName;
    exp = null;
    access = bootstrapApiKeyAccess;
  };

  bootstrapApiKeyEnvFile =
    pkgs.runCommand "rauthy-bootstrap-api-key.env" {
      nativeBuildInputs = [pkgs.coreutils];
      apiKeyJson = builtins.toJSON bootstrapApiKeyRequest;
      passAsFile = ["apiKeyJson"];
    } ''
      printf 'BOOTSTRAP_API_KEY=' > "$out"
      base64 -w0 "$apiKeyJsonPath" >> "$out"
      printf '\n' >> "$out"
    '';

  bootstrapApiKeysDir = pkgs.writeTextDir "api_keys.json" (builtins.toJSON [
    {
      name = cfg.apiKeyName;
      exp = null;
      access = bootstrapApiKeyAccess;
      secret = "generate";
    }
  ]);

  manifest = {
    groups = lib.mapAttrs (_: g: {inherit (g) present;}) cfg.groups;
    roles = lib.mapAttrs (_: r: {inherit (r) present;}) cfg.roles;
    scopes =
      lib.mapAttrs (_: s: {
        inherit (s) present;
        attr_include_access = s.attrIncludeAccess;
        attr_include_id = s.attrIncludeId;
        claims_at_root = s.claimsAtRoot;
      })
      cfg.scopes;
    user_attributes =
      lib.mapAttrs (_: a: {
        inherit (a) present;
        desc = a.desc;
        default_value = a.defaultValue;
        user_editable = a.userEditable;
      })
      cfg.userAttributes;
    users = lib.mapAttrs (name: u:
      {
        inherit
          (u)
          present
          language
          roles
          groups
          attributes
          ;
        send_password_email = u.sendPasswordEmail;
      }
      // optionalAttrs (u.requiredAuthProvider != null) {
        required_auth_provider = u.requiredAuthProvider;
      }
      // optionalAttrs (u.givenName != null || u.clearGivenName) {
        given_name =
          if u.clearGivenName
          then null
          else u.givenName;
      }
      // optionalAttrs (u.familyName != null || u.clearFamilyName) {
        family_name =
          if u.clearFamilyName
          then null
          else u.familyName;
      }
      // optionalAttrs (u.birthdate != null || u.clearBirthdate) {
        birthdate =
          if u.clearBirthdate
          then null
          else u.birthdate;
      }
      // optionalAttrs (u.timezone != null || u.clearTimezone) {
        timezone =
          if u.clearTimezone
          then null
          else u.timezone;
      }
      // optionalAttrs (u.street != null || u.clearStreet) {
        street =
          if u.clearStreet
          then null
          else u.street;
      }
      // optionalAttrs (u.zip != null || u.clearZip) {
        zip =
          if u.clearZip
          then null
          else u.zip;
      }
      // optionalAttrs (u.city != null || u.clearCity) {
        city =
          if u.clearCity
          then null
          else u.city;
      }
      // optionalAttrs (u.country != null || u.clearCountry) {
        country =
          if u.clearCountry
          then null
          else u.country;
      }
      // optionalAttrs (u.phone != null || u.clearPhone) {
        phone =
          if u.clearPhone
          then null
          else u.phone;
      }
      // optionalAttrs (u.userExpires != null) {
        user_expires = u.userExpires;
      }
      // optionalAttrs (u.preferredUsername != null || u.clearPreferredUsername) {
        preferred_username =
          if u.clearPreferredUsername
          then null
          else u.preferredUsername;
      }
      // optionalAttrs (u.passwordEmailRedirectUri != null) {
        password_email_redirect_uri = u.passwordEmailRedirectUri;
      }
      // optionalAttrs (u.initialPasswordFile != null) {
        initial_password_file = passwords.userPasswordRuntimePath "rauthy-provision" name;
      })
    cfg.users;
    clients =
      lib.mapAttrs (_: c: {
        inherit (c) present confidential scopes;
        name = c.name;
        redirect_uris = c.redirectUris;
        post_logout_redirect_uris = c.postLogoutRedirectUris;
        allowed_origins = c.allowedOrigins;
        default_scopes = c.defaultScopes;
        flows_enabled = c.flowsEnabled;
        enable_pkce = c.enablePkce;
        generated_secret_file =
          if c.generatedSecretFile == null
          then null
          else toString c.generatedSecretFile;
      })
      cfg.clients;
    providers =
      lib.mapAttrs (_: p: {
        inherit (p) present enabled issuer scope;
        name = p.name;
        typ = p.typ;
        authorization_endpoint = p.authorizationEndpoint;
        token_endpoint = p.tokenEndpoint;
        userinfo_endpoint = p.userinfoEndpoint;
        jwks_endpoint = p.jwksEndpoint;
        client_id = p.clientId;
        client_secret_file =
          if p.clientSecretFile == null
          then null
          else toString p.clientSecretFile;
        use_pkce = p.usePkce;
        client_secret_basic = p.clientSecretBasic;
        client_secret_post = p.clientSecretPost;
        auto_onboarding = p.autoOnboarding;
        auto_link = p.autoLink;
        admin_claim_path = p.adminClaimPath;
        admin_claim_value = p.adminClaimValue;
        mfa_claim_path = p.mfaClaimPath;
        mfa_claim_value = p.mfaClaimValue;
      })
      cfg.providers;
  };

  generatedStateFile = pkgs.writeText "rauthy-provision-state.json" (builtins.toJSON manifest);
  effectiveStateFile =
    if cfg.stateFile != null
    then cfg.stateFile
    else generatedStateFile;

  cliArgs =
    lib.escapeShellArgs
    ([
        "--url"
        cfg.endpoint
        "--state"
        (toString effectiveStateFile)
      ]
      ++ lib.optionals cfg.transientApiKey.enable [
        "--transient-api-key"
        "--transient-api-key-name"
        cfg.transientApiKey.name
        "--transient-api-key-ttl"
        (toString cfg.transientApiKey.ttl)
      ]
      ++ lib.optionals (cfg.apiKeyFile != null) [
        "--api-key-file"
        (toString cfg.apiKeyFile)
      ]
      ++ lib.optionals (cfg.generatedApiKey.enable && !cfg.transientApiKey.enable) [
        "--api-key-file"
        cfg.generatedApiKey.file
      ]
      ++ lib.optionals (cfg.generatedApiKey.enable && cfg.transientApiKey.enable) [
        "--key-manager-api-key-file"
        cfg.generatedApiKey.file
      ]
      ++ lib.optional (!cfg.autoRemove) "--no-auto-remove"
      ++ lib.optional cfg.acceptInvalidCerts "--accept-invalid-certs");

  provisionScript = pkgs.writeShellScript "rauthy-provision-start" ''
    set -eu
    ${optionalString (cfg.apiKeyEnvironmentFile != null) ''
      if [ -z "''${BOOTSTRAP_API_KEY_SECRET:-}" ]; then
        echo "BOOTSTRAP_API_KEY_SECRET is missing from services.rauthy.provision.apiKeyEnvironmentFile" >&2
        exit 1
      fi
      if [ "''${#BOOTSTRAP_API_KEY_SECRET}" -lt 64 ]; then
        echo "BOOTSTRAP_API_KEY_SECRET must be at least 64 characters for Rauthy's bootstrap API-key flow" >&2
        exit 1
      fi
      api_key_secret="''${BOOTSTRAP_API_KEY_SECRET}"
      unset ENC_KEYS ENC_KEY_ACTIVE HQL_SECRET_RAFT HQL_SECRET_API BOOTSTRAP_ADMIN_PASSWORD_ARGON2ID BOOTSTRAP_API_KEY_SECRET
      ${optionalString (!cfg.transientApiKey.enable) ''
        export RAUTHY_PROVISION_API_KEY=${lib.escapeShellArg "${cfg.apiKeyName}$"}"''${api_key_secret}"
      ''}
      ${optionalString cfg.transientApiKey.enable ''
        export RAUTHY_PROVISION_KEY_MANAGER_API_KEY=${lib.escapeShellArg "${cfg.apiKeyName}$"}"''${api_key_secret}"
      ''}
      unset api_key_secret
    ''}
    exec ${lib.escapeShellArg (lib.getExe cfg.package)} ${cliArgs}
  '';
  extractGeneratedApiKeyScript = pkgs.writeShellScript "rauthy-bootstrap-api-key" ''
    set -eu

    out=${lib.escapeShellArg cfg.generatedApiKey.file}
    if [ -s "$out" ]; then
      exit 0
    fi
    parent="$(dirname "$out")"
    mkdir -p "$parent"
    chmod 0700 "$parent"

    tmp="$parent/.api-key.$$.tmp"
    err="$parent/.api-key.$$.err"
    trap 'rm -f "$tmp" "$err"' EXIT
    attempts=30
    attempt=1
    umask 077
    while [ "$attempt" -le "$attempts" ]; do
      rm -f "$tmp" "$err"
      if ${lib.escapeShellArg (lib.getExe config.services.rauthy.package)} bootstrap get \
        --config-file ${lib.escapeShellArg (toString cfg.generatedApiKey.configFile)} \
        --kind api-key \
        --id ${lib.escapeShellArg cfg.apiKeyName} \
        --field token \
        --format raw > "$tmp" 2> "$err" \
        && [ -s "$tmp" ]; then
        mv "$tmp" "$out"
        exit 0
      fi

      if [ "$attempt" -lt "$attempts" ]; then
        sleep 2
      fi
      attempt=$((attempt + 1))
    done

    echo "Rauthy generated bootstrap API key was not available after $attempts attempts." >&2
    echo "Expected generated secrets file: ${lib.escapeShellArg cfg.generatedApiKey.generatedSecretsFile}" >&2
    echo "Expected API key id: ${lib.escapeShellArg cfg.apiKeyName}" >&2
    echo "Config file: ${lib.escapeShellArg (toString cfg.generatedApiKey.configFile)}" >&2
    echo "Diagnostic command: systemctl status rauthy.service rauthy-bootstrap-api-key.service && journalctl -u rauthy.service -u rauthy-bootstrap-api-key.service -n 200 --no-pager" >&2
    if [ -s "$err" ]; then
      echo "Last rauthy bootstrap get error:" >&2
      head -n 20 "$err" >&2
    fi
    exit 1
  '';
in {
  options.services.rauthy.provision = {
    enable = mkEnableOption "declarative Rauthy provisioning (users, groups, roles, OIDC clients)";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.rauthy-provision;
      defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.rauthy-provision";
      description = "The rauthy-provision package to run.";
    };

    endpoint = mkOption {
      type = types.str;
      default = "http://127.0.0.1:8080";
      example = "https://id.example.com";
      description = "Rauthy base URL (the /auth/v1 API path is appended automatically). Prefer the local listener to avoid the reverse proxy.";
    };

    apiKeyFile = mkOption {
      type = types.nullOr (types.oneOf [types.path types.str]);
      default = null;
      description = ''
        Path to a file containing the Rauthy API key (`<name>$<secret>`),
        e.g. an agenix secret path. Prefer `apiKeyEnvironmentFile` for
        bootstrap-generated keys. The key must have read+create+update+delete
        on the Users, Groups, Roles, and Clients access groups.
      '';
    };

    apiKeyEnvironmentFile = mkOption {
      type = types.nullOr (types.oneOf [types.path types.str]);
      default = null;
      description = ''
        Environment file containing `BOOTSTRAP_API_KEY_SECRET`, as used by
        Rauthy's declarative bootstrap API-key flow. When set, the unit exports
        `RAUTHY_PROVISION_API_KEY=<apiKeyName>$<BOOTSTRAP_API_KEY_SECRET>`
        before running the reconciler, keeping the secret out of argv and the
        Nix store.
      '';
    };

    generatedApiKey = mkOption {
      type = generatedApiKeySubmodule;
      default = {};
      description = "First-boot generated API-key extraction for rauthy-provision.";
    };

    transientApiKey = mkOption {
      type = transientApiKeySubmodule;
      default = {};
      description = ''
        Runtime transient API-key mode. The long-lived `apiKeyEnvironmentFile`
        key or `generatedApiKey` key mints a short-lived reconciliation key
        only when the provisioner unit runs, and the provisioner deletes the
        transient key before exit.
      '';
    };

    apiKeyName = mkOption {
      type = types.str;
      default = "rauthy-provision";
      description = "Name of the Rauthy API key created by bootstrap and paired with `BOOTSTRAP_API_KEY_SECRET`.";
    };

    autoRemove = mkOption {
      type = types.bool;
      default = true;
      description = "Honor `present = false` deletions. When false, the reconciler is run with --no-auto-remove and never deletes.";
    };

    acceptInvalidCerts = mkOption {
      type = types.bool;
      default = false;
      description = "Accept invalid TLS certificates when talking to the endpoint.";
    };

    stateFile = mkOption {
      type = types.nullOr (types.oneOf [types.path types.str]);
      default = null;
      description = ''
        JSON state file passed directly to `rauthy-provision --state`.
        When set, this replaces the module-rendered state from `groups`,
        `roles`, `scopes`, `userAttributes`, `users`, `clients`, and
        `providers`. This is the preferred interface for consumers with
        complex registry logic that is better validated outside Nix.
      '';
    };

    serviceAfter = mkOption {
      type = types.listOf types.str;
      default = ["rauthy.service"];
      description = "Units the provisioning oneshot waits for before running.";
    };

    groups = mkOption {
      type = types.attrsOf groupSubmodule;
      default = {};
      description = "Rauthy groups to provision, keyed by group name.";
    };

    roles = mkOption {
      type = types.attrsOf roleSubmodule;
      default = {};
      description = "Rauthy roles to provision, keyed by role name.";
    };

    scopes = mkOption {
      type = types.attrsOf scopeSubmodule;
      default = {};
      description = "Rauthy custom scopes to provision, keyed by scope name.";
    };

    userAttributes = mkOption {
      type = types.attrsOf userAttributeSubmodule;
      default = {};
      description = "Rauthy custom user attributes to provision, keyed by attribute name.";
    };

    users = mkOption {
      type = types.attrsOf userSubmodule;
      default = {};
      description = ''
        Rauthy users to provision, keyed by primary email address. Users are
        created passwordless (no email sent); with an upstream OIDC provider and
        Auto-Link enabled, a matching-email account auto-links on first login.
      '';
    };

    clients = mkOption {
      type = types.attrsOf clientSubmodule;
      default = {};
      description = "OIDC clients (relying parties) to provision, keyed by client id.";
    };

    providers = mkOption {
      type = types.attrsOf providerSubmodule;
      default = {};
      description = "Upstream auth providers to provision, keyed by provider id.";
    };
  };

  config = mkIf cfg.enable (lib.mkMerge (
    [
      {
        assertions =
          [
            {
              assertion = cfg.apiKeyFile != null || cfg.apiKeyEnvironmentFile != null || cfg.generatedApiKey.enable;
              message = "services.rauthy.provision must set apiKeyFile, apiKeyEnvironmentFile, or generatedApiKey.enable when provisioning is enabled.";
            }
            {
              assertion =
                lib.length (lib.filter (x: x) [
                  (cfg.apiKeyFile != null)
                  (cfg.apiKeyEnvironmentFile != null)
                  cfg.generatedApiKey.enable
                ])
                == 1;
              message = "services.rauthy.provision must set only one of apiKeyFile, apiKeyEnvironmentFile, or generatedApiKey.enable.";
            }
            {
              assertion = cfg.apiKeyName != "" && !(lib.hasInfix "$" cfg.apiKeyName);
              message = "services.rauthy.provision.apiKeyName must be non-empty and must not contain '$'.";
            }
            {
              assertion =
                cfg.stateFile
                == null
                || (cfg.groups
                  == {}
                  && cfg.roles == {}
                  && cfg.scopes == {}
                  && cfg.userAttributes == {}
                  && cfg.users == {}
                  && cfg.clients == {}
                  && cfg.providers == {});
              message = "services.rauthy.provision.stateFile replaces groups, roles, scopes, userAttributes, users, clients, and providers; do not set both.";
            }
          ]
          ++ lib.optionals (cfg.stateFile == null) (
            lib.mapAttrsToList (n: c: {
              assertion = c.generatedSecretFile == null || c.confidential;
              message = "services.rauthy.provision.clients.${n}.generatedSecretFile requires confidential = true.";
            })
            cfg.clients
            ++ lib.mapAttrsToList (n: p: {
              assertion = !(p.clientSecretBasic || p.clientSecretPost) || p.clientSecretFile != null;
              message = "services.rauthy.provision.providers.${n} enables client-secret auth but has no clientSecretFile.";
            })
            cfg.providers
            ++ lib.flatten (lib.mapAttrsToList (name: user: [
                {
                  assertion = !(user.givenName != null && user.clearGivenName);
                  message = "services.rauthy.provision.users.${name} cannot set both givenName and clearGivenName.";
                }
                {
                  assertion = !(user.familyName != null && user.clearFamilyName);
                  message = "services.rauthy.provision.users.${name} cannot set both familyName and clearFamilyName.";
                }
                {
                  assertion = !(user.birthdate != null && user.clearBirthdate);
                  message = "services.rauthy.provision.users.${name} cannot set both birthdate and clearBirthdate.";
                }
                {
                  assertion = !(user.timezone != null && user.clearTimezone);
                  message = "services.rauthy.provision.users.${name} cannot set both timezone and clearTimezone.";
                }
                {
                  assertion = !(user.street != null && user.clearStreet);
                  message = "services.rauthy.provision.users.${name} cannot set both street and clearStreet.";
                }
                {
                  assertion = !(user.zip != null && user.clearZip);
                  message = "services.rauthy.provision.users.${name} cannot set both zip and clearZip.";
                }
                {
                  assertion = !(user.city != null && user.clearCity);
                  message = "services.rauthy.provision.users.${name} cannot set both city and clearCity.";
                }
                {
                  assertion = !(user.country != null && user.clearCountry);
                  message = "services.rauthy.provision.users.${name} cannot set both country and clearCountry.";
                }
                {
                  assertion = !(user.phone != null && user.clearPhone);
                  message = "services.rauthy.provision.users.${name} cannot set both phone and clearPhone.";
                }
                {
                  assertion = !(user.preferredUsername != null && user.clearPreferredUsername);
                  message = "services.rauthy.provision.users.${name} cannot set both preferredUsername and clearPreferredUsername.";
                }
                {
                  assertion = !user.sendPasswordEmail || user.passwordEmailRedirectUri != null;
                  message = "services.rauthy.provision.users.${name}.passwordEmailRedirectUri is required when sendPasswordEmail = true.";
                }
                {
                  assertion = !(user.sendPasswordEmail && user.initialPasswordFile != null);
                  message = "services.rauthy.provision.users.${name} cannot set both sendPasswordEmail and initialPasswordFile.";
                }
                {
                  assertion =
                    user.requiredAuthProvider
                    == null
                    || (!user.sendPasswordEmail && user.initialPasswordFile == null);
                  message = "services.rauthy.provision.users.${name} with requiredAuthProvider cannot use sendPasswordEmail or initialPasswordFile.";
                }
              ])
              cfg.users)
          )
          ++ [
            {
              assertion = !cfg.generatedApiKey.enable || cfg.generatedApiKey.configFile != null;
              message = "services.rauthy.provision.generatedApiKey.configFile is required when generatedApiKey.enable = true.";
            }
            {
              assertion = !cfg.transientApiKey.enable || cfg.apiKeyEnvironmentFile != null || cfg.generatedApiKey.enable;
              message = "services.rauthy.provision.transientApiKey.enable requires apiKeyEnvironmentFile or generatedApiKey as the key-manager source.";
            }
          ];

        systemd.services.${generatedApiKeyUnit} = mkIf cfg.generatedApiKey.enable {
          description = "Extract generated Rauthy bootstrap API key";
          after = ["rauthy.service"];
          requires = ["rauthy.service"];
          path = [pkgs.coreutils];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = extractGeneratedApiKeyScript;
            EnvironmentFile = lib.optional (cfg.generatedApiKey.environmentFile != null) (toString cfg.generatedApiKey.environmentFile);
            # Rauthy can be active before first-boot bootstrap has written the
            # generated secret container.
            Restart = "on-failure";
            RestartSec = "10s";
          };

          unitConfig = {
            StartLimitBurst = 6;
            StartLimitIntervalSec = 300;
          };
        };

        systemd.services.rauthy-provision = {
          description = "Declaratively provision Rauthy (users, groups, roles, clients, providers)";
          after = cfg.serviceAfter ++ lib.optional cfg.generatedApiKey.enable "${generatedApiKeyUnit}.service";
          requires = cfg.serviceAfter ++ lib.optional cfg.generatedApiKey.enable "${generatedApiKeyUnit}.service";
          wantedBy = ["multi-user.target"];
          restartTriggers = [effectiveStateFile];

          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = provisionScript;
            EnvironmentFile = lib.mkIf (cfg.apiKeyEnvironmentFile != null) [(toString cfg.apiKeyEnvironmentFile)];
            LoadCredential = passwords.userPasswordCredentials "rauthy-provision" cfg.users;
            StateDirectory = "rauthy-provision";
            StateDirectoryMode = "0700";
            # Rauthy may still be warming up when the unit first fires.
            Restart = "on-failure";
            RestartSec = "10s";
          };

          unitConfig = {
            StartLimitBurst = 6;
            StartLimitIntervalSec = 300;
          };
        };
      }
    ]
    ++ lib.optional (lib.hasAttrByPath ["services" "rauthy" "settings"] options) {
      services.rauthy.settings.bootstrap = mkIf cfg.generatedApiKey.enable {
        bootstrap_dir = toString bootstrapApiKeysDir;
        generated_secrets_file = cfg.generatedApiKey.generatedSecretsFile;
        generated_secrets_ttl = cfg.generatedApiKey.generatedSecretsTtl;
      };
    }
    ++ lib.optional (lib.hasAttrByPath ["services" "rauthy" "environmentFiles"] options) {
      services.rauthy.environmentFiles = mkIf (cfg.apiKeyEnvironmentFile != null) [bootstrapApiKeyEnvFile];
    }
  ));
}
