# NixOS module: services.provenance.externalApps.<name>
#
# The ergonomic adapter a third-party (often non-OSS, out-of-scope) flake imports
# to integrate ONE app's OIDC client + its users into either Rauthy or kanidm,
# in a single declarative block, without earning a tenant in this repo. It is a
# thin writer over the existing provisioners — it sets `services.rauthy.provision`
# / `services.kanidm.provision` values from the backend-agnostic `lib.adapter`
# primitives, and never owns a reconciler of its own.
#
# REQUIREMENTS on the consumer:
#   * rauthy backend → also import `nixosModules.rauthy` and enable
#     `services.rauthy.provision` (this module fills clients/users/groups).
#   * kanidm backend → `services.kanidm` (nixpkgs) provides the
#     `services.kanidm.provision` options this module fills.
#   * passwordInitByEmail users → the Rauthy host must have SMTP configured
#     (e.g. relaying through Stalwart) or the set-password mail is never sent;
#     acknowledge with `mailServerConfigured = true` to silence the warning.
{self}: {
  config,
  lib,
  ...
}: let
  inherit (lib) mkOption mkIf mkMerge types;
  adapter = self.lib.adapter;

  cfg = config.services.provenance.externalApps;
  apps = lib.filterAttrs (_: a: a.enable) cfg;
  rauthyApps = lib.filterAttrs (_: a: a.backend == "rauthy") apps;
  kanidmApps = lib.filterAttrs (_: a: a.backend == "kanidm") apps;

  # ---- user submodule (uniform across backends) ----
  userType = types.submodule {
    options = {
      present = mkOption {
        type = types.bool;
        default = true;
        description = "Whether the user should exist. Set false to delete it (honored by the backend reconciler).";
      };
      email = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Primary email. REQUIRED on the rauthy backend (Rauthy keys users by email); the primary mail address on the kanidm backend.";
      };
      displayName = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "Eric Firley";
        description = "Human display name. Split best-effort into given/family at creation only.";
      };
      manageProfile = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether this app integration owns kanidm person profile fields such as
          displayName and mailAddresses. Set false for users already declared by
          the host identity baseline when the app only needs group membership.
        '';
      };
      credential = mkOption {
        type = types.attrs;
        example = lib.literalExpression "self.lib.adapter.passwordInitByEmail {}";
        description = ''
          The credential strategy descriptor: `adapter.kanidmLogin` (federated,
          nothing emailed) or `adapter.passwordInitByEmail { redirectUri ? null; }`
          (native Rauthy user emailed a set-password link). passwordInitByEmail is
          valid only on the rauthy backend.
        '';
      };
      roles = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Rauthy roles to assign (rauthy backend only; ignored on kanidm).";
      };
      groups = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Extra groups beyond the app's accessGroup (rauthy groups or kanidm groups per backend).";
      };
    };
  };

  appType = types.submodule ({name, ...}: {
    options = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Whether to provision this app.";
      };
      backend = mkOption {
        type = types.enum ["rauthy" "kanidm"];
        default = "rauthy";
        description = ''
          Where the app registers. `rauthy` federates the app with Rauthy
          (outward-facing services) — required for any passwordInitByEmail user.
          `kanidm` federates the app directly with kanidm (internal services).
        '';
      };
      displayName = mkOption {
        type = types.str;
        default = name;
        description = "Human-readable app name shown in the IdP.";
      };
      loginUrl = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "https://app.example.com/login";
        description = "App login-initiating route. Default redirect target for emailed set-password links.";
      };
      accessGroup = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "${name}-users";
        description = ''
          Group granting access to the app. On the rauthy backend it is OPTIONAL:
          when set, it is created and assigned to every one of the app's users (an
          app-wide access group); when null no group is created — leave it null
          when the app gates access itself (e.g. its own allowlist). On the kanidm
          backend a group is always required (it is the OAuth2 scopeMap target);
          null falls back to "<name>-users".
        '';
      };

      # ---- OIDC client wiring ----
      redirectUris = mkOption {
        type = types.listOf types.str;
        default = [];
        example = ["https://app.example.com/auth/callback"];
        description = "Allowed OIDC redirect URIs (rauthy client redirect_uris / kanidm originUrl).";
      };
      postLogoutRedirectUris = mkOption {
        type = types.listOf types.str;
        default = [];
        example = ["https://app.example.com/"];
        description = "Allowed Rauthy post-logout redirect URIs (rauthy backend only).";
      };
      allowedOrigins = mkOption {
        type = types.listOf types.str;
        default = [];
        example = ["https://app.example.com"];
        description = "Allowed browser/CORS origins for the Rauthy client (rauthy backend only).";
      };
      scopes = mkOption {
        type = types.listOf types.str;
        default = ["openid" "profile" "email" "groups"];
        description = "Scopes the client may request.";
      };
      confidential = mkOption {
        type = types.bool;
        default = false;
        description = "Confidential client (holds a secret). Default false — outward web apps use public PKCE so no secret is stored or synced.";
      };

      # ---- kanidm-backend extras ----
      originLanding = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "kanidm Apps-listing landing URL (kanidm backend only). Defaults to the first redirect URI.";
      };
      basicSecretFile = mkOption {
        type = types.nullOr (types.oneOf [types.path types.str]);
        default = null;
        description = "Runtime path to the OAuth2 basic secret for a confidential kanidm client. Never a Nix store path.";
      };

      # ---- users ----
      users = mkOption {
        type = types.attrsOf userType;
        default = {};
        description = "The app's users, in a uniform backend-agnostic schema.";
      };

      # ---- mail acknowledgement ----
      mailServerConfigured = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Set true once the Rauthy host has an SMTP/mail server (e.g. Stalwart)
          wired to actually deliver the passwordInitByEmail set-password links.
          Purely an acknowledgement — it silences the missing-mail-server warning;
          delivery itself is Rauthy's SMTP config (out of this module's view).
        '';
      };
    };
  });

  # kanidm always needs a scopeMap target group; fall back to "<name>-users".
  kanidmGroupOf = n: a:
    if a.accessGroup != null
    then a.accessGroup
    else "${n}-users";

  # kanidm originLanding is a required string upstream; only forward it when the
  # consumer set it, otherwise let lib.adapter default it to the first redirect.
  kanidmSystemFor = n: a:
    adapter.kanidmOAuth2System ({
        displayName = a.displayName;
        originUrl = a.redirectUris;
        group = kanidmGroupOf n a;
        public = !a.confidential;
        basicSecretFile = a.basicSecretFile;
        scopes = a.scopes;
      }
      // lib.optionalAttrs (a.originLanding != null) {inherit (a) originLanding;});

  kanidmGroupNames = lib.unique (lib.concatMap (
      n: lib.singleton (kanidmGroupOf n kanidmApps.${n}) ++ adapter.rauthyGroupsOf kanidmApps.${n}.users
    )
    (lib.attrNames kanidmApps));
  unmanagedMembersFor = group:
    lib.unique (lib.concatMap (
        n: let
          a = kanidmApps.${n};
        in
          lib.attrNames (lib.filterAttrs (_: u:
            !(u.manageProfile or true)
            && (u.present or true)
            && builtins.elem group ([(kanidmGroupOf n a)] ++ (u.groups or [])))
          a.users)
      )
      (lib.attrNames kanidmApps));
in {
  options.services.provenance.externalApps = mkOption {
    type = types.attrsOf appType;
    default = {};
    description = ''
      Third-party apps to integrate into the identity plane (kanidm or rauthy)
      without a first-class tenant. Each app declares its OIDC client + users in
      one block; the adapter writes the matching `services.<idp>.provision` values.
    '';
  };

  config = mkIf (apps != {}) {
    assertions =
      # passwordInitByEmail is a rauthy-only flow.
      lib.mapAttrsToList (n: a: {
        assertion = a.backend == "rauthy" || !(adapter.anyEmailed a.users);
        message = "services.provenance.externalApps.${n}: passwordInitByEmail users require backend = \"rauthy\" (kanidm has no emailed set-password flow). Either move the app to rauthy or give those users adapter.kanidmLogin.";
      })
      apps
      # both backends need at least one redirect URI to register a client.
      ++ lib.mapAttrsToList (n: a: {
        assertion = a.redirectUris != [];
        message = "services.provenance.externalApps.${n}: redirectUris must be set (the OIDC callback / kanidm originUrl).";
      })
      apps
      # confidential kanidm clients need a basic-secret file.
      ++ lib.mapAttrsToList (n: a: {
        assertion = !(a.backend == "kanidm" && a.confidential && a.basicSecretFile == null);
        message = "services.provenance.externalApps.${n}: a confidential kanidm client needs basicSecretFile (a runtime path, never a Nix store path).";
      })
      kanidmApps;

    # Surface the mail-server dependency for emailed users until acknowledged.
    warnings = lib.mapAttrsToList (
      n: _: "services.provenance.externalApps.${n}: has passwordInitByEmail users — the Rauthy host needs SMTP (e.g. relaying through Stalwart) to deliver the set-password links. Set mailServerConfigured = true once that is wired to silence this warning."
    ) (lib.filterAttrs (_: a: adapter.anyEmailed a.users && !a.mailServerConfigured) rauthyApps);

    # ---- rauthy backend output ----
    services.rauthy.provision = mkIf (rauthyApps != {}) {
      clients =
        lib.mapAttrs (_: a: {
          name = a.displayName;
          inherit (a) confidential;
          enablePkce = true;
          redirectUris = a.redirectUris;
          postLogoutRedirectUris = a.postLogoutRedirectUris;
          allowedOrigins = a.allowedOrigins;
          scopes = a.scopes;
          defaultScopes = a.scopes;
        })
        rauthyApps;

      # Merge all rauthy apps' users (keyed by email). Distinct apps keying the
      # same email is a real conflict (loud Nix merge error) — intentional. An
      # app's accessGroup, when set, is applied to all its users.
      users = mkMerge (lib.mapAttrsToList (
          _: a:
            adapter.rauthyUsers {
              inherit (a) users;
              loginUrl = a.loginUrl;
              commonGroups = lib.optional (a.accessGroup != null) a.accessGroup;
            }
        )
        rauthyApps);

      # Provision only groups actually referenced: a non-null accessGroup plus any
      # per-user groups. An app that gates access itself (accessGroup = null) adds
      # no spurious group.
      groups = lib.genAttrs (lib.unique (lib.concatMap (a: (lib.optional (a.accessGroup != null) a.accessGroup) ++ adapter.rauthyGroupsOf a.users) (lib.attrValues rauthyApps))) (_: {});
    };

    # ---- kanidm backend output ----
    services.kanidm.provision = mkIf (kanidmApps != {}) {
      systems.oauth2 = lib.mapAttrs kanidmSystemFor kanidmApps;

      persons = mkMerge (lib.mapAttrsToList (
          n: a:
            adapter.kanidmPersons {
              inherit (a) users;
              group = kanidmGroupOf n a;
            }
        )
        kanidmApps);

      # Profile-owned users derive membership from persons. Existing host-owned
      # users are attached directly so the app never emits an incomplete person.
      groups = lib.genAttrs kanidmGroupNames (group: {
        members = lib.mkAfter (unmanagedMembersFor group);
      });
    };
  };
}
