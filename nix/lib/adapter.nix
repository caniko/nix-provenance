# Third-party identity adapter — pure-Nix primitives a *non-tenant* flake imports
# to integrate its own users + OIDC client into the identity plane (kanidm or
# rauthy) without earning a first-class tenant in this repo.
#
# The tenants under nix/modules/<kind>/ are for systems this flake supports
# directly (immich, rauthy, vikunja, forgejo, stalwart). A closed-source or
# otherwise out-of-scope app (e.g. pink-raven) does NOT get its own module/lib;
# instead it consumes these backend-agnostic primitives. They factor out the
# pattern that was previously hand-written per consumer (see canix
# root/hosts/thething/server/rauthy.nix: usersFromKanidmPersons then external
# users appended with sendPasswordEmail).
#
# Two axes:
#   * backend       — where the app registers: `rauthy` (federates with Rauthy)
#                     or `kanidm` (federates with kanidm directly).
#   * per-user credential — how each user authenticates:
#       - kanidmLogin         : the user already has a kanidm identity. No
#                               credential is stored or emailed here.
#       - passwordInitByEmail : the user has no kanidm identity; Rauthy emails a
#                               one-time set-password link. REQUIRES a mail/SMTP
#                               server (e.g. Stalwart) on the Rauthy host.
{lib}: let
  # Best-effort split of a free-form display name into given/family. Applied at
  # creation only on both backends, so an imperfect split is harmless (the
  # upstream IdP profile claims win on later federated logins).
  splitName = display: let
    words = lib.filter (w: w != "") (lib.splitString " " display);
  in
    if words == []
    then {
      given = null;
      family = null;
    }
    else {
      given = lib.head words;
      family = let
        rest = lib.concatStringsSep " " (lib.tail words);
      in
        if rest == ""
        then null
        else rest;
    };
in rec {
  # ---- credential descriptors ----------------------------------------------
  # A third-party flake tags each user with exactly one of these.

  # Federated: the user already authenticates at kanidm. On the `rauthy` backend
  # this becomes a PASSWORDLESS Rauthy user that auto-links to the kanidm
  # upstream provider on first login; on the `kanidm` backend it is a native
  # kanidm person. Nothing is emailed and no credential is stored by this flake.
  # (This is "can": his kanidm person lives in canix.)
  kanidmLogin = {method = "kanidmLogin";};

  # External: the user has no kanidm identity. On the `rauthy` backend this
  # becomes a NATIVE Rauthy user that Rauthy emails a one-time set-password link
  # to (its `request_reset` flow, run once at creation). REQUIRES an SMTP/mail
  # server (e.g. Stalwart) reachable from the Rauthy host or the mail is never
  # delivered. Invalid on the `kanidm` backend (kanidm owns its own credential
  # reset). (This is "eric"/"caroline".)
  passwordInitByEmail = {
    # Where Rauthy lands the user after they finish setting their password.
    # Point it at the app's login-initiating route, NOT a raw OIDC callback.
    # When null the adapter module fills it from the app's `loginUrl`.
    redirectUri ? null,
  }: {
    method = "passwordInitByEmail";
    inherit redirectUri;
  };

  # External/native: the user's Rauthy password is initialized from a runtime
  # password file, typically an agenix secret path. Rauthy owns the password
  # after account creation; later declarative changes warn and update only the
  # marker hash.
  passwordFromFile = {passwordFile}: {
    method = "passwordFromFile";
    inherit passwordFile;
  };

  isPasswordInitByEmail = c: (c.method or null) == "passwordInitByEmail";
  isKanidmLogin = c: (c.method or null) == "kanidmLogin";
  isPasswordFromFile = c: (c.method or null) == "passwordFromFile";

  # Does this user set contain at least one emailed-set-password user? (Used by
  # the module to gate the mail-server warning/assertion.)
  anyEmailed = users: lib.any (u: isPasswordInitByEmail u.credential) (lib.attrValues users);

  # ---- rauthy backend -------------------------------------------------------

  # Turn a uniform user set into a `services.rauthy.provision.users` attrset
  # (keyed by primary email). `kanidmLogin` users are passwordless/federated and
  # carry the reconciliation-time required upstream provider marker;
  # `passwordInitByEmail` users carry sendPasswordEmail + the redirect.
  #
  #   rauthyUsers {
  #     loginUrl = "https://app.example.com/login";  # default redirect
  #     users = {
  #       can.email = "can@example.com"; can.credential = kanidmLogin;
  #       eric = { email = "eric@x.com"; credential = passwordInitByEmail {}; };
  #     };
  #   }
  rauthyUsers = {
    users,
    # Default post-set-password redirect for emailed users that did not set
    # their own. Usually the consuming app's login route.
    loginUrl ? null,
    language ? "en",
    # Groups applied to EVERY user in the set (e.g. an app-wide access group),
    # on top of each user's own `groups`.
    commonGroups ? [],
  }:
    lib.mapAttrs' (
      name: u: let
        email =
          if (u.email or null) == null
          then throw "adapter.rauthyUsers: user '${name}' must set `email` (Rauthy keys users by email)."
          else u.email;
        cred = u.credential;
        nm =
          if (u.displayName or null) != null
          then splitName u.displayName
          else {
            given = null;
            family = null;
          };
        emailed = isPasswordInitByEmail cred;
        filePassword = isPasswordFromFile cred;
        redirect =
          if (cred.redirectUri or null) != null
          then cred.redirectUri
          else loginUrl;
      in
        if !(isKanidmLogin cred || emailed || filePassword)
        then throw "adapter.rauthyUsers: user '${email}' has an unrecognised credential; use adapter.kanidmLogin, adapter.passwordInitByEmail, or adapter.passwordFromFile."
        else if emailed && filePassword
        then throw "adapter.rauthyUsers: user '${email}' cannot combine passwordInitByEmail and passwordFromFile."
        else if emailed && redirect == null
        then throw "adapter.rauthyUsers: emailed user '${email}' needs a redirect target — set passwordInitByEmail { redirectUri = ...; } or pass loginUrl to rauthyUsers."
        else
          lib.nameValuePair email ({
              present = u.present or true;
              givenName = u.givenName or nm.given;
              familyName = u.familyName or nm.family;
              inherit language;
              roles = u.roles or [];
              groups = lib.unique (commonGroups ++ (u.groups or []));
            }
            // lib.optionalAttrs (isKanidmLogin cred) {
              requiredAuthProvider = "kanidm";
            }
            // lib.optionalAttrs emailed {
              sendPasswordEmail = true;
              passwordEmailRedirectUri = redirect;
            }
            // lib.optionalAttrs filePassword {
              initialPasswordFile = cred.passwordFile;
            })
    )
    users;

  # The distinct Rauthy group names referenced by a user set, so the module can
  # auto-provision them (Rauthy groups must exist before they can be assigned).
  rauthyGroupsOf = users: lib.unique (lib.concatMap (u: u.groups or []) (lib.attrValues users));

  # ---- kanidm backend -------------------------------------------------------

  # Generic kanidm OAuth2 system builder — the federation client an app
  # registers directly at kanidm. The per-tenant immich/forgejo/vikunja
  # `kanidmOAuth2System` helpers are specialisations of this shape; a
  # third-party flake with no tenant uses this directly. Emits a
  # `services.kanidm.provision.systems.oauth2.<name>` attrset.
  kanidmOAuth2System = {
    originUrl,
    # The kanidm group whose members may use the client (scopeMap target).
    group,
    originLanding ? (
      if builtins.isList originUrl
      then lib.head originUrl
      else originUrl
    ),
    displayName ? "App",
    preferShortUsername ? true,
    # Public client (PKCE, no basic secret). Outward web apps usually federate
    # with rauthy instead; a kanidm-backend public client is the SPA/native case.
    public ? false,
    # Required for a confidential (non-public) client; ignored when public.
    basicSecretFile ? null,
    scopes ? ["openid" "profile" "email" "groups"],
  }:
    {
      inherit displayName originUrl originLanding preferShortUsername public;
      scopeMaps.${group} = scopes;
    }
    // lib.optionalAttrs (!public && basicSecretFile != null) {inherit basicSecretFile;};

  # Turn a uniform user set into a `services.kanidm.provision.persons` attrset.
  # Only `kanidmLogin` users are valid here — emailed-init is a rauthy-only flow
  # (kanidm has its own credential-reset path). Every person is added to `group`
  # (the client's scopeMap target) plus any per-user groups. NOTE: the referenced
  # groups must also be declared under `services.kanidm.provision.groups` — the
  # adapter module does this for you.
  kanidmPersons = {
    users,
    group,
  }: let
    managedUsers = lib.filterAttrs (_: u: u.manageProfile or true) users;
  in
    lib.mapAttrs (
      name: u:
        if !isKanidmLogin u.credential
        then throw "adapter.kanidmPersons: user '${name}' must use adapter.kanidmLogin on the kanidm backend (passwordInitByEmail and passwordFromFile are rauthy-only flows)."
        else
          {
            groups = lib.unique ([group] ++ (u.groups or []));
          }
          // lib.optionalAttrs (u.manageProfile or true) {
            present = u.present or true;
            displayName = u.displayName or name;
            mailAddresses = lib.optional ((u.email or null) != null) u.email;
          }
    )
    managedUsers;
}
