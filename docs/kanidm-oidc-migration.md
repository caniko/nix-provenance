# Kanidm OIDC migration for existing Immich deployments

Reference for cutting an already-populated Immich instance over from
local-account auth to Kanidm OIDC without detaching photo libraries.

The reconciler and NixOS module in this repo handle the steady state
once the cutover is done. The notes below cover the **first-time
migration** of an Immich instance that already has local accounts with
attached photo libraries.

## Linking semantic is undocumented upstream

Immich's OAuth admin docs
(<https://docs.immich.app/administration/oauth/>) describe the OAuth
configuration surface but do **not** specify what happens when an OIDC
identity logs in with an email that matches an existing local account.
The semantic observed in practice — `oauthId` is set on the existing
account on first login when `oauthId` was empty and email matches — is
implementation behavior, not documented guarantee.

Any migration of pre-existing photo libraries must verify this behavior
against the exact Immich version being deployed **before** flipping OIDC
on for the production users.

## Pre-cutover verification recipe (BLOCKING)

Use this throwaway test on the target Immich version before migrating
any user with attached libraries. The reconciler must not be involved
in this step — it is purely a behavioral check against Immich + Kanidm.

1. Create a throwaway Kanidm person and a matching local Immich account
   with the same email:

   ```sh
   kanidm person create test-oidc "Test OIDC Linking" --name idm_admin
   kanidm person update test-oidc --mail test-oidc@example.com --name idm_admin
   kanidm person credential set-password test-oidc --name idm_admin
   ```

   In the Immich admin UI, create a local account with email
   `test-oidc@example.com` and username `test-oidc`. Note the Immich
   user ID.

2. Create a throwaway Kanidm OAuth2 system for the verification (do
   not reuse the production client):

   ```sh
   kanidm system oauth2 create test-oidc-client "Test OIDC" \
     "https://<immich-domain>" --name idm_admin
   kanidm system oauth2 update-scope-map test-oidc-client \
     idm_all_persons "openid profile email" --name idm_admin
   ```

3. Point Immich's admin OAuth settings at `test-oidc-client` using the
   `basic_secret` printed above. Do this through the admin UI or
   `PUT /api/system-config`; do not commit anything yet.

4. From a logged-out browser, click "Login with OAuth" and complete the
   Kanidm login as `test-oidc`. Observe one of three cases.

| Case | Behavior | Decision |
|------|----------|----------|
| A | Existing `test-oidc` account is logged in; no duplicate appears; library state intact | Auto-link by email — safe. Proceed with cutover. |
| B | A new Immich user appears (kanidm-derived name); original local account untouched | Duplicate. Decide between (i) deleting local accounts pre-cutover and re-attaching libraries, or (ii) a one-time DB merge from local `user_id` to OIDC `user_id`. **Surface to the operator before proceeding.** |
| C | OIDC dance completes but Immich refuses login with an "account exists with this email" error | Hostile interaction. Do not cut over on this Immich version; defer until upstream fixes or a separate re-onboarding plan exists. |

5. Capture the Immich version the verification was performed against,
   for example:

   ```sh
   nix eval --raw .#nixosConfigurations.<host>.config.services.immich.package \
     | grep -oE 'immich-[0-9.]+' | head -1
   ```

   Record the case (A/B/C) and the Immich version in the commit message
   of the cutover change.

6. Tear down the verification artefacts:

   ```sh
   kanidm system oauth2 delete test-oidc-client --name idm_admin
   kanidm person delete test-oidc --name idm_admin
   # Delete test-oidc and any case-B duplicate in the Immich admin UI.
   ```

This verification is the gate for any migration of an Immich instance
that holds existing user libraries. Skipping it risks detaching
`can`'s, `dejana`'s, or any user's photo library on cutover.

## Immich OAuth admin-settings surface

The fields Immich exposes in admin OAuth settings, with the defaults
and conventions the reconciler relies on
(<https://docs.immich.app/administration/oauth/>):

| Field | Value used here | Notes |
|-------|-----------------|-------|
| `Enabled` | `true` | Flips OIDC on. |
| `issuer_url` | `https://<kanidm-domain>/oauth2/openid/<client_id>` | Kanidm well-known endpoint. |
| `client_id` | matches the Kanidm OAuth2 system name | Reconciler uses this for `oauthId` linking via email. |
| `client_secret` | from agenix, passed by file path | Never written to Nix store, never in the Immich DB through Nix. |
| `scope` | `openid email profile` | Profile claim provides the storage-label fallback. |
| `Storage Label Claim` | `preferred_username` (Immich default) | Decides on-disk library directory for new users. |
| `Auto Register` | `true` (Immich default) | New OIDC subjects get an Immich account. |
| Mobile redirect | `https://<immich-domain>/api/oauth/mobile-redirect` | Only required if mobile clients are in scope. |

For users that already exist locally, `Auto Register` is irrelevant —
the linking step happens via email match and empty `oauthId`. For new
users post-cutover, `Storage Label Claim` decides where the library
directory lives.

## Redirect URI shape

The Kanidm OAuth2 system origin URLs that work with Immich:

```
https://<immich-domain>/auth/login         # web login
https://<immich-domain>/user-settings      # web settings (re-link / sign-in)
app.immich:///oauth-callback               # mobile custom-scheme callback
https://<immich-domain>/api/oauth/mobile-redirect  # mobile redirect helper
```

The mobile custom scheme requires Immich's "Mobile Redirect URI" toggle
on. Web-only deployments can drop the last two.

## NixOS wiring pattern (canix reference)

The canix repo wires this on the `immich-provision-safety` branch
(commit `99d2c76`). The shape, verbatim from that commit:

```nix
{
  inputs.immich-provision.url =
    "git+ssh://git@codeberg.org/caniko/immich-provision.git?ref=main";

  # atlas-side (Immich host)
  imports = [inputs.immich-provision.nixosModules.default];

  age.secrets.immich-oidc-client-secret = {
    rekeyFile = secrets.module "immich-oidc-client-secret";
    owner = "immich";
    mode = "0400";
  };

  services.immich = {
    package = pkgsPrimaryGpu.immich.overrideAttrs (old: {
      patches =
        (old.patches or [])
        ++ [
          "${inputs.immich-provision}/patches/immich/0001-add-trusted-local-provision-token.patch"
        ];
    });

    provision = {
      enable = true;
      oauth = {
        enable = true;
        issuerUrl = "https://auth.tartanoglu.com/oauth2/openid/immich";
        clientId = "immich";
        clientSecretFile = config.age.secrets.immich-oidc-client-secret.path;
        mobileOverrideEnabled = true;
        mobileRedirectUri = "https://immich.candee.baby/api/oauth/mobile-redirect";
      };
      users = inputs.immich-provision.lib.usersFromKanidmPersons {
        inherit (kanidmIdentity) persons;
        adminUsers = ["can"];
        storageLabelFrom = "none";
      };
    };
  };
}
```

Kanidm host side (separate machine in the canix layout):

```nix
{
  age.secrets.immich-oidc-client-secret = {
    rekeyFile = secrets.module "immich-oidc-client-secret";
    owner = "kanidm";
    mode = "0400";
  };

  services.kanidm.provision.systems.oauth2.immich =
    inputs.immich-provision.lib.kanidmOAuth2System {
      originUrl = [
        "https://immich.candee.baby/auth/login"
        "https://immich.candee.baby/user-settings"
        "app.immich:///oauth-callback"
        "https://immich.candee.baby/api/oauth/mobile-redirect"
      ];
      originLanding = "https://immich.candee.baby/";
      basicSecretFile = config.age.secrets.immich-oidc-client-secret.path;
    };
}
```

Two important properties of the canix layout:

- The OIDC client secret lives at
  `age/secrets/modules/immich-oidc-client-secret.age` — a **module
  secret**, not a host secret. The same source rekeys to both Immich's
  host (read by user `immich`) and Kanidm's host (read by user
  `kanidm`).
- The patched Immich package (with
  `0001-add-trusted-local-provision-token.patch`) is built by
  overriding `services.immich.package` on the Immich host. The
  reconciler relies on the patch to mint short-lived provisioning
  tokens.

## Branch status

The canix integration above currently lives on the
`immich-provision-safety` branch, not on canix `trunk`. Tracking and
fixes for the provisioning behavior happen here in
`immich-provision`. Anyone propagating the integration to a different
deployment should pin to the same `immich-provision` revision recorded
in that canix commit until the integration lands on canix trunk.

## Acceptance gate for any deployment

Before any cutover that touches existing user libraries:

- The verification recipe above ran against the exact Immich version
  being deployed.
- The observed case (A / B / C) is recorded in the cutover commit
  message together with the Immich version.
- Case A proceeds directly. Case B requires an operator-approved
  fallback path. Case C blocks the cutover.
- The OIDC client secret rekeys to both the Immich service user and
  the Kanidm service user from a single source.
- Post-cutover, the affected users' Immich library, album, and asset
  counts are unchanged compared to a pre-cutover snapshot.
