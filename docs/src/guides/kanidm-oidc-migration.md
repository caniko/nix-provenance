# Kanidm OIDC Migration for Existing Immich Deployments

Reference for cutting an already-populated Immich instance over from
local-account auth to Kanidm OIDC without detaching photo libraries.

The reconciler and NixOS module in this repo handle the steady state once the
cutover is done. The notes below cover the **first-time migration** of an
Immich instance that already has local accounts with attached photo libraries.

## Linking semantic is undocumented upstream

Immich's OAuth admin docs
(<https://docs.immich.app/administration/oauth/>) describe the OAuth
configuration surface but do **not** specify what happens when an OIDC identity
logs in with an email that matches an existing local account. The semantic
observed in practice, `oauthId` is set on the existing account on first login
when `oauthId` was empty and email matches, is implementation behavior, not a
documented guarantee.

Any migration of pre-existing photo libraries must verify this behavior against
the exact Immich version being deployed **before** flipping OIDC on for the
production users.

## Pre-cutover verification recipe (blocking)

Use this throwaway test on the target Immich version before migrating any user
with attached libraries. The reconciler must not be involved in this step. It
is purely a behavioral check against Immich plus Kanidm.

1. Create a throwaway Kanidm person and a matching local Immich account with
   the same email:

   ```sh
   kanidm person create test-oidc "Test OIDC Linking" --name idm_admin
   kanidm person update test-oidc --mail test-oidc@example.com --name idm_admin
   kanidm person credential set-password test-oidc --name idm_admin
   ```

   In the Immich admin UI, create a local account with email
   `test-oidc@example.com` and username `test-oidc`. Note the Immich user ID.

2. Create a throwaway Kanidm OAuth2 system for the verification:

   ```sh
   kanidm system oauth2 create test-oidc-client "Test OIDC" \
     "https://<immich-domain>" --name idm_admin
   kanidm system oauth2 update-scope-map test-oidc-client \
     idm_all_persons "openid profile email" --name idm_admin
   ```

3. Point Immich's admin OAuth settings at `test-oidc-client` using the
   `basic_secret` printed above. Do this through the admin UI or
   `PUT /api/system-config`; do not commit anything yet.

4. From a logged-out browser, click "Login with OAuth" and complete the Kanidm
   login as `test-oidc`. Observe one of three cases.

| Case | Behavior | Decision |
|------|----------|----------|
| A | Existing `test-oidc` account is logged in; no duplicate appears; library state intact | Auto-link by email, safe to proceed |
| B | A new Immich user appears; original local account untouched | Duplicate. Decide between deleting local accounts pre-cutover and re-attaching libraries, or a one-time DB merge |
| C | OIDC completes but Immich refuses login with an "account exists with this email" error | Block the cutover on this Immich version |

5. Capture the Immich version the verification was performed against:

   ```sh
   nix eval --raw .#nixosConfigurations.<host>.config.services.immich.package \
     | grep -oE 'immich-[0-9.]+' | head -1
   ```

   Record the case (`A`, `B`, or `C`) and the Immich version in the commit
   message of the cutover change.

6. Tear down the verification artifacts:

   ```sh
   kanidm system oauth2 delete test-oidc-client --name idm_admin
   kanidm person delete test-oidc --name idm_admin
   ```

   Delete `test-oidc` and any case-B duplicate in the Immich admin UI.

Skipping this verification risks detaching existing user libraries on cutover.

## Immich OAuth admin-settings surface

| Field | Value used here | Notes |
|-------|-----------------|-------|
| `Enabled` | `true` | Flips OIDC on |
| `issuer_url` | `https://<kanidm-domain>/oauth2/openid/<client_id>` | Kanidm well-known endpoint |
| `client_id` | matches the Kanidm OAuth2 system name | Reconciler relies on this for email-link behavior |
| `client_secret` | from agenix, passed by file path | Never written to the Nix store |
| `scope` | `openid email profile` | `profile` provides the storage-label fallback |
| `Storage Label Claim` | `preferred_username` | Decides on-disk library directory for new users |
| `Auto Register` | `true` | New OIDC subjects get an Immich account |
| Mobile redirect | `https://<immich-domain>/api/oauth/mobile-redirect` | Needed only when mobile clients are in scope |

For users that already exist locally, `Auto Register` is irrelevant. The
linking step happens via email match and empty `oauthId`.

## Redirect URI shape

The Kanidm OAuth2 system origin URLs that work with Immich:

```text
https://<immich-domain>/auth/login
https://<immich-domain>/user-settings
app.immich:///oauth-callback
https://<immich-domain>/api/oauth/mobile-redirect
```

The mobile custom scheme requires Immich's "Mobile Redirect URI" toggle on.
Web-only deployments can drop the last two.

## NixOS wiring pattern

Immich host:

```nix
{
  inputs.immich-provision.url =
    "git+ssh://git@codeberg.org/caniko/immich-provision.git?ref=main";

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

Kanidm host:

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

Two important properties of the layout:

- The OIDC client secret is a **module secret**, not a host secret, and it
  rekeys to both the Immich host and the Kanidm host from one source.
- The patched Immich package is built by overriding `services.immich.package`
  on the Immich host. The reconciler relies on the patch to mint short-lived
  provisioning tokens.

## Acceptance gate for any deployment

- The verification recipe above ran against the exact Immich version being
  deployed.
- The observed case and version are recorded in the cutover commit message.
- Case A proceeds directly. Case B requires an operator-approved fallback path.
  Case C blocks the cutover.
- The OIDC client secret rekeys to both the Immich service user and the Kanidm
  service user from a single source.
- Post-cutover, affected users' Immich library, album, and asset counts are
  unchanged compared to a pre-cutover snapshot.
