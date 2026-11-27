# Kanidm OIDC Migration for Existing Immich Deployments

Use this guide for the first migration from local Immich accounts with photo
libraries to Kanidm OIDC. The reconciler and NixOS module handle steady state.

## Linking semantic is undocumented upstream

Immich's [OAuth settings documentation](https://docs.immich.app/administration/oauth/)
doesn't say what happens when an OIDC login matches a local account by email.
In practice, the first matching login sets `oauthId` if that field was empty.

On an instance with existing user libraries, verify this with the **exact Immich
version** before enabling OIDC for production users.

## Pre-cutover verification recipe (blocking)

Test Immich and Kanidm directly with throwaway accounts. Do not run the
reconciler for this test.

1. Create a throwaway Kanidm person and a matching local Immich account with
   the same email:

   ```sh
   kanidm person create test-oidc "Test OIDC Linking" --name idm_admin
   kanidm person update test-oidc --mail test-oidc@example.com --name idm_admin
   kanidm person credential set-password test-oidc --name idm_admin
   ```

   In the Immich admin UI, create a local account with email
   `test-oidc@example.com` and username `test-oidc`. Note the Immich user ID.

2. Create a throwaway Kanidm OAuth2 system; do not reuse the production client:

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
| B | A new Immich user appears, possibly with a Kanidm-derived name; original account untouched | Get operator approval for either pre-cutover deletion and library reattachment, or a one-time database merge from local `user_id` to OIDC `user_id` |
| C | OIDC completes but Immich refuses login with an "account exists with this email" error | Defer until an upstream fix or a separate re-onboarding plan |

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
| `client_secret` | from agenix, passed by file path | Never written to the Nix store or directly to the Immich DB through Nix |
| `scope` | `openid email profile` | `profile` provides the storage-label fallback |
| `Storage Label Claim` | `preferred_username` (Immich default) | Sets the on-disk library directory for new users |
| `Auto Register` | `true` (Immich default) | New OIDC subjects get an Immich account |
| Mobile redirect | `https://<immich-domain>/api/oauth/mobile-redirect` | Needed only when mobile clients are in scope |

For users that already exist locally, `Auto Register` is irrelevant. The
linking step happens via email match and empty `oauthId`.

## Redirect URI shape

Set the Kanidm OAuth2 origins for web login, web settings (re-link or sign-in),
the mobile callback, and the mobile redirect helper, respectively:

```text
https://<immich-domain>/auth/login
https://<immich-domain>/user-settings
app.immich:///oauth-callback
https://<immich-domain>/api/oauth/mobile-redirect
```

The mobile custom scheme requires Immich's "Mobile Redirect URI" toggle on.
Web-only deployments can drop the last two.

## NixOS wiring pattern

The `immich-provision` examples below are historical; refer to your fleet's
current Immich and Kanidm host configurations for live wiring.

Immich host:

```nix
{
  inputs.immich-provision.url =
    "git+ssh://git@github.com/caniko/immich-provision.git?ref=main";

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

- Use one **module secret**, not a host secret. The legacy source
  `age/secrets/modules/immich-oidc-client-secret.age` was rekeyed for `immich`
  and `kanidm`; current canix uses the `oauth` module secret.
- Override `services.immich.package` on the Immich host. The reconciler needs
  `0001-add-trusted-local-provision-token.patch` for short-lived tokens.

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
