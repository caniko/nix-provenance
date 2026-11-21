# Shared provider OAuth

`provenance-oauth` manages named provider enrollments for a Linux host and local user.
Compatible applications obtain access credentials through supported plugin or
command interfaces. The supported profiles are `openai/chatgpt`, `openai/opencode`,
`google/drive-file`, `google/drive`, and `google/antigravity`.

## Google profiles

Drive and Antigravity use separate grants. They can be enrolled under different
IDs for the same local user.

### Drive and rclone

Enable the Drive API in Google Cloud, configure the OAuth consent screen and
publish it **In production** (external apps in Testing normally receive refresh
tokens expiring after seven days). Create an OAuth client of type **TVs and
Limited Input devices**. Google may require verification depending on the app.
Declare `services.provenance.oauth.users.root.providers.google` with profile
`drive-file`, an agenix `enrollmentFile`, and recovery recipients as below.
Download the OAuth client JSON from Google Cloud Console **Credentials**. Keep
it private and enroll from the fleet checkout using the resolved paths described
below:

```sh
"$helper" --config "$manifest" authorize atlas google --user root \
  --profile drive-file --client-file "$client_json" --secret "$secret" \
  --pending-directory "$pending"
```

Authorize the displayed device code. Only a fresh authorization (the first
run, or `--reauth`) opens the client JSON; a retry of the same pending
transaction still takes the flag but does not read the file. Delete the file
after enrollment; the helper leaves it in place. Deploy and initialize the enrollment
as described below.
For a root backup service, render its private runtime rclone configuration with:

```sh
umask 077
provenance-oauth --config /etc/provenance/oauth/root-google.json rclone-config --remote gdrive > "$RUNTIME_DIRECTORY/rclone.conf"
```

Point rclone at that file. It contains both client credentials and refresh
token; keep it private and ephemeral. rclone refreshes the Drive grant itself.
The helper's `access` command is only for `openai/chatgpt`.
The `drive.file` scope only grants access to files created or explicitly shared
with this app, not arbitrary pre-existing Drive files.

For full Drive access, declare a separate `provider = "google"; profile =
"drive";` enrollment. Google does not offer this scope through device flow.
Create a **Desktop app** OAuth client and authorize an rclone Drive remote with
that client and the `drive` scope. Use rclone's interactive configuration to avoid
putting the client secret on the command line. Pass the private rclone token JSON
(the `token` value from the remote configuration) and the Desktop app client JSON:

```sh
"$helper" --config "$manifest" authorize atlas google --user can \
  --profile drive --client-file "$client_json" --token-file "$rclone_token" \
  --secret "$secret" --pending-directory "$pending"
```

The helper verifies the full scope with Google and identifies the Drive account.
After deployment, render `rclone-config` from that enrollment's manifest as above;
the output uses `scope = drive`. rclone still owns subsequent refreshes.

### Antigravity and agy

Sign in through agy's browser flow once. Use the resulting
`antigravity-acp/acp_token.json` under that agy profile's `GEMINI_HOME` as a
private input. Declare `services.provenance.oauth.users.can.providers.google`
with `profile = "antigravity"`, a runtime agenix `enrollmentFile`, and recovery
recipients. Enroll from the fleet checkout:

```sh
"$helper" --config "$manifest" authorize atlas google --user can \
  --profile antigravity --token-file "$agy_token" --secret "$secret" \
  --pending-directory "$pending"
```

The helper checks the `cloud-platform` scope and uses a one-time token exchange
to look up the Google account. It stores the refresh grant, not the access
token. To pin a specific Google account, set the manifest's `account` to the
expected Google subject (`sub`) and pass the same value as `--account`. As with
Drive, resuming an existing pending transaction does not reread the input file.

Deploy and initialize with `provenance-oauth-can-google-initialize.service` as
described below. In Home Manager, import `homeModules.antigravity` and enable
`nix-provenance.antigravity.googleAuth` with the desired `profileDirectories`.
Integrated Home Manager receives the enrollment binding automatically. For
standalone Home Manager, also import `homeModules.oauth` and set
`nix-provenance.oauth.accounts.google.{configFile,package,stateDirectory}` to
the public manifest, helper, and the state directory from the manifest.
Set `googleAuth.enrollment` to the ID to install by default (defaults to
`google`). Start `nix-provenance-antigravity-google-auth@ID.service` with
`systemctl --user` to switch the same profile directories to another declared
Antigravity enrollment. The ordinary unit restores the declared default on
Home Manager activation and login.
Unset the legacy `googleAuth.tokenFile` when switching to the enrollment; the
installer accepts exactly one source. It calls `agy-token` at runtime and
replaces a profile copy only when its client, refresh token or project differs
from the source, it is missing, or it is not a private mode-0600 file. agy
refreshes and rewrites its own copies independently. An agy session still
running across an Apply or Restore can save the old grant back: stop those agy
sessions, run `systemctl --user start nix-provenance-antigravity-google-auth`,
then relaunch them. The enrollment wins over a fresh sign-in inside agy: after
signing in again there, re-enroll from that copy with `authorize --reauth
--token-file`. Removing the enrollment stops new exports only; each installed
copy keeps refreshing until it is deleted or the grant is revoked at Google.

#### Interactive agy CLI keyring

The agy TUI and `agy -p` (tested contract: agy 1.5.12) do not use the ACP
profile copies. To update their Secret Service sign-in as well, set
`nix-provenance.antigravity.googleAuth.keyring.enable = true;`. This requires
an enrollment, not the legacy `tokenFile`, and an unlocked Secret Service
collection in the user's session. Like agy, the installer uses the `login`
collection if present and the default collection otherwise. `keyring.package`
defaults to `pkgs.oo7` patched to support collection paths and replacing all
matching items.

Both the ordinary unit and `nix-provenance-antigravity-google-auth@ID.service`
update the same per-user CLI sign-in. If exactly one matching item exists and
its refresh token already matches, nothing is written. Otherwise the helper
exchanges the selected refresh grant for a fresh Google access token and reads
the account email. The grant needs
`userinfo.email` in addition to Antigravity's scopes. The new entry goes to
Secret Service over stdin without a temporary keyring file. The ACP copies are
installed first: if the keyring is locked or unavailable, the unit warns and
fails without undoing those copies. Unlock the keyring and rerun the same unit.
Stop active agy sessions before switching to keep them from saving the old
sign-in back. Disabling this target or removing the enrollment does not delete
the keyring item; sign out of the CLI or revoke the Google grant separately.

## Ownership and lifecycle

nix-provenance manages enrollment generations, durable state, encrypted
checkpoints, and consumer adapters. For `openai/chatgpt` it also refreshes
the grant. rclone, agy, and native OpenCode refresh their own grants. The fleet
operator owns host selection, agenix declarations/rekeying, deployment, and
verification on the selected host.

A short-lived CLI process locks the enrollment state directory for each access.
For `openai/chatgpt` this keeps one refresh owner without introducing a network broker or patching
applications. Stock OpenCode and OMP continue to own model catalogs, inference,
and their normal request protocols.

The state directory is `/var/lib/provenance-oauth-USER-ID`, owned by the
declared user with mode `0700`; state and lock files have mode `0600`. This is
isolation between local users. Applications running as the same UID are trusted
and can read that user's files. OpenAI adapters return only access tokens,
account IDs, and expiry times. The Google exports include a refresh token and
client credentials so rclone and agy can refresh independently.

An agenix enrollment is a bootstrap artifact, not the current token store:

- A newer enrollment generation replaces live state. Older generations cannot
  replace it; reusing a generation with different contents is rejected.
  The durable refresh-intent guarantees below apply to `openai/chatgpt`.
  Google refresh tokens do not rotate, so the checkpoint holds the enrolled
  grant. The native `openai/opencode` checkpoint holds the most recently synced
  grant; see the backup interval and recovery caveat below.

- Refresh intent is durably recorded in live state and `checkpoint.age` before
  contacting the provider. A failed checkpoint before dispatch is retryable if
  the intent can be cleared. A crash or uncertain network outcome requires a
  fresh authorization rather than replaying a possibly rotated refresh token.
- A successful refresh is persisted before its access token is released. An
  interrupted checkpoint publication is repaired without repeating the exchange.
- Local removal retains a generation tombstone. Rebooting or rolling back Nix
  does not re-enable that enrollment.

Neither full-disk rollback nor restoration of an obsolete backup can be detected
without an external monotonic authority. Recovery therefore requires the latest
checkpoint, or a fresh provider authorization.

## Declare a host and user

Import the NixOS module and reference an actual runtime enrollment secret:

```nix
{config, inputs, ...}: {
  imports = [inputs.nix-provenance.nixosModules.oauth];

  services.provenance.oauth.users.can.providers.openai = {
    profile = "chatgpt";
    enrollmentFile = config.age.secrets.oauth-can-openai.path;
    recoveryRecipients = [/* your existing public age recovery recipients */];
  };
}
```

Declare `age.secrets.oauth-can-openai` using the fleet's normal agenix source
policy. Recovery recipients are required; use existing public X25519, SSH, or
age-plugin recipients whose private identities are available for recovery. Set
`services.provenance.oauth.recoveryPlugins` to the plugin packages when needed.
Checkpoint encryption must work unattended. Plugin protocol debugging
(`AGEDEBUG=plugin`) is rejected because it reveals encryption key material.

The module exports `manifests.USER.PROVIDER` and `helperPackage` under
`services.provenance.oauth`. The public manifest is also installed at
`/etc/provenance/oauth/USER-PROVIDER.json`. These contain paths and public metadata,
never the enrollment grant. Build the target's helper and manifest before first
enrollment; they do not require a plaintext grant at evaluation time.

For multiple grants, declare `services.provenance.oauth.users.USER.enrollments.ID`
instead, with the same fields plus `provider`. IDs match `[a-z0-9][a-z0-9-]{0,47}`
and cannot duplicate a `providers` key. Each uses `manifests.USER.ID`,
`/etc/provenance/oauth/USER-ID.json`, and `provenance-oauth-USER-ID` units. Legacy
`providers.PROVIDER` entries keep their existing manifests and state.

The NixOS module supplies OpenAI and Google Antigravity bindings to integrated
Home Manager; Google Drive enrollments do not create Home Manager bindings.
Standalone Home Manager imports `homeModules.oauth` and
sets `nix-provenance.oauth.accounts.openai.{configFile,package}` to the host's
public manifest and helper.
Named Home Manager bindings use `nix-provenance.oauth.accounts.ID` and carry the
provider and profile from NixOS. Set those explicitly with standalone Home Manager.

## Authorize, deploy, and finalize

Run authorization from the fleet flake directory where `agenix edit` is
configured. The manifest must match the requested host, user, provider, profile,
and account. Keep the pending directory outside source control in a private
operator-owned parent. For example, after resolving `manifest`, `helper`,
`secret`, and `pending` to those actual paths:

```sh
"$helper" --config "$manifest" authorize atlas openai --user can \
  --profile chatgpt --secret "$secret" --pending-directory "$pending"
```

Open the displayed provider URL and enter the displayed device code. No access
or refresh token is printed. Authorization saves a private pending enrollment,
asks agenix to encrypt a new temporary output, validates that output as age, and
atomically publishes the encrypted source. This works with agenix-rekey's
`--input` rule that refuses existing output files.

Retry with the same pending directory after encryption, rekey, or deployment
failure. The same grant and generation are reused. Use `--reauth` only when a
fresh authorization is needed. Add the encrypted source to the fleet's tracked
files before rekeying. `--rekey` can invoke `agenix rekey -a` for an already
tracked declaration; otherwise run the normal fleet rekey workflow after staging.

Deploy the host configuration through the fleet's deployment command. For a
**first enrollment**, explicitly initialize on the target:

```sh
sudo systemctl start provenance-oauth-can-openai-initialize.service
sudo -u can provenance-oauth --config /etc/provenance/oauth/can-openai.json status
```

Later deployments and runtime enrollment-file changes reconcile through
`provenance-oauth-can-openai.service` and its path unit. To apply immediately,
start that normal service. Normal boot never supplies `--initialize`; loss of
live state must be investigated and recovered explicitly.

Verify the target's returned generation and `enrolled` state. Then discard the
operator's pending plaintext, recording a public receipt for idempotent retries:

```sh
"$helper" --config "$manifest" finalize --pending-directory "$pending" \
  --generation "$verified_generation"
```

Finalization is the operator's acknowledgement of verified deployment. It does
not contact the target. It refuses a mismatched generation and never changes
live host state. Subsequent `authorize` retries report `finalized`; `--reauth`
starts a new generation.

## Consumers

### OpenCode native ChatGPT (`openai/opencode`)

With OpenCode v2.3.2 or compatible, sign in through its native
ChatGPT login and keep selecting `openai/MODEL`. Declare an `openai` enrollment
with `profile = "opencode"` and `account` set to its exact credential label.
Pipe the export into the enrollment command; do not save the full export:

```sh
opencode auth export openai |
  "$helper" --config "$manifest" authorize atlas openai --user can \
    --profile opencode --account 'Work Account' --token-file - \
    --secret "$secret" --pending-directory "$pending"
```

OpenCode enrollment accepts the export only on stdin (`--token-file -`).
Only the matching credential goes into agenix. After deploying and initializing
each enrollment, configure Home Manager:

```nix
nix-provenance.opencode.chatgpt = {
  enable = true;
  accounts = ["chat-work" "chat-personal"];
  active = "chat-work";
};
```

Set `chatgpt.package` if `programs.opencode.package` is not the package you
use with that OpenCode database. Home Manager installs and activates `active`
at activation and login. Start `nix-provenance-opencode-install@chat-personal.service` with
`systemctl --user` to switch live. Install only imports if the label is missing;
an existing OpenCode credential is never replaced. Sync and install require
the label to identify the enrolled native credential ID. If the label was
reassigned, re-enroll the intended login.
Without `--activate`, the CLI does not request a switch. OpenCode itself
selects the first login if the integration has no existing credential.

The `nix-provenance-opencode-sync.timer` checkpoints rotations hourly. Start
`nix-provenance-opencode-sync.service` before taking a backup or moving the
credential. A refresh since the last successful sync can make the checkpoint
unusable. Never run the same chain in two OpenCode databases at once. `access`
refuses these enrollments, and no provenance plugin is added for them.

### Shared ChatGPT adapters (`openai/chatgpt`)

**OpenCode V2:** select `provenance-openai-chatgpt/MODEL` from its stock catalog.
The separate provider ID avoids resolving an app-local OpenAI OAuth grant. The
adapter retains the native OpenAI driver, sets `store=false`, and injects
access credentials through the native HTTP and WebSocket hooks. Credentials are
acquired only for the expected HTTPS/WSS ChatGPT inference endpoints; HTTP
redirects are rejected. Later trusted proxy plugins can deliberately reroute a
request after authentication.

Custom configuration renderers must include
`nix-provenance.oauth.opencodePlugins` (or the merged
`programs.opencode.settings.plugins`) before their routing plugins.

**OMP:** the Home Manager module writes
`~/.omp/agent/extensions/provenance-oauth.ts`. The extension overrides only the
`openai-codex` credential with a command-resolved access token. It retains the
stock Codex models and protocol. OMP invalidates its command cache on an auth
retry, then invokes the shared helper again. A custom launcher must preserve
extension discovery or explicitly load this extension.

The shared adapters each expose one provider. They bind only
`nix-provenance.oauth.accounts.openai` with the `openai/chatgpt` profile.
These adapters do not import existing app-local credentials.
After verifying shared-model requests, remove obsolete grants through each application's supported logout
interface if they are no longer needed. Applications may cache an access token
until expiry; local removal does not revoke already issued provider tokens.

## Removal and recovery

Run `provenance-oauth --config MANIFEST remove` as the declared local user to
stop new access requests and persist a tombstone. For Google, removal stops new
`rclone-config`, `agy-token`, or `agy-keyring-entry` exports only. A consumer
can keep refreshing with a copy already on disk or in the keyring until the
grant is revoked in the Google account. Remove those copies separately if
needed. Reauthorization uses a newer enrollment.
For `openai/opencode`, remove or revoke the OpenCode login separately; removing
the provenance enrollment only stops copying credentials to or from OpenCode.

Back up the **current** `checkpoint.age` outside the host. A copy of the original
agenix enrollment cannot recover rotated credentials. For missing live state,
decrypt the latest checkpoint to a private `0600` file using the existing
recovery identity, then run as the declared user:

```sh
provenance-oauth --config MANIFEST restore --checkpoint PRIVATE_DECRYPTED_FILE
provenance-oauth --config MANIFEST status
```

Remove the decrypted recovery file after verification. Restore rejects existing
live state, a different target, and an uncertain refresh checkpoint. If the
latest recoverable checkpoint is uncertain, obtain a fresh authorization and
resolve the missing-state recovery explicitly; do not replay the old grant.

## Verification

```sh
cargo test --locked -p provenance-oauth --jobs 2
cargo clippy --locked -p provenance-oauth --all-targets --jobs 2 -- --deny warnings
node --test adapters/oauth/adapters.test.mjs
```

The opt-in `adapters/oauth/stock-contract.test.mjs` runs the actual installed
OpenCode and OMP binaries with isolated homes and explicit test-only credentials.
Set `OAUTH_TEST_TMPDIR`, `OPENCODE_BIN`, and `OMP_BIN` to approved scratch and
unwrapped binary paths, then run it with `node --test`. It verifies native
OpenCode and OMP Responses traffic against local fixtures, OMP's forced command
refresh, and an HTTP 401 retry with a newly resolved bearer. Tested stock versions
are OpenCode `f18083c78e54e65907000ab5a9ca4472b723ee7f`
and OMP `18.1.16` (`61b1b8aef634334eaf1412afd003a763e1d1b9c1`). A live provider
authorization and authenticated request remain a separate enrollment check.
