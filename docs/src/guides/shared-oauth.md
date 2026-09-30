# Shared provider OAuth

`provenance-oauth` authorizes a provider once for a Linux host and local user.
Compatible applications obtain access credentials through supported plugin or
command interfaces. The current profile is `openai/chatgpt`, using ChatGPT device
authorization and the provider's native Codex/Responses protocol.

## Ownership and lifecycle

nix-provenance owns authorization, grant validation, enrollment generations,
refresh, durable state, encrypted checkpoints, and consumer adapters. The fleet
operator owns host selection, agenix declarations/rekeying, deployment, and
verification on the selected host.

A short-lived CLI process locks the per-user state directory for each access.
This keeps one refresh owner without introducing a network broker or patching
applications. Stock OpenCode and OMP continue to own model catalogs, inference,
and their normal request protocols.

The state directory is `/var/lib/provenance-oauth-USER-PROVIDER`, owned by the
declared user with mode `0700`; state and lock files have mode `0600`. This is
isolation between local users. Applications running as the same UID are trusted
and can read that user's files. The adapter interface returns only access tokens,
account IDs, and expiry times; it does not give applications refresh ownership.

An agenix enrollment is a bootstrap artifact, not the current token store:

- A newer enrollment generation replaces live state. Older generations cannot
  replace it; reusing a generation with different contents is rejected.
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

When integrated Home Manager is present, enabled compatible applications are
bound automatically. Standalone Home Manager imports `homeModules.oauth` and
sets `nix-provenance.oauth.accounts.openai.{configFile,package}` to the host's
public manifest and helper.

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

Existing app-local credentials are not imported. After verifying shared-model
requests, remove obsolete grants through each application's supported logout
interface if they are no longer needed. Applications may cache an access token
until expiry; local removal does not revoke already issued provider tokens.

## Removal and recovery

Run `provenance-oauth --config MANIFEST remove` as the declared local user to
stop new access requests and persist a tombstone. Provider-wide revocation is a
separate provider account operation. Reauthorization uses a newer enrollment.

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
