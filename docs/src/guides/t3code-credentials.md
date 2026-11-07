# T3 Code runner credentials

`nixosModules.t3codeCredentials` binds existing credentials to existing per-user
T3 runners. It neither creates accounts nor gives the shared server provider
credentials. The consumer must already define `t3-runner@.service` with
`User=%i` and the selected runner instances.

```nix
{config, inputs, pkgs, ...}: {
  imports = [inputs.nix-provenance.nixosModules.t3codeCredentials];

  nix-provenance.t3code.users.alice = {
    claudeTokenFile = config.age.secrets.alice-claude.path;
    openaiConfigFile = config.services.provenance.oauth.manifests.alice.openai;
    openaiPackage = config.services.provenance.oauth.helperPackage;
  };

  systemd.services.t3code.environment.T3CODE_OPENAI_CREDENTIAL_COMMAND =
    "${inputs.nix-provenance.packages.${pkgs.stdenv.hostPlatform.system}.provenance-oauth}/bin/provenance-t3-openai";
}
```

Both provider bindings are optional. Source selection and encrypted enrollment
belong to the consumer. Declare a separate OpenAI enrollment for each host/user
with the [shared-OAuth module](shared-oauth.md); never clone rotating grants.
Use the resulting `helperPackage` so checkpoint recovery plugins are available.

For Claude, supply a runtime file containing a token from the native
`claude setup-token` flow. The adapter uses systemd `LoadCredential`; a compatible
T3 runner opens that file for the native Claude subprocess and sets only its file
descriptor number in `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR`. No token value is
put in Nix, environment variables or arguments. These tokens last one year and
must be renewed explicitly. The consumer must restart the affected runner after
replacing the source; `LoadCredential` is a service-start snapshot.

For OpenAI, `provenance-t3-openai` runs inside the session owner's runner. Its
runner-local `T3CODE_OPENAI_OAUTH_COMMAND` and
`T3CODE_OPENAI_OAUTH_CONFIG_FILE` select the public helper and manifest. It emits
access-only JSON from the existing lifecycle helper. If neither binding variable
exists it emits `null`, leaving the owner's native Codex login unchanged; partial
bindings and helper failures are errors, not fallback instructions.

The compatible T3 client supplies these access credentials through Codex's native
external-auth interface and resolves refresh callbacks through the same runner.
Neither T3 nor this adapter writes a second refresh-token store.
