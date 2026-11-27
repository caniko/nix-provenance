# Automatic review credentials

`nixosModules.roborevCredentials` binds runtime forge tokens to **existing trusted
controller/publisher units**. It supplies systemd `LoadCredential` entries and a
public host-to-credential-name manifest. It does not start a review daemon, select
a model, enroll an account, or give a backend access to forge credentials.

```nix
nix-provenance.roborev = {
  enable = true;
  controllerUnits = ["review-controller"];
  forges = {
    github = {
      host = "github.com";
      tokenFile = config.age.secrets.review-github-token.path;
    };
    codefloe = {
      host = "codefloe.com";
      tokenFile = config.age.secrets.review-codefloe-token.path;
    };
  };
};
```

The consuming controller uses
`config.nix-provenance.roborev.credentialManifest` for its `--credentials` argument
and reads the named files inside systemd's `CREDENTIALS_DIRECTORY`. Names are
`roborev-github` and `roborev-codefloe` in this example. The manifest contains no
tokens or source paths. An absent/empty credential fails at runtime; the consumer
must not fall back to an operator's credential database.

Source paths must be literal absolute strings outside `/nix/store`, normally
agenix runtime paths. Nix path literals, token contents, environment variables and
command-line token arguments are not credential sources. Host bindings must be
unique. Every selected unit must already have an `ExecStart` owner, and worker or
model-runtime units must stay outside `controllerUnits`.

Token identity is observed through the forge's authenticated API, rather than
inventing a bot/App ID. When using an operator token by explicit consumer policy,
advisory comments appear under that operator's forge identity. This module does
not create dedicated GitHub policy-App authority or merge-approval evidence.

The module's regression gate is `checks.<system>.roborev-credentials-module-eval`.
It verifies private runtime sources, unique hosts, execution ownership, the
public manifest, disabled behavior, and exclusion of backend units.
