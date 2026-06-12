## Work Standard

No shortcuts. Never fabricate, synthesize, or silently substitute missing required data. Do the necessary discovery first. If a foundational input is missing or invalid, stop and report the missing artifact or source, why it is required, the upstream producer to fix, the exact command or workflow to regenerate it, and the validation command that proves it is fixed.

## Identity And Credential Boundary

nix-provenance is an opinionated identity flake. It does not manage per-app local user credentials for downstream services.

Internal human credentials are owned by Kanidm. Internal users authenticate to downstream services through OIDC, either directly from Kanidm or through Rauthy when Rauthy is the outward-facing IdP.

External user password initialization is owned by Rauthy. Use Rauthy's email-based set-password flow for external users who do not have Kanidm identities.

App/platform-local user passwords may be provisioned only through runtime password files, normally `config.age.secrets.<name>.path`, loaded with systemd credentials and reconciled with rotation markers. Do not serialize plaintext passwords into Nix-rendered JSON, the Nix store, argv, logs, or environment variables.

Do not add PIN, password-reset email, notification-email, or other credential-adjacent provisioning to service-side modules such as Immich, Vikunja, Forgejo, or Stalwart unless this repository's identity model is explicitly changed first. Do not add fake password options to integrations that do not actually provision platform users.
