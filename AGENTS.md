## Work Standard

No shortcuts. Never fabricate, synthesize, or silently substitute missing required data. Do the necessary discovery first. If a foundational input is missing or invalid, stop and report the missing artifact or source, why it is required, the upstream producer to fix, the exact command or workflow to regenerate it, and the validation command that proves it is fixed.

## Identity And Credential Boundary

nix-provenance is an opinionated identity flake. It does not manage per-app local user credentials for downstream services.

Internal human credentials are owned by Kanidm. Internal users authenticate to downstream services through OIDC, either directly from Kanidm or through Rauthy when Rauthy is the outward-facing IdP.

External user password initialization is owned by Rauthy. Use Rauthy's email-based set-password flow for external users who do not have Kanidm identities.

App/platform-local user passwords may be provisioned only through runtime password files, normally `config.age.secrets.<name>.path`, loaded with systemd credentials and reconciled with rotation markers. Do not serialize plaintext passwords into Nix-rendered JSON, the Nix store, argv, logs, or environment variables.

Narrow exception for services without OIDC/SSO: where a service has no OIDC/SSO support at all, a service-side module may provision that service's own app-local accounts and API tokens. ntfy (`services.ntfy-sh.provision`) is the first. Rules: the secrets come only from runtime files (normally `config.age.secrets.<name>.path`, never Nix store paths or Nix path values) loaded as systemd credentials; hashing or derivation (bcrypt via `ntfy user hash`, token validation) happens at runtime inside the service's credentials unit; plaintext and hashes are never serialized to Nix-rendered state, the Nix store, argv, or logs; anonymous access must be denied by default. Honest carve-out to the environment-variable rule: ntfy's only declarative interface for predefined users and tokens is `NTFY_AUTH_USERS` (bcrypt hashes) and `NTFY_AUTH_TOKENS` (token values in plaintext), read from an environment. The exception therefore permits exactly one thing: the service's own declarative `EnvironmentFile` under `/run`, mode 0600, on tmpfs, built from credentials at service start and ordered after any operator-supplied environment file. It does not permit `Environment=`, `systemd.services.*.environment`, or any file in the store. Where OIDC exists, humans still authenticate through Kanidm or Rauthy; this exception does not extend to PINs, reset or notification emails, private keys, or any other password-like material.

Do not add PIN, password-reset email, notification-email, or other credential-adjacent provisioning to service-side modules such as Immich, Vikunja, Forgejo, or Stalwart unless this repository's identity model is explicitly changed first. Do not add fake password options to integrations that do not actually provision platform users. Public keys are a separate non-secret exception: Forgejo may reconcile declared SSH public keys, and the `github` home module may reconcile a GitHub account's declared SSH and OpenPGP public keys plus repository collaborator invitations and their acceptance. Private keys, tokens, and password-like material remain out of scope, except as admitted by the no-OIDC exception above.
