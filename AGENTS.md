## Work Standard

No shortcuts. Never fabricate, synthesize, or silently substitute missing required data. Do the necessary discovery first. If a foundational input is missing or invalid, stop and report the missing artifact or source, why it is required, the upstream producer to fix, the exact command or workflow to regenerate it, and the validation command that proves it is fixed.

## Identity And Credential Boundary

nix-provenance is an opinionated identity flake. It does not manage per-app local user credentials for downstream services, except for the native T3 Code environment enrollment and the narrow no-OIDC/SSO service exception described below.

Internal human credentials are owned by Kanidm. Internal users authenticate to downstream services through OIDC, either directly from Kanidm or through Rauthy when Rauthy is the outward-facing IdP.

### Native T3 Code environment enrollment

Native T3 Code is an explicit exception to the OIDC-only application model. Each environment runs as one existing Unix user with separate state, environment identity, and provider credentials. Enrollment may connect only that user's own environments; it must not create application-local users, passwords, principals, or a shared multi-user server.

nix-provenance may reconcile native T3 peer links and supply registration input to a supported native desktop import mechanism. T3 owns pairing, session issuance, credential storage, and desktop keyring encryption. Use its native interfaces, verify the destination environment identity and declared SSH/TLS trust, and never rewrite or decrypt its connection catalog externally. Keep credentials in private runtime files or pipes, never Nix-rendered configuration, the Nix store, argv, logs, or environment variables. Preserve unrelated manual connections and retry offline peers without granting broader access.

Fleet membership, users, endpoints, LAN/VPN route preference, and nightly selection remain consumer policy. Paperclip-specific integration belongs entirely in Paperclip. This exception does not authorize other applications' local credential provisioning or change the Kanidm/Rauthy identity model.

External user password initialization is owned by Rauthy. Use Rauthy's email-based set-password flow for external users who do not have Kanidm identities.

App/platform-local user passwords may be provisioned only through runtime password files, normally `config.age.secrets.<name>.path`, loaded with systemd credentials and reconciled with rotation markers. Do not serialize plaintext passwords into Nix-rendered JSON, the Nix store, argv, logs, or environment variables.

Narrow exception for services without OIDC/SSO: where a service has no OIDC/SSO support at all, a service-side module may provision that service's own app-local accounts and API tokens. ntfy (`services.ntfy-sh.provision`) is the first; Windmill and n8n (`nix/modules/service-bootstrap/`) follow with the service-root-secret carve-outs documented in `docs/src/concepts/architecture.md`. Rules: the secrets come only from runtime files (normally `config.age.secrets.<name>.path`, never Nix store paths or Nix path values) loaded as systemd credentials; hashing or derivation (bcrypt via `ntfy user hash`, token validation) happens at runtime inside the service's credentials unit; plaintext and hashes are never serialized to Nix-rendered state, the Nix store, argv, or logs; anonymous access must be denied by default. Honest carve-out to the environment-variable rule: ntfy's only declarative interface for predefined users and tokens is `NTFY_AUTH_USERS` (bcrypt hashes) and `NTFY_AUTH_TOKENS` (token values in plaintext), read from an environment. The exception therefore permits exactly one thing: the service's own declarative `EnvironmentFile` under `/run`, mode 0600, on tmpfs, built from credentials at service start and ordered after any operator-supplied environment file. It does not permit `Environment=`, `systemd.services.*.environment`, or any file in the store. Where OIDC exists, humans still authenticate through Kanidm or Rauthy; this exception does not extend to PINs, reset or notification emails, private keys, or any other password-like material.

Do not add PIN, password-reset email, notification-email, or other credential-adjacent provisioning to service-side modules such as Immich, Vikunja, Forgejo, or Stalwart unless this repository's identity model is explicitly changed first. Do not add fake password options to integrations that do not actually provision platform users. Public keys are a separate non-secret exception: Forgejo may reconcile declared SSH public keys, and the `github` home module may reconcile a GitHub account's declared SSH and OpenPGP public keys plus repository collaborator invitations and their acceptance. Private keys, tokens, and password-like material remain out of scope, except as admitted by the no-OIDC exception above.
