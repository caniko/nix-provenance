### The mechanism, in three parts

1. **Generate:** use a `"generate"` sentinel in the bootstrap JSON, so the
   operator commits a *declaration*, never a secret, including an encrypted one:
   ```jsonc
   // clients.json   confidential client + 64-char minted secret
   { "id": "my-client", "secret": "generate", ... }
   // users.json
   { "email": "svc@example.com", "password": "generate", ... }
   ```
   For clients I used explicit `"generate"` instead of omitting `secret`,
   because an absent secret already means *public + S256 PKCE* today.
2. **Store:** write all minted plaintexts into one `bootstrap.secrets.enc`,
   encrypted with **cryptr + `ENC_KEYS`, using the same calls as the existing DB
   columns**. No new key material and no new crypto. Write it atomically with
   `0600` permissions, and tag it with the key id so reads survive `ENC_KEY`
   rotation.
3. **Retrieve:** add an **offline**
   `rauthy bootstrap-secrets get|export|purge` subcommand that loads only
   `ENC_KEYS` and never talks to the server. This matches your requirement that
   it stays readable through the CLI because the CLI already has the encryption
   keys.

### Built to your constraints

- **No** UDS, **no** new admin-token type, **no** live reconcile, and **no**
  HTTP retrieval endpoint. This stays within the boundaries you already ruled
  out. It is first-boot and JWKS gated only.
- **Auto-purge defaults to ON with TTL 600s.** This is the main safety measure.
  It prevents the container from becoming a long-lived secret in the data
  volume or backups, which matches your "expire after ~10 minutes" stance. `0`
  opts out.

### The one new exposure I want to flag honestly

API-key secrets are stored `sha256`-only in the DB, so for a *generated* API key
the container would be the **only** place its plaintext token exists. That's a
real widening compared to supply-only keys. I've isolated that into a follow-up
PR so you can decide it separately. Clients and users, which are already
`ENC_KEYS` and argon2 stored, do not have this property.

### Phasing

- **PR 1:** `generate` for clients + users, the container, and CLI
  `get`/`export`/`purge`.
- **PR 2:** API-key `generate` (isolated for the trade above).
- **PR 3:** `list`/`reseal`, a `/encryption/migrate` warning if a container
  exists, and the K8s retrieval image.

Kubernetes is the awkward case you called out. The design keeps the server
image shell-less and adds an optional CLI image with the binary as entrypoint,
so no shell is needed. That image would run as a post-boot Job. Full details
are in the RFC.

### Decisions

1. **Location:** `${data_dir}/bootstrap.secrets.enc` vs literally next to
   `config.toml`? I leaned toward `data_dir` because `USE_VAULT_CONFIG` can mean
   there is no on-disk config, and it matches the server's write and PVC
   ownership.
2. **Auto-purge:** OK with default-on, 600s, `0` to disable?
3. **API keys:** include `generate` in PR 2, where the container is the only
   plaintext location and the TTL bounds exposure, or keep API keys supply-only
   for now?
4. **K8s:** are you OK committing to a CLI image with a binary entrypoint and
   no shell, or should that pattern stay TBD?
5. **CLI shape:** `rauthy bootstrap-secrets {get,export,purge}` with
   `--format raw|json|env`. Is that acceptable, or do you want it flatter?

If the shape's right, I'll open PR 1.
