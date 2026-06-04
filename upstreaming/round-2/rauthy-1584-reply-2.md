# rauthy#1584 — reply to sebadob (folds in his decisions)

Post this as the next comment. It confirms the settled shape and corrects the two
things he pushed back on, so it's clear I took the feedback.

---

Thanks — that settles almost everything. Updated shape below, with your
corrections folded in.

**Per-type `generate`, separate enums.** Agreed: one `Generate` variant per secret
enum (`ClientSecret`, `UserPassword`, `ApiKeySecret`), kept separate rather than a
unified `BootstrapSecret` — their requirements differ and there's little code to
share. Explicit `"generate"` sentinel (for clients, since an absent secret already
means public + S256 PKCE).

**Key-id tagging — you're right, scratch that.** cryptr's header already carries
the enc-key id and selects the key automatically as long as it's still in
`ENC_KEYS`. Nothing for us to tag; reads are rotation-safe for free, exactly like
the DB columns. I'll drop that from the design.

**Storage / exposure — corrected.** Understood: API-key secrets are hashed *and*
encrypted (sha256, deliberately not argon2 for the hot path — high-entropy keys
don't need slow hashing), and not decryptable. So they behave like argon2'd user
passwords: for **both users and API keys, the container is the only place the
plaintext exists**; only **client** secrets are recoverable from the DB. That means
including API keys adds no new *category* of exposure beyond what generated user
passwords already carry — so I'll **include them**. Operators either save the
values, disable auto-purge, or supply an existing secret. (My earlier "API keys are
the unique new exposure" framing was wrong — users have the same property.)

**Auto-purge — agreed, plus the startup gap you caught.** Default-on, 600s, `0` to
disable. To cover a shutdown before the timer fires, I'll also **check on every
startup** and delete if expired — stamping the purge deadline in the file's
*cleartext* header (next to the magic + version) so startup can purge with a
stat+read, no decrypt needed.

**`get` output formats.** Yes — `--format` with `json`, `env` (KEY=VALUE per line),
and `raw` (bare value, for `$(...)`).

**Location:** `${data_dir}/bootstrap.secrets.enc` — agreed; keeps it with the
store/JWKS/PVC and survives `USE_VAULT_CONFIG` / config living in `/etc`.

**CLI name + export.** Dropping `-secrets` → `rauthy bootstrap {get,purge}` (leaves
room for other bootstrap subcommands later). For cleartext export I'll take your
config-option suggestion: a `secrets_export_path` that writes the generated
cleartext to a path you choose at first boot (pairs with auto-purge of the
encrypted container), rather than leaning on a CLI `export`. I can add CLI `export`
too since it's cheap, but I'll leave it out of PR 1 unless you want it.

**K8s — agreed it's a separate, more involved design; TBD, out of these PRs.** Your
ServiceAccount → K8s-API-writes-a-`Secret` route is nicer than the CLI-image idea I
floated, and in that mode Rauthy can write straight into the `Secret` and skip our
own encryption entirely (the `Secret` becomes the store). I'll spec it as a
follow-up once the local file + CLI path lands, so the first PRs carry no K8s
assumptions.

**PR 1 (what I'll open):** `generate` for clients + users; the `${data_dir}`
container (atomic temp+rename `0600`, cryptr/`ENC_KEYS`, magic+version+deadline
cleartext header); auto-purge (startup check + timer, default 600s, `0` off);
`rauthy bootstrap {get,purge}` with `--format raw|json|env`; and `secrets_export_path`.
**PR 2:** API-key `generate` — separated only because it needs the
`ApiKeyEntity::create()`-return capture / skip-`set_api_key_secret` refactor, not as
a security gate (per the above).

Two tiny confirms before I open PR 1:
1. Subcommand name — `bootstrap` or `bootstrap-data`?
2. Ship `secrets_export_path` in PR 1 and leave CLI `export` for later — good?

If that's right, I'll open PR 1.
