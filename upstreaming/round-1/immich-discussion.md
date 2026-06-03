# Immich — Discord heads-up + feature-request Discussion (no PR yet)

**Repo:** `immich-app/immich` · **Vehicle:** issue-first. Blank issues are
disabled; feature requests go to a GitHub **Discussion** (`feature-request`),
and CONTRIBUTING mandates a **Discord `#contributing`** heads-up *before* code.
A cold PR is closed on sight. Round 1 is **only** the heads-up + Discussion —
the PR is Round 2, gated on the team's answer.

> [!IMPORTANT]
> **Drop the password-optional DTO change from the ask.** jrasm91 closed #24539
> (a contributor's OIDC-admin DTO/auth-policy change) and shipped his own
> `IMMICH_ALLOW_SETUP` answer in #24628. Our patch's DTO hunk applies cleanly
> against **v2.7.5** (still class-validator, `password!` required) — the version
> nixpkgs builds — but **#26597** migrated `UserAdminCreateDto` to **Zod** on
> `main` (merged 2026-04-14, not yet in any release), so it'll break on the first
> release past v2.7.5. So we can cite a *working* patch today; just pitch only the
> CLI token command, and *ask* whether password-optional is wanted given #24628
> rather than proposing it.

> [!NOTE]
> A CLI that mints a full **admin session** token is auth-sensitive (cf.
> GHSA-237r-x578-h5mv). Lead with "reuses the existing session primitive, adds
> no new auth surface," and expect questions on TTL bounds (we cap 1–3600),
> audit logging, and "why a full-admin session vs a scoped key." Most likely
> outcome is **ignored, not rejected** — it's low on a photo app's roadmap.

---

## Step 1 — Discord `#contributing` heads-up

> Hi — I'd like to propose a small server CLI addition before opening anything,
> per CONTRIBUTING. For headless/declarative deployments (NixOS, k8s, Ansible),
> the only documented way to bootstrap admin access is a long-lived admin API
> key or UI clicks. I'd like to add `immich-admin provision-token --ttl <s>`
> that mints a **short-lived** admin session through the existing session table
> (same primitive `auth.service` already uses), so tools can authenticate
> without persisting a permanent key. No new auth mechanism, just a CLI sibling
> of `reset-admin-password`. Would the team be open to this? I'll write it up as
> a feature-request Discussion. (Disclosure: I use AI assistance in my tooling;
> any PR would be hand-written and reviewed.)

## Step 2 — feature-request Discussion

File at `https://github.com/immich-app/immich/discussions/new?category=feature-request`.

**Title:** `CLI: short-lived admin provisioning token for headless/declarative bootstrap`

**Body:**

> ### Problem
>
> Declarative/headless Immich deployments (NixOS, k8s, Ansible) have no good way
> to bootstrap admin authentication. Today the options are: persist a long-lived
> admin **API key**, click through the UI, or write the DB out of band. The
> community pattern (e.g. immich-rest-cli, discussion #28291) ends in a
> never-expiring admin key — a standing secret that's a poor fit for declarative
> infra and high-value photo libraries.
>
> ### Proposal
>
> Add an `immich-admin` subcommand:
>
> ```
> immich-admin provision-token --ttl 300   # seconds, 1..3600, default 300
> ```
>
> It would:
> - run in the server environment (DB access), like the other `immich-admin`
>   commands;
> - find the existing admin account (fail clearly if none exists);
> - create a **normal admin session** via the existing session repository, with
>   `expiresAt = now + ttl`, using the same `randomBytesAsText` + `hashSha256`
>   path `auth.service` already uses for browser sessions;
> - print the raw bearer token to stdout (the caller pipes it to a private
>   runtime file).
>
> **It adds no new auth primitive** — it's the existing session mechanism,
> exposed to local root who already controls the service. The token self-expires,
> which is a strict improvement over today's never-expiring API key.
>
> ### Explicitly out of scope
> - No long-lived API-key fallback.
> - Provisioning tools match users by email and never write `oauthId`, relying
>   on Immich's existing email-link-on-first-OAuth-login behaviour.
>
> ### Question for the team
> One thing I'd run an OIDC-only admin path into: creating an admin user without
> a password. I saw #24628 (`IMMICH_ALLOW_SETUP`) landed for the
> admin-bootstrap case — is that the intended mechanism, or would you want
> password-optional admin creation handled separately? Happy to follow whatever
> you prefer; I'd keep that out of the token-command PR regardless.
>
> If the direction is acceptable I'll open a microscopic PR: one command, one
> `CliService` method, one `*.spec.ts`, plus a `server-commands.md` docs entry.

## If/when blessed (Round 2 — not now)

- One command + `CliService.createProvisionToken` + spec + docs. Conventional
  title `feat(server):`, fill the LLM-usage field honestly.
- **Rebuild the spec test against the live tag at PR time.** The patch's
  assertion `token: Buffer.from('raw-provision-token (hashed)')` is **already
  correct** against v2.7.5 — `hashSha256` returns a `Buffer` (`digest()` with no
  encoding), and the mock factory returns `Buffer.from(\`${input} (hashed)\`)`.
  Do **not** "fix" it to a hex string. What does need redoing on `main`: the DTO
  is Zod (#26597) and the `describe`-block neighbourhood shifted — re-anchor the
  hunk, but keep the Buffer assertion shape.
- Keep the diff free of the DTO change.
