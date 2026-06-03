# kanidm — LDAP docs PR + issue #3070 comment

**Repo:** `kanidm/kanidm` · **Branch from:** `master` · **Vehicle:** docs PR
(book chapters are first-class; Firstyear engaged #3516/#4158 personally).

> [!CAUTION]
> **AI-provenance wall.** kanidm's PR template has a mandatory "This PR contains
> no AI generated code" checkbox, backed by a copyright/legal stance. Everything
> below is **reference material, not text to paste.** Write the chapter yourself,
> in your own words, from these verified facts. The CLI transcripts/configs are
> facts you can reuse; the prose is not. Do not tick the box over derived text.

> [!IMPORTANT]
> **Scope is narrower than you'd think — `ldap.md` already covers a lot.** The
> existing page already documents: `dn=token` api-token binds for elevated read,
> that posix binds get anonymous perms, the `(class=account)`/`(class=group)`
> filters, and `set-ldap-allow-unix-password-bind ... -D admin` (the `admin`
> requirement is already shown). **Do not re-state any of that** or you'll get a
> "already documented" bounce. The genuinely missing, non-obvious facts are only:
> 1. reading **PII attributes like `mail`** over LDAP needs the binding service
>    account to be a member of **`idm_people_pii_read`** — an api-token bind
>    alone is *not* enough;
> 2. only persons with the **POSIX extension** are returned/authenticatable, so
>    mail delivery to a non-posix person silently fails;
> 3. a worked **mail-server integration** example tying it together.
> 4. **(highest-value, added after the v1.10.3 review)** kanidm v1.10.x shipped
>    per-application LDAP **application passwords** (`idm_application_*`) — a
>    per-user, per-application secret that is the modern alternative to the
>    unix-pw bind for LDAP/mail auth — and the stable LDAP page **does not mention
>    them at all**. Documenting application passwords as the recommended per-user
>    LDAP auth path is *less* likely to be bounced than re-explaining the PII gate,
>    because it's net-new content, not adjacent to anything already on the page.
>
> **Verify (1), (2) and (4) against the kanidm release you run before submitting**
> — gateway/ACP semantics have shifted across versions (application passwords are
> new in v1.10.x), and a docs PR asserting stale behavior gets bounced for
> correctness.

---

## Suggested placement

Extend `book/src/integrations/ldap.md`. The cleanest fit is a new subsection
after **"Service Accounts"** (which already introduces `dn=token`) and a short
note under **"People Accounts"** for posix-only visibility. Firstyear may prefer
a dedicated mail-integration page — offer to move it if asked.

## Reference outline (write your own prose)

**New subsection — "Reading PII attributes (e.g. mail) over LDAP":**
- An api-token (`dn=token`) bind grants elevated read, but **PII attributes such
  as `mail` are gated behind `idm_people_pii_read`**. A service account that is
  not a member of that group will bind and search successfully yet see no `mail`
  value — the usual symptom when a mail server "finds the user but can't route
  mail."
- Fix: add the service account to `idm_people_pii_read`, then bind as
  `dn=token`. A worked check:

  ```bash
  # service account must be a member of idm_people_pii_read
  ldapsearch -H ldaps://idm.example.com:3636 -x \
    -D "dn=token" -w "$API_TOKEN" \
    -b 'dc=idm,dc=example,dc=com' '(name=test1)' mail
  # mail: test1@example.com   <- only present with idm_people_pii_read
  ```

**Add to "People Accounts" (posix-only visibility):**
- Only persons with the POSIX extension (a `gidNumber`, i.e. posix-enabled) are
  returned over the LDAP gateway. A non-posix person is invisible to LDAP search,
  so an LDAP-backed mail server will not resolve a mailbox for them even if the
  `mail` attribute is set in kanidm. Posix-enable + set a posix password for any
  person that must authenticate or receive mail via LDAP.

**Optional — "Integrating a mail server" worked example:**
- Tie it together with the resolved Stalwart config from discussion #3516: a
  read-only `dn=token` service account in `idm_people_pii_read`, posix-enabled
  recipients, and (if per-user auth is needed) `set-ldap-allow-unix-password-bind`
  enabled with the `admin` account.

## Framing (PR description)

> Following discussions #3516 (Stalwart mail server) and #4158, this documents
> two LDAP-gateway behaviours integrators keep tripping on: that reading `mail`
> requires the bind service account to be in `idm_people_pii_read`, and that
> only posix-enabled persons are visible over LDAP. Both are correct,
> security-preserving behaviours that simply weren't documented.

Explicitly endorse the security model — never propose relaxing the PII gate or
the posix-bind single-factor rule. You're an integrator who hit this in
production (mail), which is exactly their audience.

## Pre-submit checklist
- [ ] Chapter written from scratch by a human; "no AI generated code" box honest.
- [ ] `mdbook build` from `book/` clean, no broken links.
- [ ] `idm_people_pii_read` requirement + posix-only visibility re-verified
      against your current kanidm version, with a real `ldapsearch` transcript.
- [ ] Content does **not** restate `dn=token`, the `-D admin` toggle, or the
      class filters already on the page.

---

## Separate: comment on issue #3070 (do NOT open a new issue)

#3070 reports `kanidm system domain set-display-name` returning a misleading
`NoMatchingEntries` (404) to `idm_admin` instead of a clear authorization error.
Same ACP family bites the unix-pw-bind toggle. Add a comment — but first confirm
the toggle genuinely 404s for `idm_admin` (not just "needs `-D admin`"), or a
reviewer will say it's a distinct attribute.

> Confirming this also affects `kanidm system domain set-ldap-allow-unix-password-bind`:
> run as `idm_admin` it returns `NoMatchingEntries` rather than a permission
> error, even though the real cause is that the domain entry is only writable by
> `admin`. The misleading 404-vs-403 made this hard to diagnose (the entry
> clearly exists). +1 on returning an authorization error here — the
> `admin`/`idm_admin` split itself is correct and shouldn't change, just the
> error semantics.
>
> Repro:
> ```
> $ kanidm system domain set-ldap-allow-unix-password-bind true   # as idm_admin
> Error: ... NoMatchingEntries
> $ kanidm system domain set-ldap-allow-unix-password-bind true -D admin
> # succeeds
> ```

Do **not** ask to give `idm_admin` the privilege — that breaks the split by
design and will draw a hard no.
