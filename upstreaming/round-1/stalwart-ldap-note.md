# Stalwart — Kanidm LDAP note (docs PR)

**Repo:** `stalwartlabs/website` (the docs repo — **not** the FLA-gated code
repo) · **File:** `src/content/docs/docs/auth/backend/ldap.md` · **Vehicle:**
small docs PR. mdecimus merges these directly.

> [!WARNING]
> **This is the weakest PR in the round — do it last (after the kanidm chapter)
> and keep it tiny.** Reading the live 0.16 page changed the scope sharply:
> - `url`, `bindAuthentication: true` (default), and the "directory doesn't
>   return password hashes → use bind authentication" scenario are **already
>   documented** (with an Active Directory example). Don't restate them.
> - Our old `class` vs `objectClass` claim looks **stale/wrong**: kanidm's LDAP
>   output exposes `objectclass` (lowercase) and Stalwart's default
>   `attrClass: ["objectClass"]` matches it case-insensitively (issue #2363
>   closed). **Do not tell people to set `attrClass: ["class"]`.**
> - 0.16 moved config into JMAP/WebUI objects; express examples as the current
>   JSON objects (`"@type": "Ldap"`, camelCase), never v0.15.5 TOML.
>
> A "just cross-link to Kanidm's own LDAP docs" response is plausible and
> reasonable. That's fine — it's still a net win, and #3 gives you the chapter
> to link.

## Genuine residual content (Kanidm-specific only)

Append a short `:::tip[Kanidm]` admonition near the existing **Authentication
methods** / **Bind authentication** section. Cover only what isn't already there:

- Kanidm's read-only LDAP gateway **never returns password hashes**, so keep
  `bindAuthentication: true` (the default) — hash-comparison mode (`false`)
  cannot work against Kanidm.
- Only Kanidm persons with the **POSIX extension and a POSIX password** are
  visible/authenticatable over LDAP, and per-user bind requires
  `ldap_allow_unix_pw_bind` enabled **on the Kanidm side**.
- Bind the Stalwart service account with **`dn=token`** and a Kanidm
  service-account API token; that account must be in **`idm_people_pii_read`** to
  read `mail`.
- **Do not set `attrClass`** — the 0.16 default `["objectClass"]` already matches
  Kanidm's LDAP output (`objectclass`, lowercase, matched case-insensitively).
  (This is precisely what our *local* 0.15.5 lib got wrong by forcing
  `attributes.class = "class"`; the upstream note should steer operators away
  from that mistake.)
- Link to Kanidm's LDAP integration chapter (the one from draft #3) for the
  Kanidm-side setup rather than duplicating it.

## Draft admonition (current-schema JSON)

```markdown
:::tip[Kanidm]

[Kanidm](https://kanidm.github.io/kanidm/stable/integrations/ldap.html) exposes
a read-only LDAP gateway that never returns password hashes, so keep
`bindAuthentication` set to `true` (the default) — hash comparison cannot work.
Bind the service account with `dn=token` and a Kanidm service-account API token,
and make that account a member of `idm_people_pii_read` so it can read `mail`.
Only Kanidm persons that are POSIX-enabled with a POSIX password are visible over
LDAP. See Kanidm's LDAP integration guide for the directory-side setup.

```json
{
  "@type": "Ldap",
  "url": "ldaps://idm.example.com:3636",
  "bindDn": "dn=token",
  "bindSecret": { "@type": "Value", "secret": "%{env:KANIDM_LDAP_TOKEN}%" },
  "bindAuthentication": true,
  "baseDn": "dc=idm,dc=example,dc=com"
}
```

:::
```

## Framing (PR description)

> Following the resolved community config in kanidm/kanidm#3516, a short note on
> the LDAP backend page for users integrating Kanidm's read-only LDAP gateway —
> the one non-obvious gotcha is that Kanidm never returns password hashes, so
> bind authentication (already the default) is mandatory, plus the
> `idm_people_pii_read` requirement to read `mail`.

## Pre-submit checklist
- [ ] `npm install && npm run build` passes (link validation fails the build).
- [ ] Verify the exact current field names against `/docs/ref/object/directory`
      before submitting; adjust the JSON if 0.16 renamed anything.
- [ ] Confirm the `dn=token` secret reference syntax against a current Stalwart
      example (the `%{env:...}%` form above is illustrative).
- [ ] Note does not restate `url` / default `bindAuthentication` / no-hash prose
      already on the page.
- [ ] Cross-links the kanidm chapter from PR #3 (so land #3 first).
