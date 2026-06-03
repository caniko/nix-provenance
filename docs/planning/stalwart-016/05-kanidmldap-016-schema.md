# Phase 05 — Update the kanidmLdap lib/module to the 0.16 registry-object schema

> **Recommended Codex model: GPT 5.4 medium**
>
> Moderate, well-specified coding work: the exact 0.16 directory schema + the precise
> lib/module delta are already pinned by the migration spec, so this is largely a
> mechanical rename/restructure of an existing helper plus eval-check hardening. `5.4
> medium` (not `5.4-mini`) because there's one real correctness trap — the
> silent-default-on-unknown-keys failure mode — that the assertions must fail-closed
> against; getting that wrong ships a directory that authenticates nobody. Not `5.5`:
> no design ambiguity remains once the spec is followed.

## Working tree

`/data/nvme0/can/Projects/nix-provenance`. **Prerequisite:** phase 02 confirmed the
0.16 directory schema is in force (the schema itself is already pinned by the migration
spec; phase 02 confirms nothing changed in 0.16.7 and resolves the secret-macro
question). Can run in parallel with phases 03 and 06 (disjoint files).

## Goal

`nix/lib/stalwart.nix`'s `kanidmLdapDirectory` emits the **0.16 registry-object**
shape (flat camelCase keys, `bindAuthentication` boolean, `@type`-tagged `bindSecret`,
`filterLogin`/`filterMailbox`, `attr*` arrays), `nix/modules/ldap/stalwart.nix` exposes
the matching options (dropping the dead 0.15 auth-bind enum options), and
`nix/checks.nix` asserts the new keys are present and the old ones are gone — so the
silent-default trap can't ship.

## Why this matters now

The kanidmLdap module currently emits the **0.15.5** schema (`url`, `bind.dn`,
`bind.secret`, `bind.auth.method`/`template`/`search`, `filter.name`/`filter.email`,
`attributes.*`, `tls.allow-invalid-certs`). On 0.16 those keys don't error — they are
**silently dropped** (no `deny_unknown_fields`, `#[serde(default)]`), yielding an
all-default LDAP directory (`url ldap://localhost:389`, empty `bindDn` → anonymous
read that can't see `mail`, `filterLogin (mail=?)` that won't match kanidm logins).
Phase 04 places this object into the registry, so it must already be the 0.16 shape.

## Out of scope

- Pushing the object into the registry / the provisioning mechanism (phase 04).
- The NixOS transport module (phase 03).
- Supporting both 0.15 and 0.16 schemas via a toggle — target **0.16 only**. The 0.15
  transport (TOML) is gone, so a dual-emit helper is dead weight; the 0.15.5-schema
  version remains in git history (`25139d9`) as the rollback baseline.

## Plan

1. Rewrite `kanidmLdapDirectory` in `nix/lib/stalwart.nix` to emit the 0.16 object
   (per migration spec §2b/§3a). Concretely:
   - `"@type" = "ldap"` (the registry tag), `url`, `baseDn`, `bindDn` (default `"dn=token"`).
   - `bindSecret` as the `@type`-tagged enum — add `mkBindSecretFile`/`mkBindSecretEnv`/
     `mkBindSecretValue` helpers (`{ "@type"="file"; filePath=…; }` etc.). Prefer the
     `file`/`env` variants over a `%{file}%` macro unless phase 02 proved macros expand
     in registry objects.
   - `bindAuthentication ? true` (search-then-bind = the kanidm path; `false` = local
     hash compare, impossible for kanidm — never default it false).
   - `filterLogin` (replaces `filter.name`), `filterMailbox` (replaces `filter.email`);
     keep the kanidm match `(&(class=person)(|(name=?)(spn=?)(mail=?)))` (the `?` full-
     value placeholder still works). Drop the `attributes.name` concept (no name attr).
   - `attrEmail`/`attrEmailAlias`/`attrDescription` as **arrays**; omit `attrClass`
     (defaults to `["objectClass"]`) but expose a `classAttr` option — verify `class`
     vs `objectClass` against the live gateway (kanidm may emit lowercase `objectclass`;
     upstream #2363 says the default matches case-insensitively).
   - `useTls` (STARTTLS) + `allowInvalidCerts`.
2. Update `nix/modules/ldap/stalwart.nix` options: **delete** `authMethod`,
   `authTemplate`, `authSearch`; **add** `bindAuthentication` (bool, default true),
   `bindSecretFile` (or a structured `bindSecret`), `filterLogin`/`filterMailbox` (str),
   `classAttr` (str, default `"objectClass"`), `useTls` (bool). Keep `url`, `baseDn`,
   `bindDn`, `directoryId`, `requireStorageRetention`, the assertions, the warnings.
   Note: in 0.16 the directory is a **registry object**, not a `services.stalwart.settings`
   entry — so this module now *produces the object* for phase 04 to place, rather than
   writing into `settings.directory.<id>`. Adjust the module's output target accordingly
   (coordinate the exact handoff shape with phase 04).
3. **Fail closed on the silent-default trap.** Add assertions: `bindAuthentication == true`
   (or a loud warning if false), and `bindDn != ""` — turning the dangerous all-default
   directory into an eval error.
4. Update `nix/modules/test/stalwart-eval.nix` to the new option names (drop
   `bindSecretMacro`/`authMethod`/etc.).
5. **Strengthen `nix/checks.nix`** `stalwart-module-eval`: assert the emitted JSON
   contains `"@type":"ldap"`, `bindAuthentication`, `filterLogin`, `bindDn`, `baseDn`,
   and assert it does **not** contain any 0.15 key (`bind.auth`/`filter.name`/`base-dn`/
   `allow-invalid-certs`/`attributes`). This is the cheap regression guard.
6. `alejandra` + `nix build .#checks.<sys>.stalwart-module-eval` + `nixfmt` green.

## Acceptance criteria

- [ ] `nix eval` of the emitter (via the eval test) produces a JSON object with
      `@type=ldap`, `url`, `baseDn`, `bindDn="dn=token"`, an `@type`-tagged `bindSecret`,
      `bindAuthentication=true`, `filterLogin`, `filterMailbox`, `attrEmail` (array),
      and **none** of: `bind.auth`, `filter.name`, `filter.email`, `attributes.*`,
      `base-dn`, `tls.allow-invalid-certs`.
- [ ] `nix/modules/ldap/stalwart.nix` no longer has `authMethod`/`authTemplate`/
      `authSearch`; has `bindAuthentication`/`filterLogin`/`filterMailbox`/`classAttr`/
      `useTls`/structured `bindSecret`; and asserts `bindAuthentication == true` &&
      `bindDn != ""` (eval error otherwise).
- [ ] `nix build .#checks.<sys>.stalwart-module-eval` passes with the strengthened
      assertions (new keys present, old keys absent).
- [ ] `nixfmt`/`alejandra --check` clean; `cargo`-side checks unaffected.
- [ ] A short comment in the lib cites the 0.16.7 source for the schema (so the next
      reader knows it's verified, not guessed).

## Files likely touched

- `nix/lib/stalwart.nix` — rewrite `kanidmLdapDirectory`; add `mkBindSecret*` helpers.
- `nix/modules/ldap/stalwart.nix` — options surface (delete 0.15 auth opts; add 0.16);
  tighten assertions; adjust output to the registry-object handoff.
- `nix/modules/test/stalwart-eval.nix` — new option names.
- `nix/checks.nix` — strengthen `stalwart-module-eval`.

## Pitfalls

- **The silent-default trap (the whole reason this phase is `medium`, not `mini`).**
  0.16 drops unknown keys silently. If you leave any 0.15 key, you get a default
  directory that authenticates nobody and reads no `mail`, with **no error**. The
  checks (5) + assertions (3) are the guard — don't skip them.
- **`bindSecret` is no longer a string.** It's an `@type`-tagged enum. Emitting a bare
  string macro silently yields the default (no bind) → anonymous read → no `mail`.
- **`class` vs `objectClass`.** The current module uses `class=person`. 0.16's default
  `attrClass` is `["objectClass"]`, case-insensitive. Make `classAttr` an option and
  verify against the live kanidm gateway before trusting either (phase 07 smoke).
- **Output target.** In 0.15 the module wrote `services.stalwart.settings.directory.<id>`
  (TOML). In 0.16 it produces a registry object for phase 04. Don't keep writing into
  `settings` — that path is dead. Settle the handoff shape with phase 04.

## Reference

- Migration spec §2b/§3a/§3b/§3c (exact 0.16 schema + lib/module/check delta):
  `stalwart-016-ldap-migration` workflow output (`…/tasks/wkd5kkpy3.output`).
- Source: `crates/registry/src/schema/structs.rs:3176-3229` (LdapDirectory),
  `…/structs_impl.rs:23228-23258` (defaults), `crates/directory/src/backend/ldap/{config,lookup}.rs`.
- The 0.15.5-schema version (rollback baseline): nix-provenance commit `25139d9`.
- Memory: `kanidm-ldap-bind-credentials`, `stalwart-016-config-rearchitecture`.
- Consumed by: phase 04 (places the object into the registry).
</content>
