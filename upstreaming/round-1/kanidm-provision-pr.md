# kanidm-provision — PR draft: provision POSIX/unix passwords

**Repo:** `oddlama/kanidm-provision` · **Branch from:** `main` · **Vehicle:** cold
single-concern PR (the repo has no CONTRIBUTING/template/issue policy; every
existing feature PR was opened cold). A tracking issue is optional.

> [!IMPORTANT]
> **The code below is written against `main`, not the v1.3.0 tag.** The
> `enable_unix` block this PR edits and the `gidNumber`/`loginShell` fields were
> added by #31, which is merged to **main only** (not in v1.3.0, which nixpkgs
> builds). Branch from `main`, rebase past #31, and **re-verify the exact line
> numbers** — they will not match v1.3.0. Frame the PR as "completing the POSIX
> story #31 started."
>
> **Note the local overlap honestly in the PR framing.** nix-provenance's
> `identity-cli` currently sets posix passwords directly (and carries its own
> posix-extend path that overlaps #31's `enableUnix`/`gidNumber`/`loginShell`).
> Pitch this PR as the first step to *consolidate the posix-password half into
> kanidm-provision so we can retire that local path* — we're reducing our own
> workaround surface, not adding a parallel one. That pre-empts the obvious "why
> does your tool also do posix work?" question.
>
> (Forward note: kanidm v1.10.x's per-application LDAP "application passwords" may
> eventually make a posix-password field legacy, but that's a different,
> undocumented, user-self-service model — not a reason to wait.)

**Scope decision:** this PR does **only** the POSIX-password half. The
`ldap_allow_unix_pw_bind` domain toggle is intentionally a *separate, later* PR —
`state.rs` has no Domain entity to hang it on (designing one is an orphan-removal
/ JSON-key decision), and the toggle requires the `admin` account whereas this
tool authenticates as `idm_admin`. Don't let that bikeshed hold up the easy win.

Service-account API-token minting and claim-map value types are **out of scope**
and should not be mentioned as "coming" — token values are returned once,
server-side (impossible declaratively without a server patch), and array claim
maps are already supported (`ClaimMap.values_by_group: HashMap<String, Vec<String>>`).

---

## PR title

```
feat: provision POSIX/unix passwords for persons
```

## PR body

> Completes the POSIX provisioning story for persons. The tool can already
> posix-*enable* a person and set `gidNumber`/`loginShell` (#31), but a POSIX
> account is unusable for an LDAP/mail bind without a POSIX password — which
> previously had to be set out of band. This adds an optional, file-backed
> `unixPasswordFile` on `Person`.
>
> **No kanidm patch required.** Unlike the oauth2 basic-secret feature, this
> uses the stock, unprivileged endpoint `PUT /v1/person/{name}/_unix/_credential`
> (the same one `kanidm person posix set-password` drives), so it works against
> an unmodified server.
>
> Details:
> - `unixPasswordFile` is read from a file and trimmed, mirroring the existing
>   `basicSecretFile` convention; the value is **never** logged or placed in any
>   tracing field.
> - It only applies when `enableUnix` is true; if set without `enableUnix` the
>   tool warns and skips (consistent with the existing `gidNumber`/`loginShell`
>   handling).
> - kanidm exposes no way to read a POSIX password back, so there is nothing to
>   diff against; the password is re-asserted on every run. This is idempotent
>   in effect (converges to the desired value) but always issues the PUT.
>
> Validated against the nixpkgs kanidm NixOS VM test path (the repo's tests were
> removed in favour of upstream nixpkgs tests, so no in-repo test is added).
>
> README feature matrix + JSON schema updated in this PR.

---

## Code changes

### `src/state.rs` — add the field to `Person`

After the `login_shell` field:

```rust
    pub login_shell: Option<String>,
    /// Optional. Path to a file whose trimmed contents are set as this person's
    /// POSIX/unix password. Requires `enableUnix`. kanidm exposes no way to read
    /// it back, so it is re-asserted on every run.
    pub unix_password_file: Option<String>,
```

(`#[serde(rename_all = "camelCase")]` is already on the struct, so the JSON key
is `unixPasswordFile`.)

### `src/client.rs` — add the setter

Place it directly after `update_unix_attrs` (`json!` and `log_event` are already
in scope, `ENDPOINT_PERSON` is defined in this file):

```rust
    /// Set a person's POSIX/unix password via the stock unix credential endpoint.
    /// kanidm stores only a hash and exposes no read path, so the value cannot be
    /// diffed and is written unconditionally. The secret is never logged.
    pub fn set_person_unix_password(&self, name: &str, password_file: &str) -> Result<()> {
        let password =
            std::fs::read_to_string(password_file).wrap_err_with(|| format!("failed to read {:?}", password_file))?;
        let password = password.trim();

        log_event("Updating", &format!("{ENDPOINT_PERSON}/{name}/_unix/_credential"));
        self.client
            .put(format!("{}{ENDPOINT_PERSON}/{name}/_unix/_credential", self.url))
            .headers(self.idm_admin_headers.clone())
            .json(&json!({ "value": password }))
            .send()?
            .detailed_error_for_status()?;
        Ok(())
    }
```

### `src/main.rs` — wire it into `sync_persons`

Replace the existing `if person.enable_unix { … }` block (currently lines ~164–173):

```rust
            if person.enable_unix {
                let mut unix_attrs = HashMap::new();
                if let Some(gid_number) = &person.gid_number {
                    unix_attrs.insert("gidnumber", gid_number.clone().into());
                }
                if let Some(login_shell) = &person.login_shell {
                    unix_attrs.insert("loginshell", login_shell.clone().into());
                }
                let _ = kanidm_client.update_unix_attrs(ENDPOINT_PERSON, &name, unix_attrs);

                if let Some(unix_password_file) = &person.unix_password_file {
                    kanidm_client.set_person_unix_password(name, unix_password_file)?;
                }
            } else if person.unix_password_file.is_some() {
                println!(
                    "{}",
                    format!("WARN: ignoring unixPasswordFile for person {name} because enableUnix is false")
                        .yellow()
                        .bold()
                );
            }
```

### `README.md` — feature matrix + schema

In the **Persons** table, change the Credentials row:

```diff
-| ❌ | Credentials
+| ✅ | Credentials (POSIX/unix password)
```

In the persons block of the JSON schema, after `"loginShell": "/bin/sh"`:

```diff
       # Optional.
-      "loginShell": "/bin/sh"
+      "loginShell": "/bin/sh",
+      # Optional. Path to a file containing this person's POSIX/unix password.
+      # Requires enableUnix. Whitespace is trimmed. Re-applied on every run
+      # (kanidm does not expose the password for reading/diffing).
+      "unixPasswordFile": "./person1.posix"
```

---

## Pre-submit checklist

- [ ] `cargo fmt` and `cargo clippy` clean.
- [ ] Confirm the endpoint/body against the kanidm version you run: it should be
      `PUT /v1/person/{name}/_unix/_credential` with body `{"value": "<pw>"}`
      (matches `idm_person_account_unix_cred_put`). Re-check if you target an
      older release.
- [ ] Conventional-commit subject (`feat:`).
- [ ] PR body notes validation via the nixpkgs VM test; no in-repo test added.
- [ ] Expected failure mode is maintainer **silence**, not rejection (#29 sat
      ~10 months). Keep it trivially self-reviewable; offer to split if asked.
