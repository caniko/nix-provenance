# Phase 02 — Build the `vikunja-provision` reconciler crate

> **Recommended Codex model: GPT 5.5 medium**
>
> The substantive coding phase, but well-templated: it mirrors `rauthy-provision`
> almost line-for-line and reuses `provenance-core`, so the structure is pinned.
> What earns `medium` over `low` is real correctness content a weak model would
> botch — the membership-diff with bot-exclusion, the `6005`/`1005` business-code
> handling, and the **write-403-is-a-hard-fail** rule that prevents silent partial
> convergence. Not `high`: there is no open design question once the verified API
> contract and the sibling crate are followed. Bump to `high` only if the reviewer
> wants extra rigor on the diff/error semantics.

## Working tree

`/data/nvme0/can/Projects/nix-provenance`. Independent of Phase 01 (disjoint
files). Gates Phase 03 (the Nix module/checks consume this crate and its CLI
flags). Build/test with the dev shell (`nix develop`) so `cargo`, `clippy`,
`nextest` match the flake toolchain.

## Goal

A new `crates/vikunja-provision/` crate — a binary that reads a JSON state file of
desired Vikunja teams + memberships (rendered from kanidm groups) and reconciles a
running Vikunja instance toward it over `/api/v1`, idempotently, using a long-lived
scoped API token. It is a near-exact sibling of `rauthy-provision`, reuses
`provenance-core`, and `cargo build -p vikunja-provision` + `cargo test -p
vikunja-provision` pass.

## Why this matters now

This is the engine of the chosen Vikunja team-sync bridge (Option A in
[../../../upstreaming/bridges.md](../../../upstreaming/bridges.md)). kanidm cannot
emit the array-of-objects OIDC claim Vikunja team-sync needs (kanidm#2641), so we
provision teams out-of-band through Vikunja's REST API. Doing it as a
`provenance-core`-backed reconciler keeps it DRY with `immich-provision` /
`rauthy-provision` and makes it the durable answer, not a throwaway.

## Out of scope

- The NixOS module, packaging, checks, and bookkeeping (Phase 03).
- The SSO-claim cleanup (Phase 01).
- Minting the API token (a one-time manual admin step — documented in the crate
  README, performed at deploy time, not in this phase).
- Numeric user-ID resolution / `/users` search — members are addressed by username
  (the `users` route group is not token-reachable); do not add it.
- Managing OIDC-synced teams — those are read-only to the API; this crate manages
  only API-created local teams.

## Plan

1. **Scaffold the crate** mirroring `crates/rauthy-provision/`:
   - `crates/vikunja-provision/Cargo.toml`: workspace-inherited `edition`,
     `rust-version`, `repository`, `authors`; `license = "MIT OR Apache-2.0"`;
     `[[bin]] name = "vikunja-provision"`. Deps: `anyhow.workspace`,
     `clap.workspace`, `serde.workspace`, `serde_json.workspace`,
     `provenance-core = { path = "../provenance-core" }`, and **local** `reqwest`
     `{ version = "0.12", default-features = false, features = ["json",
     "rustls-tls-native-roots", "blocking"] }` (mirror rauthy — Vikunja is an
     external HTTPS service; rustls, no openssl, aarch64-clean). **No `spow`** (no
     Proof-of-Work here). `[lints.clippy] all = { level = "warn", priority = -1 }`.
   - `LICENSE-MIT` + `LICENSE-APACHE` (copy from `rauthy-provision`), and a
     `README.md` documenting: the API model, the one-time scoped-token mint
     (`teams` + `teams_members` scopes — derive exact strings from `GET
     /api/v1/routes` on the deployed instance), and the bot-username exclusion.
   - Add `"crates/vikunja-provision"` to `members` in the root `Cargo.toml`.
2. **`src/state.rs`** — desired state:
   - `State { teams: BTreeMap<String, TeamSpec> }` (key = team name).
   - `TeamSpec { present: bool (default true, via a `default_present` fn like the
     other crates' present-spec serde), members: Vec<String> (default empty),
     admins: Vec<String> (default empty), description: Option<String> }`.
   - Derive `Deserialize`; document that `members`/`admins` are kanidm usernames.
3. **`src/client.rs`** — thin blocking client (mirror `RauthyClient`):
   - Build via `provenance_core::http::build_blocking_client("vikunja-provision/<ver>",
     accept_invalid_certs, Some(Duration::from_secs(30)))`; base API `"{url}/api/v1"`;
     auth header `format!("Bearer {token}")`; `Debug` redacts the token.
   - Use `provenance_core::http::ensure_success as ok` for the success path, but
     **inspect status/body before** treating non-2xx as fatal so business codes can
     be classified (see below).
   - Endpoints: `wait_ready` (poll `GET /api/v1/info` until 200, then validate the
     token with one authenticated `GET /teams`); `list_teams` (`GET /teams`);
     `get_team` (`GET /teams/{id}` → members[]); `create_team` (`PUT /teams`,
     `{name, description?}`); `update_team` (`POST /teams/{id}`); `delete_team`
     (`DELETE /teams/{id}`); `add_member` (`PUT /teams/{id}/members`,
     `{username, admin}`); `remove_member` (`DELETE /teams/{id}/members/{username}`).
   - **Business-code handling:** Vikunja returns a JSON `{code, message}` on errors.
     On `add_member`, treat code `6005` (already a member) as a no-op success and
     `1005` (user does not exist yet — not logged in) as a tolerated soft-skip that
     logs and continues (the user joins on a later pass after first OIDC login).
   - **Write-403 is a HARD FAIL.** Any `403` on a write (`PUT`/`POST`/`DELETE`)
     must `bail!` with a message naming the operation and pointing at token scope
     drift — never a per-team `continue`. (See Pitfalls: silent partial convergence.)
4. **`src/main.rs`** — Cli + reconcile (mirror `rauthy-provision/src/main.rs`):
   - `clap` `Cli { --url, --state (PathBuf), --token-file (Option<PathBuf>),
     --token (Option<String>, env "VIKUNJA_PROVISION_TOKEN", hide_env_values),
     --bot-username (String — the service-account username to exclude),
     --ready-timeout (default 30), --accept-invalid-certs, --no-auto-remove,
     --allow-team-delete }`.
   - Resolve the token with `provenance_core::secret::resolve(token_file, token,
     "API token", "--token-file", "VIKUNJA_PROVISION_TOKEN")`.
   - `reconcile_teams`: for each desired team, `match (spec.present, found-by-name)`
     → create-if-missing (`PUT /teams`); update description on drift (`POST`);
     delete only when `present = false && allow_team_delete && !no_auto_remove`.
     Use the `match (present, current)` control shape the other crates use.
   - `reconcile_memberships`: desired = `spec.members` minus the bot username;
     observed = `get_team(id).members[].username` minus the bot username; add the
     set-difference (tolerate `6005`/`1005`); remove the extras **only when
     `!no_auto_remove`** (membership removal is the destructive direction — gate it
     like rauthy's deletions). **Never** add/remove the bot username. Reuse
     `provenance_core::setops` (`union`/`is_subset` patterns) where they fit;
     factor the diff into a pure function for testing.
   - `log(format_args!(...))` prefixed `[vikunja-provision]` like rauthy.
5. **Unit tests** (`#[cfg(test)]` in `main.rs`, mirror rauthy's): the membership
   diff is a pure function over `(desired, observed, bot)` → `(to_add, to_remove)`.
   Cover: set-match → empty deltas; missing member → in `to_add`; extra member → in
   `to_remove`; **bot in observed → never in `to_remove`**; bot in desired → never
   in `to_add`; unordered sets → no spurious delta.
6. Run `cargo fmt`, `cargo clippy -p vikunja-provision --all-targets -- -D warnings`,
   `cargo test -p vikunja-provision`.

## Acceptance criteria

- [ ] `cargo build -p vikunja-provision` succeeds; the binary is `vikunja-provision`.
- [ ] `cargo test -p vikunja-provision` passes, including membership-diff tests that
      assert the bot username is never in `to_add` or `to_remove`, and that
      matched sets yield empty deltas.
- [ ] `cargo clippy -p vikunja-provision --all-targets -- -D warnings` is clean.
- [ ] `src/client.rs` classifies `6005` (no-op) and `1005` (tolerated soft-skip) on
      member-add, and `bail!`s on any write-`403` (grep the source: a 403 branch
      that returns an error, not a `continue`/`Ok`).
- [ ] The crate reuses `provenance-core` (`http::build_blocking_client`,
      `http::ensure_success`, `secret::resolve`, `setops::*`) — no re-implemented
      HTTP/secret/set plumbing.
- [ ] `Cargo.toml` keeps `reqwest` local with `rustls-tls-native-roots`; the root
      `Cargo.toml` `[workspace.dependencies]` still has no `reqwest`; the crate is
      `MIT OR Apache-2.0` and does not depend on `immich-provision`.
- [ ] `cargo fmt --check` clean.

## Files likely touched

- `crates/vikunja-provision/Cargo.toml` — new (mirror rauthy; no spow).
- `crates/vikunja-provision/src/main.rs` — Cli + reconcile + tests.
- `crates/vikunja-provision/src/client.rs` — blocking client + business codes.
- `crates/vikunja-provision/src/state.rs` — desired-state types.
- `crates/vikunja-provision/{LICENSE-MIT,LICENSE-APACHE,README.md}` — new.
- `Cargo.toml` (root) — add the crate to `members`.

## Pitfalls

- **Silent partial convergence (the reason this is `medium`).** If a write-`403`
  is swallowed as a per-team skip, adds succeed while removes fail (or vice-versa)
  and membership is corrupted with no error. Symptom: members drift but the tool
  exits 0. Cause: catching 403 and continuing. Recovery: 403 on any write → `bail!`
  naming the op and token-scope drift. This is non-negotiable.
- **Bot self-removal.** The token's service account is auto-added as a team admin
  on create and is blocked from removing itself while sole member (last-member
  guard → 400). If the bot username isn't excluded from the observed set, the tool
  tries to remove it every run (churn / 400s). Exclude it from **both** desired and
  observed sets. Don't rely on "it's permanently immovable" — once real users join,
  it *can* be removed, which would also be wrong.
- **`6005`/`1005` misread as fatal.** `provenance_core::http::ensure_success` treats
  any non-2xx as an error; member-add returns these business codes on
  already-member / not-yet-logged-in. Classify them *before* `ok()`, or the first
  re-run (idempotent case) fails. New users only converge after their first OIDC
  login — document that expectation.
- **TLS feature drift.** Use `rustls-tls-native-roots` locally; do NOT hoist
  `reqwest` to the workspace (the `tls-feature-isolation` check fails the build,
  and a unioned feature set silently changes TLS roots). No openssl → aarch64-clean.
- **License firewall.** The crate is permissive; it must not depend on the AGPL
  `immich-provision` (the `license-firewall` check greps for it). It only depends on
  `provenance-core` (also permissive).
- **Inverted REST.** `PUT /teams` creates, `POST /teams/{id}` updates — do not
  assume conventional REST verbs.

## Reference

- Mirror template: `crates/rauthy-provision/src/{main.rs,client.rs,state.rs}`,
  `crates/rauthy-provision/Cargo.toml`.
- Shared plumbing: `crates/provenance-core/src/{http.rs,secret.rs,setops.rs,serde_ext.rs}`.
- Verified API contract + guardrails: [../../../upstreaming/bridges.md](../../../upstreaming/bridges.md)
  ("Recommended bridge, concretely"; the two load-bearing guardrails).
- Consumed by: Phase 03 (the module defaults to this package; the checks build/lint/test it).
