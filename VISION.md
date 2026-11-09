# nix-provenance vision

Declarative identity and OIDC provisioning for NixOS, Kanidm, and Rauthy: a DRY
monorepo of reconcilers and their NixOS/Home Manager modules. Internal users
live in Kanidm; external users are initialized through Rauthy; downstream
services get their app-side users, groups, roles, OIDC clients, and public keys
from a Nix-rendered state file.

## Problem

Per-application user management is bespoke and credential-prone. Each service
has its own admin API, field set, and idempotency bugs, and every hand-written
provisioner re-decides how passwords are handled and where they leak.

## Principles

- **Credentials are explicit and runtime-owned.** Internal human credentials are
  Kanidm's, external password initialization is Rauthy's email flow, and
  app-local passwords exist only as runtime password-file references (normally
  `config.age.secrets.<name>.path`) loaded through systemd credentials;
  reconcilers store rotation-marker hashes. Plaintext must never enter
  Nix-rendered JSON, the Nix store, argv, logs, or environment variables.
- **One spine.** A Nix option tree becomes a `builtins.toJSON` state file
  (`writeText`), an idempotent HTTP-admin reconciler applies it, and a
  `Type=oneshot RemainAfterExit` unit runs ordered after the system it
  provisions with credentials resolved from a runtime file.
- **A tenant is not always a crate.** `nix/modules/` encodes the kind: `idp/`,
  `service-oidc/`, `config-only/`, `ldap/`, `adapter/`.
- **Reconcilers share one control shape.** `match (present, current)` yields
  create, update-if-drifted, delete-if-allowed, or no-op.
- **DRY with an explicit license boundary.** Shared Nix and the permissive
  crates are `MIT OR Apache-2.0`; `immich-provision` is `AGPL-3.0-only`, and
  `LICENSING.md` carries the per-path SPDX map.
- **Do not fabricate with the data you have.** `AGENTS.md` forbids synthesizing
  or substituting missing required data; the rule is to stop and name the
  upstream producer, regeneration command, and validation command.

## Scope

Reconcilers `immich-provision`, `rauthy-provision`, `vikunja-provision`,
`forgejo-provision`, `provenance-oauth` (host/user-scoped OAuth enrollment,
refresh, and access-only adapters), plus `nixosModules`, `homeModules.fj` and
`homeModules.oauth`, and `lib` helpers such as `usersFromKanidmPersons`,
`kanidmOAuth2System`, and `passwords`.

## Non-goals

- PINs, app-local password-reset links, and notification emails.
- Per-app local user credentials for downstream services, with one explicit
  exception: native T3 Code environment enrollment, which may connect only one
  existing user's own environments and must use T3's native interfaces.
- Fleet membership, endpoints, and route preference are consumer policy, and
  Paperclip-specific integration belongs entirely in Paperclip.

## Direction

Recent work shares host-scoped ChatGPT authorization across stock apps through
access-only adapters, keeps rbw login state durable outside disposable caches,
reconciles Stalwart 0.16 listener PROXY trust, and adds native T3 Code
enrollment. The planning tree carries a staged Rauthy bootstrap-generate
sequence of two PRs.

## Place in the fleet

canix consumes the flake's modules directly (`root/modules/services/t3code.nix`,
`home/user/shared/development.nix`, `home/user/dejana/default.nix`) and
documents the identity model in `docs/src/reference/matrix.md`; Atlas's update
automation tracks the repository.
