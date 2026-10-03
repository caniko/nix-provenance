# Tuwunel private rooms

Import `nixosModules.tuwunel` and declare a provisioned service account with a
runtime `passwordFile`. For an owner-created private room, set both `creator`
and `encrypted`; the legacy admin-created room path remains available when
both are absent/false.

```nix
services.matrix-tuwunel.provision.rooms.assistant = {
  alias = "#assistant:matrix.example.com";
  creator = "assistant";
  encrypted = true;
  invite = ["@owner:matrix.example.com"];
  expectedRoomId = null;
};
```

The owner creates the room with invite-only access, forbidden guest access and
Megolm encryption in its initial state. Reconciliation checks canonical state
keys, the joined owner and every active membership before adding missing
invitations. It refuses undeclared members and invitations, public rooms and
unencrypted rooms. It does not retrofit encryption or evict members.

After bootstrap, inspect the actual room and record its observed ID in
`expectedRoomId`. A pinned alias resolving elsewhere or disappearing fails
instead of creating a replacement. Current membership cannot establish the
absence of historical access; review existing-room history separately.

Room reconciliation logs in with `TUWUNEL_PROVISION`, reuses its initialized
HTTP transport and logs out after success or reconciliation failure. Logout
failure prevents a successful result. A process crash cannot execute cleanup;
inspect/revoke the provisioning device during recovery. Personal clients need
their own persistent devices and crypto state.

## Qualification

Run native tests and warnings-denied Clippy in the approved development shell:

```sh
direnv exec . cargo test -p tuwunel-provision --locked
direnv exec . cargo clippy -p tuwunel-provision --locked --all-targets -- --deny warnings
```

`crates/tuwunel-provision/tests/rooms.rs` executes the actual provisioner against
a bounded localhost HTTP fixture. It covers request/authentication policy,
missing invitations, missing/drifted pinned aliases, unsuitable state,
invitation errors, logout on failure and legacy admin-room behavior.

The separate `checks.x86_64-linux.tuwunel-private-rooms-vmtest` boots a
disposable Tuwunel instance through the actual NixOS provisioner unit. Synthetic
credentials are test-only. The server fixture checks initial encryption before
the first human invitation, both owners' isolated rooms, Can's join, repeated
reconciliation, observed-ID pinning, alias loss/drift, unsafe existing rooms,
unexpected invitations and provisioning-device removal. It does not implement
client-side crypto or prove encrypted conversational delivery.

Qualify these exact outputs on the producer's hosted PR:

- `.#packages.x86_64-linux.tuwunel-provision`
- `.#checks.x86_64-linux.tuwunel-provision-test`
- `.#checks.x86_64-linux.tuwunel-provision-clippy`
- `.#checks.x86_64-linux.tuwunel-module-eval`
- `.#checks.x86_64-linux.tuwunel-private-rooms-vmtest`

Add those installables to `[ci].nix_builds` in `simit.toml`, retaining per-crate
CI. The matrix policy is supported by Simit
`beea3e284a613d46468779bd998e51be2d63566c`:

```toml
[ci.nix_build]
only = false
timeout_minutes = 90
max_parallel = 1
max_jobs = 1
cores = 2
kvm = true
capture_results = true
artifact_retention_days = 14
```

Generate and verify workflows through that immutable generator:

```sh
nix run github:caniko/simit/beea3e284a613d46468779bd998e51be2d63566c -- init ci --package tuwunel-provision
nix run github:caniko/simit/beea3e284a613d46468779bd998e51be2d63566c -- init ci --package tuwunel-provision --check --diff
```

These are qualification instructions, not passing receipts. If the generator
is unavailable, leave generated workflows unchanged and report the blocker.
Consume a published revision only after the required gates pass for that exact
candidate. Host activation and real Matrix/E2EE acceptance are separate gates.
