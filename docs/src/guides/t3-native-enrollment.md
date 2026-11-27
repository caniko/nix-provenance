# Native T3 Code environment enrollment

`provenance-t3-enroll` links one existing Unix user's own T3 Code peers and
passes a private document to native desktop import. This is the T3 exception
to the repository's identity boundary. T3 owns pairing, sessions, credential
storage, its catalog, and keyring encryption.

The helper never reads, rewrites, or decrypts T3's connection catalog, secret
store, or database. It creates no T3 users, principals, passwords, or shared
multi-user server. Fleet membership, users, endpoints, LAN/VPN route preference,
scheduling, and nightly selection remain consumer policy (Canix for the current
fleet).

## Required T3 capability

The helper drives two native T3 surfaces:

- `t3 environment link URL --expect-environment-id ID --pairing-code -`
  (pairing code on stdin) plus `t3 environment list --json`.
- The desktop app's `--version --json` capability document and
  `--import-connections FILE` entry point.

The consumer pins a build with both surfaces; this repo pins no fork revision.
An older CLI fails its command. Plain `--version` output, even with `--json`,
fails before reading or exchanging a pairing code and never starts the GUI or
invokes import. There is no emulation, catalog rewrite, or broader-route fallback.

The destination environment must have Linked environments enabled (Settings →
Labs). Both ends must be T3 versions whose peer links enforce the link limits;
T3 refuses an incompatible peer explicitly.

`stock` nightly builds at the time this guide was written do not contain the
unattended import/link surfaces. Review and qualification happen in the T3
producer repository first; runtime acceptance is a consumer responsibility.

## Public manifest

Everything in the manifest is non-secret. Credentials are referenced by literal
private runtime paths and never serialized into this file.

```json
{
  "user": "alice",
  "baseDir": "/home/alice/.t3",
  "t3": "/run/current-system/sw/bin/t3",
  "desktop": "/run/current-system/sw/bin/t3-code",
  "peers": [
    {
      "environmentId": "env_atlas",
      "access": "approval-required",
      "urls": ["https://atlas.example.ts.net"],
      "owner": {
        "host": "atlas",
        "t3": "/run/current-system/sw/bin/t3",
        "baseDir": "/home/alice/.t3"
      },
      "desktop": {
        "bearer": {
          "httpBaseUrl": "https://atlas.example.ts.net/",
          "wsBaseUrl": "wss://atlas.example.ts.net/"
        },
        "ssh": {
          "alias": "atlas",
          "hostname": "atlas.example",
          "username": "alice",
          "port": 22
        }
      }
    }
  ]
}
```

- `user` must match the process's effective Unix user: no user switching or
  privilege elevation.
- `baseDir` is the required explicit local T3 data directory. It must already
  exist as a real directory owned by the effective user, not group/other
  writable, and outside the Nix store. Every local list/link passes
  `--base-dir`; `T3CODE_HOME` is removed so an ambient live install is never
  selected. The desktop import child instead receives `T3CODE_HOME=<baseDir>`,
  so it cannot select a different state. Canix owns creating it (for example a
  user service `StateDirectory`); the helper never initializes a foreign or
  missing path.
- `urls` are bare origins, preferred first. A verified link keeps that order;
  an offline primary may leave an ordered subset, never an extra or reordered
  route. Use `https` except on loopback or Tailscale, where `http` is allowed.
- `access` is the exact T3 `AuthMcpClientAccess` level (`read-only`,
  `approval-required`, `auto-accept-edits`, `auto`, `full-access`) and is never
  defaulted or widened.
- `owner` is the automatic same-owner executor. `host` must match the local
  hostname/loopback (operate as the current euid) or an already-trusted SSH
  alias (strict `BatchMode=yes` and `StrictHostKeyChecking=yes`; no key or trust
  flags are added). `t3` and `baseDir` are explicit absolute target paths. The
  base directory must already exist as a real directory owned by the expected
  owner and not group/other-writable; a missing, symlinked, foreign, or writable
  path fails before describe or minting and is never created by the helper. The
  helper verifies the remote login owner (`id -un`/`id -u` plus `stat`) and then
  reads the native environment descriptor before any pairing or session minting.
  Only the exact local hostname or loopback names select local mode; no DNS
  resolution is performed, so an FQDN alias remains an SSH declaration.
- A local owner never links the environment to itself and never mints a pairing
  code. The native describe descriptor is the verified environment, and a local
  bearer desktop route additionally requires
  `<baseDir>/userdata/server-runtime.json` to name the live loopback `http`
  origin already declared by the peer before the desktop session is minted.
- `environmentId` is required in manual file mode. With an owner executor it may
  be omitted; the descriptor supplies it. A declared value is cross-checked and
  a mismatch fails before minting.
- `pairingCodeFile` and desktop `credentialFile` are manual-file mode only. They
  are forbidden together with `owner`; an owner executor mints a fresh one-time
  pairing code for each link attempt and one session token per declared bearer
  or SSH target. Manual mode still requires one credential file per desktop
  target and reads a supplied pairing code only when a link must be made.
- A pairing code or token is never placed in argv or environment variables. The
  link code travels on stdin; minted tokens are held in zeroizing memory only
  long enough to write the private `0600` desktop import document. The link
  command always passes the exact `--expect-environment-id`, so T3 filters a
  wrong destination before the pairing code is exchanged.
- `desktop.bearer` and `desktop.ssh` are optional import routes for an already
  verified peer. Bearer URLs must already be T3-normalized (`https://host/`,
  `wss://host/`). Every declared bearer or SSH target gets its own profile and
  credential; the import never reuses an existing local keyring token for a
  changed endpoint. SSH username must be omitted or equal the manifest `user`;
  an omitted username is written into the import document as that owner, never
  left for OpenSSH config to resolve to another user.
- Pairing scopes come from the native `mcpClientScopes` for the declared access
  (`read-only`, `approval-required`, `auto-accept-edits`, `auto`, `full-access`).
  No admin or impersonation scope is requested. Desktop sessions use the native
  standard client scope set and a `30d` TTL; pairing codes use the native `5m`
  TTL. Import records are limited to the declared target, profile, and credential;
  learned/network/authorization flags are not import input.

## Secret file boundary

In manual file mode, pairing codes and bearer tokens must be regular UTF-8 files
that:

- are absolute, normalized runtime paths outside `/nix/store`;
- are owned by the effective user and have mode `0600` (no group/other bits);
- are at most 8 KiB and contain no interior control characters;
- are not symlinks (opened with `O_NOFOLLOW`).

The helper reads them into zeroizing memory, writes desktop tokens only into a
fresh `0700` runtime directory as a `0600` document, and removes the directory
after the import attempt. It never puts credentials in argv, environment
variables, the Nix store, or its own stdout/stderr. Credential-bearing child
output is never captured or echoed; failures report the command and exit status
only. A hard kill can leave the private directory behind; it is owned by the user
with `0700`/`0600` modes, so remove it under the normal runtime-temp cleanup
policy.

## Per-run behavior

1. Validate the manifest, the effective user, declared command paths, URLs,
   access values, SSH fields, owner fields, and secret path shapes. Nothing is
   spawned on a validation failure. Mixing an owner executor with manual secret
   files is rejected.
2. If desktop routes are declared, run the safe `--version --json` capability
   probe. A plain version or missing `import-connections` capability fails
   before any pairing code is read or exchanged, and no import is attempted.
3. For each owner executor, verify the login owner (`id -un` over strict SSH, or
   the current euid locally), then read `t3 environment describe --json [--base-dir]`.
   The descriptor supplies or cross-checks the environment id before any
   pairing/session minting.
4. Read the current links through `t3 environment list --json`.
5. For a peer already linked with the declared access, an ordered declared URL
   route (full or offline-primary subset), and a reachable status, keep it and
   do not mint a pairing code.
6. Otherwise link with exactly the declared URLs, `--expect-environment-id`,
   and access. An owner executor mints a fresh `5m` pairing code for every link
   attempt; manual mode reuses its supplied file. There is no alternate URL,
   weaker access, or local catalog write.
7. After linking, verify the expected environment id, declared URL order, and
   access. A mismatch is an error. The helper never unlinks or edits a link in
   response: a pre-existing manual link must not be deleted, and a local unlink
   would not revoke an exchanged remote credential anyway.
8. Only after every declared peer verifies, build the desktop import document
   from the verified label, environment id, declared routes, and credentials.
   Owner mode lists sessions carrying the exact deterministic
   `provenance-t3-enroll:<user>:<environment>:<record>` label and subject,
   mints a dedicated `30d` session token per declared bearer or SSH target over
   the same verified owner path, and imports the private document. On success it
   revokes only the previously managed sessions it replaced; on import failure
   it revokes only sessions minted in this run and leaves old working sessions
   and unrelated manual sessions untouched. Manual file mode does not own or
   revoke issuance. Removing or renaming a route does not revoke its previously
   managed sessions; they remain until the native `30d` expiry. There is no
   namespace-wide revocation or session ledger.

The import includes only declared `targets`, `profiles`, and `credentials`.
T3's merge preserves unrelated manual connections. For `app-running` or an
unavailable keyring, the helper retries the same document with a bounded timeout,
then reports failure. It never switches stores or edits the catalog.

## NixOS module

```nix
{config, inputs, ...}: {
  imports = [inputs.nix-provenance.nixosModules.t3Enrollment];

  services.nix-provenance.t3Enrollment = {
    enable = true;
    user = "alice";
    baseDir = "/home/alice/.t3";
    # Substitute the consumer's pinned T3 build paths.
    t3 = "/run/current-system/sw/bin/t3";
    desktop = "/run/current-system/sw/bin/t3-code";
    peers = [
      {
        environmentId = "env_atlas";
        access = "approval-required";
        urls = ["https://atlas.example.ts.net"];
        pairingCodeFile = "/run/credentials/alice-t3-enroll.service/atlas-code";
        desktop.bearer = {
          httpBaseUrl = "https://atlas.example.ts.net/";
          wsBaseUrl = "wss://atlas.example.ts.net/";
          credentialFile = "/run/credentials/alice-t3-enroll.service/atlas-token";
        };
      }
    ];
  };
}
```

The module renders the non-secret manifest at
`config.services.nix-provenance.t3Enrollment.manifestFile` (and exports the same
value as `manifest`), installs the helper, and only asserts the identity, path,
access, and unique-id boundaries. It does not create a service, timer, user,
endpoint, or credential. With an owner executor, set `owner = {host;t3;baseDir;}`
and omit `pairingCodeFile`/`credentialFile`; no T3 credential is loaded into
systemd. The consumer owns the systemd unit and its credential materialization,
for example:

```nix
systemd.user.services.can-t3-enroll = {
  serviceConfig = {
    Type = "oneshot";
    # Keep this above the sum of per-child budgets: default 30s per T3/owner
    # command, 120s per desktop import, multiplied by bounded attempts.
    TimeoutStartSec = "15min";
    ExecStart = "${config.services.nix-provenance.t3Enrollment.package}/bin/provenance-t3-enroll --manifest ${config.services.nix-provenance.t3Enrollment.manifestFile} --attempts 3";
    LoadCredential = [
      "atlas-code:/run/agenix/t3-atlas-pairing-code"
      "atlas-token:/run/agenix/t3-atlas-bearer-token"
    ];
  };
};
```

Run it manually while validating a consumer:

```sh
provenance-t3-enroll --manifest /etc/nix-provenance/t3-enrollment.json
```

Set `--attempts` above one only for transient offline peers or a desktop app
that was briefly running. A consumed one-time pairing code still requires a new
code; retries never broaden access.

## Owner executor limits

`owner` selects automatic mode; omit it for manual files. The helper uses the
existing OpenSSH client only for owner and path checks and the fixed native
commands below:

- `id -un` owner check.
- `t3 environment describe --json --base-dir PATH`.
- `t3 auth pairing create --json --ttl 5m --scope … --base-dir PATH`.
- `t3 auth session issue --json --ttl 30d --label … --subject … --base-dir PATH`.
- `t3 auth session list --json --base-dir PATH`.
- `t3 auth session revoke SESSION --base-dir PATH`.

There is no arbitrary shell command or remote URL field. The SSH destination,
login user, T3 path, base directory, environment id, scopes, and TTL are all
validated; every remote argument is single-quoted before OpenSSH joins it. The
client uses `BatchMode=yes`, `StrictHostKeyChecking=yes`, and a bounded connect
timeout; it never adds keys or trust flags. One bounded runner owns stdin/stdout
with nonblocking polling: captured stdout is capped at 64 KiB and drained, stderr
is discarded, each child shares one deadline including post-exit drain, and a
timeout kills only the process group created and tracked at spawn. Missing or
foreign base directories are never created by the helper. A local owner match
uses the current euid and the explicit base directory, never SSH.

Pairing scopes are the native `mcpClientScopes` for the declared access; no
admin/impersonation scope is added. Desktop sessions use the native standard
client scope set with a `30d` TTL. A reachable matching link never mints a
pairing code. Every owner link attempt mints a fresh code, so an ambiguous
exchange is never retried with a possibly consumed code.

Canix remains policy-only: it declares fleet membership, user, endpoints,
routing, and build; provenance owns owner discovery and native minting.

## Qualification boundary

Fake `t3`, SSH, and desktop adapters test trust and input boundaries, private
files, idempotency, route order, capability preflight, SSH owner binding,
mint refusal on owner/environment mismatch, fresh-code retry, and import shape.
For live acceptance, use a signed T3 build with both native surfaces, an
already-trusted SSH path, the user's keyring, and consumer-owned wiring. Verify
imported entries and preservation of manual connections.
No upstream PR is made until maintainer approval.
