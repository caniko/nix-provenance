# Phase 02 Run Model Findings

Date: 2026-06-03.

This note maps Stalwart 0.16.7 startup and registry provisioning from the pinned
phase-01 binaries:

- `stalwart`: `/nix/store/lgsb3vs9w8wbszy07vzpjzmdwk8il397-stalwart-0.16.7/bin/stalwart`
- `stalwart-cli`: `/nix/store/iqr6y0sjl1h33g41x2ysxv47r5a7i8vy-stalwart-cli-1.0.0/bin/stalwart-cli`
- Stalwart source: `/nix/store/1ffpazhgphnbr0x6w7vwas2g2xnhjvnk-source`
- CLI source: `/nix/store/pv1n8ra26bjac9xp3d8s2nda0bwf985g-source`

## Executive Findings

- The `-c <path>` file is a JSON `DataStore` object, not the old TOML config.
- A present PostgreSQL `DataStore` JSON boots against PostgreSQL and creates SQL
  tables. A missing config file enters bootstrap mode using an ephemeral store.
- `STALWART_RECOVERY_MODE=1` keeps a PostgreSQL-backed instance in recovery mode
  and exposes only recovery HTTP on port 8080. It does not activate registry
  `NetworkListener` sockets.
- `STALWART_RECOVERY_ADMIN=user:password` pins the recovery Basic Auth account.
  Without it, bootstrap mode prints a one-time generated `admin` password.
- `stalwart-cli apply` is the headless provisioning path. It consumes
  newline-delimited JSON operations with `@type` values `create`, `update`, and
  `destroy`.
- Registry sets are JSON objects of `{ "<value>": true }`, not arrays. This is
  required for listener binds, LDAP attribute sets, aliases, ACME contact lists,
  DNS record publish sets, and role/permission sets.
- `NetworkListener` objects are consumed on normal startup. Recovery mode opens
  only the recovery listener.
- TLS/ACME is not a listener-local TOML block in 0.16. It is represented by
  `DnsServer`, `AcmeProvider`, and `Domain.{dnsManagement,certificateManagement}`.
- Secret expansion is native registry object variants. Use `{"@type":"File",
  "filePath":"..."}` or `{"@type":"EnvironmentVariable","variableName":"..."}`.
  The old `%{file:...}%` / `%{env:...}%` string macros are not a registry secret
  expansion mechanism in the inspected 0.16 source.

## Bootstrap JSON

Minimal PostgreSQL bootstrap file proven locally:

```json
{
  "@type": "PostgreSql",
  "host": "127.0.0.1",
  "port": 55432,
  "database": "stalwart",
  "authUsername": "stalwart",
  "authSecret": { "@type": "None" },
  "useTls": false,
  "allowInvalidCerts": false,
  "poolMaxConnections": 4
}
```

For thething, keep the same shape but set `port` to `5432` and use:

```json
"authSecret": { "@type": "File", "filePath": "/run/credentials/stalwart.service/pg_password" }
```

Source evidence:

- `crates/store/src/registry/local.rs:71-88` reads `local_path` and parses it with
  `serde_json::from_str::<DataStore>()`.
- `crates/registry/src/schema/structs.rs:888-893` defines `DataStore` with
  `#[serde(tag = "@type")]` variants including `PostgreSql`.
- `crates/registry/src/schema/structs.rs:4140-4164` defines the
  `PostgreSqlStore` fields.
- `crates/registry/src/schema/structs_impl.rs:30727-30745` shows PostgreSQL
  defaults: `port = 5432`, `database = "stalwart"`,
  `authUsername = "stalwart"`, `poolMaxConnections = 10`.

Local boot command and log:

```sh
STALWART_RECOVERY_MODE=1 \
STALWART_RECOVERY_ADMIN='admin:phase02pass' \
STALWART_HOSTNAME='mail.local.test' \
/nix/store/lgsb3vs9w8wbszy07vzpjzmdwk8il397-stalwart-0.16.7/bin/stalwart \
  -c /tmp/stalwart-016-phase02/config.json
```

```text
2026-06-03T11:19:40Z WARN Server started in recovery mode (server.recovery-mode) details = "Port 8080 is open for troubleshooting and recovery.", hostname = "mail.local.test", version = "0.16.7"
2026-06-03T11:19:40Z INFO Network listener started (network.listen-start) listenerId = "http-recovery", localIp = ::, localPort = 8080, tls = false
```

## Recovery Mode Mechanics

Source evidence:

- `crates/store/src/registry/local.rs:38-45` parses
  `STALWART_RECOVERY_MODE` as truthy when it is `1` or case-insensitive `true`;
  `STALWART_RECOVERY_ADMIN` is parsed as `username:password`.
- `crates/store/src/build/registry.rs:35-66` enters bootstrap/recovery when the
  config file is missing, opens an ephemeral store, and prints a generated
  `admin` credential if `STALWART_RECOVERY_ADMIN` is not provided.
- `crates/common/src/auth/authentication.rs:78-118` authenticates the recovery
  admin as a fallback Basic Auth account.
- `crates/http/src/auth/permissions.rs:60-128` gives recovery/bootstrap auth
  bootstrap/system permissions and deliberately strips some account/password/API
  key permissions from the recovery admin.

Operational flow:

1. Start with the PostgreSQL `config.json` and
   `STALWART_RECOVERY_MODE=1 STALWART_RECOVERY_ADMIN=admin:<secret>`.
2. Use `stalwart-cli --url http://127.0.0.1:8080 --user admin --password <secret>`.
3. Apply registry objects.
4. Restart without `STALWART_RECOVERY_MODE` so normal `NetworkListener` objects
   are activated.

Important: recovery mode does not activate the registry mail listeners. After
creating SMTP/submission/IMAPS listeners and running `Action/ReloadSettings`,
`ss` still showed only recovery HTTP:

```text
State  Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0      1024               *:8080            *:*
```

After restarting without recovery mode, the provisioned listeners were active.

## `stalwart-cli apply` Format

CLI/source and runtime evidence:

- `stalwart-cli` 1.0.8 parses `--file` input as newline-delimited JSON
  operations; a JSON array fails with `invalid plan NDJSON`.
- `src/commands/apply.rs:143-166` defines the operation format:
  `{"@type":"create","object":"...","value":{...}}`,
  `{"@type":"update","object":"...","id":"...","value":...}`, and
  `{"@type":"destroy","object":"...","value":...}`.
- `src/commands/apply.rs:333-382` supports `#clientId` references across
  operations.

Working shape:

```jsonl
{"@type":"create","object":"NetworkListener","value":{"smtp":{"name":"smtp","bind":{"127.0.0.1:2525":true},"protocol":"smtp","useTls":false,"tlsImplicit":false}}}
{"@type":"create","object":"Directory","value":{"kanidm":{"@type":"Ldap","url":"ldaps://auth.tartanoglu.com:3636","baseDn":"dc=auth,dc=tartanoglu,dc=com","bindDn":"dn=token","bindSecret":{"@type":"File","filePath":"/run/credentials/stalwart.service/kanidm_bind"},"bindAuthentication":true,"filterLogin":"(|(mail=?)(spn=?)(name=?))","filterMailbox":"(|(mail=?)(mailAlternateAddress=?))"}}}
{"@type":"create","object":"Domain","value":{"example.test":{"name":"example.test"}}}
```

Do not use arrays for registry set fields. Source:
`crates/registry/src/types/map.rs:118-213` serializes `Map<T>` as object keys
with boolean values and rejects arrays.

## Proven Headless Provisioning Example

The local run applied a plan with three listeners, an LDAP directory, and a
domain. The first account attempt with embedded `credentials` failed; creating a
user account without credentials succeeded. Phase 04/06 must not assume password
credentials can be embedded in an `Account` create without further proof.

Successful apply output for listeners, directory, and domain:

```text
Plan: 0 destroy, 0 update, 4 create (6 objects)
✓ created NetworkListener (3)
✓ created Directory (1)
✓ created Domain (1)
✗ create Account: Account: create failed for `alice` (operation #4): error: invalidPatch |   Invalid value for object property |   Properties: credentials
Done: 0 destroyed, 0 updated, 5 created (1 failed)
```

Successful account create without credentials:

```text
Plan: 0 destroy, 0 update, 1 create (1 objects)
✓ created Account (1)
Done: 0 destroyed, 0 updated, 1 created (0 failed)
```

Resulting queries:

```text
[{"name":"imaps","bind":{"127.0.0.1:2993":true},"protocol":"imap","useTls":true,"tlsImplicit":true,"id":"iubycnecabaa"},{"name":"submission","bind":{"127.0.0.1:2587":true},"protocol":"smtp","useTls":true,"tlsImplicit":false,"id":"iubycneaaaqa"},{"name":"smtp","bind":{"127.0.0.1:2525":true},"protocol":"smtp","useTls":false,"tlsImplicit":false,"id":"iubycnd1aaaa"}]
[{"description":"throwaway Kanidm LDAP directory","url":"ldaps://auth.tartanoglu.com:3636","bindDn":"dn=token","bindSecret":{"filePath":"/tmp/stalwart-016-phase02/kanidm.token","@type":"File"},"bindAuthentication":true,"filterLogin":"(|(mail=?)(spn=?)(name=?))","filterMailbox":"(|(mail=?)(mailAlternateAddress=?))","id":"iubycnegabqa"}]
[{"name":"alice2","domainId":"b","description":"throwaway phase 02 account without password","emailAddress":"alice2@example.test","id":"b"}]
```

Normal-mode listener proof after restart:

```text
State  Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0      1024       127.0.0.1:2993      0.0.0.0:*
LISTEN 0      1024       127.0.0.1:2587      0.0.0.0:*
LISTEN 0      1024       127.0.0.1:2525      0.0.0.0:*
```

Exact low-port proof is blocked in this shell:

- Missing artifact/capability: the test process has no `CAP_NET_BIND_SERVICE`,
  and `/proc/sys/net/ipv4/ip_unprivileged_port_start` is `1024`.
- Why required: binding 25, 587, and 993 below 1024 requires root, file
  capability, or a host sysctl allowing unprivileged low ports.
- Upstream producer to fix: the local test runner / host environment.
- Regeneration command: run the normal-mode listener test as root, set
  `cap_net_bind_service=+ep` on a copied `stalwart` binary, or temporarily set
  `sysctl net.ipv4.ip_unprivileged_port_start=0`.
- Validation command: `ss -ltn '( sport = :25 or sport = :587 or sport = :993 )'`.

The exact production listener objects are the same as the proven high-port
objects except for `bind`:

```json
{
  "@type": "create",
  "object": "NetworkListener",
  "value": {
    "smtp": {
      "name": "smtp",
      "bind": { "[::]:25": true },
      "protocol": "smtp",
      "useTls": false,
      "tlsImplicit": false
    },
    "submission": {
      "name": "submission",
      "bind": { "[::]:587": true },
      "protocol": "smtp",
      "useTls": true,
      "tlsImplicit": false
    },
    "imaps": {
      "name": "imaps",
      "bind": { "[::]:993": true },
      "protocol": "imap",
      "useTls": true,
      "tlsImplicit": true
    },
    "https-admin": {
      "name": "https-admin",
      "bind": { "127.0.0.1:8580": true },
      "protocol": "http",
      "useTls": false,
      "tlsImplicit": false
    }
  }
}
```

## TLS And ACME Representation

Relevant schema:

- `NetworkListener`: `bind`, `protocol`, `useTls`, `tlsImplicit`.
- `DnsServer`: variant object; for Cloudflare use `{"@type":"Cloudflare", ...}`.
- `AcmeProvider`: `directory`, `contact`, `challengeType`, `renewBefore`.
- `Domain`: `dnsManagement` and `certificateManagement` variants.
- `SystemSettings.defaultCertificateId` is the default SNI fallback certificate
  when using manual certificates.

Proven ACME/DNS provisioning:

```json
[
  {
    "@type": "create",
    "object": "DnsServer",
    "value": {
      "cloudflare": {
        "@type": "Cloudflare",
        "description": "Cloudflare DNS provider",
        "secret": { "@type": "File", "filePath": "/run/credentials/stalwart.service/cloudflare_token" },
        "timeout": 30000,
        "ttl": 300,
        "pollingInterval": 5000,
        "propagationTimeout": 120000
      }
    }
  },
  {
    "@type": "create",
    "object": "AcmeProvider",
    "value": {
      "letsencrypt": {
        "directory": "https://acme-v02.api.letsencrypt.org/directory",
        "contact": { "cloudflare@rotas.mozmail.com": true },
        "challengeType": "Dns01",
        "renewBefore": "R34",
        "maxRetries": 3
      }
    }
  }
]
```

The server normalizes ACME contact to `mailto:`:

```text
[{"challengeType":"Dns01","contact":{"mailto:cloudflare@rotas.mozmail.com":true},"directory":"https://acme-v02.api.letsencrypt.org/directory","renewBefore":"R34","maxRetries":3,"id":"iubykxtyaaqa"}]
```

Correct domain update uses `DnsRecordType` keys from `stalwart-cli describe
DnsRecordType`, not raw DNS RR-type names:

```json
{
  "dnsManagement": {
    "@type": "Automatic",
    "dnsServerId": "<dns-server-id>",
    "publishRecords": {
      "mx": true,
      "spf": true,
      "dkim": true,
      "tlsa": true,
      "mtaSts": true,
      "tlsRpt": true,
      "caa": true
    }
  },
  "certificateManagement": {
    "@type": "Automatic",
    "acmeProviderId": "<acme-provider-id>",
    "subjectAlternativeNames": { "mail.tartanoglu.com": true }
  }
}
```

Proven query after corrected update:

```text
[{"name":"example.test","certificateManagement":{"acmeProviderId":"iubykxtyaaqa","subjectAlternativeNames":{"mail.example.test":true},"@type":"Automatic"},"dnsManagement":{"dnsServerId":"iubykud7aaaa","origin":null,"publishRecords":{"mx":true,"spf":true,"dkim":true,"tlsa":true,"mtaSts":true,"tlsRpt":true,"caa":true},"@type":"Automatic"},"id":"b"}]
```

## Secrets

Source evidence:

- `crates/registry/src/schema/structs.rs:4530-4558` defines
  `SecretKey` / `SecretKeyOptional` variants `Value`, `EnvironmentVariable`,
  and `File`.
- `crates/registry/src/schema/structs.rs:4567-4582` defines the same native
  variants for `SecretText`.
- `crates/registry/src/utils/secret.rs:13-28` resolves `SecretKey` and
  `SecretText` by matching those enum variants.
- `crates/registry/src/utils/secret.rs:93-121` reads file paths and environment
  variables. It does not parse `%{file:...}%` or `%{env:...}%`.
- Searching the inspected registry/common/store/smtp/directory source for
  `%{file:` and `%{env:` found no registry macro expansion path.

Use native variants:

```json
{ "@type": "File", "filePath": "/run/credentials/stalwart.service/kanidm_bind" }
{ "@type": "EnvironmentVariable", "variableName": "BREVO_LOGIN" }
{ "@type": "Value", "secret": "literal-only-for-tests" }
```

Do not use old TOML macros inside registry secret fields:

```json
{ "@type": "Value", "secret": "%{file:/run/credentials/stalwart.service/brevo_key}%" }
```

That is just a literal `Value` secret in 0.16 registry data.

## thething Settings Mapping

Current live source inspected:
`/data/nvme0/can/Projects/canix/root/hosts/thething/server/stalwart.nix`.

| Current 0.15 setting concern | 0.16 registry representation |
|---|---|
| PostgreSQL `store.postgresql` and storage roles | `config.json` `DataStore/PostgreSql` for primary registry/data store. Also set singleton `BlobStore`, `SearchStore`, `TracingStore`, and `MetricsStore` to `Default` or `PostgreSql` as desired; defaults can use data store. |
| `storage.data`, `storage.fts`, `storage.lookup`, `storage.blob` | No old dotted TOML. 0.16 has singleton store-role objects: `DataStore`, `BlobStore`, `SearchStore`, `TracingStore`, `MetricsStore`, and lookup/store objects where needed. |
| `directory.kanidm` LDAP | `Directory` object variant `Ldap`; `Domain.directoryId` and/or singleton `Authentication.directoryId` point at the directory. |
| `session.auth.directory = 'kanidm'` | `Authentication.directoryId = <Directory id>`. |
| `session.auth.mechanisms = [plain, login]` | Not yet empirically mapped in this phase; must be checked before phase 04 relies on password SMTP auth. |
| `server.listener.smtp` | `NetworkListener` object: `protocol = "smtp"`, `bind = {"[::]:25": true}`, `useTls = false`, `tlsImplicit = false`. |
| `server.listener.submission` | `NetworkListener` object: `protocol = "smtp"`, `bind = {"[::]:587": true}`, `useTls = true`, `tlsImplicit = false`. |
| `server.listener.imaps` | `NetworkListener` object: `protocol = "imap"`, `bind = {"[::]:993": true}`, `useTls = true`, `tlsImplicit = true`. |
| `server.listener.https` loopback admin | `NetworkListener` object: `protocol = "http"`, `bind = {"127.0.0.1:8580": true}`. Required if CLI access is needed after leaving recovery mode. |
| `certificate.default` | For automatic per-domain certs, use `Domain.certificateManagement = {"@type":"Automatic", "acmeProviderId": ...}`. For manual/default fallback, use `Certificate` plus `SystemSettings.defaultCertificateId`. |
| `acme.letsencrypt` Cloudflare DNS-01 | `DnsServer/Cloudflare` object, `AcmeProvider` object, and `Domain.dnsManagement` / `Domain.certificateManagement` automatic variants. |
| `authentication.fallback-admin` | Use `STALWART_RECOVERY_ADMIN` only for recovery/provisioning. A permanent admin should be a registry `Account`/`Role` or supported admin auth path; do not treat recovery admin as normal production fallback. |
| Brevo relay `queue.route.relay` | `MtaRoute` object variant `Relay` with `authUsername` and `authSecret` native secret object. |
| Brevo route strategy `queue.strategy.route` | Singleton `MtaOutboundStrategy.route` expression. Source defaults use `match: [{"if":"is_local_domain(rcpt_domain)","then":"'local'"}], else: "'mx'"`; for Brevo set else to `"'relay'"` after creating `MtaRoute/Relay` named `relay`. |
| Auto-ban rates | Singleton `Security`: `authBanRate`, `scanBanRate`, `abuseBanRate`, plus optional `*BanPeriod`. `Rate` object is `{ "count": <n>, "period": <duration-ms> }`; source `Rate` has `count` and `period`. |
| Spam filter | Registry singleton/object family: `SpamSettings`, `SpamRule`, `SpamTag`, `SpamDnsblSettings`, `SpamDnsblServer`, `SpamClassifier`, `SpamLlm`, `SpamPyzor`, file extensions/training samples. Existing 0.15 settings need explicit recreation if non-default. |
| Logging/telemetry | Registry objects/singletons: `Tracer`, `EventTracingLevel`, `Metrics`, `MetricsStore`, `TracingStore`, `Alert`, `Metric`, `Log`. Existing 0.15 settings need explicit recreation if non-default. |
| Firewall ports | Still NixOS firewall, not Stalwart registry. Keep `networking.firewall.allowedTCPPorts = [25 587 993]`. |
| Caddy reverse proxy for admin | Still external NixOS/Caddy config. Stalwart only needs the loopback HTTP listener. |

## Remaining Blockers For Later Phases

- Exact low-port bind proof is blocked by the current shell capability, as
  described above. The registry object shape is proven; the exact socket proof
  still needs a privileged validation run.
- Account password credential provisioning through `Account.credentials` failed
  with `invalidPatch`. Phase 04/06 must either find the correct credential patch
  shape or use a separate supported credential/password endpoint before claiming
  fully headless account-password provisioning.
- SMTP AUTH mechanism configuration was not conclusively mapped. Do not assume
  the old `session.auth.mechanisms` key has a one-line registry equivalent until
  phase 04 proves it.
