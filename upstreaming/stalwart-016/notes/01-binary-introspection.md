# Phase 01 binary introspection

This note records the Stalwart 0.16.7 / `stalwart-cli` 1.0.0 CLI surface that
phase 02 depends on.

## `stalwart` entrypoint

There is no `server` subcommand in Stalwart 0.16.7. The server starts from the
top-level `stalwart` binary. In `crates/common/src/manager/boot.rs`, the built-in
help text is:

```text
Usage: stalwart [OPTIONS]

Options:
  -c, --config <PATH>              Start server with the specified configuration file
  -e, --export <PATH>              Export all store data to a specific path
  -i, --import <PATH>              Import store data from a specific path
  -o, --console                    Open the store console
  -h, --help                       Print help
  -V, --version                    Print version
```

Source:
- <https://github.com/stalwartlabs/stalwart/blob/v0.16.7/crates/common/src/manager/boot.rs>

## `--config` meaning and bootstrap file shape

`-c/--config` is not a TOML settings file in 0.16.7. `BootManager::init()` passes
the provided path directly to `RegistryStore::init(PathBuf::from(config_path))`.
`RegistryStoreInner::read_data_store()` then reads that path as text and parses it
with `serde_json::from_str::<DataStore>()`.

That means phase 02 needs to generate a JSON bootstrap file whose top-level shape
matches the `DataStore` enum from `crates/registry/src/schema/structs.rs`, not the
old TOML module output. The accepted top-level variants are:

- `RocksDb`
- `Sqlite`
- `FoundationDb`
- `PostgreSql`
- `MySql`

Concrete field examples from the schema:

- `SqliteStore` has `path`, optional `poolWorkers`, and `poolMaxConnections`.
- `RocksDbStore` has `path`, `blobSize`, `bufferSize`, and optional `poolWorkers`.

If the referenced file does not exist, `read_data_store()` returns `Bootstrap`
instead of failing, and the boot path reports that port `8080` is opened for
initial setup.

Source:
- <https://github.com/stalwartlabs/stalwart/blob/v0.16.7/crates/common/src/manager/boot.rs>
- <https://github.com/stalwartlabs/stalwart/blob/v0.16.7/crates/store/src/registry/local.rs>
- <https://github.com/stalwartlabs/stalwart/blob/v0.16.7/crates/registry/src/schema/structs.rs>

## Recovery mode env

Recovery mode is source-visible in `crates/store/src/registry/local.rs`:

- `STALWART_RECOVERY_MODE`: truthy when set to `1` or `true` (case-insensitive)
- `STALWART_RECOVERY_ADMIN`: parsed as `username:password`

When recovery mode is active, the boot path reports that port `8080` is open for
troubleshooting and recovery.

Related env in the same initializer:

- `STALWART_HOSTNAME`
- `STALWART_ROLE`
- `STALWART_PUSH_SHARD`
- `STALWART_PUBLIC_URL`
- `STALWART_HTTPS_PORT`

Source:
- <https://github.com/stalwartlabs/stalwart/blob/v0.16.7/crates/store/src/registry/local.rs>
- <https://github.com/stalwartlabs/stalwart/blob/v0.16.7/crates/common/src/manager/boot.rs>

## `stalwart-cli` surface

Built package version:

```text
1.0.0
```

Command:

```text
/nix/store/iqr6y0sjl1h33g41x2ysxv47r5a7i8vy-stalwart-cli-1.0.0/bin/stalwart-cli --help
```

Output:

```text
Stalwart Command Line Interface

Usage: stalwart-cli [OPTIONS] <COMMAND>

Commands:
  get       Fetch a single object by id
  query     Query objects with optional filters
  create    Create an object
  update    Update an object by id
  delete    Delete one or more objects by id
  describe  Describe objects and enums from the schema
  apply     Apply a bulk plan of creates, updates, and destroys from a JSON file
  snapshot  Snapshot one or more object types into a plan file consumable by `apply`
```

Auth/config flags come from the same help output and `src/cli/mod.rs` / `src/app/config.rs`:

- `--url` or `STALWART_URL`
- `--user` or `STALWART_USER`
- `--password` or `STALWART_PASSWORD`
- `--api-key` or `STALWART_TOKEN`
- `-k/--insecure`
- `--no-color`

`stalwart-cli apply` is the phase 06-relevant subcommand:

Command:

```text
/nix/store/iqr6y0sjl1h33g41x2ysxv47r5a7i8vy-stalwart-cli-1.0.0/bin/stalwart-cli apply --help
```

Output:

```text
Apply a bulk plan of creates, updates, and destroys from a JSON file

Usage: stalwart-cli apply [OPTIONS] <--file <PATH>|--stdin>

Options:
      --file <PATH>          Path to the JSON plan file
      --stdin                Read the JSON plan from stdin
      --dry-run              Parse and validate the plan without calling the server
      --continue-on-error    Keep going after operation failures; report all errors at the end
      --quiet                Suppress per-operation log lines; print only the final summary
      --json                 Emit one NDJSON record per completed operation to stdout
      --progress             Print per-batch progress during large destroys and creates
```

Sources:
- runtime output from the built `stalwart-cli` package
- <https://github.com/stalwartlabs/cli/blob/v1.0.0/src/cli/mod.rs>
- <https://github.com/stalwartlabs/cli/blob/v1.0.0/src/app/config.rs>
