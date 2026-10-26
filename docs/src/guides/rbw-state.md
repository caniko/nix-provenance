# Durable rbw login state

rbw stores its login tokens and encrypted vault database in its XDG cache
directory. Cache removal therefore logs the client out. The Home Manager adapter
keeps this state under the user's durable XDG state directory instead:

```nix
{inputs, pkgs, ...}: {
  imports = [inputs.nix-provenance.homeModules.rbw];
  nix-provenance.rbw.enable = true;
  programs.rbw.settings = {
    email = "your-existing-bitwarden-account@example.com";
    pinentry = pkgs.pinentry-qt;
  };
}
```

## Lifecycle

The default backing directory is `~/.local/state/nix-provenance/rbw`, mode
`0700`. Client and agent wrappers bind their XDG cache/data roots to its `cache/`
and `data/` subdirectories. Configuration and runtime sockets keep their normal
XDG locations. Each `RBW_PROFILE` gets independent state.

A user service prepares the default profile at login; every wrapped command also
prepares its selected profile. First preparation takes a bounded migration lock,
stops the old agent, and moves the existing cache and device identity. Migration
requires legacy and backing directories on the same filesystem. Symlinks,
hard-linked files, foreign ownership, and competing state trees are rejected.
Interrupted directory moves can resume. Migration tightens directories to `0700`
and files to `0600`; wrapped clients create subsequent files with umask `0077`.

rbw owns registration, login, token refresh, vault encryption and unlocking.
Enrollment uses the supported interactive commands:

```sh
rbw register
rbw login
rbw sync
```

Registration is needed for a new device using the official Bitwarden server.
Supply the personal API key through pinentry. Login uses the master password and
the account's supported MFA method. `BW_SESSION` belongs to the official `bw`
client and does not enroll rbw.

Check file metadata without printing credential values:

```sh
provenance-rbw --config ~/.config/nix-provenance/rbw.json status
```

`vaultDatabases` reports file presence, not server-side authentication validity.

## Recovery and removal

Include the entire backing directory in private credential-state backups. Stop
the agent with `rbw stop-agent` before taking or restoring a consistent backup.
Use encrypted off-host storage; the database contains bearer credentials in
addition to encrypted vault items.

After migration, recreated legacy cache directories are never imported again.
`rbw purge` removes the live database and stays logged out. A missing backing
profile directory fails with an explicit recovery error rather than silently
importing obsolete tokens. Restore the current complete backup while the agent
is stopped. If no current backup exists, preserve the damaged backing directory
for investigation, select a new empty `stateDirectory`, and enroll interactively.

The adapter contains only public paths in Nix/store manifests. Runtime tokens,
master passwords and device API keys are never rendered into the Nix store.
