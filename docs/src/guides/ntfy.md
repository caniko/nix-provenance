# ntfy Users, Tokens and ACLs

`nixosModules.ntfy` (config-only) provisions ntfy's predefined users, access
tokens and ACLs from runtime password files. Plaintext never enters the Nix
store: a oneshot `ntfy-sh-credentials` loads each file with systemd
credentials, hashes passwords with `ntfy user hash`, validates tokens against
`lib.ntfy.tokenPattern` (`^tk_[A-Za-z0-9]{29}$`) and writes
`NTFY_AUTH_USERS` / `NTFY_AUTH_TOKENS` to `/run/ntfy-sh-provision/env` (0600),
which `ntfy-sh.service` loads as an `EnvironmentFile`. Hashes are recomputed on
every start.

```nix
services.ntfy-sh = {
  enable = true;
  settings.auth-file = "/var/lib/ntfy-sh/user.db"; # required
  provision = {
    enable = true;
    users.can = { role = "admin"; passwordFile = config.age.secrets.ntfy-can.path; };
    users.syndb-publisher = { role = "user"; passwordFile = config.age.secrets.ntfy-pub.path; };
    tokens.syndb-publisher = [{ tokenFile = config.age.secrets.ntfy-pub-token.path; label = "ci"; }];
    access = ["syndb-publisher:syndb-alerts:wo"];
  };
};
```

`access` is merged into `settings.auth-access`. Token users must be declared in
`users`. A pre-existing `services.ntfy-sh.environmentFile` is kept.
