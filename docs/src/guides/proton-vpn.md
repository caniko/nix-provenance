# Proton VPN account login

Import `inputs.nix-provenance.homeModules.proton-vpn` to install the official
Proton VPN GUI and CLI and optionally enroll an existing Proton account:

```nix
nix-provenance.proton-vpn = {
  enable = true;
  login = {
    enable = true;
    credentialsFile = config.age.secrets.proton-account.path;
    credentialServiceUnits = ["agenix.service"];
    keyringServiceUnit = "oo7-daemon.service";
  };
};
```

`credentialsFile` is a private runtime JSON document containing the string fields
`username`, `password`, and optionally `totpSecret`. The last field is the base32
authenticator seed for Proton's SHA-1/six-digit/30-second TOTP profile. Populate
real credentials through your secret manager; never render their values in Nix.
The username/password must belong to the existing Proton account, not its
OpenVPN credentials. This integration authenticates clients; it does not create
or reset Proton accounts.

## Interactive credential enrollment

The package also installs `proton-vpn-auth enroll --out /run/user/<uid>/account.json`.
It prompts on the controlling terminal with echo disabled for the existing
username, password and password confirmation, then the existing base32
authenticator seed and seed confirmation. `--password-only` explicitly omits
TOTP for an account without that second factor. Credential values have no CLI
flags and are never printed. The helper disables core dumps and creates a new
mode-0600 document only under a private, user-owned `$XDG_RUNTIME_DIR`, refusing
existing files and destinations outside it. The consuming secret manager must
encrypt and remove this transient document; nix-provenance owns neither downstream
account selection nor encrypted source storage. Canix exposes this workflow as
`canix secret proton-vpn enroll ACCOUNT` and performs encryption, cleanup and rekey.

## Session authentication

The user service loads the JSON using systemd credentials, invokes
`proton-vpn-auth login`, and passes the password and challenge-time TOTP to the stock
`protonvpn` client through private pipes. `setsid` prevents Python `getpass` from
reading an unrelated controlling terminal. The helper suppresses arbitrary
client output, including errors that could contain credential material. Exit 2
means a credential/account/protocol problem; exit 75 means a bounded retry is
appropriate. The service retries at most three times within five minutes.

The adapter keeps a matching locally enrolled session and verifies session
persistence after signing in. Proton's native SSO/keyring owns access/refresh
tokens. Another enrolled account is a conflict requiring an explicit signout;
the helper does not log that account out or disconnect its tunnel.

The CLI requires a desktop D-Bus and unlocked Secret Service session and cannot
run concurrently with the official GUI. Login runs at graphical-session startup
and when the credential document changes. It does not automatically connect the
VPN. A CAPTCHA or unsupported second-factor challenge remains a login failure;
it is never bypassed or reported as success.

Each Home Manager user selects a runtime credential file. Consumers can rekey
the same encrypted source for multiple users to share an account without copying
the source or sharing their mutable local session stores.

Verify `nix-provenance-proton-vpn-login.service`, run `protonvpn info` with the
GUI closed, then open `protonvpn-app` separately to verify cross-client account
recognition. Live provider access requires real account verification, beyond the
adapter's local-session enrollment check.
