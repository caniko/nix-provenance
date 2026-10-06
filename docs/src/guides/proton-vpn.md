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

The user service loads the JSON using systemd credentials, invokes
`proton-vpn-auth`, and passes the password and challenge-time TOTP to the stock
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
