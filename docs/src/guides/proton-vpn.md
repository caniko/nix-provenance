# Proton VPN account login

Import `inputs.nix-provenance.homeModules.proton-vpn` to install the official
Proton VPN GUI and CLI and optionally enroll an existing Proton account:

```nix
nix-provenance.proton-vpn = {
  enable = true;
  login = {
    enable = true;
    encryptedFile = "${config.age.secrets.proton-account.file}";
    identityPaths = config.age.identityPaths;
    keyringServiceUnit = "oo7-daemon.service";
  };
};
age.secrets.proton-account.enable = false;
```

`encryptedFile` is a rekeyed age ciphertext containing a JSON document with fields
`username`, `password`, and optionally `totpSecret`. The last field is the base32
authenticator seed for Proton's SHA-1/six-digit/30-second TOTP profile. Populate
real credentials through your secret manager; never render their values in Nix.
The username/password must belong to the existing Proton account, not its
OpenVPN credentials. This integration authenticates clients; it does not create
or reset Proton accounts.
Interpolate a Nix path as shown so the ciphertext retains its store context and
belongs to the home closure even while agenix plaintext installation is disabled.

## Interactive credential enrollment

The package also installs `proton-vpn-auth enroll --stdout`, for a consuming
secret manager to capture through a private pipe and encrypt immediately.
It prompts on the controlling terminal with echo disabled for the existing
username, password and password confirmation, then the existing base32
authenticator seed and seed confirmation. `--password-only` explicitly omits
TOTP for an account without that second factor. Credential values have no CLI
flags and are never printed to the terminal. The helper disables core dumps and
dumpability, locks credential memory, and acquires a logind sleep inhibitor
before prompting. Regular-file output, terminal output and the former `--out`
interface are rejected. The consuming secret manager must encrypt the document
without persisting plaintext; nix-provenance owns neither downstream
account selection nor encrypted source storage. Canix exposes this workflow as
`canix secret proton-vpn enroll ACCOUNT` and performs streaming encryption and rekey.

## Pipe-only credential documents

Secret-manager integrations can invoke `proton-vpn-auth enroll --stdin --stdout`
with private pipes. Input is one JSON object containing `username`, `password`,
and `totpSecret`; stdout contains only the validated canonical account document.
This mode needs no runtime directory and creates no plaintext file. It refuses
terminal input/output, unknown JSON fields, and input over 64 KiB. Child callers
must bound execution and output, suppress arbitrary diagnostics, and encrypt the
returned bytes before persisting anything.

`totpSecret` accepts a base32 seed or an `otpauth://totp/` URI. Enrollment
normalizes the seed to uppercase unpadded base32. URI parameters must select
SHA-1, six digits, and a 30-second period; omitted parameters use that standard
TOTP profile. Duplicate, malformed, unknown, or incompatible parameters fail
without output. A generated one-time code is not an enrollment seed.
`--password-only` requires the seed to be absent; it never silently discards 2FA.
Interactive enrollment uses the same seed normalization.

Vault lookup, field selection, account bindings, encryption, rotation, and rekey
remain the consuming secret manager's responsibility. The helper only creates
the document for an existing external Proton account.

## Session authentication

The user service loads only ciphertext using systemd credentials, invokes
`proton-vpn-auth login`, and passes the password and challenge-time TOTP to the stock
`protonvpn` client through private pipes. `setsid` prevents Python `getpass` from
reading an unrelated controlling terminal. The helper suppresses arbitrary
client output, including errors that could contain credential material. Exit 2
means a credential/account/protocol problem; exit 75 means a bounded retry is
appropriate. The service retries at most three times within five minutes.

`login --encrypted-file FILE --identity PRIVATE_KEY` decrypts natively with
SSH-ed25519 or X25519 identities. `--identity` is repeatable. Identity files must
be private, user-owned regular files; encrypted/plugin identities require a
separate noninteractive rekey recipient. `encryptedFile` replaces the old
plaintext `credentialsFile` option. Keep `rekeyFile` on the agenix entry and
disable its runtime plaintext installation with `enable = false`.

Before decryption the adapter disables core dumps and dumpability, locks writable
mappings and future allocations, and holds a logind block sleep inhibitor.
The service sets `MemorySwapMax=0` and `LimitMEMLOCK=8M`; native runs need an
adequate memlock allowance and permission to inhibit sleep. Missing protections
fail closed. This prevents normal swap, dump and hibernation persistence while
the account necessarily exists briefly in protected RAM. Secret buffers are
zeroized; library/cryptographic scratch remains protected until process exit.
The password and seed are dropped before the initial session probe, loaded again
only for authentication, and wiped promptly after use and before final verification.
Only a generated TOTP code reaches the official client, never the seed. Trusted
root can override these operating-system controls.

The adapter keeps a matching locally enrolled session and verifies session
persistence after signing in. Proton's native SSO/keyring owns access/refresh
tokens. Another enrolled account is a conflict requiring an explicit signout;
the helper does not log that account out or disconnect its tunnel.

The CLI requires a desktop D-Bus and unlocked Secret Service session and cannot
run concurrently with the official GUI. Login runs at graphical-session startup
and when the credential document changes. It does not automatically connect the
VPN. A CAPTCHA or unsupported second-factor challenge remains a login failure;
it is never bypassed or reported as success.

Each Home Manager user selects an encrypted credential file. Consumers can rekey
the same encrypted source for multiple users to share an account without copying
the source or sharing their mutable local session stores.

Verify `nix-provenance-proton-vpn-login.service`, run `protonvpn info` with the
GUI closed, then open `protonvpn-app` separately to verify cross-client account
recognition. Live provider access requires real account verification, beyond the
adapter's local-session enrollment check.
