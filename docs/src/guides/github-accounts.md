# GitHub Accounts

`homeModules.github` reconciles GitHub accounts from Home Manager. Each declared
account gets a `nix-provenance-github-<name>` user oneshot that runs
`github-provision` with that account's own personal access token. The unit runs
on activation, when the token file changes, and daily, so newly created
repositories gain invitations and pending invitations are accepted.

The reconciler only adds what is declared:

- **OpenPGP keys** (`gpgKeys.<name>`) are matched by GitHub's long key id, the
  last 16 digits of the declared fingerprint.
- **SSH authentication keys** (`sshKeys.<title>`) are matched by title. Changing
  the key under an existing title fails closed instead of rotating implicitly.
- **Collaborators** (`collaborators.<user>`) are invited to every non-archived
  repository the account owns (`repositories = "owned"`) or to named
  `owner/name` repositories. Users who already collaborate or have a pending
  invitation are left alone; existing permissions are never changed.
- **Invitations** are accepted only when both the inviter and the repository
  owner appear in `acceptInvitationsFrom`.

Undeclared keys, collaborators, and invitations are never touched. Keys declared
with `present = false` are deleted only with `allowDelete = true`.

The token must authenticate as `login`; a mismatch exits with status 2, which
the unit treats as permanent instead of retrying. Fine-grained tokens cannot
reach repositories owned by another personal account, so a bot collaborating on
someone else's repositories needs a classic token. Required scopes:

| Declares | Classic token scopes |
|----------|----------------------|
| `gpgKeys` | `write:gpg_key` |
| `sshKeys` | `admin:public_key` |
| `collaborators`, `acceptInvitationsFrom` | `repo` |

## Example: an owner and its bot

```nix
{config, inputs, ...}: {
  imports = [inputs.nix-provenance.homeModules.github];

  nix-provenance.github = {
    enable = true;
    accounts = {
      owner = {
        tokenFile = config.age.secrets.owner-github-token.path;
        collaborators.bot.repositories = "owned";
      };
      bot = {
        tokenFile = config.age.secrets.bot-github-token.path;
        gpgKeys.workstation = {
          key = builtins.readFile ./bot.asc;
          fingerprint = "156AB02BB1A3E9CB59FE933A41D0F8D92B7498F2";
        };
        sshKeys.workstation.key = builtins.readFile ./bot.pub;
        acceptInvitationsFrom = ["owner"];
        # Invite before accepting within one activation.
        after = ["owner"];
      };
    };
  };
}
```

Private keys and tokens stay in the secret manager. Only public keys and the
token file's runtime path enter the rendered state.
