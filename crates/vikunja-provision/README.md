# vikunja-provision

Declarative provisioning client for Vikunja teams and memberships.

`vikunja-provision` reads a JSON state file rendered from kanidm groups and
reconciles API-managed local Vikunja teams over `/api/v1` with a long-lived
scoped API token. It is idempotent: create missing teams, update team
descriptions, add missing members, and remove extra members only when destructive
removal is enabled.

## CLI

```
vikunja-provision --url <BASE_URL> --state <state.json> \
    --bot-username <USERNAME> \
    [--token-file <FILE> | VIKUNJA_PROVISION_TOKEN=...] \
    [--ready-timeout 30] [--no-auto-remove] [--allow-team-delete] \
    [--accept-invalid-certs]
```

The base URL has `/api/v1` appended automatically.

## API model

This tool manages only API-created local teams. Do not co-manage OIDC-synced
teams; Vikunja treats those as read-only through the API.

Membership add/remove is by username, not numeric user id. The state should use
the same kanidm usernames users receive at OIDC login. Vikunja lazily creates a
user record on first OIDC login, so a not-yet-seen user is soft-skipped and will
join the team on a later pass after first login.

Vikunja's team API uses inverted verbs:

- `PUT /teams` creates a team.
- `GET /teams` lists teams visible to the token.
- `GET /teams/{id}` reads one team, including members.
- `POST /teams/{id}` updates a team.
- `DELETE /teams/{id}` deletes a team.
- `PUT /teams/{id}/members` adds a member.
- `DELETE /teams/{id}/members/{username}` removes a member.

Member-add business codes are handled before generic HTTP failure handling:

- `6005` means the user is already a member and is treated as success.
- `1005` means the user does not exist yet and is logged as a soft skip.

Any `403` on a write is a hard failure. It usually means token scope drift after
a Vikunja upgrade or token reconfiguration, and continuing would allow partial
convergence.

## API token

Mint a long-lived scoped token for a dedicated bot/service account. The token
needs the deployed instance's `teams` and `teams_members` route scopes for the
methods listed above.

Do not hardcode guessed scope strings in automation. Vikunja scoped tokens pin
path and method, so derive the exact strings from the live instance:

```
curl -fsS -H "Authorization: Bearer <admin-token>" \
  https://vikunja.example.com/api/v1/routes
```

Then mint a token covering the corresponding `teams` and `teams_members` scopes.
Store the final token in a runtime secret file and pass it with `--token-file`,
or use `VIKUNJA_PROVISION_TOKEN` for local testing.

## Bot username

The token's service account is auto-added to teams it creates. Always pass its
username with `--bot-username`; the reconciler excludes that username from both
desired and observed sets and will never add or remove it.

## State file

```json
{
  "teams": {
    "ops": {
      "present": true,
      "description": "Operations",
      "members": ["alice", "bob"],
      "admins": ["carol"]
    },
    "old-team": {
      "present": false
    }
  }
}
```

`present` defaults to `true`. `members` and `admins` default to empty arrays.
Members listed in `admins` are also members of the team.

Membership removals are skipped with `--no-auto-remove`. Team deletion requires
both `present: false` and `--allow-team-delete`, and is also skipped by
`--no-auto-remove`.

## License

Dual-licensed under MIT or Apache-2.0.
