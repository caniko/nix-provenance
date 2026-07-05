# Rauthy State Renderer

`rauthy-state-render` is an offline renderer for generic Rauthy provisioning
models. It validates a JSON model and writes a `rauthy-provision --state` JSON
file.

```bash
rauthy-state-render --input generic-rauthy-model.json --out rauthy-provision-state.json
rauthy-state-render --input generic-rauthy-model.json --out rauthy-provision-state.json --pretty
```

The input schema mirrors Rauthy provisioning concepts, not any consumer's
identity registry. Consumer-specific adapters should translate local data into
this model before calling the renderer.

```json
{
  "groups": {
    "internal": { "present": true }
  },
  "roles": {},
  "userAttributes": {
    "vikunja_groups": {
      "present": true,
      "desc": "Vikunja OIDC team memberships",
      "userEditable": false
    }
  },
  "scopes": {
    "vikunja_groups": {
      "present": true,
      "attrIncludeId": ["vikunja_groups"],
      "claimsAtRoot": true
    }
  },
  "providers": {
    "kanidm": {
      "present": true,
      "name": "Kanidm",
      "issuer": "https://auth.example.com/oauth2/openid/rauthy",
      "authorizationEndpoint": "https://auth.example.com/ui/oauth2",
      "tokenEndpoint": "https://auth.example.com/oauth2/token",
      "userinfoEndpoint": "https://auth.example.com/oauth2/openid/rauthy/userinfo",
      "jwksEndpoint": "https://auth.example.com/oauth2/openid/rauthy/public_key.jwk",
      "clientId": "rauthy",
      "clientSecretFile": "/run/secrets/rauthy-kanidm-client-secret",
      "scope": "openid email profile groups",
      "usePkce": true,
      "clientSecretBasic": true,
      "clientSecretPost": false,
      "autoOnboarding": false,
      "autoLink": true
    }
  },
  "clients": {
    "public-client": {
      "present": true,
      "confidential": false,
      "enablePkce": true,
      "redirectUris": ["https://app.example.com/callback"],
      "scopes": ["openid", "profile", "email"],
      "defaultScopes": ["openid", "profile", "email"]
    },
    "confidential-client": {
      "present": true,
      "confidential": true,
      "enablePkce": false,
      "redirectUris": ["https://service.example.com/auth/openid/rauthy"],
      "generatedSecretFile": "/var/lib/rauthy-provision/clients/service.secret"
    }
  },
  "users": {
    "person@example.com": {
      "present": true,
      "givenName": "Person",
      "familyName": "Example",
      "language": "en",
      "timezone": "Europe/Oslo",
      "preferredUsername": "person",
      "roles": [],
      "groups": ["internal"],
      "attributes": {
        "vikunja_groups": [{ "name": "team-a", "oidcID": "team-a" }]
      },
      "sendPasswordEmail": false
    },
    "external@example.com": {
      "present": true,
      "preferredUsername": "external",
      "sendPasswordEmail": true,
      "passwordEmailRedirectUri": "https://app.example.com/login"
    },
    "bot@example.com": {
      "present": true,
      "initialPasswordFile": "/run/credentials/rauthy-provision.service/password-bot"
    }
  }
}
```

Validation currently rejects empty entity keys, public clients without PKCE,
public clients with generated secret files, password-email users without a
redirect URI, users that set both `sendPasswordEmail` and `initialPasswordFile`,
non-positive user expiry timestamps, and upstream providers that select
client-secret authentication without a secret file.
