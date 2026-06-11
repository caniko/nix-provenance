# Kanidm State Renderer

`kanidm-state-render` is an offline renderer for generic Kanidm provisioning
models. It emits JSON suitable for nixpkgs'
`services.kanidm.provision.extraJsonFile`, which is merged into the typed
NixOS module-generated `kanidm-provision` state.

```bash
kanidm-state-render --input generic-kanidm-model.json --out kanidm-provision-extra.json
kanidm-state-render --input generic-kanidm-model.json --out kanidm-provision-extra.json --pretty
```

The input schema mirrors Kanidm provisioning concepts: `groups`, `persons`,
and `systems.oauth2`. It is intentionally not a consumer identity-registry
schema. Fleet-specific user kinds, app names, hostnames, and secret paths are
mapped by the consuming flake before invoking the renderer.

Example:

```json
{
  "groups": {
    "staff": {},
    "app-users": {}
  },
  "persons": {
    "alice": {
      "displayName": "Alice Example",
      "legalName": "Alice Example",
      "mailAddresses": ["alice@example.com"],
      "groups": ["staff", "app-users"],
      "enableUnix": true,
      "gidNumber": 1000,
      "loginShell": "/run/current-system/sw/bin/bash"
    }
  },
  "systems": {
    "oauth2": {
      "app": {
        "displayName": "App",
        "originUrl": "https://app.example.com/oauth/callback",
        "originLanding": "https://app.example.com/",
        "basicSecretFile": "/run/secrets/app-oidc-secret",
        "preferShortUsername": true,
        "scopeMaps": {
          "app-users": ["openid", "profile", "email"]
        }
      }
    }
  }
}
```

Use it from Nix by generating the generic input, rendering it in a derivation,
and passing the result to the nixpkgs module:

```nix
let
  input = pkgs.writeText "generic-kanidm-model.json" (builtins.toJSON model);
  state = pkgs.runCommand "kanidm-provision-extra.json" {
    nativeBuildInputs = [inputs.nix-provenance.packages.${pkgs.stdenv.buildPlatform.system}.kanidm-state-render];
  } ''
    kanidm-state-render --input ${input} --out "$out"
  '';
in {
  services.kanidm.provision.extraJsonFile = state;
}
```

The renderer validates cross-references that nixpkgs skips when
`extraJsonFile` is set: duplicate entity names, unknown groups, unknown group
members, invalid public/confidential client settings, claim-map groups, and
POSIX extension consistency.
