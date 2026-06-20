# Caddy OIDC helpers — pure-Nix primitives that emit caddy-security plugin
# config for OIDC providers. Consumed by canix-toolbelt's service registry
# auth coupler and by any downstream flake that needs to attach OIDC
# authentication to a Caddy reverse proxy route.
{lib}: {
  # Build a caddy-security generic OIDC provider config from a Kanidm
  # client registration. The issuer URL is derived from the kanidm domain
  # and client name — no downstream interpolation needed.
  #
  # Usage:
  #   caddy.mkKanidmOidcProvider {
  #     kanidmDomain = "auth.tartanoglu.com";
  #     clientName = "hermes-webui";
  #   }
  #   → { driver = "generic"; client_id = "hermes-webui";
  #       metadata_url = "https://auth.tartanoglu.com/oauth2/openid/hermes-webui/.well-known/openid-configuration";
  #       scopes = ["openid" "profile" "email"]; }
  mkKanidmOidcProvider = {
    kanidmDomain,
    clientName,
    scopes ? ["openid" "profile" "email"],
  }: {
    driver = "generic";
    client_id = clientName;
    metadata_url = "https://${kanidmDomain}/oauth2/openid/${clientName}/.well-known/openid-configuration";
    inherit scopes;
  };

  # Build a caddy-security generic OIDC provider config from a Rauthy
  # client registration. The issuer URL is derived from the rauthy domain
  # and client name.
  mkRauthyOidcProvider = {
    rauthyDomain,
    clientName,
    scopes ? ["openid" "profile" "email"],
  }: {
    driver = "generic";
    client_id = clientName;
    metadata_url = "https://${rauthyDomain}/.well-known/openid-configuration";
    base_auth_url = "https://${rauthyDomain}/ui/oauth2";
    token_url = "https://${rauthyDomain}/oauth2/token";
    inherit scopes;
  };
}
