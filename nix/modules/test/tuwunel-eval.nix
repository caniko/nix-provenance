{
  lib,
  self,
  ...
}: {
  imports = [self.nixosModules.tuwunel];

  services.matrix-tuwunel = {
    enable = true;
    settings.global = {
      server_name = "matrix.example.com";
      port = [6167];
    };
    provision = {
      enable = true;
      adminTokenUser = "matrix-admin";
      users.matrix-admin = {
        admin = true;
        passwordFile = "/run/agenix/matrix-admin-password";
        displayName = "Matrix Provisioning Admin";
      };
      oidcProviders.kanidm = {
        brand = "kanidm";
        clientId = "matrix";
        clientSecretFile = "/run/agenix/matrix-oidc-client-secret";
        issuerUrl = "https://auth.example.com/oauth2/openid/matrix";
        callbackUrl = "https://matrix.example.com/_matrix/client/unstable/login/sso/callback/matrix";
        scope = ["openid" "profile" "email"];
        useridClaims = ["preferred_username"];
        trusted = false;
        registration = true;
        uniqueIdFallbacks = false;
        default = true;
        displayName = "Kanidm";
      };
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
