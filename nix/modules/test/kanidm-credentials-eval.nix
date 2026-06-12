{
  lib,
  self,
  ...
}: {
  imports = [self.nixosModules.kanidmCredentials];

  services.kanidm-credentials = {
    enable = true;
    instanceUrl = "https://auth.example.com:8443";
    ldapUrl = "ldaps://auth.example.com:3636";
    idmAdminPasswordFile = "/run/agenix/idm-admin";
    adminPasswordFile = "/run/agenix/admin";
    ldapUnixBind = true;
    posixAccounts = {
      can = {
        passwordFile = "/run/agenix/posix-can";
        primaryPasswordFile = "/run/agenix/primary-can";
      };
      noreply.passwordFile = "/run/agenix/posix-noreply";
    };
    serviceAccount = {
      name = "stalwart-ldap";
      displayName = "Stalwart LDAP search bind";
    };
  };

  system.stateVersion = lib.mkDefault "25.11";
}
