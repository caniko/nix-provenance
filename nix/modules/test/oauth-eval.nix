{self, ...}: {
  imports = [self.nixosModules.oauth];
  networking.hostName = "oauth-test";
  users.users.alice = {isNormalUser = true;};
  services.provenance.oauth.users.alice.providers.openai = {
    enrollmentFile = "/run/agenix/oauth-alice-openai";
    # Public test recipient; never an enrollment or synthetic live grant.
    recoveryRecipients = ["age1luyy6j8g4689rqj2qwlu4znr3zjael48pq8tlgl5fu7l2l8r7qvqdfxaa5"];
  };
  system.stateVersion = "26.05";
}
