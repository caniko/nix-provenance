{
  lib,
  self,
  ...
}: {
  # Twice: each canix enrollment module imports it, so the key must dedupe.
  imports = [self.nixosModules.oauth self.nixosModules.oauth];
  # Exercise the integrated bindings without adding a Home Manager input.
  options.home-manager = {
    users = lib.mkOption {type = lib.types.attrs;};
    sharedModules = lib.mkOption {type = lib.types.listOf lib.types.deferredModule;};
  };
  config = {
    networking.hostName = "oauth-test";
    users.users.alice = {isNormalUser = true;};
    services.provenance.oauth.users.alice.providers.openai = {
      enrollmentFile = "/run/agenix/oauth-alice-openai";
      # Public test recipient; never an enrollment or synthetic live grant.
      recoveryRecipients = ["age1luyy6j8g4689rqj2qwlu4znr3zjael48pq8tlgl5fu7l2l8r7qvqdfxaa5"];
    };
    services.provenance.oauth.users.alice.providers.google = {
      profile = "antigravity";
      enrollmentFile = "/run/agenix/oauth-alice-google";
      recoveryRecipients = ["age1luyy6j8g4689rqj2qwlu4znr3zjael48pq8tlgl5fu7l2l8r7qvqdfxaa5"];
    };
    services.provenance.oauth.users.alice.enrollments.drive = {
      provider = "google";
      profile = "drive";
      enrollmentFile = "/run/agenix/oauth-alice-drive";
      recoveryRecipients = ["age1luyy6j8g4689rqj2qwlu4znr3zjael48pq8tlgl5fu7l2l8r7qvqdfxaa5"];
    };
    services.provenance.oauth.users.alice.enrollments.work = {
      provider = "openai";
      profile = "opencode";
      account = "Work Account";
      enrollmentFile = "/run/agenix/oauth-alice-work";
      recoveryRecipients = ["age1luyy6j8g4689rqj2qwlu4znr3zjael48pq8tlgl5fu7l2l8r7qvqdfxaa5"];
    };
    services.provenance.oauth.users.root.providers.google = {
      profile = "drive-file";
      enrollmentFile = "/run/agenix/oauth-root-google";
      recoveryRecipients = ["age1luyy6j8g4689rqj2qwlu4znr3zjael48pq8tlgl5fu7l2l8r7qvqdfxaa5"];
    };
    services.provenance.oauth.users.root.enrollments.backup = {
      provider = "google";
      profile = "drive";
      enrollmentFile = "/run/agenix/oauth-root-backup";
      recoveryRecipients = ["age1luyy6j8g4689rqj2qwlu4znr3zjael48pq8tlgl5fu7l2l8r7qvqdfxaa5"];
    };
    system.stateVersion = "26.05";
  };
}
