# Operator-side `identity-cli` for Rauthy email-credential recovery.
#
# Installs the CLI and points it at the Rauthy instance plus a rendered
# provision-state subset, so `identity-cli rauthy list-email-users` and
# `reset-password` work without flags. Consumers pass the same generic user
# model they feed `rauthy-state-render`; only users provisioned with an
# emailed set-password link are rendered, with the fields the CLI reads.
{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.nix-provenance.identityCli;
  emailUser = user:
    lib.filterAttrs (_: value: value != null) {
      send_password_email = true;
      password_email_redirect_uri = user.passwordEmailRedirectUri or null;
      given_name = user.givenName or null;
      family_name = user.familyName or null;
    };
in {
  options.services.nix-provenance.identityCli = {
    enable = lib.mkEnableOption "the identity-cli operator tool";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.identity-cli;
      defaultText = lib.literalExpression "nix-provenance.packages.\${system}.identity-cli";
      description = "identity-cli package to install.";
    };

    rauthy = {
      url = lib.mkOption {
        type = lib.types.str;
        example = "https://id.example.org";
        description = "Rauthy base URL exported as RAUTHY_URL.";
      };

      users = lib.mkOption {
        type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
        default = {};
        description = ''
          Generic Rauthy user model keyed by email, in the shape consumed by
          `rauthy-state-render`. Users with `sendPasswordEmail = true` become
          the state exported as RAUTHY_PROVISION_STATE.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [cfg.package];
    environment.variables = {
      RAUTHY_URL = cfg.rauthy.url;
      RAUTHY_PROVISION_STATE = pkgs.writeText "rauthy-email-users.json" (builtins.toJSON {
        users = lib.mapAttrs (_: emailUser) (lib.filterAttrs (_: user: user.sendPasswordEmail or false) cfg.rauthy.users);
      });
    };
  };
}
