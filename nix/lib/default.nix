# Assembles the flake `lib` output. The two `usersFromKanidmPersons` have
# OPPOSITE semantics (immich `group` FILTERS kanidm persons and keys by username;
# rauthy `groups` are APPLIED as rauthy-side groups and keys by email), so they
# are kept as two distinct namespaced functions — never merged behind a switch.
{lib}: let
  immich = import ./immich.nix {inherit lib;};
  rauthy = import ./rauthy.nix {inherit lib;};
  vikunja = import ./vikunja.nix {inherit lib;};
  forgejo = import ./forgejo.nix {inherit lib;};
  stalwart = import ./stalwart.nix {inherit lib;};
  adapter = import ./adapter.nix {inherit lib;};
  passwords = import ./passwords.nix {inherit lib;};
  caddy = import ./caddy.nix {inherit lib;};
in {
  inherit immich rauthy vikunja forgejo stalwart adapter passwords caddy;

  # Back-compat alias retained ONLY during the canix migration: the live consumer
  # historically called `lib.usersFromKanidmPersons` on the rauthy-provision
  # flake. Dropped once canix moves to `lib.rauthy.usersFromKanidmPersons`.
  inherit (rauthy) usersFromKanidmPersons;
}
