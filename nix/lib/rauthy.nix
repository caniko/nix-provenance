# Pure-Nix helpers exposed as the flake's `lib` output.
{lib}: {
  # Derive a `services.rauthy.provision.users` attrset (keyed by primary email)
  # from a `services.kanidm.provision.persons` attrset, so a kanidm-provision
  # deployment can stay the single source of truth for internal humans and feed
  # rauthy-provision without duplicating account data. Each kanidm person
  # becomes a passwordless Rauthy user that auto-links to the kanidm upstream
  # OIDC provider on first login and is checked against that provider during
  # reconciliation.
  #
  # Names are split best-effort from the kanidm `displayName` and applied at
  # creation only; Rauthy refreshes them from the kanidm profile claims on
  # federated login, so the split need not be perfect.
  #
  #   usersFromKanidmPersons {
  #     persons = config.services.kanidm.provision.persons;
  #     groups  = [ "internal" ];   # rauthy-side groups (NOT kanidm groups)
  #   }
  usersFromKanidmPersons = {
    persons,
    language ? "en",
    # Rauthy roles applied to every derived user.
    roles ? [],
    # Rauthy groups applied to every derived user. These are rauthy-side group
    # names and must be provisioned separately (services.rauthy.provision.groups);
    # they are a different namespace from kanidm groups.
    groups ? [],
    # When true, also copy each person's kanidm group names through as rauthy
    # groups. Off by default — the namespaces usually differ.
    carryKanidmGroups ? false,
  }:
    lib.mapAttrs' (
      username: person: let
        emails = person.mailAddresses or [];
        primaryEmail =
          if emails == []
          then throw "usersFromKanidmPersons: kanidm person '${username}' has no mailAddresses; cannot derive a Rauthy user (Rauthy keys users by email)."
          else lib.head emails;
        display = person.displayName or username;
        words = lib.filter (w: w != "") (lib.splitString " " display);
        given =
          if words == []
          then null
          else lib.head words;
        family = let
          rest = lib.concatStringsSep " " (lib.tail words);
        in
          if rest == ""
          then null
          else rest;
        personGroups =
          if carryKanidmGroups
          then (person.groups or [])
          else [];
      in
        lib.nameValuePair primaryEmail {
          givenName = given;
          familyName = family;
          inherit language roles;
          groups = lib.unique (groups ++ personGroups);
          requiredAuthProvider = "kanidm";
        }
    )
    persons;
}
