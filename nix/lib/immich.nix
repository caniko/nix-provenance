{lib}: {
  usersFromKanidmPersons = {
    persons,
    group ? "immich-users",
    adminUsers ? [],
    storageLabelFrom ? "username",
    defaultQuotaSizeInBytes ? null,
    shouldChangePassword ? false,
  }:
    lib.mapAttrs' (
      username: person: let
        groups = person.groups or [];
        emails = person.mailAddresses or [];
        primaryEmail =
          if emails == []
          then throw "usersFromKanidmPersons: kanidm person '${username}' has no mailAddresses"
          else lib.head emails;
        storageLabel =
          if storageLabelFrom == "username"
          then username
          else if storageLabelFrom == "none"
          then null
          else throw "usersFromKanidmPersons: storageLabelFrom must be 'username' or 'none'";
      in
        lib.nameValuePair username (lib.filterAttrs (_: value: value != null) {
          email = primaryEmail;
          name = person.displayName or username;
          isAdmin = lib.elem username adminUsers;
          inherit storageLabel shouldChangePassword;
          quotaSizeInBytes = defaultQuotaSizeInBytes;
        })
    )
    (lib.filterAttrs (_: person: lib.elem group (person.groups or [])) persons);

  kanidmOAuth2System = {
    originUrl,
    basicSecretFile,
    originLanding ? originUrl,
    group ? "immich-users",
    displayName ? "Immich",
    preferShortUsername ? true,
    scopes ? ["openid" "profile" "email"],
  }: {
    inherit displayName originUrl originLanding basicSecretFile preferShortUsername;
    public = false;
    scopeMaps.${group} = scopes;
  };
}
