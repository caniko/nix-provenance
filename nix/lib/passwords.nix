{lib}: let
  inherit (lib) mkOption types;

  sanitize = value:
    builtins.replaceStrings
    ["@" "." "/" ":" " " "\\" "\"" "'"]
    ["-" "-" "-" "-" "-" "-" "-" "-"]
    value;

  credentialName = key: let
    raw = sanitize key;
    prefix = builtins.substring 0 32 raw;
    suffix = builtins.substring 0 12 (builtins.hashString "sha256" key);
  in "password-${prefix}-${suffix}";
in {
  passwordFileOption = mkOption {
    type = types.nullOr (types.oneOf [types.path types.str]);
    default = null;
    description = ''
      Runtime file containing this user's platform-local password. Point this at
      an agenix secret path, for example `config.age.secrets.<name>.path`.
    '';
  };

  inherit credentialName;

  userPasswordCredentials = unit: users:
    lib.mapAttrsToList (key: user: "${credentialName key}:${toString user.passwordFile}")
    (lib.filterAttrs (_: user: (user.passwordFile or null) != null) users);

  userPasswordRuntimePath = unit: key: "/run/credentials/${unit}.service/${credentialName key}";
}
