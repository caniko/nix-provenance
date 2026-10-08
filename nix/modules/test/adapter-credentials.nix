{
  lib,
  adapter,
}: let
  personsFor = manageProfile: credential:
    adapter.kanidmPersons {
      group = "internal-tool-users";
      users.host = {inherit manageProfile credential;};
    };
  rejects = manageProfile: credential:
    !(builtins.tryEval (builtins.deepSeq (personsFor manageProfile credential) true)).success;
  invalidCredentials = [
    (adapter.passwordInitByEmail {})
    (adapter.passwordFromFile {passwordFile = "/run/credentials/test/password";})
    {method = "unknown";}
  ];
in
  assert personsFor false adapter.kanidmLogin == {};
  assert (personsFor true adapter.kanidmLogin).host.groups == ["internal-tool-users"];
  assert lib.all (manageProfile: lib.all (rejects manageProfile) invalidCredentials) [false true]; true
