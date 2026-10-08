{
  lib,
  roomIdType,
}:
assert lib.all roomIdType.check [null "!room:example.test" "!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"];
assert lib.all (value: !(roomIdType.check value)) ["" "!" "!short" "#alias:example.test" "!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]; true
