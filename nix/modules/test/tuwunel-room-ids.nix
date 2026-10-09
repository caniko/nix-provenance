{
  lib,
  roomIdType,
}:
assert lib.all roomIdType.check [null "!room:example.test" "!room:example.test:8448" "!room:001.2.3.4" "!room:[::1]" "!room:[2001:db8::1]:8448" "!room:[::ffff:192.0.2.1]:8448" "!é\n:example.test" "!${lib.concatStrings (lib.replicate 241 "a")}:example.test" "!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"];
assert lib.all (value: !(roomIdType.check value)) ["" "!" "!short" "#alias:example.test" "!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" "!:example.test" "!room:" "!room:not a server" "!room:example.test:garbage" "!room:example.test:" "!room:example.test:123456" "!room:example.test/path" "!room:user@example.test" "!room:[12345::]" "!room:[:::]" "!room:[::1]junk" "!room:999.1.2.3" "!${lib.concatStrings (lib.replicate 242 "a")}:example.test" "!${lib.concatStrings (lib.replicate 122 "é")}:example.test"]; true
