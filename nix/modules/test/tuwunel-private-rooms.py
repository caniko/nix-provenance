"""Disposable-server protocol acceptance; this does not test client-side crypto."""

import json
import pathlib
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:6167/_matrix/client/v3"


def api(method, path, token=None, body=None, expected=200):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        BASE + path,
        data=None if body is None else json.dumps(body).encode(),
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status, data = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, data = error.code, error.read()
    assert status == expected, f"{method} {path} returned {status}, expected {expected}"
    return json.loads(data)


def login(user):
    return api(
        "POST",
        "/login",
        body={
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": user},
            "password": (pathlib.Path("/run/test-matrix-passwords") / user).read_text(),
            "device_id": "VM_OBSERVER",
        },
    )["access_token"]


def encoded(value):
    return urllib.parse.quote(value, safe="")


def room_path(room, suffix):
    return f"/rooms/{encoded(room)}/{suffix}"


def assert_no_provisioning_device(token):
    devices = api("GET", "/devices", token)["devices"]
    assert all(device["device_id"] != "TUWUNEL_PROVISION" for device in devices)


def assert_registration_closed():
    denied = api(
        "POST", "/register",
        body={"username": "must-not-register", "password": secrets.token_urlsafe(32)},
        expected=403,
    )
    assert denied["errcode"] == "M_FORBIDDEN"


def main():
    command = subprocess.check_output(
        ["systemctl", "show", "tuwunel-provision.service", "-p", "ExecStart", "--value"],
        text=True,
        timeout=10,
    )
    match = re.search(r"--state (\S+)", command)
    assert match, "service must execute the rendered declarative state"
    state = json.loads(pathlib.Path(match.group(1)).read_text())
    credentials = pathlib.Path("/run/test-provision-credentials")
    credentials.mkdir(mode=0o700)
    for user, spec in state["users"].items():
        source = pathlib.Path("/run/test-matrix-passwords") / user
        assert source.stat().st_mode & 0o777 == 0o600
        assert len(source.read_text()) >= 32
        path = credentials / spec["credential_name"]
        path.write_text(source.read_text())
        path.chmod(0o600)

    def reconcile(candidate, expected_error=None):
        path = pathlib.Path("/run/test-provision-state.json")
        path.write_text(json.dumps(candidate))
        result = subprocess.run(
            [
                sys.argv[1],
                "--state",
                str(path),
                "--admin-token-file",
                "/var/lib/tuwunel/admin-token",
                "--credential-dir",
                str(credentials),
                "--marker-dir",
                "/var/lib/tuwunel/markers",
            ],
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if expected_error is None:
            assert result.returncode == 0, result.stderr
        else:
            assert result.returncode != 0, "unsafe reconciliation unexpectedly succeeded"
            assert expected_error in result.stderr, result.stderr

    assert_registration_closed()
    tokens = {user: login(user) for user in ["iris", "argus", "can", "matrix-admin"]}
    try:
        rooms = {}
        for user in ["iris", "argus"]:
            spec = state["rooms"][user]
            room = api(
                "GET", f"/directory/room/{encoded(spec['alias'])}", tokens[user]
            )["room_id"]
            rooms[user] = room
            events = api("GET", room_path(room, "state"), tokens[user])
            contents = {
                (event["type"], event["state_key"]): event["content"]
                for event in events
            }
            assert contents[("m.room.encryption", "")]["algorithm"] == "m.megolm.v1.aes-sha2"
            assert contents[("m.room.join_rules", "")]["join_rule"] == "invite"
            assert contents[("m.room.guest_access", "")]["guest_access"] == "forbidden"
            active = {
                event["state_key"]: event["content"]["membership"]
                for event in events
                if event["type"] == "m.room.member"
                and event["content"]["membership"] in ["join", "invite", "knock"]
            }
            assert active == {f"@{user}:example.test": "join", "@can:example.test": "invite"}
            # Observe event ordering on the real server, not just the request JSON.
            history = api(
                "GET", room_path(room, "messages") + "?dir=b&limit=100", tokens[user]
            )["chunk"]
            history.reverse()
            encryption = next(
                i for i, event in enumerate(history)
                if event["type"] == "m.room.encryption"
            )
            invitation = next(
                i for i, event in enumerate(history)
                if event["type"] == "m.room.member"
                and event.get("state_key") == "@can:example.test"
            )
            assert encryption < invitation, "invitation preceded initial encryption"
            assert_no_provisioning_device(tokens[user])
            other = "argus" if user == "iris" else "iris"
            api("GET", room_path(room, "state"), tokens[other], expected=403)
            api("POST", room_path(room, "join"), tokens["matrix-admin"], {}, expected=403)
            api("POST", room_path(room, "join"), tokens["can"], {})
            api(
                "PUT", room_path(room, "state/m.room.join_rules"), tokens["can"],
                {"join_rule": "public"}, expected=403,
            )
            api(
                "POST", room_path(room, "invite"), tokens["can"],
                {"user_id": "@matrix-admin:example.test"}, expected=403,
            )
            spec["expectedRoomId"] = room

        assert rooms["iris"] != rooms["argus"]
        powers = api(
            "GET", room_path(rooms["iris"], "state/m.room.power_levels"), tokens["iris"],
        )
        unsafe_powers = json.loads(json.dumps(powers))
        unsafe_powers.setdefault("users", {})["@can:example.test"] = 50
        api(
            "PUT", room_path(rooms["iris"], "state/m.room.power_levels"), tokens["iris"],
            unsafe_powers,
        )
        reconcile(state, "nonowner can change room policy")
        assert_no_provisioning_device(tokens["iris"])
        api(
            "PUT", room_path(rooms["iris"], "state/m.room.power_levels"), tokens["iris"],
            powers,
        )
        # Repeat the actual oneshot, then reconcile with observed IDs pinned.
        subprocess.run(
            ["systemctl", "restart", "tuwunel-provision.service"],
            check=True, timeout=60,
        )
        assert_registration_closed()
        reconcile(state)
        for user in ["iris", "argus"]:
            assert_no_provisioning_device(tokens[user])
            alias = state["rooms"][user]["alias"]
            observed = api("GET", f"/directory/room/{encoded(alias)}", tokens[user])
            assert observed["room_id"] == rooms[user]

        alias = state["rooms"]["iris"]["alias"]
        api("DELETE", f"/directory/room/{encoded(alias)}", tokens["iris"])
        reconcile(state, "refusing to create a replacement")
        assert_no_provisioning_device(tokens["iris"])
        api("GET", f"/directory/room/{encoded(alias)}", tokens["iris"], expected=404)
        replacement = api(
            "POST", "/createRoom", tokens["iris"],
            {"room_alias_name": "hermes-iris", "preset": "private_chat"},
        )["room_id"]
        assert replacement != rooms["iris"]
        reconcile(state, "not its declared room ID")
        assert_no_provisioning_device(tokens["iris"])
        api("DELETE", f"/directory/room/{encoded(alias)}", tokens["iris"])
        api(
            "PUT", f"/directory/room/{encoded(alias)}", tokens["iris"],
            {"room_id": rooms["iris"]},
        )

        # Refuse an existing unencrypted room rather than retrofitting encryption.
        unsafe_alias = "#unsafe:example.test"
        unsafe = api(
            "POST", "/createRoom", tokens["iris"],
            {
                "room_alias_name": "unsafe", "preset": "private_chat",
                # private_chat permits guests on Tuwunel. Isolate missing
                # encryption from the independent guest-access refusal.
                "initial_state": [{
                    "type": "m.room.guest_access", "state_key": "",
                    "content": {"guest_access": "forbidden"},
                }],
            },
        )["room_id"]
        candidate = json.loads(json.dumps(state))
        candidate["rooms"] = {
            "unsafe": {
                **state["rooms"]["iris"],
                "alias": unsafe_alias, "expectedRoomId": unsafe,
            }
        }
        reconcile(candidate, "refusing to retrofit encryption")
        assert_no_provisioning_device(tokens["iris"])
        unsafe_state = api("GET", room_path(unsafe, "state"), tokens["iris"])
        assert not any(event["type"] == "m.room.encryption" for event in unsafe_state)
        assert not any(
            event.get("state_key") == "@can:example.test" for event in unsafe_state
        )

        api(
            "POST", room_path(rooms["iris"], "invite"), tokens["iris"],
            {"user_id": "@matrix-admin:example.test"},
        )
        reconcile(state, "undeclared active member or invitation")
        assert_no_provisioning_device(tokens["iris"])
        api(
            "POST", room_path(rooms["iris"], "kick"), tokens["iris"],
            {"user_id": "@matrix-admin:example.test"},
        )
        reconcile(state)
        assert_no_provisioning_device(tokens["iris"])
        print("PASS: real-server private-room creation, isolation, pinning and device logout")
    finally:
        for token in tokens.values():
            api("POST", "/logout", token)


if __name__ == "__main__":
    main()
