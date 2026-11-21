"""Run with dbus-python and PyGObject: python3 repro-fixed.py /path/to/oo7-cli."""

import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

ROOT = "/org/freedesktop/secrets"
SERVICE = "org.freedesktop.Secret.Service"
COLLECTION = "org.freedesktop.Secret.Collection"
ITEM = "org.freedesktop.Secret.Item"
LOGIN = f"{ROOT}/collection/login"
DEFAULT = f"{ROOT}/collection/work"
SESSION = f"{ROOT}/session/mock"
NATIVE = {"service": "gemini", "username": "antigravity"}
AUTH_LABEL = "Password for 'antigravity' on 'gemini'"
PROPS = "org.freedesktop.DBus.Properties"
ENTRY = b'{"token":{"refresh_token":"mock-work"}}'
PLAIN = "text/plain"
CHARSET = "text/plain; charset=utf8"


class Service(dbus.service.Object):
    has_login = False

    @dbus.service.method(SERVICE, in_signature="s", out_signature="o")
    def ReadAlias(self, alias):
        return DEFAULT if alias == "default" else "/"

    @dbus.service.method(SERVICE, in_signature="sv", out_signature="vo")
    def OpenSession(self, algorithm, _):
        if algorithm != "plain":
            raise dbus.exceptions.DBusException("plain only", name="org.freedesktop.DBus.Error.NotSupported")
        return "", SESSION

    @dbus.service.method(SERVICE, in_signature="ao", out_signature="aoo")
    def Unlock(self, objects):
        return objects, "/"

    @dbus.service.method(PROPS, in_signature="ss", out_signature="v")
    def Get(self, interface, prop):
        assert (interface, prop) == (SERVICE, "Collections")
        return dbus.Array([LOGIN, DEFAULT] if self.has_login else [DEFAULT], signature="o")

    @dbus.service.method(PROPS, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return {"Collections": self.Get(interface, "Collections")}


class Item(dbus.service.Object):
    def __init__(self, name, collection, path, attrs, secret):
        super().__init__(name, path)
        self.collection, self.path, self.attrs, self.secret = collection, path, attrs, secret

    @dbus.service.method(PROPS, in_signature="ss", out_signature="v")
    def Get(self, interface, prop):
        return self.GetAll(interface)[prop]

    @dbus.service.method(PROPS, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        assert interface == ITEM
        return {
            "Label": AUTH_LABEL,
            "Attributes": dbus.Dictionary(self.attrs, signature="ss"),
            "Created": dbus.UInt64(1),
            "Modified": dbus.UInt64(1),
            "Locked": False,
        }

    @dbus.service.method(ITEM, in_signature="o", out_signature="(oayays)")
    def GetSecret(self, session):
        assert session == SESSION
        return session, dbus.ByteArray(b""), dbus.ByteArray(self.secret), self.attrs.get("xdg:content-type", PLAIN)

    @dbus.service.method(ITEM, out_signature="o")
    def Delete(self):
        self.collection.items.remove((self.attrs, self.path))
        del self.collection.objects[self.path]
        self.remove_from_connection()
        return "/"


class Collection(dbus.service.Object):
    fail_store = False
    vanish = None

    def __init__(self, name, path):
        super().__init__(name, path)
        self.name, self.path = name, path
        self.items = []
        self.objects = {}
        self.next_item = 0

    @dbus.service.method(PROPS, in_signature="ss", out_signature="v")
    def Get(self, interface, prop):
        assert (interface, prop) == (COLLECTION, "Items")
        return dbus.Array(self.objects.keys(), signature="o")

    @dbus.service.method(PROPS, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return {"Items": self.Get(interface, "Items")}

    @dbus.service.method(COLLECTION, in_signature="a{ss}", out_signature="ao")
    def SearchItems(self, attrs):
        return [path for fields, path in self.items if attrs.items() <= fields.items()]

    def seed(self, attrs, secret):
        self.next_item += 1
        path = f"{self.path}/{self.next_item}"
        self.items.append((attrs, path))
        self.objects[path] = Item(self.name, self, path, attrs, secret)
        return path

    @dbus.service.method(COLLECTION, in_signature="a{sv}(oayays)b", out_signature="oo")
    def CreateItem(self, props, secret, replace):
        assert props[f"{ITEM}.Label"] == AUTH_LABEL
        assert dict(props[f"{ITEM}.Attributes"]) == NATIVE
        if self.fail_store:
            raise dbus.exceptions.DBusException("fixture failure", name="org.freedesktop.DBus.Error.Failed")
        attrs = NATIVE | {"xdg:content-type": PLAIN}
        self.replace = replace
        if replace:
            # oo7-server removes matches for the stored attributes, including the content type.
            for path in self.SearchItems(attrs):
                self.objects[path].Delete()
        fresh = self.seed(attrs, bytes(secret[2]))
        if self.vanish:
            self.objects[self.vanish].Delete()
        return fresh, "/"


def check(oo7, service, login, default):
    env = {key: os.environ[key] for key in ("DBUS_SESSION_BUS_ADDRESS", "PATH", "HOME")}
    attrs = [f"{key}={value}" for key, value in NATIVE.items()]
    cli = [oo7, "--prefer-collection-path", LOGIN]
    search = cli + ["search", "--all", "--json", *attrs]
    store = cli + ["store", "--replace-all", AUTH_LABEL, *attrs]

    def run(args, **kwargs):
        return subprocess.run(args, env=env, capture_output=True, timeout=6, **kwargs)

    def ok(args, **kwargs):
        result = run(args, **kwargs)
        if result.returncode:
            raise RuntimeError(result.stderr.decode())
        return result.stdout

    # No login collection: exact store falls back to the default.
    assert json.loads(ok(search)) == []
    ok(store, input=ENTRY)
    assert len(default.items) == 1 and not login.items

    # Distinct login exists with no corresponding ReadAlias; -c only checks aliases.
    service.has_login = True
    wrong = run([oo7, "-c", "login", "lookup", "--secret-only", *attrs])
    assert wrong.returncode != 0
    stale = b'{"token":{"refresh_token":"stale"}}'
    login.seed(NATIVE | {"xdg:content-type": PLAIN}, stale)
    login.seed(NATIVE | {"xdg:content-type": PLAIN}, stale)
    charset = login.seed(NATIVE | {"xdg:content-type": CHARSET}, stale)
    unrelated = login.seed(NATIVE | {"username": "other"}, stale)
    old = {path: item.secret for path, item in login.objects.items()}
    assert [item["secret"].encode() for item in json.loads(ok(search))] == [stale] * 3
    login.fail_store = True
    failure = run(store, input=ENTRY)
    assert failure.returncode == 1 and b"fixture failure" in failure.stderr, failure
    assert {path: item.secret for path, item in login.objects.items()} == old
    print("S2: forced create failure exited 1 and preserved every old item and secret.")
    login.fail_store = False
    result = run(store, input=ENTRY)
    matches = [item["secret"].encode() for item in json.loads(ok(search))]
    if result.returncode == 1 and matches == [stale, ENTRY]:
        assert set(login.objects) & old.keys() == {charset, unrelated}
        print(f"S2 reproduced: store exited 1; stale charset item precedes fresh item: {result.stderr.decode().strip()}")
    assert result.returncode == 0 and not login.replace, result.stderr.decode()
    assert matches == [ENTRY]
    assert set(login.objects) & old.keys() == {unrelated} and len(default.items) == 1
    print("S2: store exited 0 with exactly one matching item holding the new secret.")

    # Also simulate another writer deleting one pre-store path before cleanup.
    login.vanish = login.seed(NATIVE, stale)
    login.seed(NATIVE, stale)
    ok(store, input=ENTRY)
    assert unrelated in login.objects
    assert [item["secret"].encode() for item in json.loads(ok(search))] == [ENTRY]
    print("S2: an already-vanished path did not stop cleanup.")


def run(oo7):
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    name = dbus.service.BusName("org.freedesktop.secrets", bus=dbus.SessionBus(), do_not_queue=True)
    service = Service(name, ROOT)
    login = Collection(name, LOGIN)
    default = Collection(name, DEFAULT)
    loop = GLib.MainLoop()
    errors = []

    def worker():
        try:
            check(oo7, service, login, default)
        except BaseException as exc:
            errors.append(exc)
        finally:
            GLib.idle_add(loop.quit)

    GLib.idle_add(lambda: threading.Thread(target=worker, daemon=True).start())
    loop.run()
    if errors:
        raise errors[0]


if __name__ == "__main__":
    if len(sys.argv) == 2:
        with tempfile.TemporaryDirectory() as home:
            config = Path(home) / "bus.conf"
            address = f"unix:abstract=agy-fixed-{os.getpid()}"
            config.write_text(
                f"<busconfig><type>session</type><listen>{address}</listen>"
                '<policy context="default"><allow send_destination="*"/><allow receive_sender="*"/>'
                '<allow own="*"/></policy></busconfig>'
            )
            env = os.environ | {"HOME": home}
            sys.exit(subprocess.call(["dbus-run-session", f"--config-file={config}", "--",
                                      sys.executable, "-B", __file__, sys.argv[1], address], env=env))
    assert os.environ["DBUS_SESSION_BUS_ADDRESS"].split(",")[0] == sys.argv[2]
    assert sys.argv[2].startswith("unix:abstract=agy-fixed-")
    run(sys.argv[1])
