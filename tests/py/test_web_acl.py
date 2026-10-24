#!/usr/bin/env python3
"""
Permissions of web users (src/web_acl.c): levels admin / user / guest, owners and
shares of boxes, tonies and library folders, admin restrictions, user management.

    make test_py TESTS=web_acl
"""

import http.client
import json
import os
import sys
import urllib.parse
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import taf  # noqa: E402
from sim.box import Box  # noqa: E402

BASE = urllib.parse.urlsplit(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "0"))

pytestmark = pytest.mark.skipif(not SANDBOX or not HTTPS_API_PORT, reason="needs the sandbox from tests/py/with_server.sh")

PW = {"admin": "Admin-Password-1", "alice": "Alice-Password-1", "bob": "Bob-Password-11", "gast": "Gast-Password-1", "kid": "Kid-Password-11"}
RUID_A = "0123456789abcdef"
RUID_B = "fedcba9876543210"


class Client:
    def __init__(self, user=None):
        self.cookie = None
        if user:
            status, data = self.post("/api/auth/login", {"username": user, "password": PW[user]})
            assert status == 200 and data.get("ok"), (user, data)

    def request(self, method, path, body=None, raw=False, content_type="application/x-www-form-urlencoded"):
        h = {"Sec-Fetch-Site": "same-origin"}
        if self.cookie:
            h["Cookie"] = "tc_web_session=" + self.cookie
        data = None
        if body is not None:
            data = body if raw else json.dumps(body)
            h["Content-Type"] = content_type if raw else "application/json"
        conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=20)
        try:
            conn.request(method, path, body=data, headers=h)
            r = conn.getresponse()
            text = r.read().decode("utf-8", errors="replace")
            sc = r.getheader("Set-Cookie") or ""
            if sc.startswith("tc_web_session="):
                self.cookie = sc.split(";", 1)[0].split("=", 1)[1] or None
            try:
                payload = json.loads(text) if text else {}
            except ValueError:
                payload = {"_text": text}
            return r.status, payload
        finally:
            conn.close()

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body=None, raw=False):
        return self.request("POST", path, body if body is not None else {}, raw=raw)

    def upload(self, path, filename, data):
        boundary = "tcboundary"
        body = b"--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n\r\n%s\r\n--%s--\r\n" % (
            boundary.encode(), filename.encode(), data, boundary.encode())
        return self.request("POST", path, body, raw=True, content_type="multipart/form-data; boundary=" + boundary)


def box_ids():
    import time
    admin = Client("admin")
    for _ in range(50):
        boxes = admin.get("/api/getBoxes")[1]["boxes"]
        if sum(1 for b in boxes for mac in ("deadbeefa001", "deadbeefa002") if mac in b["commonName"].lower()) == 2:
            break
        time.sleep(0.1)
    print("BOXES", boxes)
    return {mac: next(b["ID"] for b in boxes if mac in b["commonName"].lower()) for mac in ("deadbeefa001", "deadbeefa002")}


@pytest.fixture(scope="module")
def world():
    anon = Client()
    assert anon.post("/api/auth/users/create", {"username": "admin", "password": PW["admin"]})[0] == 200
    assert anon.post("/api/auth/enabled", {"enabled": True})[0] == 200
    admin = Client("admin")
    for name, level in (("alice", "user"), ("bob", "user"), ("gast", "guest")):
        status, data = admin.post("/api/auth/users/create", {"username": name, "password": PW[name], "level": level})
        assert status == 200, data
    boxes = [Box("deadbeefa001", SANDBOX, BASE.hostname, HTTPS_API_PORT), Box("deadbeefa002", SANDBOX, BASE.hostname, HTTPS_API_PORT)]
    for b in boxes:
        assert b.request("GET", "/v1/time")[0] == 200
    ids = box_ids()
    box1, box2 = ids["deadbeefa001"], ids["deadbeefa002"]
    assert admin.post("/api/acl/set", {"type": "box", "id": box1, "owners": ["alice"]})[0] == 200
    assert admin.post("/api/acl/set", {"type": "box", "id": box2, "owners": ["bob"]})[0] == 200
    yield {"box1": box1, "box2": box2, "boxes": boxes}
    for b in boxes:
        b.close()


def test_first_user_is_admin_and_old_users_stay_admins(world):
    _, data = Client("admin").get("/api/acl/mine")
    assert data["level"] == "admin" and data["admin"] is True


def test_boxes_are_filtered(world):
    def visible(user):
        return {b["ID"] for b in Client(user).get("/api/getBoxes")[1]["boxes"]}

    assert visible("alice") == {world["box1"]}
    assert visible("bob") == {world["box2"]}
    assert visible("gast") == set()
    assert {world["box1"], world["box2"]} <= visible("admin")


def test_box_settings_of_owner(world):
    alice = Client("alice")
    b1, b2 = world["box1"], world["box2"]
    assert alice.get("/api/settings/getIndex?overlay=%s" % b1)[0] == 200
    assert alice.get("/api/settings/getIndex?overlay=%s" % b2)[0] == 403
    assert alice.get("/api/settings/getIndex")[0] == 403
    assert alice.post("/api/settings/set/toniebox.max_vol_spk?overlay=%s" % b1, "2", raw=True)[0] == 200
    # saved at once: users may not trigger the write of the config
    assert "overlay.%s.toniebox.max_vol_spk=2" % b1 in (Path(SANDBOX) / "config" / "config.overlay.ini").read_text()
    assert alice.post("/api/settings/set/toniebox.max_vol_spk?overlay=%s" % b2, "2", raw=True)[0] == 403
    # settings that touch the server or the files stay with the admin, also per box
    assert alice.post("/api/settings/set/core.contentdir?overlay=%s" % b1, "x", raw=True)[0] == 403
    # global settings do nothing per box, so they are not the user's either
    assert alice.post("/api/settings/set/frontend.default_ui?overlay=%s" % b1, "1", raw=True)[0] == 403
    assert alice.post("/api/settings/set/toniebox.max_vol_spk", "2", raw=True)[0] == 403
    # an unknown overlay must not fall back to the global settings
    assert alice.post("/api/settings/set/toniebox.max_vol_spk?overlay=nobox", "2", raw=True)[0] == 403
    # global settings the web UI needs
    assert alice.get("/api/settings/get/frontend.split_model_content")[0] == 200
    assert alice.get("/api/settings/get/core.certdir")[0] == 403
    index = alice.get("/api/settings/getIndex?overlay=%s" % b1)[1]["options"]
    names = {o["ID"] for o in index}
    assert "toniebox.max_vol_spk" in names and "core.contentdir" not in names


def test_admin_only_routes(world):
    alice = Client("alice")
    for path in ("/api/stats", "/api/cacheStats", "/api/toniesJsonReload", "/api/triggerWriteConfig", "/content/json/x", "/v1/ota"):
        assert alice.get(path)[0] == 403, path
    assert alice.post("/api/settings/removeOverlay?overlay=%s" % world["box1"])[0] == 403
    assert alice.get("/api/auth/events/get")[0] == 403


def test_share_box_with_limited_rights(world):
    alice, gast = Client("alice"), Client("gast")
    b1 = world["box1"]
    assert gast.get("/api/settings/getIndex?overlay=%s" % b1)[0] == 403
    status, data = alice.post("/api/acl/set", {"type": "box", "id": b1, "shares": {"gast": "box.view, box.setting:toniebox.max_vol_spk"}})
    assert status == 200, data
    assert {b["ID"] for b in gast.get("/api/getBoxes")[1]["boxes"]} == {b1}
    assert gast.post("/api/settings/set/toniebox.max_vol_spk?overlay=%s" % b1, "1", raw=True)[0] == 200
    assert gast.post("/api/settings/set/toniebox.max_vol_hdp?overlay=%s" % b1, "1", raw=True)[0] == 403
    names = {o["ID"] for o in gast.get("/api/settings/getIndex?overlay=%s" % b1)[1]["options"]}
    assert names == {"toniebox.max_vol_spk"}
    # shared users do not share on, and only admins assign owners
    assert gast.post("/api/acl/set", {"type": "box", "id": b1, "shares": {"bob": "box.view"}})[0] == 403
    assert alice.post("/api/acl/set", {"type": "box", "id": b1, "owners": ["alice", "bob"]})[0] == 403
    assert alice.post("/api/acl/set", {"type": "box", "id": b1, "shares": {"gast": "box.share"}})[0] == 400
    assert alice.post("/api/acl/set", {"type": "box", "id": world["box2"], "shares": {"gast": "box.view"}})[0] == 403
    # a guest gets no more than the guest level, even if everything is shared: no sharing on
    # wildcards would include sharing on, so they are refused; everything else explicitly
    assert alice.post("/api/acl/set", {"type": "box", "id": b1, "shares": {"gast": "box.*"}})[0] == 400
    assert alice.post("/api/acl/set", {"type": "box", "id": b1, "shares": {"gast": "box.view, box.settings, box.cfw"}})[0] == 200
    assert gast.post("/api/settings/set/toniebox.max_vol_hdp?overlay=%s" % b1, "1", raw=True)[0] == 200
    assert gast.post("/api/acl/set", {"type": "box", "id": b1, "shares": {"bob": "box.view"}})[0] == 403
    assert gast.post("/api/auth/users/create", {"username": "gast2", "password": "Gast2-Password-1", "level": "guest"})[0] == 403
    # withdraw
    assert alice.post("/api/acl/set", {"type": "box", "id": b1, "shares": {}})[0] == 200
    assert gast.get("/api/getBoxes")[1]["boxes"] == []


def test_admin_restricts_a_user(world):
    admin, b1 = Client("admin"), world["box1"]
    assert admin.post("/api/auth/users/update", {"username": "alice", "deny": "box.setting:toniebox.*"})[0] == 200
    alice = Client("alice")
    assert alice.post("/api/settings/set/toniebox.max_vol_spk?overlay=%s" % b1, "2", raw=True)[0] == 403
    assert alice.post("/api/settings/set/cloud.enabled?overlay=%s" % b1, "false", raw=True)[0] == 200
    # restrictions are the admin's
    assert alice.post("/api/auth/users/update", {"username": "alice", "deny": ""})[0] == 403
    assert admin.post("/api/auth/users/update", {"username": "alice", "deny": ""})[0] == 200
    assert alice.post("/api/settings/set/toniebox.max_vol_spk?overlay=%s" % b1, "2", raw=True)[0] == 200


def test_tag_belongs_to_the_box_owner_after_first_placement(world):
    alice, bob = Client("alice"), Client("bob")
    # nobody owns the tag yet: everyone may use it
    assert bob.get("/api/getTagInfo?ruid=%s" % RUID_A)[0] != 403
    box1 = world["boxes"][0]
    box1.request("GET", "/v1/claim/%s" % RUID_A)
    assert alice.get("/api/getTagInfo?ruid=%s" % RUID_A)[0] != 403
    assert bob.get("/api/getTagInfo?ruid=%s" % RUID_A)[0] == 403
    mine = alice.get("/api/acl/mine")[1]
    assert mine["tonies"][RUID_A.upper()]["owner"] is True
    # a tag placed later on another box keeps its owner
    world["boxes"][1].request("GET", "/v1/claim/%s" % RUID_A)
    assert bob.get("/api/getTagInfo?ruid=%s" % RUID_A)[0] == 403
    # the owner shares it
    assert alice.post("/api/acl/set", {"type": "tonie", "id": RUID_A, "shares": {"bob": "tonie.view"}})[0] == 200
    assert bob.get("/api/getTagInfo?ruid=%s" % RUID_A)[0] != 403
    assert bob.post("/content/json/set/%s" % RUID_A, "live=true", raw=True)[0] == 403
    # admin assigns an unplaced tag by hand
    assert Client("admin").post("/api/acl/set", {"type": "tonie", "id": RUID_B, "owners": ["bob"]})[0] == 200
    assert alice.get("/api/getTagInfo?ruid=%s" % RUID_B)[0] == 403


def test_tonie_source_must_be_readable(world):
    alice = Client("alice")
    status, _ = alice.post("/content/json/set/%s" % RUID_A, "source=lib://private/bob/x.taf", raw=True)
    assert status == 403
    assert alice.post("/content/json/set/%s" % RUID_A, "source=lib://private/alice/x.taf", raw=True)[0] != 403
    assert alice.post("/content/json/set/%s" % RUID_A, "source=/etc/passwd", raw=True)[0] == 403


def test_playlist_files_must_be_readable(world):
    alice = Client("alice")
    lib = Path(SANDBOX) / "data" / "library"
    for folder in ("private/alice", "private/bob"):
        (lib / folder).mkdir(parents=True, exist_ok=True)
    (lib / "private/bob/secret.taf").write_bytes(b"x")

    def playlist(*files, target="lib://private/alice/list.taf"):
        return json.dumps({"type": "tap", "filepath": target, "name": "list", "files": [{"filepath": f, "name": "t"} for f in files]})

    (lib / "private/alice/steal.tap").write_text(playlist("lib://private/bob/secret.taf"))
    (lib / "private/alice/own.tap").write_text(playlist("lib://private/alice/x.taf"))
    (lib / "private/alice/into_bob.tap").write_text(playlist("lib://private/alice/x.taf", target="lib://private/bob/out.taf"))

    # assigning or building a playlist needs read on its files and write where its TAF goes
    for name in ("steal", "into_bob"):
        assert alice.post("/content/json/set/%s" % RUID_A, "source=lib://private/alice/%s.tap" % name, raw=True)[0] == 403
        assert alice.post("/api/tapBuild?special=library", "path=private/alice/%s.tap" % name, raw=True)[0] == 403
    assert alice.post("/content/json/set/%s" % RUID_A, "source=lib://private/alice/own.tap", raw=True)[0] != 403
    assert alice.post("/api/tapBuild?special=library", "path=private/alice/own.tap", raw=True)[0] != 403

    # splitting needs read on the TAF and write next to it
    assert alice.post("/api/tafSplit?special=library", "path=private/bob/secret.taf", raw=True)[0] == 403

    # an uploaded playlist pointing to other users' files is not kept
    boundary = "----acltap"
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="up.tap"; filename="up.tap"\r\n'
        "Content-Type: application/json\r\n\r\n" + playlist("lib://private/bob/secret.taf") + f"\r\n--{boundary}--\r\n"
    ).encode()
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=20)
    try:
        conn.request(
            "POST",
            "/api/fileUpload?special=library&path=private/alice",
            body=body,
            headers={
                "Sec-Fetch-Site": "same-origin",
                "Cookie": "tc_web_session=" + alice.cookie,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        assert conn.getresponse().status == 403
    finally:
        conn.close()
    assert not (lib / "private/alice/up.tap").exists()


def test_library_folders(world):
    alice, bob = Client("alice"), Client("bob")
    lib = "/api/fileIndexV2?special=library&path="
    assert alice.get(lib + "private/alice")[0] == 200
    assert bob.get(lib + "private/alice")[0] == 403
    assert bob.get(lib + "private/carol")[0] == 403
    root = {f["name"] for f in bob.get(lib + "private")[1]["files"]}
    assert "bob" in root and "alice" not in root
    assert "private" in {f["name"] for f in bob.get(lib)[1]["files"]}
    # by/ is read only, new top-level folders are open
    assert alice.post("/api/dirCreate?special=library", "by/new", raw=True)[0] == 403
    assert alice.post("/api/dirCreate?special=library", "shared_top", raw=True)[0] == 200
    assert bob.get(lib + "shared_top")[0] == 200
    # only the library: the content root is the admin's
    assert alice.get("/api/fileIndexV2?path=")[0] == 403
    assert alice.get(lib + "..")[0] == 403
    # sharing a sub folder of the private one
    assert alice.post("/api/dirCreate?special=library", "private/alice/forbob", raw=True)[0] == 200
    assert alice.post("/api/acl/set", {"type": "folder", "id": "private/alice/forbob", "shares": {"bob": "folder.read"}})[0] == 200
    assert bob.get(lib + "private/alice/forbob")[0] == 200
    assert bob.post("/api/dirCreate?special=library", "private/alice/forbob/x", raw=True)[0] == 403
    # on the way to the shared folder bob sees only that folder
    status, data = bob.get(lib + "private/alice")
    assert status == 200 and {f["name"] for f in data["files"] if f["name"] != ".."} == {"forbob"}
    assert bob.post("/api/fileDelete?special=library", "private/alice/forbob", raw=True)[0] == 403
    assert bob.post("/api/dirDelete?special=library", "private/alice", raw=True)[0] == 403


def test_user_management_by_level(world):
    alice, admin = Client("alice"), Client("admin")
    assert alice.post("/api/auth/users/create", {"username": "kid", "password": PW["kid"], "level": "guest"})[0] == 200
    assert alice.post("/api/auth/users/create", {"username": "boss", "password": "Boss-Password-1", "level": "admin"})[0] == 403
    names = set(alice.get("/api/auth/users/get")[1]["users"])
    assert names == {"alice", "kid"}
    assert alice.post("/api/auth/users/delete", {"username": "bob"})[0] == 403
    assert alice.post("/api/auth/users/updatePassword", {"username": "bob", "password": "Other-Password-1"})[0] == 403
    assert alice.post("/api/auth/users/update", {"username": "kid", "level": "user"})[0] == 200
    assert alice.post("/api/auth/users/update", {"username": "kid", "level": "admin"})[0] == 403
    assert Client("kid").get("/api/acl/mine")[1]["level"] == "user"
    assert alice.post("/api/auth/users/delete", {"username": "kid"})[0] == 200
    # the last admin can not go
    status, data = admin.post("/api/auth/users/update", {"username": "admin", "level": "user"})
    assert status == 409 and data["error"] == "last_admin"
    # old sessions of others are not visible to users
    assert all(s["username"] == "alice" for s in alice.get("/api/auth/sessions/get?all=1")[1]["sessions"])


def test_levels_set_by_admin(world):
    admin, alice = Client("admin"), Client("alice")
    assert alice.post("/api/acl/levels/set", {"user": "*"})[0] == 403
    assert admin.post("/api/acl/levels/set", {"user": "box.view, tonie.*, folder.*"})[0] == 200
    assert Client("alice").post("/api/settings/set/cloud.enabled?overlay=%s" % world["box1"], "true", raw=True)[0] == 403
    assert admin.post("/api/acl/levels/set", {"user": "*"})[0] == 200
    assert admin.post("/api/acl/levels/set", {"user": "box.fly"})[0] == 400


def test_review_upload_name_can_not_leave_the_folder(world):
    alice = Client("alice")
    status, _ = alice.post("/api/pcmUpload?special=library&path=&name=private/bob/evil&audioId=1", "x", raw=True)
    assert status == 403
    assert alice.post("/api/tafUpload?special=library&path=&name=..%2Fx", "x", raw=True)[0] == 403


def test_review_moving_a_folder_keeps_restricted_sub_folders(world):
    admin, alice = Client("admin"), Client("alice")
    assert admin.post("/api/dirCreate?special=library", "music", raw=True)[0] == 200
    assert admin.post("/api/dirCreate?special=library", "music/kids", raw=True)[0] == 200
    assert admin.post("/api/acl/set", {"type": "folder", "id": "music/kids", "owners": ["bob"], "shares": {}})[0] == 200
    assert alice.get("/api/fileIndexV2?special=library&path=music/kids")[0] == 403
    status, _ = alice.post("/api/fileMove?special=library", "source=music&target=private/alice/music", raw=True)
    assert status == 403
    assert alice.post("/api/dirDelete?special=library", "music", raw=True)[0] == 403
    # the owner of all of it may move it, the entries go along
    assert admin.post("/api/fileMove?special=library", "source=music&target=music2", raw=True)[0] in (200, 500)
    _, entry = admin.get("/api/acl/get?type=folder&id=music2/kids")
    assert entry["owners"] == ["bob"]


def test_review_wildcard_shares_respect_restrictions(world):
    admin, alice = Client("admin"), Client("alice")
    b1 = world["box1"]
    assert admin.post("/api/auth/users/update", {"username": "alice", "deny": "box.cfw, box.setting:toniebox.*"})[0] == 200
    alice = Client("alice")
    for rights in ("box.*", "box.cfw", "box.settings", "box.setting:*", "box.setting:toniebox.max_vol_spk", "*"):
        assert alice.post("/api/acl/set", {"type": "box", "id": b1, "shares": {"bob": rights}})[0] == 400, rights
    assert alice.post("/api/acl/set", {"type": "box", "id": b1, "shares": {"bob": "box.view, box.setting:cloud.enabled"}})[0] == 200
    assert admin.post("/api/auth/users/update", {"username": "alice", "deny": ""})[0] == 200
    assert Client("alice").post("/api/acl/set", {"type": "box", "id": b1, "shares": {}})[0] == 200


def test_review_secret_and_system_settings_are_not_readable(world):
    alice, b1 = Client("alice"), world["box1"]
    for name in ("core.server_cert_tb2.data.ca_key", "core.server_cert.file.key", "web_auth.lockout_attempts", "mqtt.password", "core.client_cert.file.key"):
        assert alice.get("/api/settings/get/%s?overlay=%s" % (name, b1))[0] == 403, name
    assert alice.get("/api/settings/get/internal.ip?overlay=%s" % b1)[0] == 200
    assert alice.get("/api/settings/get/toniebox.max_vol_spk?overlay=%s" % b1)[0] == 200
    assert alice.post("/api/settings/set/toniebox.max_vol_spk?overlay=%s" % ("x" * 20), "1", raw=True)[0] == 403
    assert alice.get("/api/getTagIndex?special=library")[0] == 403
    assert alice.get("/api/getTagIndex")[0] == 200


def test_firmware_update_with_box_update(world):
    """the firmware update of a box goes with box.update; the builds themselves stay the admin's"""
    b1, b2 = world["box1"], world["box2"]
    if Client("admin").get("/api/settings/get/cfw.update.channel")[0] != 200:
        pytest.skip("server without custom firmware support")
    alice = Client("alice")
    assert alice.get("/api/settings/get/cfw.update.channel?overlay=%s" % b1)[0] == 200
    assert alice.post("/api/settings/set/cfw.update.channel?overlay=%s" % b1, "1", raw=True)[0] == 200
    assert alice.post("/api/settings/set/cfw.update.channel?overlay=%s" % b2, "1", raw=True)[0] == 403
    assert alice.post("/api/settings/set/cfw.update.channel", "1", raw=True)[0] == 403
    assert alice.post("/api/settings/set/cfw.firmware.github_repo?overlay=%s" % b1, "x/y", raw=True)[0] == 403
    assert alice.post("/api/cfw/firmware/delete", {"build": 1})[0] == 403
    admin = Client("admin")
    assert admin.post("/api/auth/users/update", {"username": "alice", "deny": "box.update"})[0] == 200
    try:
        assert Client("alice").post("/api/settings/set/cfw.update.channel?overlay=%s" % b1, "0", raw=True)[0] == 403
    finally:
        assert admin.post("/api/auth/users/update", {"username": "alice", "deny": ""})[0] == 200


def test_header_status_and_cfw_switches_for_users(world):
    alice = Client("alice")
    assert alice.get("/v1/time")[0] == 200
    assert alice.get("/api/settings/get/cfw.show_tag_settings")[0] != 403
    assert alice.get("/v1/ota")[0] == 403


def test_level_limit_also_on_own_boxes(world):
    """what the limit of a level leaves out, the user does not get on the own boxes either"""
    admin, b1 = Client("admin"), world["box1"]
    catalog = admin.get("/api/acl/catalog")[1]
    assert "levelDeny" not in catalog
    names = {o["id"] for o in catalog["boxSettings"]}
    assert "cloud.enabled" in names and "toniebox.max_vol_spk" in names
    assert not any(n.startswith(("core.contentdir", "core.settings_level", "internal.", "web_auth.", "frontend.", "encode.")) or "password" in n for n in names)
    assert "core.flex_enabled" in names
    # only what the page of a box shows per box
    assert not names & {"cloud.enableV3Ota", "cloud.markCustomTagByUid", "cfw.show_battery", "cfw.event_image"}
    assert catalog["boxSettingGroups"].get("cloud")
    limit = "box.view, box.setting:toniebox.*, tonie.*, folder.*"
    assert admin.post("/api/acl/levels/set", {"user": limit})[0] == 200
    try:
        alice = Client("alice")
        assert alice.post("/api/settings/set/cloud.enabled?overlay=%s" % b1, "false", raw=True)[0] == 403
        assert alice.post("/api/settings/set/toniebox.max_vol_spk?overlay=%s" % b1, "2", raw=True)[0] == 200
        assert alice.post("/api/acl/levels/set", {"user": "*"})[0] == 403
    finally:
        assert admin.post("/api/acl/levels/set", {"user": "*"})[0] == 200
    assert Client("alice").post("/api/settings/set/cloud.enabled?overlay=%s" % b1, "true", raw=True)[0] == 200


def test_own_groups(world):
    admin, b1 = Client("admin"), world["box1"]
    status, data = admin.post("/api/acl/groups/set", {"name": "Teens", "base": "user", "rights": "box.view, box.setting:toniebox.*"})
    assert status == 200, data
    gid = data["id"]
    assert Client("alice").post("/api/acl/groups/set", {"name": "x", "base": "user", "rights": "*"})[0] == 403
    assert admin.post("/api/acl/groups/set", {"name": "bad", "base": "admin", "rights": ""})[0] == 400
    assert admin.post("/api/acl/groups/set", {"name": "", "base": "user", "rights": ""})[0] == 400
    assert admin.post("/api/acl/groups/set", {"id": "user", "name": "x", "base": "user", "rights": ""})[0] == 400
    assert admin.post("/api/acl/groups/set", {"name": "x", "base": "user", "rights": "nope.x"})[0] == 400
    assert any(g["id"] == gid and g["name"] == "Teens" for g in admin.get("/api/acl/catalog")[1]["groups"])
    PW["teen"] = "Teen-Password-11"
    status, data = admin.post("/api/auth/users/create", {"username": "teen", "password": PW["teen"], "group": gid, "level": "admin"})
    assert status == 200, data
    users = {u["username"]: u for u in admin.get("/api/auth/users/get")[1]["userDetails"]}
    assert users["teen"]["level"] == "user" and users["teen"]["group"] == gid
    assert admin.post("/api/acl/set", {"type": "box", "id": b1, "owners": ["alice", "teen"]})[0] == 200
    try:
        teen = Client("teen")
        assert teen.get("/api/acl/mine")[1]["group"] == gid
        assert teen.post("/api/settings/set/toniebox.max_vol_spk?overlay=%s" % b1, "2", raw=True)[0] == 200
        assert teen.post("/api/settings/set/cloud.enabled?overlay=%s" % b1, "true", raw=True)[0] == 403
        # a member's group keeps its kind, and the group stays while it has members
        assert admin.post("/api/acl/groups/set", {"id": gid, "name": "Teens", "base": "guest", "rights": ""})[0] == 409
        assert admin.post("/api/acl/groups/delete", {"id": gid})[0] == 409
        # alice (user, limit *) may give the group; a group with more than she has she may not
        assert admin.post("/api/acl/levels/set", {"user": "box.view, tonie.*, folder.*, users.manage"})[0] == 200
        PW["teen2"] = "Teen-Password-22"
        status, _ = Client("alice").post("/api/auth/users/create", {"username": "teen2", "password": PW["teen2"], "group": gid})
        assert status == 403
        assert admin.post("/api/acl/levels/set", {"user": "*"})[0] == 200
        status, data = Client("alice").post("/api/auth/users/create", {"username": "teen2", "password": PW["teen2"], "group": gid})
        assert status == 200, data
        assert Client("alice").post("/api/auth/users/create", {"username": "x1", "password": "X1-Password-1111", "group": "g99"})[0] == 400
        # back to the built-in group of a level
        assert admin.post("/api/auth/users/update", {"username": "teen", "level": "user"})[0] == 200
        assert Client("teen").post("/api/settings/set/cloud.enabled?overlay=%s" % b1, "true", raw=True)[0] == 200
        assert admin.post("/api/auth/users/update", {"username": "teen", "group": gid})[0] == 200
        assert Client("teen").post("/api/settings/set/cloud.enabled?overlay=%s" % b1, "true", raw=True)[0] == 403
    finally:
        admin.post("/api/acl/levels/set", {"user": "*"})
        for name in ("teen", "teen2"):
            admin.post("/api/auth/users/delete", {"username": name})
        admin.post("/api/acl/set", {"type": "box", "id": b1, "owners": ["alice"]})
    assert admin.post("/api/acl/groups/delete", {"id": gid})[0] == 200
    assert all(g["id"] != gid for g in admin.get("/api/acl/catalog")[1]["groups"])


def test_long_rights_lists_apply_in_full(world):
    """long lists from the rights tree are taken in full, the last entry counts"""
    admin, b1 = Client("admin"), world["box1"]
    filler = ", ".join("box.setting:core.x%04d" % i for i in range(100))
    user_deny = filler[:1000].rsplit(",", 1)[0] + ", box.setting:cloud.enabled"
    limit = filler[:2000].rsplit(",", 1)[0] + ", box.view, box.setting:toniebox.max_vol_spk"
    assert admin.post("/api/auth/users/update", {"username": "alice", "deny": user_deny})[0] == 200
    assert admin.post("/api/acl/levels/set", {"user": limit})[0] == 200
    try:
        alice = Client("alice")
        assert alice.post("/api/settings/set/toniebox.max_vol_spk?overlay=%s" % b1, "2", raw=True)[0] == 200
        assert alice.post("/api/settings/set/toniebox.slap_enabled?overlay=%s" % b1, "true", raw=True)[0] == 403
        assert alice.post("/api/settings/set/cloud.enabled?overlay=%s" % b1, "true", raw=True)[0] == 403
    finally:
        assert admin.post("/api/acl/levels/set", {"user": "*"})[0] == 200
        assert admin.post("/api/auth/users/update", {"username": "alice", "deny": ""})[0] == 200
    assert Client("alice").post("/api/settings/set/toniebox.max_vol_spk?overlay=%s" % b1, "2", raw=True)[0] == 200


def custom_tonie(model, title="Test"):
    audio_id = str(sum(map(ord, model.lower())))
    return {"model": model, "audio_id": [audio_id], "hash": ["0" * 40], "title": title, "series": title}


def test_users_add_custom_tonies_and_change_only_their_own(world):
    admin, alice, bob, gast = Client("admin"), Client("alice"), Client("bob"), Client("gast")
    assert alice.post("/api/toniesCustomJsonUpsert", custom_tonie("Alice-1"))[0] == 200
    assert alice.post("/api/toniesCustomJsonUpsert", custom_tonie("alice-1", "Neu"))[0] == 200
    assert "alice-1" in alice.get("/api/acl/mine")[1]["models"]
    assert bob.post("/api/toniesCustomJsonUpsert", custom_tonie("alice-1"))[0] == 403
    assert bob.post("/api/toniesCustomJsonDelete", {"models": ["alice-1"]})[0] == 403
    assert bob.post("/api/toniesCustomJsonRename", {"fromModel": "alice-1", "toModel": "bob-1"})[0] == 403
    assert gast.post("/api/toniesCustomJsonUpsert", custom_tonie("gast-1"))[0] == 403
    assert admin.post("/api/toniesCustomJsonUpsert", custom_tonie("admin-1"))[0] == 200
    assert alice.post("/api/toniesCustomJsonUpsert", custom_tonie("admin-1"))[0] == 403
    assert alice.post("/api/toniesCustomJsonRename", {"fromModel": "alice-1", "toModel": "alice-2"})[0] == 200
    assert list(alice.get("/api/acl/mine")[1]["models"]) == ["alice-2"]
    assert alice.post("/api/toniesCustomJsonDelete", {"models": ["alice-2"]})[0] == 200
    assert alice.get("/api/acl/mine")[1]["models"] == {}
    assert [m["model"] for m in alice.get("/api/toniesCustomJson")[1]] == ["admin-1"]
    assert admin.post("/api/toniesCustomJsonDelete", {"models": ["admin-1"]})[0] == 200


def test_users_add_new_pictures_of_custom_tonies(world):
    alice, gast = Client("alice"), Client("gast")
    path = "/api/fileUpload?special=custom_img&path="
    assert alice.upload(path, "alice.png", b"png")[0] == 200
    assert (Path(SANDBOX) / "data" / "www" / "custom_img" / "alice.png").read_bytes() == b"png"
    # the folder is served as it is: no pages, and nothing of others replaced
    assert alice.upload(path, "alice.png", b"other")[0] != 200
    assert alice.upload(path, "alice.html", b"<script>")[0] != 200
    assert not (Path(SANDBOX) / "data" / "www" / "custom_img" / "alice.html").exists()
    assert gast.upload(path, "gast.png", b"png")[0] == 403
    assert Client("admin").upload(path, "alice.png", b"admin")[0] == 200


def put_taf(where, audio_id):
    """A TAF in the sandbox: where is "library/<path>" or "content/default/<HI8>/<LO8>"."""
    path = Path(SANDBOX) / "data" / where
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(taf.build(audio_id, os.urandom(3 * 4096)))
    return path


def test_custom_tonies_follow_the_places_they_are_used(world):
    admin, alice, bob = Client("admin"), Client("alice"), Client("bob")
    tonie = custom_tonie("Used-1")
    audio_id = int(tonie["audio_id"][0])
    assert admin.post("/api/toniesCustomJsonUpsert", tonie)[0] == 200
    # used nowhere: only the admin
    assert alice.post("/api/toniesCustomJsonUpsert", tonie)[0] == 403
    # used only in alice's folder: alice changes it, bob not
    alices = put_taf("library/private/alice/used/used.taf", audio_id)
    assert alice.post("/api/toniesCustomJsonUpsert", custom_tonie("Used-1", "Neu"))[0] == 200
    assert bob.post("/api/toniesCustomJsonUpsert", tonie)[0] == 403
    assert "Used-1" in alice.get("/api/toniesCustomJsonChangeable")[1]["models"]
    assert "Used-1" not in bob.get("/api/toniesCustomJsonChangeable")[1]["models"]
    # also used in bob's folder or on bob's tonie: neither of them
    bobs = put_taf("library/private/bob/used.taf", audio_id)
    assert alice.post("/api/toniesCustomJsonUpsert", tonie)[0] == 403
    bobs.unlink()
    assert admin.post("/api/acl/set", {"type": "tonie", "id": RUID_B, "owners": ["bob"]})[0] == 200
    on_tonie = put_taf("content/default/FEDCBA98/76543210", audio_id)
    assert alice.post("/api/toniesCustomJsonUpsert", tonie)[0] == 403
    on_tonie.unlink()
    # deleting the folder's file takes the tonie along when asked, it is used nowhere else
    assert alice.post("/api/toniesCustomJsonOrphans", ["private/alice/used"])[1] == ["Used-1"]
    assert bob.post("/api/toniesCustomJsonOrphans", ["private/alice/used"])[1] == []
    assert alice.post("/api/fileDelete?special=library&models=1", "private/alice/used/used.taf", raw=True)[0] == 200
    assert not alices.exists()
    assert "Used-1" not in [m["model"] for m in admin.get("/api/toniesCustomJson")[1]]


def test_pictures_of_custom_tonies_are_deleted_with_them(world):
    admin, alice, bob = Client("admin"), Client("alice"), Client("bob")
    imgs = Path(SANDBOX) / "data" / "www" / "custom_img"
    upload = "/api/fileUpload?special=custom_img&path="
    delete = "/api/fileDelete?special=custom_img"
    assert alice.upload(upload, "own.png", b"png")[0] == 200
    assert "own.png" in alice.get("/api/acl/mine")[1]["images"]
    assert alice.upload(upload + "sub", "deep.png", b"png")[0] == 403
    assert bob.post(delete, "own.png", raw=True)[0] == 403
    assert alice.post(delete, "own.png", raw=True)[0] == 200 and not (imgs / "own.png").exists()
    # the last tonie showing a picture takes it along when asked
    assert alice.upload(upload, "pic.png", b"png")[0] == 200
    for model in ("Pic-1", "Pic-2"):
        assert alice.post("/api/toniesCustomJsonUpsert", {**custom_tonie(model), "pic": "/custom_img/pic.png"})[0] == 200
    assert alice.post("/api/toniesCustomJsonDelete", {"models": ["Pic-1"], "pictures": True})[0] == 200
    assert (imgs / "pic.png").exists()
    assert alice.post("/api/toniesCustomJsonDelete", {"models": ["Pic-2"], "pictures": True})[0] == 200
    assert not (imgs / "pic.png").exists() and "pic.png" not in alice.get("/api/acl/mine")[1]["images"]
    # a picture of the admin shown only by a tonie alice may change is hers to delete
    assert admin.upload(upload, "admins.png", b"png")[0] == 200
    tonie = {**custom_tonie("Pic-3"), "pic": "/custom_img/admins.png"}
    assert admin.post("/api/toniesCustomJsonUpsert", tonie)[0] == 200
    assert alice.post(delete, "admins.png", raw=True)[0] == 403
    put_taf("library/private/alice/pic.taf", int(tonie["audio_id"][0]))
    assert bob.post(delete, "admins.png", raw=True)[0] == 403
    assert "admins.png" in alice.get("/api/toniesCustomJsonChangeable")[1]["images"]
    assert alice.post(delete, "admins.png", raw=True)[0] == 200
    # no way out of the picture folder
    evil = {**custom_tonie("Pic-4"), "pic": "/custom_img/../index.html"}
    (Path(SANDBOX) / "data" / "www" / "index.html").write_text("ui")
    assert alice.post("/api/toniesCustomJsonUpsert", evil)[0] == 200
    assert alice.post("/api/toniesCustomJsonDelete", {"models": ["Pic-4"], "pictures": True})[0] == 200
    assert (Path(SANDBOX) / "data" / "www" / "index.html").exists()


def test_users_never_take_the_audio_id_of_an_official_tonie(world):
    admin, alice = Client("admin"), Client("alice")
    official = {"no": "1", "model": "10000001", "audio_id": ["4711"], "hash": ["1" * 40], "title": "Offiziell", "series": "O",
                "episodes": "", "tracks": [], "release": "0", "language": "de-de", "category": "audio-play", "pic": ""}
    (Path(SANDBOX) / "config" / "tonies.json").write_text(json.dumps([official]))
    assert admin.get("/api/toniesJsonReload")[0] == 200
    assert alice.post("/api/toniesCustomJsonUpsert", {**custom_tonie("Copy-1"), "audio_id": ["4711"]})[0] == 400
    assert admin.post("/api/toniesCustomJsonUpsert", {**custom_tonie("Copy-1"), "audio_id": ["4711"]})[0] == 200


def test_admin_sees_what_a_user_owns(world):
    admin, alice = Client("admin"), Client("alice")
    status, owned = admin.get("/api/acl/owned?user=alice")
    assert status == 200 and world["box1"] in [b["id"] for b in owned["boxes"] if b["owner"]]
    assert "private/alice" in [f["id"] for f in owned["folders"]]
    assert alice.get("/api/acl/owned?user=alice")[0] == 403


def test_deleting_a_folder_with_its_content_drops_its_owners(world):
    admin, alice, bob = Client("admin"), Client("alice"), Client("bob")
    assert alice.post("/api/dirCreate?special=library", "gone", raw=True)[0] == 200
    assert admin.post("/api/acl/set", {"type": "folder", "id": "gone", "owners": ["alice"]})[0] == 200
    put_taf("library/gone/a.taf", 4242)
    assert alice.post("/api/fileDelete?special=library", "gone", raw=True)[0] == 200
    assert "gone" not in alice.get("/api/acl/mine")[1]["folders"]
    # a new folder of the same name is open again, not alice's
    assert bob.post("/api/dirCreate?special=library", "gone", raw=True)[0] == 200
    assert bob.post("/api/dirCreate?special=library", "gone/sub", raw=True)[0] == 200
