"""
Custom firmware (CC3200 CFW) support: hello and settings files in the freshness-check answer, the
records of the box, remote commands on the log connection and the firmware update.

One simulated CFW box goes through these tests in file order, each building on the state the ones
before left (pytest keeps the order of a file).

    make test_py TESTS=cfw
"""

import hashlib
import http.client
import json
import os
import struct
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import cfw  # noqa: E402
from sim.box import Box  # noqa: E402
from sim.mqtt_broker import MqttBroker  # noqa: E402
from sim.upstream import FakeCloud  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "0"))

pytestmark = pytest.mark.skipif(not SANDBOX or not HTTPS_API_PORT, reason="needs the sandbox from tests/py/with_server.sh")

BUILD = 1791210720  # 2026-10-05 14:32:00 UTC
CAPS_ALL = 0x1FFF
CAPS_WITHOUT_EXTENSIONS = CAPS_ALL & ~(1 << 9)
FIGURE_UID = 0xE0040350DEADBEEF
FIGURE_RUID = "EFBEADDE500304E0"  # the same UID in content path order
GLOBAL_RUID = "0000000000000000"
ORIGINAL_BUILD = 1620325289
# the CFW presents the original firmware 3.4.0 towards the API host, its own build in X-CFW-Build
OFW_BUILD = 1779199517
CFW_AGENT = f"TB/{OFW_BUILD} SP/1 HW/16"


def api(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=30)
    try:
        conn.request(method, path, json.dumps(body) if isinstance(body, dict) else body, headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def api_bytes(method, path):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=30)
    try:
        conn.request(method, path)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def api_json(method, path, body=None):
    status, text = api(method, path, body)
    return status, json.loads(text)


def persist():
    # API changes live in memory until written; the server reloads the written files within a main loop
    # pass plus the file time granularity (see test_cloud_proxy.setting)
    assert api("GET", "/api/triggerWriteConfig")[0] == 200
    time.sleep(1.2)


def set_setting(name, value, overlay=None):
    value = str(value).lower() if isinstance(value, bool) else str(value)
    assert api("POST", f"/api/settings/set/{name}" + (f"?overlay={overlay}" if overlay else ""), value)[0] == 200
    persist()


def reset_setting(name, overlay=None):
    assert api("POST", f"/api/settings/reset/{name}" + (f"?overlay={overlay}" if overlay else ""))[0] == 200
    persist()


def setting_value(name, overlay=None):
    return api("GET", f"/api/settings/get/{name}" + (f"?overlay={overlay}" if overlay else ""))[1]


def wait_until(condition, timeout=5.0):
    deadline = time.time() + timeout
    while not condition():
        assert time.time() < deadline, "condition not met in time"
        time.sleep(0.1)


class BoxStart:
    """uptime and sequence numbers of the log records of one start of the box"""

    def __init__(self, sequence):
        self.uptime = 1000 * sequence
        self.sequence = sequence

    def next(self):
        self.uptime += 100
        self.sequence += 1
        return {"uptime": self.uptime, "sequence": self.sequence}


def freshness(box):
    status, _, body = box.request("POST", "/v1/freshness-check", cfw.freshness_request(FIGURE_UID, 0x6AB13B80))
    assert status == 200, body
    return cfw.fields(body)


def files(answer, ruid):
    return [value[8:] for field, value in answer if field == 100 and value[:8] == bytes.fromhex(ruid)]


def box_entry(box):
    # a new box writes its overlay to the config, and the server reloads the config file a moment
    # later; while it does, the box may be missing from the list for a short time
    for _ in range(50):
        status, data = api_json("GET", "/api/cfw/boxes")
        assert status == 200
        entry = next((e for e in data["boxes"] if e["commonName"].lower() == box.mac), None)
        if entry is not None:
            return entry
        time.sleep(0.1)
    raise AssertionError("box %s not in /api/cfw/boxes" % box.mac)


def ota(box, version):
    """item 3 of a box running build version: the CFW sends it in X-CFW-Build and the original firmware's build
    as cv; the original firmware sends its own build as cv"""
    if "X-CFW-Build" in box.headers:
        return box.request("GET", f"/v1/ota/3?cv={OFW_BUILD}", headers={"X-CFW-Build": str(version)})
    return box.request("GET", f"/v1/ota/3?cv={version}")


def upload(image, channel):
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"ng-cfw.bin\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + image + f"\r\n--{boundary}--\r\n".encode()
    status, text = api("POST", f"/api/cfw/firmware/upload?channel={channel}", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    return status, json.loads(text)


def upload_query(image, query):
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"image.bin\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + image + f"\r\n--{boundary}--\r\n".encode()
    status, text = api("POST", f"/api/cfw/firmware/upload?{query}", body, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    return status, json.loads(text)


def global_report(timestamp, speaker=None):
    """settings change report of the global file: LED dimmed, both-ears switch-off on, slap and
    volume lock on, headphones 15 and, if given, the speaker limit"""
    packed = 3 | (1 << 8) | (1 << 9) | (1 << 10) | (2 << 14) | (1 << 16) | ((1 << 7) if speaker is not None else 0)
    values = ((speaker or 0) << 16) | (15 << 20) | (0b111 << 24) | (1 << 27) | (1 << 29)
    return bytes(8) + struct.pack("<III", packed, values, timestamp)


@pytest.fixture(scope="module", autouse=True)
def cfw_enabled():
    """the CFW support is off by default (as without it); these tests need it on"""
    set_setting("cfw.enabled", True)
    yield
    set_setting("cfw.enabled", False)


@pytest.fixture(scope="module")
def box():
    b = Box("deadbeefcf01", SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=CFW_AGENT, headers={"X-CFW-Build": str(BUILD)})
    assert b.request("GET", "/v1/time")[0] == 200
    yield b
    b.close()


@pytest.fixture(scope="module")
def box_id(box):
    return box_entry(box)["id"]


@pytest.fixture(scope="module")
def start():
    return BoxStart(sequence=10)


def send_hello(box, start, capabilities=CAPS_ALL):
    box.rtnl(cfw.hello(BUILD, capabilities, **start.next()))
    wait_until(lambda: box_entry(box)["helloValid"] and box_entry(box)["capabilities"] == capabilities)


def test_hello_in_freshness_answer(box):
    # old-style limits, taken over when the first CFW box connects
    set_setting("toniebox.max_vol_spk", 1)
    set_setting("toniebox.slap_enabled", False)
    assert setting_value("cfw.show_tag_settings") == "false" and setting_value("cfw.show_box_settings") == "false"
    answer = freshness(box)
    assert (101, 1) in answer, answer
    assert {3, 7} <= {field for field, _ in answer}


def test_hello_answer_is_recorded(box, start):
    send_hello(box, start)
    entry = box_entry(box)
    assert entry["isCfw"] and entry["version"] == BUILD


def test_hello_on_each_log_connection(box, start):
    """command 63 once per log connection of a box that is known by its X-CFW-Build header"""
    for _ in range(2):
        sock = box.rtnl(cfw.record(8672, bytes(12), group=27, **start.next()), keep_open=True)
        try:
            reader = cfw.FrameReader(sock)
            frames = []
            wait_until(lambda: frames.extend(reader.frames(0.5)) or [(1, 63)] in frames, timeout=10)
            sock.sendall(cfw.record(8672, bytes(12), group=27, **start.next()))
            frames.extend(reader.frames(1.5))
            assert frames.count([(1, 63)]) == 1, frames
        finally:
            sock.close()


def test_no_hello_on_the_log_connection_of_the_original_firmware():
    other = Box("deadbeefcf09", SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=f"TB/{ORIGINAL_BUILD} SP/1 HW/16")
    try:
        assert other.request("GET", "/v1/time")[0] == 200
        sock = other.rtnl(cfw.record(8672, bytes(12), group=27, uptime=1000, sequence=1), keep_open=True)
        try:
            assert cfw.FrameReader(sock).frames(2.0) == []
        finally:
            sock.close()
    finally:
        other.close()


def test_box_host_is_offered_for_a_new_box(box):
    # the address the boxes use, for the server line of a new box's card
    freshness(box)
    status, data = api_json("GET", "/api/cfw/boxHost")
    assert status == 200 and data["host"] == box.host, data
    assert data["apiPort"] > 0


def test_first_cfw_box_shows_the_settings_once(box, start):
    wait_until(lambda: setting_value("cfw.show_box_settings") == "true")
    assert setting_value("cfw.show_tag_settings") == "true"
    # 50 % -> step 9, slap to skip off -> slap lock
    assert setting_value("cfw.box.speaker_limit") == "9" and setting_value("cfw.box.slap_lock") == "true"
    assert setting_value("cfw.box.headphone_limit") == "15"
    # switched off by the user: a later hello does not switch it on again
    set_setting("cfw.show_tag_settings", False)
    send_hello(box, start)
    time.sleep(1.2)
    assert setting_value("cfw.show_tag_settings") == "false"


def test_volume_fields_dropped_after_hello(box):
    fields = {field for field, _ in freshness(box)}
    assert 3 not in fields and 7 not in fields and 101 in fields


def test_profile_is_delivered(box):
    profile = {"resume": True, "sleepMinutes": 30, "ledLevel": 2}
    assert api("POST", f"/api/cfw/tag?ruid={FIGURE_RUID}", {"kind": "profile", "profile": profile})[0] == 200
    tag = api_json("GET", f"/api/cfw/tag?ruid={FIGURE_RUID}")[1]
    assert tag["kind"] == "profile" and tag["profile"]["resume"] is True and tag["profile"]["sleepMinutes"] == 30
    assert tag["profile"]["shuffle"] is None

    delivered = files(freshness(box), FIGURE_RUID)
    assert len(delivered) == 1 and delivered[0][4] == 1 and delivered[0][5] == 1
    assert cfw.tbs_body(delivered[0]) == bytes([0x01, 1, 1, 0x03, 2, 30, 0, 0x06, 1, 2])
    # the server knows the box holds it now
    assert not files(freshness(box), FIGURE_RUID)


def test_event_tag_round_trip():
    ruid = "11223344556677E0"
    event = {"tones": False, "actions": [{"action": 13, "mode": 0, "value": 0}, {"action": 9, "mode": 1, "value": 6}]}
    assert api("POST", f"/api/cfw/tag?ruid={ruid}", {"kind": "event", "event": event})[0] == 200
    assert api_json("GET", f"/api/cfw/tag?ruid={ruid}")[1]["event"] == event
    tags = api_json("GET", "/api/cfw/tags")[1]["tags"]
    assert next(tag for tag in tags if tag["ruid"] == ruid)["kind"] == "event"
    # the idle power-off times take the whole 16-bit parameter as minutes
    event = {"tones": True, "actions": [{"action": 17, "mode": 0, "value": 30}, {"action": 18, "mode": 0, "value": 65535}]}
    assert api("POST", f"/api/cfw/tag?ruid={ruid}", {"kind": "event", "event": event})[0] == 200
    assert api_json("GET", f"/api/cfw/tag?ruid={ruid}")[1]["event"] == event
    # "none" replaces it with an empty profile
    assert api("POST", f"/api/cfw/tag?ruid={ruid}", {"kind": "none"})[0] == 200
    assert api_json("GET", f"/api/cfw/tag?ruid={ruid}")[1]["kind"] == "none"


def test_invalid_values_are_refused():
    for body in ({"kind": "profile", "profile": {"speakerLimit": 16}},
                 {"kind": "profile", "profile": {"sleepMinutes": 1.5}},
                 {"kind": "profile", "profile": {"sleepMinutes": -1}},
                 {"kind": "event", "event": {"actions": [{"action": 19, "mode": 0, "value": 0}]}},
                 {"kind": "event", "event": {"actions": [{"action": 1, "mode": 0, "value": 16384}]}},
                 {"kind": "event", "event": {"actions": []}},
                 {"kind": "other"}):
        assert api("POST", f"/api/cfw/tag?ruid={FIGURE_RUID}", body)[0] == 400, body


def test_box_settings_are_delivered(box, box_id):
    files(freshness(box), GLOBAL_RUID)  # whatever the box gets first
    try:
        set_setting("cfw.box.both_ears_off", False)
        set_setting("cfw.box.headphone_limit", 12, box_id)
        delivered = files(freshness(box), GLOBAL_RUID)
        assert len(delivered) == 1 and delivered[0][4] == 3
        # speaker 9, headphones 12 (this box), LED on, both ears off, slap lock, tilt and volume unlocked
        assert cfw.tbs_body(delivered[0]) == bytes([0x04, 1, 9, 0x05, 1, 12, 0x06, 1, 0, 0x07, 1, 0, 0x08, 1, 1, 0x09, 1, 0, 0x0A, 1, 0])
        assert not files(freshness(box), GLOBAL_RUID)
        # an idle power-off time other than 10 minutes is a 2-byte record
        set_setting("cfw.box.idle_off_station", 1440, box_id)
        delivered = files(freshness(box), GLOBAL_RUID)
        assert len(delivered) == 1 and cfw.tbs_body(delivered[0])[-4:] == bytes([0x0C, 2, 0xA0, 0x05])
    finally:
        set_setting("cfw.box.both_ears_off", True)
        reset_setting("cfw.box.headphone_limit", box_id)
        reset_setting("cfw.box.idle_off_station", box_id)


def test_original_box_gets_rounded_limits():
    other = Box("deadbeefcf03", SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=f"TB/{ORIGINAL_BUILD} SP/1 HW/16")
    try:
        assert other.request("GET", "/v1/time")[0] == 200
        set_setting("cfw.box.speaker_limit", 8)
        set_setting("cfw.box.headphone_limit", 13)
        answer = dict(freshness(other))
        # nearest of the steps 6/9/12/15: 8 -> 50 %, 13 -> 75 %; slap lock -> slap to skip off; no files
        assert answer[3] == 1 and answer[7] == 2 and answer[4] == 0 and 100 not in answer, answer
        # the box's settings show the values it gets
        shown = {o["ID"]: o for o in api_json("GET", "/api/settings/getIndex?overlay=deadbeefcf03&nolevel=true")[1]["options"]}
        assert shown["toniebox.max_vol_spk"]["value"] == 1 and shown["toniebox.max_vol_spk"]["derived"] is True
        assert shown["toniebox.slap_enabled"]["value"] is False
        # an old setting of this box still wins
        set_setting("toniebox.max_vol_spk", 2, "deadbeefcf03")
        assert dict(freshness(other))[3] == 2
        # CFW box settings hidden, but forced for this box: what its dialog shows applies
        set_setting("cfw.show_box_settings", False)
        assert dict(freshness(other))[7] == 3  # the old global headphone limit 100 %
        set_setting("cfw.force_box_settings", True, "deadbeefcf03")
        set_setting("cfw.box.headphone_limit", 8, "deadbeefcf03")
        assert dict(freshness(other))[7] == 1  # step 8 -> step 9 = 50 %
    finally:
        set_setting("cfw.show_box_settings", True)
        set_setting("cfw.box.speaker_limit", 9)
        set_setting("cfw.box.headphone_limit", 15)
        other.close()


def test_settings_report_from_box(box, start):
    timestamp = int(time.time()) + 100
    # figure 0102030405060708: shuffle on (presence bit 5, value bit 13), volume lock on
    payload = bytes.fromhex("0102030405060708") + struct.pack("<III", 1 | (1 << 5) | (1 << 13), (1 << 26) | (1 << 29), timestamp)
    box.rtnl(cfw.record(cfw.FUNC_SETTINGS_CHANGED, payload, **start.next()))
    wait_until(lambda: api_json("GET", "/api/cfw/tag?ruid=0102030405060708")[1]["kind"] == "profile")
    tag = api_json("GET", "/api/cfw/tag?ruid=0102030405060708")[1]
    assert tag["origin"] == "box" and tag["timestamp"] == timestamp
    assert tag["profile"]["shuffle"] is True and tag["profile"]["volumeLock"] is True and tag["profile"]["resume"] is None
    # the box holds that file: it is not sent back
    assert not files(freshness(box), "0102030405060708")


def test_box_settings_report_becomes_box_setting(box, box_id, start):
    files(freshness(box), GLOBAL_RUID)
    timestamp = int(time.time()) + 100
    try:
        box.rtnl(cfw.record(cfw.FUNC_SETTINGS_CHANGED, global_report(timestamp, speaker=5), **start.next()))
        wait_until(lambda: setting_value("cfw.box.speaker_limit", box_id) == "5")
        assert setting_value("toniebox.led", box_id) == "2" and setting_value("cfw.box.volume_lock", box_id) == "true"
        assert setting_value("cfw.box.speaker_limit") == "9"
        time.sleep(1.2)
        assert not files(freshness(box), GLOBAL_RUID)

        # the box removed its speaker limit (mode clear): it gets teddyCloud's value again, at once by
        # command 64 as it has remote control
        sock = box.rtnl(cfw.record(cfw.FUNC_SETTINGS_CHANGED, global_report(timestamp + 1), **start.next()), keep_open=True)
        try:
            reader = cfw.FrameReader(sock)
            frames = []

            def pushed():
                frames.extend(reader.frames(0.5))
                return any(dict(frame).get(1) == 64 and cfw.tbs_body(dict(frame)[3][8:])[:3] == bytes([0x04, 1, 9]) for frame in frames)

            wait_until(pushed, timeout=10)
        finally:
            sock.close()
        assert setting_value("cfw.box.speaker_limit", box_id) == "9"
    finally:
        for name in ("cfw.box.speaker_limit", "cfw.box.headphone_limit", "toniebox.led", "cfw.box.both_ears_off", "cfw.box.slap_lock", "cfw.box.tilt_lock", "cfw.box.volume_lock"):
            reset_setting(name, box_id)


def test_idle_times_report_becomes_box_setting(box, box_id, start):
    files(freshness(box), GLOBAL_RUID)
    timestamp = int(time.time()) + 200
    try:
        # an event tag set 2 minutes on battery and 1440 on the station: the sixth number of the report
        report = global_report(timestamp)
        packed = struct.unpack_from("<I", report, 8)[0] | (1 << 17) | (1 << 18)
        report = report[:8] + struct.pack("<I", packed) + report[12:] + struct.pack("<I", 2 | (1440 << 16))
        box.rtnl(cfw.record(cfw.FUNC_SETTINGS_CHANGED, report, **start.next()))
        wait_until(lambda: setting_value("cfw.box.idle_off_station", box_id) == "1440")
        assert setting_value("cfw.box.idle_off_battery", box_id) == "2" and setting_value("cfw.box.idle_off_station") == "10"
        time.sleep(1.2)
        assert not files(freshness(box), GLOBAL_RUID)
    finally:
        for name in ("cfw.box.idle_off_battery", "cfw.box.idle_off_station", "cfw.box.speaker_limit", "cfw.box.headphone_limit", "toniebox.led", "cfw.box.both_ears_off", "cfw.box.slap_lock", "cfw.box.tilt_lock", "cfw.box.volume_lock"):
            reset_setting(name, box_id)


def test_event_tag_for_box_without_extensions(box, start):
    ruid = "AABBCCDD000004E0"
    event = {"tones": True, "actions": [{"action": 1, "mode": 0, "value": 0}, {"action": 2, "mode": 2, "value": 0}, {"action": 13, "mode": 0, "value": 0}]}
    try:
        # a new start of the box, with a firmware without bit 9
        start.__init__(sequence=20)
        send_hello(box, start, capabilities=CAPS_WITHOUT_EXTENSIONS)
        assert api("POST", f"/api/cfw/tag?ruid={ruid}", {"kind": "event", "event": event})[0] == 200
        delivered = files(freshness(box), ruid)
        # only the actions 1 to 9 in mode toggle: the meaning of the others would change
        assert len(delivered) == 1 and cfw.tbs_body(delivered[0]) == bytes([0x10, 3, 1, 0, 0])
        only_global = {"tones": True, "actions": [{"action": 13, "mode": 0, "value": 0}]}
        assert api("POST", f"/api/cfw/tag?ruid={ruid}", {"kind": "event", "event": only_global})[0] == 200
        assert not files(freshness(box), ruid)
    finally:
        api("POST", f"/api/cfw/tag?ruid={ruid}", {"kind": "none"})
        start.__init__(sequence=10)
        send_hello(box, start)


def test_remote_command_reaches_the_box(box, box_id, start):
    sock = box.rtnl(cfw.hello(BUILD, CAPS_ALL, **start.next()), keep_open=True)
    try:
        reader = cfw.FrameReader(sock)
        status, text = api("POST", f"/api/cfw/remote?overlay={box_id}", {"command": "volume", "volume": 9})
        assert status == 200, text
        frames = []
        wait_until(lambda: frames.extend(reader.frames(0.5)) or [(1, 70), (3, b"\x09")] in frames, timeout=10)
        # no sequence numbers: the box closes the connection on one it does not expect
        assert all(field != 2 for frame in frames for field, _ in frame)
    finally:
        sock.close()


def test_remote_control_through_mqtt(box, box_id, start):
    # Home Assistant: buttons, volume and play tag on the MQTT device of the box, and its state
    broker = MqttBroker()
    sock = None
    status = struct.pack("<9I", 2, 0, 0, 0, 3, 0, 5 | (15 << 8), 0, 0)
    try:
        box.rtnl(cfw.record(cfw.FUNC_STATUS, status, **start.next()))
        set_setting("mqtt.hostname", "127.0.0.1")
        set_setting("mqtt.port", broker.port)
        set_setting("mqtt.enabled", True)
        pause = f"/box/{box_id}/CfwPause/set".lower()
        wait_until(lambda: any(t.lower().endswith(pause) for t in list(broker.subscribed)), timeout=30)
        base = next(t for t in list(broker.subscribed) if t.lower().endswith(pause))[: -len("/CfwPause/set")]
        # the discovery of every box known so far comes first: as long as the subscription above
        wait_until(lambda: any("CfwVolume" in t and t.endswith("/config") for t in list(broker.published)), timeout=30)

        sock = box.rtnl(cfw.hello(BUILD, CAPS_ALL, **start.next()), keep_open=True)
        reader = cfw.FrameReader(sock)
        broker.publish(base + "/CfwPause/set", "PRESS")
        broker.publish(base + "/CfwVolume/set", "11")
        frames = []
        wait_until(lambda: frames.extend(reader.frames(0.5)) or (any((1, 65) in f for f in frames) and [(1, 70), (3, b"\x0b")] in frames), timeout=10)

        box.rtnl(cfw.record(cfw.FUNC_STATUS, status, **start.next()))
        wait_until(lambda: broker.value(base + "/CfwState") == "playing")
        assert broker.value(base + "/CfwChapter") == "3" and broker.value(base + "/CfwVolume") == "5"
    finally:
        set_setting("mqtt.enabled", False)
        reset_setting("mqtt.hostname")
        reset_setting("mqtt.port")
        if sock:
            sock.close()
        broker.close()


def test_update_check_now_without_assignment(box, box_id, start):
    # automatic delivery: "now" without a build only starts the check and keeps the assignment as it is
    sock = box.rtnl(cfw.hello(BUILD, CAPS_ALL, **start.next()), keep_open=True)
    try:
        reader = cfw.FrameReader(sock)
        status, text = api("POST", f"/api/cfw/deliver?overlay={box_id}", {"now": True})
        assert status == 200, text
        frames = []
        wait_until(lambda: frames.extend(reader.frames(0.5)) or any((1, 73) in frame for frame in frames), timeout=10)
        assert box_entry(box)["update"]["target"] == 0
    finally:
        sock.close()


def test_remote_command_after_a_silent_minute(box, box_id, start):
    # the box logs only on events; its log connection must outlast the server's 60 s request timeout
    sock = box.rtnl(cfw.hello(BUILD, CAPS_ALL, **start.next()), keep_open=True)
    try:
        reader = cfw.FrameReader(sock)
        frames = []
        deadline = time.time() + 70
        while time.time() < deadline:
            frames.extend(reader.frames(1))
        status, text = api("POST", f"/api/cfw/remote?overlay={box_id}", {"command": "volume", "volume": 7})
        assert status == 200, text
        wait_until(lambda: frames.extend(reader.frames(0.5)) or [(1, 70), (3, b"\x07")] in frames, timeout=10)
    finally:
        sock.close()


def test_remote_result_and_status(box, box_id, start):
    status = struct.pack("<9I", 2, 0xDEADBEEF, 0xE0040350, 0x6AB13B80, 2, 120, 6 | (15 << 8), 3900 | (1 << 31), 0b001)
    box.rtnl(cfw.record(cfw.FUNC_REMOTE_RESULT, struct.pack("<III", 72, 0, 0), **start.next()),
             cfw.record(cfw.FUNC_STATUS, status, **start.next()))
    wait_until(lambda: "status" in api_json("GET", f"/api/cfw/status?overlay={box_id}")[1])
    data = api_json("GET", f"/api/cfw/status?overlay={box_id}")[1]
    assert data["status"]["state"] == "playing" and data["status"]["ruid"] == FIGURE_RUID
    assert data["status"]["volume"] == 6 and data["status"]["limit"] == 15 and data["status"]["charging"] is True
    assert data["status"]["locks"] == {"slap": True, "tilt": False, "volume": False}
    assert data["lastResult"]["command"] == 72 and data["lastResult"]["result"] == 0


def test_battery_report_shown_and_logged(box, box_id, start):
    later = start.next()
    later["uptime"] += 120000  # past the first minute of a start, when the voltage is still near rest
    box.rtnl(cfw.record(cfw.FUNC_BATTERY, cfw.battery(3712, station=True, reason=0, adc=920), **start.next()),
             cfw.record(cfw.FUNC_BATTERY, cfw.battery(3650, low=True, state=2, step=6, adc=905), **later))

    def battery():
        entry = next(b for b in api_json("GET", "/api/cfw/boxes")[1]["boxes"] if b["id"] == box_id)
        return entry.get("battery")

    wait_until(lambda: battery() is not None and battery()["mv"] == 3650)
    assert battery()["low"] is True and battery()["station"] is False and battery()["reason"] == 1
    status, text = api("GET", f"/api/cfw/battery?overlay={box_id}")
    assert status == 200, text
    lines = text.strip().split("\n")
    assert lines[0].startswith("time,mv,station,low,critical,implausible,reason,state,step")
    assert lines[1].split(",")[1:7] == ["3712", "1", "0", "0", "0", "0"] and lines[1].split(",")[10] == "920"
    assert lines[2].split(",")[1:10] == ["3650", "0", "1", "0", "0", "1", "2", "6", "0"]
    # the charge: none on the charger; while playing at step 6 the play drop of that volume (30 mV
    # until learned) is added, 3680 mV idle is 23 % on the default curve
    assert battery()["percent"] == 23 and battery()["learned"] is False and "remainingMin" not in battery()
    sandbox = os.environ.get("TC_SANDBOX")
    if sandbox:
        model = json.load(open(os.path.join(sandbox, "config", "cfw", "battery", f"{box_id}.model.json")))
        assert model["version"] == 1 and model["cycle"]["active"] is True and model["last"]["station"] is False
        # the last report is kept with the box state: shown again after a restart
        state = json.load(open(os.path.join(sandbox, "config", "cfw", "boxes", f"{box_id}.json")))
        assert state["battery"][0] == 3650 and state["batteryResult"]["percent"] == 23


def test_tag_record_names_the_tonie(box, box_id, start):
    """record 8627 of a placed figure: the UID halves as teddyCloud reads them; a low half from 0x80000000 on
    (here 0xFEEDBEEF) must not spoil the high half"""
    box.rtnl(cfw.record(8627, cfw.tag_valid("E0040350FEEDBEEF"), group=15, **start.next()))
    wait_until(lambda: api("GET", f"/api/settings/get/internal.last_ruid?overlay={box_id}")[1] == "efbeedfe500304e0")


def test_firmware_upload_checks_the_image():
    status, result = upload(cfw.slot_image(BUILD + 10, family=b"XXXX"), "beta")
    assert status == 400 and "CFW1" in result["message"]
    broken = bytearray(cfw.slot_image(BUILD + 10))
    broken[5] ^= 1
    assert upload(bytes(broken), "beta")[0] == 400
    status, result = upload(cfw.slot_image(BUILD + 10, code_size=213000), "beta")
    assert status == 400 and "212992" in result["message"]  # the limit of a CC3200 slot image
    status, result = upload(cfw.slot_image(BUILD + 10, code_size=200000), "beta")
    assert status == 200, result
    assert result["image"]["build"] == BUILD + 10 and result["image"]["version"] == "CFW_0.2.0" and result["image"]["channel"] == "beta"


def test_update_manual_and_automatic(box, box_id):
    release = cfw.slot_image(BUILD + 20)
    beta = cfw.slot_image(BUILD + 30)
    assert upload(release, "release")[0] == 200
    assert upload(beta, "beta")[0] == 200
    try:
        # manual (the default): nothing without an assignment
        assert ota(box, BUILD)[0] == 304
        assert api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": BUILD + 20})[0] == 200
        status, _, body = ota(box, BUILD)
        assert status == 200 and body == release
        assert api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": 0})[0] == 200

        # automatic: the newest image of the channel or of a more stable one
        set_setting("cfw.update.mode", 1, box_id)
        set_setting("cfw.update.channel", 2, box_id)
        assert ota(box, BUILD)[2] == beta
        set_setting("cfw.update.channel", 1, box_id)
        assert ota(box, BUILD)[2] == release
    finally:
        api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": 0})


def test_rolled_back_image_is_not_offered_again(box, box_id):
    try:
        # the release image BUILD + 20 was offered last; it starts, then the box runs the old build again
        assert ota(box, BUILD + 20)[0] == 304
        assert ota(box, BUILD)[0] == 304
        assert box_entry(box)["rolledBackBuild"] == BUILD + 20

        # an offered image that never runs counts as rolled back after three starts
        image = cfw.slot_image(BUILD + 40)
        assert upload(image, "release")[0] == 200
        for _ in range(3):
            assert ota(box, BUILD)[2] == image
        assert ota(box, BUILD)[0] == 304
        assert box_entry(box)["rolledBackBuild"] == BUILD + 40

        # a build newer than the offered one is no rollback and ends the one shown
        newer = cfw.slot_image(BUILD + 45)
        assert upload(newer, "release")[0] == 200
        assert ota(box, BUILD)[2] == newer
        assert ota(box, BUILD + 47)[0] == 304
        entry = box_entry(box)
        assert entry["rolledBackBuild"] == 0 and entry["lastOfferedBuild"] == 0
    finally:
        reset_setting("cfw.update.mode", box_id)
        reset_setting("cfw.update.channel", box_id)


def test_original_firmware_box_is_not_offered_an_image(box, box_id):
    other = Box("deadbeefcf02", SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=f"TB/{ORIGINAL_BUILD} SP/1 HW/16")
    try:
        assert other.request("GET", "/v1/time")[0] == 200
        assert api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": BUILD + 30})[0] == 200
        assert api("POST", "/api/cfw/deliver?overlay=deadbeefcf02", {"build": BUILD + 30})[0] == 200
        assert ota(other, ORIGINAL_BUILD)[0] == 304
        # the CFW box gets the image assigned the same way
        assert ota(box, BUILD)[0] == 200
    finally:
        api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": 0})
        api("POST", "/api/cfw/deliver?overlay=deadbeefcf02", {"build": 0})
        other.close()


def test_switched_off_behaves_like_upstream(box, box_id):
    assert api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": BUILD + 30})[0] == 200
    assert ota(box, BUILD)[0] == 200
    set_setting("cfw.enabled", False)
    other = Box("deadbeefcf05", SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=CFW_AGENT, headers={"X-CFW-Build": str(BUILD)})
    try:
        fields = {field for field, _ in freshness(box)}
        assert 101 not in fields and 100 not in fields and {3, 7} <= fields
        assert ota(box, BUILD)[0] == 304
        # the API is gone and a new box leaves no CFW state behind
        assert api("GET", "/api/cfw/boxes")[0] == 404
        assert api("POST", "/api/cfw/deliver?overlay=deadbeefcf05", {"build": 0})[0] == 404
        assert upload(cfw.slot_image(BUILD + 99), "beta")[0] == 404
        assert other.request("GET", "/v1/time")[0] == 200
        assert 101 not in {field for field, _ in freshness(other)}
        boxes = Path(SANDBOX) / "config" / "cfw" / "boxes"
        assert not any("deadbeefcf05" in path.name.lower() for path in boxes.glob("*.json"))
    finally:
        other.close()
        set_setting("cfw.enabled", True)
        api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": 0})


def test_card_build_unknown_to_the_server_gets_the_assigned_image(box, box_id):
    # a build written to the card: not in the library, not yet in a hello, as the update check comes first
    assert api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": BUILD + 30})[0] == 200
    try:
        status, _, body = ota(box, BUILD + 7)
        assert status == 200 and int.from_bytes(body[-176 + 8 : -176 + 12], "little") == BUILD + 30
    finally:
        api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": 0})


def test_event_tag_serves_no_content(box, box_id, start):
    """an event tag keeps its source but plays no content: the CFW box gets none, a box without the CFW gets
    the notice, and every freshness check marks it, so a cached content is not played"""
    ruid, uid = "0A0B0C0D500304E0", 0xE00403500D0C0B0A
    notice = os.path.join(SANDBOX, "data", "www", "cfw", "event-notice-en.taf")
    os.makedirs(os.path.dirname(notice), exist_ok=True)
    with open(os.path.join(os.path.dirname(__file__), "..", "..", "contrib", "data", "www", "cfw", "event-notice-en.taf"), "rb") as f:
        expected = f.read()
    with open(notice, "wb") as f:
        f.write(expected)
    other = Box("deadbeefcf04", SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=f"TB/{ORIGINAL_BUILD} SP/1 HW/16")
    event = {"actions": [{"action": 1, "mode": 0, "value": 3}]}
    try:
        assert other.request("GET", "/v1/time")[0] == 200
        set_setting("cfw.event_notice_language", 1)
        assert api("POST", f"/api/cfw/tag?ruid={ruid}", {"kind": "event", "event": event})[0] == 200
        status, _, body = other.request("GET", f"/v1/content/{ruid}")
        assert status == 200 and body == expected
        box.rtnl(cfw.hello(BUILD, CAPS_ALL, **start.next()))
        assert box.request("GET", f"/v1/content/{ruid}")[0] == 404
        status, _, answer = other.request("POST", "/v1/freshness-check", cfw.freshness_request(uid, 0x6AB13B80))
        assert status == 200 and (1, struct.pack("<Q", uid)) in cfw.fields(answer)
        tag = api_json("GET", f"/api/getTagIndex")[1]["tags"]
        entry = next(t for t in tag if t["ruid"].upper() == ruid)
        assert entry["cfwEvent"] is True and entry["sourceInfo"]["picture"] == "/img_cfw_event.png"
    finally:
        api("POST", f"/api/cfw/tag?ruid={ruid}", {"kind": "none"})
        reset_setting("cfw.event_notice_language")
        other.close()


def test_setup_page_as_item_7(box):
    page = b"<html>x</html"
    path = os.path.join(SANDBOX, "data", "firmware", "cfw", "default.htm")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(page)
    try:
        status, _, body = box.request("GET", "/v1/ota/7?cv=0")
        assert status == 200 and body == page
        assert box.request("GET", "/v1/ota/7?cv=913657113")[0] == 304  # the box has this page
        # without X-CFW-Build it is a request of the original firmware: not answered with the page
        original = Box(box.mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=CFW_AGENT)
        try:
            status, _, body = original.request("GET", "/v1/ota/7?cv=0")
            assert body != page
        finally:
            original.close()
        set_setting("cfw.setup_page_update", False)
        assert box.request("GET", "/v1/ota/7?cv=0")[0] == 304
    finally:
        reset_setting("cfw.setup_page_update")
        os.remove(path)


def test_settings_index():
    options = api_json("GET", "/api/settings/getIndex?nolevel=true")[1]["options"]
    led = next(o for o in options if o["ID"] == "toniebox.led")
    assert led["values"] == [{"value": 0, "label": "On"}, {"value": 1, "label": "Off"}, {"value": 2, "label": "Dimmed"}]
    # group titles only on request: older web UIs do not know them
    assert not any(o["type"] == "desc" for o in options)
    grouped = api_json("GET", "/api/settings/getIndex?nolevel=true&groups=true")[1]["options"]
    group = next(o for o in grouped if o["ID"] == "cfw.box")
    assert group["type"] == "desc" and group["label"] == "Custom firmware functions"


def test_github_needs_a_repository():
    status, result = api_json("POST", "/api/cfw/firmware/github")
    assert status == 502 and "repository" in result["message"]


def test_cloud_gets_the_user_agent_of_the_original_firmware(box, box_id, start):
    """the CFW box itself sends the User-Agent of the original firmware,
    which teddyCloud passes on unchanged; its X-CFW-Build header stays with teddyCloud"""
    send_hello(box, start)
    cloud = FakeCloud(SANDBOX)
    try:
        set_setting("cloud.remote_hostname", "localhost")
        set_setting("cloud.remote_port", cloud.port)
        set_setting("cloud.enabled", True)
        freshness(box)
        wait_until(lambda: any(path == "/v1/freshness-check" for _, path, _, _ in cloud.requests))
        headers = next(h for _, path, h, _ in cloud.requests if path == "/v1/freshness-check")
        assert headers["User-Agent"] == CFW_AGENT
        assert not any(name.lower() == "x-cfw-build" for name in headers)
    finally:
        set_setting("cloud.enabled", False)
        for name in ("cloud.remote_hostname", "cloud.remote_port"):
            reset_setting(name)
        cloud.close()


def test_original_firmware_3_4_is_not_the_cfw(box, box_id, start):
    """the same User-Agent without X-CFW-Build is the original firmware 3.4.0: no image for it, also when one is
    assigned (a box that fell back to the original firmware must not install the CFW from flash)"""
    original = Box(box.mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=CFW_AGENT)
    assert upload(cfw.slot_image(BUILD + 33), "alpha")[0] == 200  # one no earlier test offered (not rolled back)
    assert api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": BUILD + 33})[0] == 200
    try:
        assert original.request("GET", "/v1/time")[0] == 200
        entry = box_entry(box)
        assert not entry["isCfw"] and entry["version"] == OFW_BUILD
        assert ota(original, OFW_BUILD)[0] == 304
        status, _, body = ota(box, BUILD)
        assert status == 200 and int.from_bytes(body[-176 + 8 : -176 + 12], "little") == BUILD + 33
        assert box_entry(box)["isCfw"]
    finally:
        api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": 0})
        original.close()
    send_hello(box, start)


def test_original_firmware_start_is_recognised(box, box_id, start):
    original = Box(box.mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=f"TB/{ORIGINAL_BUILD} SP/1 HW/16")
    try:
        assert original.request("GET", "/v1/time")[0] == 200
        wait_until(lambda: not box_entry(box)["isCfw"])
        assert box_entry(box)["version"] == ORIGINAL_BUILD
    finally:
        original.close()
    send_hello(box, start)
    assert box_entry(box)["isCfw"]


def test_only_the_header_tells_the_cfw(box, box_id, start):
    """only X-CFW-Build tells that a request comes from the CFW; without it the request is the
    original firmware's, even with a build the box reported in a hello as the CFW's"""
    box.rtnl(cfw.hello(BUILD + 3, CAPS_ALL, **start.next()))
    wait_until(lambda: box_entry(box)["version"] == BUILD + 3)
    plain = Box(box.mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=f"TB/{BUILD + 3} SP/1 HW/16")
    assert api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": BUILD + 30})[0] == 200
    try:
        assert plain.request("GET", "/v1/time")[0] == 200
        entry = box_entry(box)
        assert not entry["isCfw"] and entry["version"] == BUILD + 3
        assert ota(plain, BUILD + 3)[0] == 304
    finally:
        api("POST", f"/api/cfw/deliver?overlay={box_id}", {"build": 0})
        plain.close()
    send_hello(box, start)
    assert box_entry(box)["isCfw"]


ESP32_OFW_AGENT = "toniebox-esp32-eu/v5.233.0"


def test_esp32_image_upload():
    status, result = upload(cfw.esp32_image(BUILD + 50, digest_text=False), "beta")
    assert status == 200, result
    assert result["image"]["build"] == BUILD + 50 and result["image"]["platform"] == "esp32" and result["image"]["version"] == "CFW_0.3.0"
    # an image without build date and time is refused
    undated = bytearray(cfw.esp32_image(BUILD + 53, digest_text=False))
    undated[32 + 80: 32 + 112] = bytes(32)
    status, result = upload(cfw.esp32_fix(bytes(undated)), "beta")
    assert status == 400 and "date and time" in result["message"]
    # the original firmware's project: kept as the original firmware, outside the channels
    status, result = upload(cfw.esp32_image(BUILD + 51, project=b"toniebox-esp32-eu"), "beta")
    assert status == 200 and result["image"]["original"] and result["image"]["channel"] == "none"
    # edit and delete name the platform of the image
    assert api("POST", "/api/cfw/firmware/delete", {"build": result["image"]["build"]})[0] == 404
    assert api("POST", "/api/cfw/firmware/delete", {"build": result["image"]["build"], "platform": "esp32"})[0] == 200
    broken = bytearray(cfw.esp32_image(BUILD + 51))
    broken[100] ^= 1
    assert upload(bytes(broken), "beta")[0] == 400


def test_esp32_install_through_the_original_firmware():
    """the image assigned to an ESP32 box with the original firmware, once, with the
    server the box asked in its server block"""
    esp = Box("deadbeefe301", SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=ESP32_OFW_AGENT)
    try:
        assert esp.request("GET", "/v1/time")[0] == 200
        entry = box_entry(esp)
        assert entry["platform"] == "esp32" and not entry["isCfw"]
        # an image of the other platform is not one the box can take
        assert upload(cfw.slot_image(BUILD + 35), "beta")[0] == 200
        assert api("POST", f"/api/cfw/deliver?overlay={entry['id']}", {"build": BUILD + 35})[0] == 404
        assert api("POST", f"/api/cfw/deliver?overlay={entry['id']}", {"build": BUILD + 50})[0] == 200
        status, _, body = ota(esp, 1701777214)
        assert status == 200
        image, text = body[:-64], body[-64:]
        assert hashlib.sha256(image).hexdigest().encode() == text
        assert cfw.esp32_server_block(body) == (BASE.hostname, HTTPS_API_PORT)
        assert hashlib.sha256(image[:-32]).digest() == image[-32:]
        assert box_entry(esp)["esp32Delivered"] == BUILD + 50
        # only once: the box asks again (the image did not stay) and gets nothing, the build counts as rolled back
        assert ota(esp, 1701777214)[0] == 304
        assert box_entry(esp)["rolledBackBuild"] == BUILD + 50
        # assigned again: delivered again
        assert api("POST", f"/api/cfw/deliver?overlay={entry['id']}", {"build": BUILD + 50})[0] == 200
        set_setting("cfw.update.allow_rolled_back", True, entry["id"])
        assert ota(esp, 1701777214)[0] == 200
    finally:
        api("POST", "/api/cfw/deliver?overlay=deadbeefe301", {"build": 0})
        reset_setting("cfw.update.allow_rolled_back", "deadbeefe301")
        esp.close()


def test_esp32_platform_survives_a_settings_reload():
    """the platform of an ESP32 box that has not asked since the settings were written and reloaded (which
    resets the platform taken from the User-Agent) stays ESP32: its images stay assignable"""
    esp = Box("deadbeefe303", SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=ESP32_OFW_AGENT)
    try:
        assert esp.request("GET", "/v1/time")[0] == 200
        assert box_entry(esp)["platform"] == "esp32"
        set_setting("cfw.update.allow_rolled_back", True, "deadbeefe303")
        assert box_entry(esp)["platform"] == "esp32"
        assert upload(cfw.esp32_image(BUILD + 54, digest_text=False), "beta")[0] == 200
        assert api("POST", "/api/cfw/deliver?overlay=deadbeefe303", {"build": BUILD + 54})[0] == 200
    finally:
        api("POST", "/api/cfw/deliver?overlay=deadbeefe303", {"build": 0})
        reset_setting("cfw.update.allow_rolled_back", "deadbeefe303")
        esp.close()


def test_esp32_cfw_box_gets_only_esp32_images():
    esp = Box("deadbeefe302", SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=ESP32_OFW_AGENT, headers={"X-CFW-Build": str(BUILD + 50)})
    try:
        assert esp.request("GET", "/v1/time")[0] == 200
        newer = cfw.esp32_image(BUILD + 60)
        assert upload(newer, "release")[0] == 200
        set_setting("cfw.update.mode", 1, "deadbeefe302")
        set_setting("cfw.update.channel", 3, "deadbeefe302")
        status, _, body = ota(esp, BUILD + 50)
        assert status == 200 and body == newer
    finally:
        reset_setting("cfw.update.mode", "deadbeefe302")
        reset_setting("cfw.update.channel", "deadbeefe302")
        esp.close()


def test_esp32_cfw_with_the_original_user_agent():
    """the ESP32 CFW sends the User-Agent of its original firmware and its build in X-CFW-Build: it is the CFW
    and gets CFW images, not the installation for the original firmware; the same User-Agent without the header is
    the original firmware"""
    mac = "deadbeefe305"
    esp = Box(mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=ESP32_OFW_AGENT, headers={"X-CFW-Build": str(BUILD + 50)})
    ofw = Box(mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=ESP32_OFW_AGENT)
    try:
        assert esp.request("GET", "/v1/time")[0] == 200
        entry = box_entry(esp)
        assert entry["isCfw"] and entry["version"] == BUILD + 50
        newer = cfw.esp32_image(BUILD + 70)
        assert upload(newer, "release")[0] == 200
        set_setting("cfw.update.mode", 1, mac)
        set_setting("cfw.update.channel", 3, mac)
        status, _, body = ota(esp, BUILD + 50)
        assert status == 200 and body == newer
        assert ofw.request("GET", "/v1/time")[0] == 200
        assert not box_entry(esp)["isCfw"]
    finally:
        reset_setting("cfw.update.mode", mac)
        reset_setting("cfw.update.channel", mac)
        esp.close()
        ofw.close()


def original_esp32_build(image):
    """the key of an original image in the library: from the SHA-256 of the image as uploaded (before the
    patches, so another upload of it with other patches replaces it), below every CFW build number"""
    return 1 + int.from_bytes(hashlib.sha256(image[:-32]).digest()[:4], "little") % 1000000000


def test_esp32_original_firmware_upload_with_patches():
    """the original firmware of the ESP32 box from a flash dump (the slot with the highest version),
    with teddyCloud's host patch, kept out of the channels"""
    older = cfw.esp32_original_image(version=b"v5.99.9", code_size=3000)
    newest = cfw.esp32_original_image()
    dump = cfw.esp32_flash_dump([older, cfw.esp32_image(BUILD + 50, digest_text=False), newest])
    # a host longer than the shortest vendor host would overwrite what follows
    status, result = upload_query(dump, "hostname=203.0.113.123")
    assert status == 400 and "at most 12" in result["message"]
    # patches are for the original firmware only
    assert upload_query(cfw.esp32_image(BUILD + 52, digest_text=False), "hostname=tc.local")[0] == 400
    # the port patch needs the connect function of a real original image
    assert upload_query(newest, "port=8443")[0] == 400
    status, result = upload_query(dump, "hostname=tc.local&channel=release")
    assert status == 200, result
    image = result["image"]
    build = image["build"]
    assert build < 1000000001 and image["original"] and image["platform"] == "esp32"
    assert image["version"] == "v5.233.1" and image["channel"] == "none" and image["patches"] == "host tc.local (2 times)"
    # the stored body: patched, checksum, hash and digest text right
    status, data = api_json("GET", "/api/cfw/firmware")
    assert any(entry["build"] == build and entry["original"] for entry in data["images"])
    path = Path(SANDBOX) / "data" / "firmware" / "cfw" / f"esp32-{build}.bin"
    body = path.read_bytes()
    stored, text = body[:-64], body[-64:]
    assert hashlib.sha256(stored).hexdigest().encode() == text
    assert hashlib.sha256(stored[:-32]).digest() == stored[-32:]
    assert build == original_esp32_build(newest)
    assert b"https://tc.local\x00" in stored and b"\x00tc.local\x00\x00\x00\x00\x00" in stored and b"tbs.toys" not in stored
    # the edit keeps it out of the channels
    assert api("POST", "/api/cfw/firmware/edit", {"build": build, "platform": "esp32", "channel": "release", "notes": "back"})[0] == 200
    assert next(entry for entry in api_json("GET", "/api/cfw/firmware")[1]["images"] if entry["build"] == build)["channel"] == "none"


def test_esp32_return_to_the_original_firmware():
    """the original image assigned to an ESP32 box with the custom firmware is delivered as item 3,
    never automatically; when the box asks as the original firmware afterwards, the assignment goes"""
    mac = "deadbeefe303"
    esp = Box(mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=ESP32_OFW_AGENT, headers={"X-CFW-Build": str(BUILD + 50)})
    ofw = None
    try:
        status, result = upload_query(cfw.esp32_original_image(), "hostname=tc.local")
        assert status == 200
        original = result["image"]["build"]
        assert esp.request("GET", "/v1/time")[0] == 200
        # automatic delivery never offers the original firmware
        set_setting("cfw.update.mode", 1, mac)
        set_setting("cfw.update.channel", 3, mac)
        status, _, body = ota(esp, BUILD + 50)
        assert status != 200 or b"toniebox-esp32-eu" not in body
        entry = box_entry(esp)
        assert api("POST", f"/api/cfw/deliver?overlay={entry['id']}", {"build": original})[0] == 200
        status, _, body = ota(esp, BUILD + 50)
        assert status == 200 and b"toniebox-esp32-eu" in body and b"https://tc.local\x00" in body
        assert hashlib.sha256(body[:-64]).hexdigest().encode() == body[-64:]
        esp.close()
        # the box restarted into the original firmware, which runs its update check
        ofw = Box(mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=ESP32_OFW_AGENT)
        assert ofw.request("GET", "/v1/time")[0] == 200
        ota(ofw, 1701777214)
        assert setting_value("cfw.update.target", entry["id"]) == ""
    finally:
        api("POST", f"/api/cfw/deliver?overlay={mac}", {"build": 0})
        reset_setting("cfw.update.mode", mac)
        reset_setting("cfw.update.channel", mac)
        esp.close()
        if ofw is not None:
            ofw.close()


def library_entry(build, platform="cc3200"):
    status, data = api_json("GET", "/api/cfw/firmware")
    assert status == 200
    return next(entry for entry in data["images"] if entry["build"] == build and entry["platform"] == platform)


def test_release_package_with_setup_page():
    """a release package brings an image per platform and the setup page; the library tells when the
    page differs from the one of the older image, and item 7 serves the page of the firmware the box runs"""
    assert cfw.page_version(b"<html>x</html") == 913657113  # as the firmware computes it
    page1 = b"<html>page one</html>"
    page2 = b'<html><head><meta name="cfw-page-version" content="CFW_9.9.9"></head>page two</html>'
    readme = b"# Release\n"
    first, second, third = BUILD + 300, BUILD + 400, BUILD + 500
    packages = [
        # built from one commit, both images carry the same build number
        # the SD bootloader, its preloader and the card tree travel with the package but are no images
        {"cc3200/ng-cfw.bin": cfw.slot_image(first), "cc3200/ngbootloader.bin": bytes(range(256)) * 64,
         "cc3200/flash/sys/mcuimg.bin": bytes(range(256)) * 32, "cc3200/card/revvox/boot/ng-cfw1.bin": cfw.slot_image(first),
         "cc3200/card/revvox/boot/ngbootloader.bin": bytes(range(256)) * 64, "cc3200/card/cfw/setup.htm": b"<html>card copy</html>",
         "esp32/toniebox-cfw-esp32.bin": cfw.esp32_image(first), "setup.htm": page1, "README.md": readme},
        {"cc3200/ng-cfw.bin": cfw.slot_image(second), "setup.htm": page1},
        {"cc3200/ng-cfw.bin": cfw.slot_image(third), "setup.htm": page2},
    ]
    builds = [(first, "cc3200"), (first, "esp32"), (second, "cc3200"), (third, "cc3200")]
    mac = "deadbeefc031"
    runner = None
    try:
        package = cfw.release_package(packages[0])
        status, result = upload(package, "beta")
        assert status == 200 and sorted((i["build"], i["platform"]) for i in result["images"]) == [(first, "cc3200"), (first, "esp32")]
        assert result["message"] == "OK", result["message"]
        # kept for the installation in the browser, beside the CC3200 image only
        assert library_entry(first, "cc3200")["package"] and not library_entry(first, "esp32")["package"]
        status, body = api_bytes("GET", f"/api/cfw/firmware/package?build={first}")
        assert status == 200 and body == package
        for platform, version in (("cc3200", "CFW_0.2.0"), ("esp32", "CFW_0.3.0")):
            entry = library_entry(first, platform)
            # a page without its own version gets the one of the image it came with
            assert entry["page"] == cfw.page_version(page1) and entry["pageNew"] and entry["pageLabel"] == version
        assert upload(cfw.release_package(packages[1]), "beta")[0] == 200
        assert not library_entry(second)["package"]
        assert api_bytes("GET", f"/api/cfw/firmware/package?build={second}")[0] == 404
        assert library_entry(second)["page"] == cfw.page_version(page1) and not library_entry(second)["pageNew"]
        assert upload(cfw.release_package(packages[2]), "beta")[0] == 200
        assert library_entry(third)["page"] == cfw.page_version(page2) and library_entry(third)["pageNew"]
        assert library_entry(third)["pageLabel"] == "CFW_9.9.9"

        # item 7: the page of the box's firmware; the box's own value is remembered
        runner = Box(mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=CFW_AGENT, headers={"X-CFW-Build": str(third)})
        assert runner.request("GET", "/v1/time")[0] == 200
        status, _, body = runner.request("GET", f"/v1/ota/7?cv={cfw.page_version(page1)}")
        assert status == 200 and body == page2
        # the box installs it without a restart: from now on it counts as having it, not only from its next start
        assert box_entry(runner)["pageVersion"] == cfw.page_version(page2)
        assert runner.request("GET", f"/v1/ota/7?cv={cfw.page_version(page2)}")[0] == 304
        assert box_entry(runner)["pageVersion"] == cfw.page_version(page2)

        # a page alone: for one image, or as the default page of the images without one
        page3 = b'<!DOCTYPE html><html><head><meta name="cfw-page-version" content="CFW_9.9.10"></head></html>'
        status, result = upload_query(page3, f"build={second}&platform=cc3200")
        assert status == 200 and result["page"]["label"] == "CFW_9.9.10"
        assert library_entry(second)["page"] == cfw.page_version(page3) and library_entry(second)["pageNew"]
        status, result = upload_query(b"<html>default</html>", "")
        assert status == 200 and result["page"]["label"].startswith("#")
        assert api_json("GET", "/api/cfw/firmware")[1]["defaultPage"]["page"] == cfw.page_version(b"<html>default</html>")
        # kept in the firmware directory (a volume of the Docker image), not served as a static file
        assert (Path(SANDBOX) / "data" / "firmware" / "cfw" / "default.htm").read_bytes() == b"<html>default</html>"
        assert not (Path(SANDBOX) / "data" / "www" / "cfw" / "setup.htm").exists()
        assert upload_query(page3, "build=1&platform=cc3200")[0] == 400

        # a package packed again with compression is refused with a reason
        status, result = upload(cfw.release_package(packages[1], compressed=True), "beta")
        assert status == 400 and "compressed" in result["message"]
    finally:
        if runner is not None:
            runner.close()
        for build, platform in builds:
            api("POST", "/api/cfw/firmware/delete", {"build": build, "platform": platform})
        default_page = os.path.join(SANDBOX, "data", "firmware", "cfw", "default.htm")
        if os.path.exists(default_page):
            os.remove(default_page)


def test_setup_page_needs_a_firmware():
    """the page has its own version and names the firmware it needs at
    least (cfw-page-requires); item 7 does not serve it to a box whose firmware is older"""
    def page(version, needs):
        return f'<html><head><meta name="cfw-page-version" content="{version}"><meta name="cfw-page-requires" content="{needs}"></head></html>'.encode()

    fits, too_new = page("1.0", "CFW_0.1.6"), page("2.0", "CFW_9.9.9")
    first, second = BUILD + 900, BUILD + 1000
    mac = "deadbeefc033"
    runner = None
    try:
        for build, p in ((first, fits), (second, too_new)):
            assert upload(cfw.release_package({"cc3200/ng-cfw.bin": cfw.slot_image(build), "setup.htm": p}), "alpha")[0] == 200
        assert library_entry(first)["pageLabel"] == "1.0" and library_entry(first)["pageRequires"] == "CFW_0.1.6"
        assert library_entry(second)["pageLabel"] == "2.0" and library_entry(second)["pageRequires"] == "CFW_9.9.9"

        runner = Box(mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=CFW_AGENT, headers={"X-CFW-Build": str(first)})
        assert runner.request("GET", "/v1/time")[0] == 200
        status, _, body = runner.request("GET", "/v1/ota/7?cv=0")
        assert status == 200 and body == fits
        runner.close()
        # the image's own firmware (CFW_0.2.0) is older than the page asks for: the box keeps its page
        runner = Box(mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=CFW_AGENT, headers={"X-CFW-Build": str(second)})
        assert runner.request("GET", f"/v1/ota/7?cv={cfw.page_version(fits)}")[0] == 304
    finally:
        if runner is not None:
            runner.close()
        for build in (first, second):
            api("POST", "/api/cfw/firmware/delete", {"build": build, "platform": "cc3200"})
