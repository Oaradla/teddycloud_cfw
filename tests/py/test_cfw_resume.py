"""
Global resume of the custom firmware: two simulated boxes hand a figure over through the server's positions,
with the revisions, a conflict decided in the API and the wait for the box the figure still plays on.

    make test_py TESTS=cfw_resume
"""

import http.client
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import cfw  # noqa: E402
from sim.box import Box  # noqa: E402

BASE = urlparse(os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80"))
SANDBOX = os.environ.get("TC_SANDBOX")
HTTPS_API_PORT = int(os.environ.get("TEDDYCLOUD_HTTPS_API_PORT", "0"))

pytestmark = pytest.mark.skipif(not SANDBOX or not HTTPS_API_PORT, reason="needs the sandbox from tests/py/with_server.sh")

BUILD = 1791210720
CAPS = 0x7FFF
FIGURE_UID = 0xE0040350DEADBEEF
FIGURE_RUID = "EFBEADDE500304E0"
CFW_AGENT = "TB/1779199517 SP/1 HW/16"


def api(method, path, body=None):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=30)
    try:
        conn.request(method, path, json.dumps(body) if isinstance(body, dict) else body)
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def api_json(method, path, body=None):
    status, text = api(method, path, body)
    return status, json.loads(text)


def set_setting(name, value):
    assert api("POST", f"/api/settings/set/{name}", str(value).lower())[0] == 200
    assert api("GET", "/api/triggerWriteConfig")[0] == 200
    time.sleep(1.2)


def wait_until(condition, timeout=5.0):
    deadline = time.time() + timeout
    while not condition():
        assert time.time() < deadline, "condition not met in time"
        time.sleep(0.1)


class LogBox:
    """a CFW box with an open log connection after its hello"""

    def __init__(self, mac):
        self.box = Box(mac, SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=CFW_AGENT, headers={"X-CFW-Build": str(BUILD)})
        assert self.box.request("GET", "/v1/time")[0] == 200
        self.uptime, self.sequence = 1000, 10
        self.sock = self.box.rtnl(cfw.hello(BUILD, CAPS, self.uptime, self.sequence), keep_open=True)
        self.reader = cfw.FrameReader(self.sock)

    def record(self, function, payload):
        self.uptime += 100
        self.sequence += 1
        return cfw.record(function, payload, uptime=self.uptime, sequence=self.sequence)

    def send(self, function, payload):
        self.sock.sendall(self.record(function, payload))

    def report(self, position, base=0, listened=0, reason=0):
        self.send(cfw.FUNC_POSITION, cfw.position(FIGURE_UID, position, base, listened, reason))

    def query(self, position=0, base=0, listened=0):
        self.send(cfw.FUNC_POSITION_QUERY, cfw.position(FIGURE_UID, position, base, listened, reason=4))
        frames = []
        wait_until(lambda: frames.extend(self.reader.frames(0.3)) or any((1, cfw.CMD_POSITION) in f for f in frames), timeout=8)
        frame = next(f for f in frames if (1, cfw.CMD_POSITION) in f)
        return cfw.position_answer(dict(frame)[3])

    def close(self):
        self.sock.close()
        self.box.close()


@pytest.fixture(scope="module", autouse=True)
def cfw_enabled():
    set_setting("cfw.enabled", True)
    yield
    set_setting("cfw.enabled", False)


@pytest.fixture(scope="module")
def boxes():
    a, b = LogBox("deadbeefcf21"), LogBox("deadbeefcf22")
    status, text = api("POST", f"/api/cfw/tag?ruid={FIGURE_RUID}", {"kind": "profile", "profile": {"globalResume": True}})
    assert status == 200, text
    yield a, b
    a.close()
    b.close()


def resume():
    return api_json("GET", f"/api/cfw/tag?ruid={FIGURE_RUID}")[1]["resume"]


def test_profile_holds_global_resume(boxes):
    data = api_json("GET", f"/api/cfw/tag?ruid={FIGURE_RUID}")[1]
    assert data["profile"]["globalResume"] is True


def test_position_handed_to_the_other_box(boxes):
    a, b = boxes
    a.report(30, base=0, listened=120)
    wait_until(lambda: api("GET", f"/api/cfw/tag?ruid={FIGURE_RUID}")[1].count('"revision":1') > 0)
    assert b.query() == (0, 1, 30)
    assert a.query() == (1, None, None)  # its own position: keep it


def test_diverged_positions_wait_for_a_decision(boxes):
    a, b = boxes
    b.report(300, base=1, listened=900)
    a.report(100, base=1, listened=600)
    wait_until(lambda: resume()["conflict"])
    assert len(resume()["branches"]) == 2
    assert a.query(100, base=1) == (2, None, None)
    branch = next(i for i, p in enumerate(resume()["branches"]) if p["position"] == 300)
    assert api("POST", f"/api/cfw/resume/choose?ruid={FIGURE_RUID}&branch={branch}")[0] == 200
    assert a.query(100, base=1) == (0, 3, 300)
    assert b.query(300, base=1) == (1, None, None)


def test_query_waits_for_the_box_it_plays_on(boxes):
    a, b = boxes
    a.report(310, base=3, listened=40, reason=1)  # a plays it now
    time.sleep(0.5)
    b.send(cfw.FUNC_POSITION_QUERY, cfw.position(FIGURE_UID, 300, base=1, reason=4))
    time.sleep(0.5)
    a.report(320, base=3, listened=60)  # taken off a
    frames = []
    wait_until(lambda: frames.extend(b.reader.frames(0.3)) or any((1, cfw.CMD_POSITION) in f for f in frames), timeout=8)
    frame = next(f for f in frames if (1, cfw.CMD_POSITION) in f)
    assert cfw.position_answer(dict(frame)[3]) == (0, 4, 320)
