"""
Global resume for all tonies (cfw.global_resume): the server delivers every tonie as if global resume were set on
it, unless the tonie has a value of its own; live content is left out, and switching off takes it back.

    make test_py TESTS=cfw_global_resume_all
"""

import http.client
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlparse

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
CFW_AGENT = "TB/1779199517 SP/1 HW/16"
FIGURE_UID = 0xE0040350DEADBEEF
PLAIN_RUID = "11D0C0DE500304E0"
OWN_RUID = "22D0C0DE500304E0"
LIVE_RUID = "33D0C0DE500304E0"
GLOBAL_RESUME = bytes([0x0D, 1, 1])
SHUFFLE = bytes([0x02, 1, 1])


def api(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(BASE.hostname, BASE.port, timeout=30)
    try:
        conn.request(method, path, json.dumps(body) if isinstance(body, dict) else body, headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


def set_setting(name, value):
    assert api("POST", f"/api/settings/set/{name}", str(value).lower())[0] == 200
    assert api("GET", "/api/triggerWriteConfig")[0] == 200
    time.sleep(1.2)


def content(ruid, form):
    status, text = api("POST", f"/content/json/set/{ruid}", form, {"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 200, text


def set_profile(ruid, profile):
    time.sleep(1.1)  # time stamps count seconds: a new file of the same second would be the same file
    status, text = api("POST", f"/api/cfw/tag?ruid={ruid}", {"kind": "profile", "profile": profile})
    assert status == 200, text


def files(box):
    """the settings files of one freshness-check answer, as profile bodies by ruid"""
    status, _, body = box.request("POST", "/v1/freshness-check", cfw.freshness_request(FIGURE_UID, 0x6AB13B80))
    assert status == 200, body
    return {value[:8].hex().upper(): cfw.tbs_body(value[8:]) for field, value in cfw.fields(body) if field == 100}


@pytest.fixture(scope="module")
def box():
    set_setting("cfw.enabled", True)
    content(PLAIN_RUID, "nocloud=true")
    content(OWN_RUID, "nocloud=true")
    content(LIVE_RUID, "source=" + quote("http://127.0.0.1:9/stream.mp3"))
    b = Box("deadbeefcf32", SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=CFW_AGENT, headers={"X-CFW-Build": str(BUILD)})
    assert b.request("GET", "/v1/time")[0] == 200
    b.rtnl(cfw.hello(BUILD, CAPS, uptime=1000, sequence=10))
    time.sleep(0.5)
    yield b
    b.close()
    set_setting("cfw.global_resume", False)
    set_setting("cfw.enabled", False)


def test_off_sends_nothing(box):
    assert PLAIN_RUID not in files(box)


def test_on_gives_every_tonie_global_resume_but_live_ones(box):
    set_setting("cfw.global_resume", True)
    delivered = files(box)
    assert delivered.get(PLAIN_RUID) == GLOBAL_RESUME
    assert delivered.get(LIVE_RUID, b"") == b""
    assert files(box) == {}  # each file once
    tag = json.loads(api("GET", f"/api/cfw/tag?ruid={PLAIN_RUID}")[1])
    assert tag["kind"] == "profile" and tag["profile"]["globalResume"] is None


def test_own_values_come_first(box):
    set_profile(OWN_RUID, {"shuffle": True})
    assert files(box).get(OWN_RUID) == SHUFFLE + GLOBAL_RESUME
    set_profile(OWN_RUID, {"shuffle": True, "globalResume": False})
    assert files(box).get(OWN_RUID) == SHUFFLE + bytes([0x0D, 1, 0])


def test_off_takes_it_back(box):
    set_profile(OWN_RUID, {"shuffle": True})
    files(box)
    set_setting("cfw.global_resume", False)
    delivered = files(box)
    assert delivered.get(PLAIN_RUID) == b""
    assert delivered.get(OWN_RUID) == SHUFFLE
    assert json.loads(api("GET", f"/api/cfw/tag?ruid={PLAIN_RUID}")[1])["kind"] == "none"
