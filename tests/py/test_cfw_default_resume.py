"""
"Global resume by default" (cfw.default_global_resume): every tonie with content gets a profile with global resume,
live content excepted; the user's own settings are left alone and switching the setting off takes the profiles back.

    make test_py TESTS=cfw_default_resume
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
PLAIN_RUID = "11D0C0DE500304E0"  # a tonie with ordinary content
OWN_RUID = "22D0C0DE500304E0"  # a tonie whose settings the user changes
LIVE_RUID = "33D0C0DE500304E0"  # a stream
GLOBAL_RESUME = bytes([0x0D, 1, 1])


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


def tag(ruid):
    status, text = api("GET", f"/api/cfw/tag?ruid={ruid}")
    assert status == 200, text
    return json.loads(text)


def files(box):
    status, _, body = box.request("POST", "/v1/freshness-check", cfw.freshness_request(FIGURE_UID, 0x6AB13B80))
    assert status == 200, body
    return {value[:8].hex().upper(): cfw.tbs_body(value[8:]) for field, value in cfw.fields(body) if field == 100}


@pytest.fixture(scope="module")
def box():
    set_setting("cfw.enabled", True)
    content(PLAIN_RUID, "nocloud=true")
    content(OWN_RUID, "nocloud=true")
    content(LIVE_RUID, "source=" + quote("http://127.0.0.1:9/stream.mp3"))
    b = Box("deadbeefcf31", SANDBOX, BASE.hostname, HTTPS_API_PORT, user_agent=CFW_AGENT, headers={"X-CFW-Build": str(BUILD)})
    assert b.request("GET", "/v1/time")[0] == 200
    b.rtnl(cfw.hello(BUILD, CAPS, uptime=1000, sequence=10))
    time.sleep(0.5)
    yield b
    b.close()
    set_setting("cfw.default_global_resume", False)
    set_setting("cfw.enabled", False)


def test_off_by_default(box):
    assert tag(PLAIN_RUID)["kind"] == "none"
    assert PLAIN_RUID not in files(box)


def test_on_gives_tonies_global_resume_but_not_live_ones(box):
    set_setting("cfw.default_global_resume", True)
    delivered = files(box)
    assert delivered.get(PLAIN_RUID) == GLOBAL_RESUME
    assert delivered.get(OWN_RUID) == GLOBAL_RESUME
    assert LIVE_RUID not in delivered
    assert tag(PLAIN_RUID)["profile"]["globalResume"] is True
    assert tag(LIVE_RUID)["kind"] == "none"


def test_own_settings_are_kept(box):
    status, text = api("POST", f"/api/cfw/tag?ruid={OWN_RUID}", {"kind": "profile", "profile": {"shuffle": True}})
    assert status == 200, text
    set_setting("cfw.default_global_resume", False)
    set_setting("cfw.default_global_resume", True)
    profile = tag(OWN_RUID)["profile"]
    assert profile.get("shuffle") is True and not profile.get("globalResume")


def test_off_takes_the_default_back(box):
    files(box)
    set_setting("cfw.default_global_resume", False)
    delivered = files(box)
    assert delivered.get(PLAIN_RUID) == b""  # an empty profile replaces the settings on the box
    assert tag(PLAIN_RUID)["kind"] == "none"
    assert tag(OWN_RUID)["profile"].get("shuffle") is True
