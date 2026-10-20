#!/usr/bin/env python3
"""
Web UI login: users, lockout, trusted proxies, cross-site checks, TOTP 2FA,
sessions and network filters (src/handler_web_auth.c).

    make test_py TESTS=web_auth

The tests share one server. Addresses from outside are simulated with
127.0.0.1 as trusted proxy and X-Forwarded-For; every test that locks an
address uses its own one.
"""

import base64
import hashlib
import hmac
import http.client
import json
import os
import stat
import struct
import time
import urllib.parse

import pytest

BASE_URL = os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80").rstrip("/")
_P = urllib.parse.urlsplit(BASE_URL)
HOST = _P.hostname or "127.0.0.1"
PORT = _P.port or 80
SANDBOX = os.environ.get("TC_SANDBOX")

ADMIN = "admin"
ADMIN_PW = "Correct-Horse-42"


def totp(secret_b32, at=None, step_offset=0):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    counter = int((at or time.time()) // 30) + step_offset
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


class Client:
    """Keeps the session cookie like a browser; sends Sec-Fetch-Site like the web UI."""

    def __init__(self, forwarded_for=None, proto=None):
        self.cookie = None
        self.forwarded_for = forwarded_for
        self.proto = proto
        self.bearer = None

    def request(self, method, path, body=None, headers=None, raw=False):
        h = {"Sec-Fetch-Site": "same-origin"}
        if self.cookie:
            h["Cookie"] = "other=1; tc_web_session=" + self.cookie
        if self.bearer:
            h["Authorization"] = "Bearer " + self.bearer
        if self.forwarded_for:
            h["X-Forwarded-For"] = self.forwarded_for
        if self.proto:
            h["X-Forwarded-Proto"] = self.proto
        if headers:
            h.update(headers)
        data = None
        if body is not None:
            data = body if raw else json.dumps(body)
            h["Content-Type"] = "text/plain" if raw else "application/json"
        conn = http.client.HTTPConnection(HOST, PORT, timeout=20)
        try:
            conn.request(method, path, body=data, headers={k: v for k, v in h.items() if v is not None})
            r = conn.getresponse()
            text = r.read().decode("utf-8", errors="replace")
            hdrs = {k.lower(): v for k, v in r.getheaders()}
            set_cookie = hdrs.get("set-cookie", "")
            if set_cookie.startswith("tc_web_session="):
                value = set_cookie.split(";", 1)[0].split("=", 1)[1]
                self.cookie = value or None
            try:
                payload = json.loads(text) if text else {}
            except ValueError:
                payload = {"_text": text}
            return r.status, payload, hdrs
        finally:
            conn.close()

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body if body is not None else {}, **kw)

    def login(self, username=ADMIN, password=ADMIN_PW):
        return self.post("/api/auth/login", {"username": username, "password": password})


def admin():
    c = Client()
    status, data, _ = c.login()
    assert status == 200 and data.get("ok"), data
    return c


def set_setting(client, name, value):
    if value == "":
        # the API sets no empty values, the default of these settings is empty
        status, _, _ = client.request("POST", "/api/settings/reset/" + name, "", raw=True)
    else:
        status, _, _ = client.request("POST", "/api/settings/set/" + name, str(value).lower() if isinstance(value, bool) else str(value), raw=True)
    assert status == 200
    # written to the config at once: a reload of the config file (after a change of the login
    # settings, for instance) would otherwise drop the value again
    assert client.get("/api/triggerWriteConfig")[0] == 200
    for _ in range(50):
        current = client.get("/api/settings/get/" + name)[1]
        if current == value or (isinstance(current, dict) and current.get("_text", "").strip() == str(value)):
            return
        time.sleep(0.1)
    raise AssertionError("setting %s did not change: %r" % (name, current))


def unlock(client, ip=None, username=None):
    client.post("/api/auth/unlock", {k: v for k, v in (("ip", ip), ("username", username)) if v})


@pytest.fixture(scope="module", autouse=True)
def login_enabled():
    c = Client()
    status, data, _ = c.get("/api/auth/status")
    assert status == 200 and data["enabled"] is False
    assert c.post("/api/auth/users/create", {"username": ADMIN, "password": ADMIN_PW})[0] == 200
    assert c.post("/api/auth/enabled", {"enabled": True})[0] == 200
    a = admin()
    set_setting(a, "web_auth.trusted_proxies", "127.0.0.1")
    yield
    a = admin()
    a.post("/api/auth/enabled", {"enabled": False})


def test_api_needs_login():
    status, data, _ = Client().get("/api/acl/mine")
    assert status == 401 and data["error"] == "unauthorized"
    assert Client().get("/web/")[0] == 200


def test_session_cookie_attributes():
    c = Client()
    status, data, hdrs = c.login()
    assert status == 200
    cookie = hdrs["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert "Secure" not in cookie  # plain HTTP
    assert c.get("/api/acl/mine")[0] == 200
    # page scripts can not get the token from the login response
    assert "token" not in c.login()[1]
    # behind a trusted proxy with https the cookie is Secure and can not be set by sibling domains
    s = Client(forwarded_for="198.51.100.20", proto="https")
    _, _, hdrs = s.login()
    assert hdrs["set-cookie"].startswith("__Host-tc_web_session=") and "Secure" in hdrs["set-cookie"]
    token = hdrs["set-cookie"].split(";", 1)[0].split("=", 1)[1]
    # the __Host- cookie wins over a planted plain one
    status, data, _ = s.get("/api/auth/status", headers={"Cookie": "tc_web_session=%s; __Host-tc_web_session=%s" % ("0" * 64, token)})
    assert data["loggedIn"] is True


def test_security_headers():
    _, _, hdrs = Client().get("/web/")
    assert hdrs.get("x-content-type-options") == "nosniff"
    assert hdrs.get("x-frame-options") == "SAMEORIGIN"
    assert "frame-ancestors 'self'" in hdrs.get("content-security-policy", "")


def test_wrong_password_and_unknown_user_look_the_same():
    c = Client(forwarded_for="198.51.100.30")
    s1, d1, _ = c.login(password="wrong-password-1")
    s2, d2, _ = c.login(username="nobody")
    assert (s1, d1) == (s2, d2) == (401, {"error": "unauthorized", "message": "Invalid username or password"})
    unlock(admin(), ip="198.51.100.30")


def test_password_policy():
    a = admin()
    for pw, err in (("short", "password_too_short"), ("password1", "password_too_short"), ("teddycloud", "password_too_common"),
                    ("aaaaaaaaaaaa", "password_too_common"), ("policyuser", "password_is_username")):
        status, data, _ = a.post("/api/auth/users/create", {"username": "policyuser", "password": pw})
        assert status == 400 and data["error"] == err, (pw, data)


def test_lockout_per_address():
    a = admin()
    attacker = Client(forwarded_for="203.0.113.10")
    for _ in range(5):
        assert attacker.login(password="nope-nope-nope")[0] == 401
    status, data, _ = attacker.login()
    assert status == 429 and data["retryAfter"] > 0
    # other addresses are not affected
    assert Client(forwarded_for="203.0.113.11").login()[0] == 200
    assert Client().login()[0] == 200
    _, events, _ = a.get("/api/auth/events/get")
    assert any(e["ip"] == "203.0.113.10" for e in events["lockedAddresses"])
    assert any(e["type"] == "ip_locked" and e["ip"] == "203.0.113.10" for e in events["events"])
    unlock(a, ip="203.0.113.10")
    assert attacker.login()[0] == 200


def test_forwarded_for_from_untrusted_peer_is_ignored():
    a = admin()
    set_setting(a, "web_auth.trusted_proxies", "10.99.99.99")
    try:
        _, data, _ = Client(forwarded_for="198.51.100.77").get("/api/auth/status", headers={"Cookie": "tc_web_session=" + a.cookie})
        assert data["client"]["ip"] == "127.0.0.1"
        assert data["client"]["lan"] is True
        assert data["client"]["forwardedForIgnored"] is True
    finally:
        set_setting(a, "web_auth.trusted_proxies", "127.0.0.1")
    _, data, _ = Client(forwarded_for="1.1.1.1, 198.51.100.77").get("/api/auth/status", headers={"Cookie": "tc_web_session=" + a.cookie})
    assert data["client"] == {"ip": "198.51.100.77", "lan": False, "secure": False, "viaTrustedProxy": True, "forwardedForIgnored": False}


def test_overlong_forwarded_for_can_not_fake_a_local_address():
    a = admin()
    padding = ", ".join(["192.168.1.10"] * 60)
    _, data, _ = Client(forwarded_for=padding + ", 203.0.113.99").get("/api/auth/status", headers={"Cookie": "tc_web_session=" + a.cookie})
    assert data["client"]["ip"] == "203.0.113.99" and data["client"]["lan"] is False
    # one huge value: the proxy appends its hop to the right end
    _, data, _ = Client(forwarded_for="1" * 700 + ", 203.0.113.98").get("/api/auth/status", headers={"Cookie": "tc_web_session=" + a.cookie})
    assert data["client"]["ip"] == "203.0.113.98"
    _, data, _ = Client(forwarded_for="garbage").get("/api/auth/status", headers={"Cookie": "tc_web_session=" + a.cookie})
    assert data["client"]["ip"] == "unknown" and data["client"]["lan"] is False


def test_account_lockout_from_outside_keeps_lan_working():
    a = admin()
    assert a.post("/api/auth/users/create", {"username": "victim", "password": "Victim-Password-1"})[0] == 200
    for i in range(15):
        Client(forwarded_for="203.0.113.%d" % (100 + i)).login("victim", "guess-%d-xxxxx" % i)
    # correct password from yet another outside address is refused now
    assert Client(forwarded_for="203.0.113.200").login("victim", "Victim-Password-1")[0] == 401
    # but from the LAN it works
    assert Client().login("victim", "Victim-Password-1")[0] == 200
    unlock(a, username="victim")
    assert Client(forwarded_for="203.0.113.201").login("victim", "Victim-Password-1")[0] == 200
    for i in range(15):
        unlock(a, ip="203.0.113.%d" % (100 + i))


def test_lan_only_user():
    a = admin()
    assert a.post("/api/auth/users/create", {"username": "lanuser", "password": "Lan-User-Password", "lanOnly": True})[0] == 200
    assert Client(forwarded_for="198.51.100.40").login("lanuser", "Lan-User-Password")[0] == 401
    assert Client(forwarded_for="192.168.1.40").login("lanuser", "Lan-User-Password")[0] == 200
    unlock(a, ip="198.51.100.40")


def test_cross_site_requests_are_rejected():
    a = admin()
    status, data, _ = a.post("/api/auth/users/create", {"username": "csrf", "password": "Csrf-Password-1"}, headers={"Sec-Fetch-Site": "cross-site"})
    assert status == 403 and data["error"] == "cross_site"
    status, _, _ = a.post("/api/auth/users/create", {"username": "csrf", "password": "Csrf-Password-1"},
                          headers={"Sec-Fetch-Site": None, "Origin": "http://evil.example"})
    assert status == 403
    # a GET of the API from another site as well
    assert a.get("/api/acl/mine", headers={"Sec-Fetch-Site": "same-site"})[0] == 403
    # same origin by Origin header
    assert a.get("/api/acl/mine", headers={"Sec-Fetch-Site": None, "Origin": "http://%s:%d" % (HOST, PORT)})[0] == 200
    # navigation to the web UI from a link is fine
    assert Client().get("/web/", headers={"Sec-Fetch-Site": "cross-site"})[0] == 200
    # a bearer token can not be sent by another site
    b = Client()
    _, data, _ = b.post("/api/auth/login", {"username": ADMIN, "password": ADMIN_PW, "wantToken": True})
    b.cookie = None
    b.bearer = data["token"]
    assert b.get("/api/acl/mine", headers={"Sec-Fetch-Site": "cross-site"})[0] == 200


def test_bearer_token_does_not_fall_back_to_cookie():
    a = admin()
    a.bearer = "0" * 64
    assert a.get("/api/acl/mine")[0] == 401


def test_totp_flow():
    a = admin()
    assert a.post("/api/auth/users/create", {"username": "otp", "password": "Otp-User-Password"})[0] == 200
    c = Client()
    assert c.login("otp", "Otp-User-Password")[0] == 200
    assert c.post("/api/auth/2fa/setup", {"password": "wrong"})[0] == 403
    status, setup, _ = c.post("/api/auth/2fa/setup", {"password": "Otp-User-Password"})
    assert status == 200 and setup["otpauthUri"].startswith("otpauth://totp/TeddyCloud:otp?secret=" + setup["secret"])
    # starting again (reload, new login) keeps the key that may already be in the app
    assert c.post("/api/auth/2fa/setup", {"password": "Otp-User-Password"})[1]["secret"] == setup["secret"]
    assert c.post("/api/auth/2fa/enable", {"code": "000000" if totp(setup["secret"]) != "000000" else "111111"})[0] == 400
    status, enabled, _ = c.post("/api/auth/2fa/enable", {"code": totp(setup["secret"])})
    assert status == 200 and len(enabled["recoveryCodes"]) == 10
    used_step_code = totp(setup["secret"])

    # password alone is no login any more
    d = Client()
    status, step1, _ = d.login("otp", "Otp-User-Password")
    assert status == 200 and step1["ok"] is False and step1["twoFactorRequired"] is True and d.cookie is None
    assert d.get("/api/acl/mine")[0] == 401
    assert d.post("/api/auth/login2fa", {"challenge": step1["challenge"], "code": "123456"})[0] == 401
    # the code used for enabling can not be replayed
    if totp(setup["secret"]) == used_step_code:
        assert d.post("/api/auth/login2fa", {"challenge": step1["challenge"], "code": used_step_code})[0] == 401
        time.sleep(31 - time.time() % 30)
    status, data, _ = d.post("/api/auth/login2fa", {"challenge": step1["challenge"], "code": totp(setup["secret"])})
    assert status == 200 and data["ok"] and d.cookie
    assert d.get("/api/acl/mine")[0] == 200
    # the challenge is used up
    assert Client().post("/api/auth/login2fa", {"challenge": step1["challenge"], "code": totp(setup["secret"])})[0] == 401

    # recovery code, once
    code = enabled["recoveryCodes"][0]
    e = Client()
    _, step1, _ = e.login("otp", "Otp-User-Password")
    status, data, _ = e.post("/api/auth/login2fa", {"challenge": step1["challenge"], "recoveryCode": code.lower()})
    assert status == 200 and data["recoveryCodesLeft"] == 9
    f = Client()
    _, step1, _ = f.login("otp", "Otp-User-Password")
    assert f.post("/api/auth/login2fa", {"challenge": step1["challenge"], "recoveryCode": code})[0] == 401

    # the admin can reset it
    status, data, _ = a.post("/api/auth/users/update", {"username": "otp", "reset2fa": True})
    assert status == 200 and data["user"]["twoFactor"] is False
    assert d.get("/api/acl/mine")[0] == 401  # sessions of the user ended
    unlock(a, ip="127.0.0.1")


def test_totp_codes_can_not_be_guessed_with_the_password():
    a = admin()
    a.post("/api/auth/users/create", {"username": "otpguess", "password": "Otp-Guess-Password"})
    c = Client()
    c.login("otpguess", "Otp-Guess-Password")
    _, setup, _ = c.post("/api/auth/2fa/setup", {"password": "Otp-Guess-Password"})
    c.post("/api/auth/2fa/enable", {"code": totp(setup["secret"])})
    wrong = "000000" if totp(setup["secret"]) != "000000" else "111111"
    # the password is right every time, the wrong codes must still add up
    for i in range(15):
        attacker = Client(forwarded_for="203.0.113.%d" % (20 + i // 4))
        status, step1, _ = attacker.login("otpguess", "Otp-Guess-Password")
        assert status == 200 and "challenge" in step1, (i, status, step1)
        assert attacker.post("/api/auth/login2fa", {"challenge": step1["challenge"], "code": wrong})[0] == 401
    # now even the right password and code from outside do not get in
    late = Client(forwarded_for="203.0.113.30")
    status, step1, _ = late.login("otpguess", "Otp-Guess-Password")
    if status == 200 and "challenge" in step1:
        status = late.post("/api/auth/login2fa", {"challenge": step1["challenge"], "code": totp(setup["secret"], step_offset=1)})[0]
    assert status in (401, 429)
    _, events, _ = a.get("/api/auth/events/get")
    assert any(e["type"] == "account_locked" and e["username"] == "otpguess" for e in events["events"])
    # from the LAN the owner still gets in
    _, step1, _ = Client().login("otpguess", "Otp-Guess-Password")
    assert "challenge" in step1
    for i in range(4):
        unlock(a, ip="203.0.113.%d" % (20 + i))
    unlock(a, ip="203.0.113.30")
    unlock(a, username="otpguess")


def test_confirm_with_password():
    a = admin()
    assert a.post("/api/auth/confirm", {"password": "wrong-password"})[0] == 403
    status, data, _ = a.post("/api/auth/confirm", {"password": ADMIN_PW})
    assert status == 200 and data["validFor"] == 600
    unlock(a, ip="127.0.0.1")


def test_totp_challenge_bound_to_address():
    a = admin()
    a.post("/api/auth/users/create", {"username": "otp2", "password": "Otp2-User-Password"})
    c = Client()
    c.login("otp2", "Otp2-User-Password")
    _, setup, _ = c.post("/api/auth/2fa/setup", {"password": "Otp2-User-Password"})
    c.post("/api/auth/2fa/enable", {"code": totp(setup["secret"])})
    _, step1, _ = Client(forwarded_for="198.51.100.50").login("otp2", "Otp2-User-Password")
    status, _, _ = Client(forwarded_for="198.51.100.51").post("/api/auth/login2fa", {"challenge": step1["challenge"], "code": totp(setup["secret"], step_offset=1)})
    assert status == 401
    unlock(a, ip="198.51.100.51")


def test_required_2fa_restricts_the_session():
    a = admin()
    assert a.post("/api/auth/users/create", {"username": "must2fa", "password": "Must-2fa-Password", "require2fa": True})[0] == 200
    c = Client()
    status, data, _ = c.login("must2fa", "Must-2fa-Password")
    assert status == 200 and data["twoFactorSetupRequired"] is True
    status, data, _ = c.get("/api/acl/mine")
    assert status == 403 and data["error"] == "2fa_setup_required"
    _, st, _ = c.get("/api/auth/status")
    assert st["loggedIn"] is False and st["twoFactorSetupRequired"] is True
    _, setup, _ = c.post("/api/auth/2fa/setup", {"password": "Must-2fa-Password"})
    assert c.post("/api/auth/2fa/enable", {"code": totp(setup["secret"])})[0] == 200
    assert c.get("/api/acl/mine")[0] == 200
    # can not switch it off again
    status, data, _ = c.post("/api/auth/2fa/disable", {"password": "Must-2fa-Password", "code": totp(setup["secret"], step_offset=1)})
    assert status == 403 and data["error"] == "2fa_required"


def test_own_password_change_needs_current_password_and_ends_other_sessions():
    a = admin()
    a.post("/api/auth/users/create", {"username": "pwchange", "password": "Pw-Change-Password"})
    c1, c2 = Client(), Client()
    c1.login("pwchange", "Pw-Change-Password")
    c2.login("pwchange", "Pw-Change-Password")
    status, data, _ = c1.post("/api/auth/users/updatePassword", {"username": "pwchange", "password": "Pw-Change-Password-2"})
    assert status == 403 and data["error"] == "wrong_password"
    status, data, _ = c1.post("/api/auth/users/updatePassword",
                              {"username": "pwchange", "password": "Pw-Change-Password-2", "currentPassword": "Pw-Change-Password"})
    assert status == 200 and data["sessionsRevoked"] == 1
    assert c1.get("/api/acl/mine")[0] == 200
    assert c2.get("/api/acl/mine")[0] == 401


def test_password_change_demanded_by_the_admin():
    a = admin()
    assert a.post("/api/auth/users/create", {"username": "mustpw", "password": "Must-Pw-Password", "mustChangePassword": True})[0] == 200
    c = Client()
    assert c.login("mustpw", "Must-Pw-Password")[0] == 200
    _, st, _ = c.get("/api/auth/status")
    assert st["loggedIn"] is True and st["passwordChangeRequired"] is True
    status, data, _ = c.get("/api/acl/mine")
    assert status == 403 and data["error"] == "password_change_required"
    # only the own password, and not the same one again
    status, data, _ = c.post("/api/auth/users/updatePassword", {"username": ADMIN, "password": "Taken-Over-Password"})
    assert status == 403
    status, data, _ = c.post("/api/auth/users/updatePassword",
                             {"username": "mustpw", "password": "Must-Pw-Password", "currentPassword": "Must-Pw-Password"})
    assert status == 400 and data["error"] == "password_unchanged"
    assert c.post("/api/auth/users/updatePassword",
                  {"username": "mustpw", "password": "Must-Pw-Password-2", "currentPassword": "Must-Pw-Password"})[0] == 200
    assert c.get("/api/acl/mine")[0] == 200
    assert c.get("/api/auth/status")[1]["passwordChangeRequired"] is False
    # an admin setting the password asks again, and can take the demand back
    assert a.post("/api/auth/users/updatePassword", {"username": "mustpw", "password": "Must-Pw-Password-3", "mustChangePassword": True})[0] == 200
    user = next(u for u in a.get("/api/auth/users/get")[1]["userDetails"] if u["username"] == "mustpw")
    assert user["mustChangePassword"] is True
    assert a.post("/api/auth/users/update", {"username": "mustpw", "mustChangePassword": False})[0] == 200
    c = Client()
    c.login("mustpw", "Must-Pw-Password-3")
    assert c.get("/api/acl/mine")[0] == 200


def test_sessions_list_and_revoke():
    a = admin()
    other = admin()
    _, data, _ = a.get("/api/auth/sessions/get")
    mine = [s for s in data["sessions"] if s["username"] == ADMIN]
    assert sum(s["current"] for s in mine) == 1
    target = [s for s in mine if not s["current"]][-1]
    assert len(target["id"]) == 16
    assert a.post("/api/auth/sessions/revoke", {"others": True})[1]["revoked"] >= 1
    assert other.get("/api/acl/mine")[0] == 401
    assert a.get("/api/acl/mine")[0] == 200


def test_logout_ends_session():
    c = admin()
    assert c.get("/api/auth/logout")[0] == 200
    assert c.cookie is None


def test_network_filters():
    a = admin()
    set_setting(a, "web_auth.remote_access", False)
    try:
        assert Client(forwarded_for="198.51.100.60").get("/web/")[0] == 403
        assert Client(forwarded_for="192.168.7.7").get("/web/")[0] == 200
        set_setting(a, "web_auth.allow_networks", "198.51.100.0/24")
        assert Client(forwarded_for="198.51.100.60").get("/web/")[0] == 200
    finally:
        set_setting(a, "web_auth.remote_access", True)
        set_setting(a, "web_auth.allow_networks", "")
    set_setting(a, "web_auth.remote_https_only", True)
    try:
        status, data, _ = Client(forwarded_for="198.51.100.61").get("/web/")
        assert status == 403 and data["error"] == "https_required"
        assert Client(forwarded_for="198.51.100.61", proto="https").get("/web/")[0] == 200
        assert Client().get("/web/")[0] == 200
    finally:
        set_setting(a, "web_auth.remote_https_only", False)
    set_setting(a, "web_auth.deny_networks", "198.51.100.62")
    try:
        assert Client(forwarded_for="198.51.100.62").get("/web/")[0] == 403
        assert Client(forwarded_for="198.51.100.63").get("/web/")[0] == 200
    finally:
        set_setting(a, "web_auth.deny_networks", "")


@pytest.mark.skipif(not SANDBOX, reason="needs the sandbox of with_server.sh")
def test_files_hold_no_secrets_in_clear():
    config = os.path.join(SANDBOX, "config")
    users_file = os.path.join(config, "web_users.json")
    sessions_file = os.path.join(config, "web_sessions.json")
    c = admin()
    with open(users_file) as f:
        text = f.read()
    assert ADMIN_PW not in text and "pbkdf2-sha256$" in text
    with open(sessions_file) as f:
        assert c.cookie not in f.read()
    for path in (users_file, sessions_file, os.path.join(config, "web_auth.key")):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, path
