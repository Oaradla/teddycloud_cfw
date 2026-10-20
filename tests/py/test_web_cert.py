#!/usr/bin/env python3
"""
Own certificate of the HTTPS web port (core.server_cert.file.web_crt/web_key),
for a web UI on the internet without a reverse proxy.

    make test_py TESTS=web_cert
"""

import http.client
import os
import socket
import ssl
import subprocess
import tempfile
import time

import pytest

BASE = os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80")
WEB_PORT = int(os.environ.get("TC_HTTPS_WEB_PORT", "8443"))
API_PORT = int(os.environ.get("TC_HTTPS_API_PORT", "443"))


def api(method, path, body=None):
    host, port = BASE.split("//")[1].split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=10)
    try:
        conn.request(method, path, body=body, headers={"Content-Type": "text/plain"})
        r = conn.getresponse()
        return r.status, r.read().decode()
    finally:
        conn.close()


def peer_cn(port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname="tc.example.test") as tls:
            der = tls.getpeercert(binary_form=True)
    out = subprocess.run(["openssl", "x509", "-inform", "der", "-noout", "-subject"], input=der, capture_output=True, check=True)
    return out.stdout.decode().strip()


def make_cert(directory, kind, cn):
    key = os.path.join(directory, kind + "-key.pem")
    crt = os.path.join(directory, kind + "-cert.pem")
    args = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"] if kind == "ec" else ["-newkey", "rsa:2048"]
    subprocess.run(["openssl", "req", "-x509", *args, "-nodes", "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=" + cn],
                   check=True, capture_output=True)
    return crt, key


def wait_cn(port, text):
    for _ in range(50):
        try:
            cn = peer_cn(port)
            if text in cn:
                return cn
        except OSError:
            pass
        time.sleep(0.2)
    return peer_cn(port)


@pytest.fixture
def certs():
    with tempfile.TemporaryDirectory() as d:
        yield d
    api("POST", "/api/settings/reset/core.server_cert.file.web_crt", "")
    api("POST", "/api/settings/reset/core.server_cert.file.web_key", "")


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_web_port_uses_own_certificate(certs, kind):
    before = peer_cn(WEB_PORT)
    crt, key = make_cert(certs, kind, "web-%s.example.test" % kind)
    assert api("POST", "/api/settings/set/core.server_cert.file.web_key", key)[0] == 200
    assert api("POST", "/api/settings/set/core.server_cert.file.web_crt", crt)[0] == 200
    assert "web-%s.example.test" % kind in wait_cn(WEB_PORT, "web-%s" % kind)
    assert before != peer_cn(WEB_PORT)
    # the boxes keep the server certificate
    assert "web-" not in peer_cn(API_PORT)


def test_missing_files_fall_back_to_server_certificate(certs):
    before = peer_cn(WEB_PORT)
    assert api("POST", "/api/settings/set/core.server_cert.file.web_key", os.path.join(certs, "missing-key.pem"))[0] == 200
    assert api("POST", "/api/settings/set/core.server_cert.file.web_crt", os.path.join(certs, "missing.pem"))[0] == 200
    time.sleep(0.5)
    assert peer_cn(WEB_PORT) == before
