#!/usr/bin/env python3
"""
Web UI tests: the legacy admin GUI is gone (#489).

Verifies the sunset of the legacy admin GUI:
- "/" and the parser-rewritten "index.shtm" redirect to the web UI at /web (web2 only when chosen and installed)
- "/web/" serves the built SPA
- the removed "/legacy.html" is no longer served

Recommended usage:

1) Fully automated via Makefile (build + start server + run tests + stop server):
   make test_py TESTS=legacy_gone

2) Against an already running TeddyCloud server:
   TEDDYCLOUD_BASE_URL=http://127.0.0.1:80 python3 tests/py/test_web_legacy_gone.py
"""

import http.client
import os
import unittest
import urllib.parse


BASE_URL = os.environ.get("TEDDYCLOUD_BASE_URL", "http://127.0.0.1:80").rstrip("/")
_PARSED_URL = urllib.parse.urlsplit(BASE_URL)
HOST = _PARSED_URL.hostname or "127.0.0.1"
PORT = _PARSED_URL.port or 80


class WebLegacyGoneTests(unittest.TestCase):
    @classmethod
    def request(cls, path):
        """Return (status, headers, body) without following redirects."""
        connection = http.client.HTTPConnection(HOST, PORT, timeout=10)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            headers = {name.lower(): value for name, value in response.getheaders()}
            body = response.read().decode("utf-8", errors="replace")
            return response.status, headers, body
        finally:
            connection.close()

    def test_root_redirects_to_web(self):
        # 302: a browser must follow a later change of frontend.default_ui
        status, headers, _ = self.request("/")
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("location"), "/web")

    def test_web2_as_default_when_installed(self):
        # the sandbox links the repository's web UI; a folder of its own gets web2 beside a classic index
        sandbox = os.environ.get("TC_SANDBOX")
        if not sandbox:
            self.skipTest("needs the sandbox from tests/py/with_server.sh")
        web = os.path.join(sandbox, "data", "www", "web")
        if os.path.islink(web):
            os.unlink(web)
        os.makedirs(os.path.join(web, "v2"), exist_ok=True)
        with open(os.path.join(web, "index.html"), "w") as f:
            f.write('<div id="root"></div>')
        with open(os.path.join(web, "v2", "index.html"), "w") as f:
            f.write("web2")
        connection = http.client.HTTPConnection(HOST, PORT, timeout=10)
        connection.request("POST", "/api/settings/set/frontend.default_ui", "1")
        self.assertEqual(connection.getresponse().status, 200)
        connection.close()
        try:
            status, headers, _ = self.request("/")
            self.assertEqual(status, 302)
            self.assertEqual(headers.get("location"), "/web/v2/index.html")
            status, _, body = self.request("/web/v2/")
            self.assertEqual((status, body), (200, "web2"))
        finally:
            connection = http.client.HTTPConnection(HOST, PORT, timeout=10)
            connection.request("POST", "/api/settings/reset/frontend.default_ui", "")
            connection.getresponse().read()
            connection.close()
            os.remove(os.path.join(web, "v2", "index.html"))
            os.rmdir(os.path.join(web, "v2"))

    def test_web2_as_default_only_when_installed(self):
        # without web2 under /web/v2/ the classic interface stays the start page
        connection = http.client.HTTPConnection(HOST, PORT, timeout=10)
        connection.request("POST", "/api/settings/set/frontend.default_ui", "1")
        self.assertEqual(connection.getresponse().status, 200)
        connection.close()
        try:
            status, headers, _ = self.request("/")
            self.assertEqual(status, 302)
            self.assertEqual(headers.get("location"), "/web")
        finally:
            connection = http.client.HTTPConnection(HOST, PORT, timeout=10)
            connection.request("POST", "/api/settings/reset/frontend.default_ui", "")
            connection.getresponse().read()
            connection.close()

    def test_web_serves_spa(self):
        status, _, body = self.request("/web/")
        self.assertEqual(status, 200)
        self.assertIn('id="root"', body)

    def test_legacy_admin_gui_is_gone(self):
        status, _, body = self.request("/legacy.html")
        self.assertNotEqual(status, 200)
        self.assertNotIn("library/react.development.js", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
