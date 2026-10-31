#!/usr/bin/env python3
"""
Cloud content moved to the library lands in cloud.cacheToLibraryDir.

Uses /api/migrateContent2Lib, which takes the same path as content cached from the cloud.

Run via: make test_py TESTS=cache_to_library
"""

import json
import shutil
import unittest
from urllib.parse import quote

from test_hardening import BASE_DIR, Base, request
from test_taf_length import white_noise_wav

RUID = "0123456789abcdef"


class CacheToLibraryDir(Base):
    def setUp(self):
        super().setUp()
        self.put_library("__cachedir.wav", white_noise_wav(1))
        status, text = self.encode(["__cachedir.wav"], "__cachedir.taf")
        self.assertEqual(status, 200, text)
        self.taf = BASE_DIR / "data/library/__cachedir.taf"
        self.content = BASE_DIR / "data/content/default" / RUID[:8].upper() / RUID[8:].upper()

    def tearDown(self):
        shutil.rmtree(self.content.parent, ignore_errors=True)
        request("POST", "/api/settings/reset/cloud.cacheToLibraryDir")
        super().tearDown()

    def migrate(self, cache_dir):
        self.assertEqual(request("POST", "/api/settings/set/cloud.cacheToLibraryDir", cache_dir)[0], 200)
        self.content.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.taf, self.content)
        status, text = request("POST", "/api/migrateContent2Lib", f"ruid={RUID}&libroot=false")
        self.assertEqual(status, 200, text)
        return self.audio_id()

    def audio_id(self):
        status, text = request("GET", "/api/fileIndexV2?special=library&path=" + quote("/"))
        self.assertEqual(status, 200, text)
        entry = next(f for f in json.loads(text)["files"] if f["name"] == "__cachedir.taf")
        return entry["tafHeader"]["audioId"]

    def assert_moved_to(self, relative):
        path = BASE_DIR / "data/library" / relative
        self.assertTrue(path.is_file(), path)
        self.assertFalse(self.content.exists())
        path.unlink()

    def test_default_dir(self):
        audio_id = self.migrate("by/audioID")
        self.assert_moved_to(f"by/audioID/{audio_id}.taf")

    def test_own_dir(self):
        audio_id = self.migrate("cloud/tonies")
        self.assert_moved_to(f"cloud/tonies/{audio_id}.taf")

    def test_dotdot_stays_in_library(self):
        audio_id = self.migrate("../outside")
        self.assert_moved_to(f"{audio_id}.taf")


if __name__ == "__main__":
    unittest.main()
