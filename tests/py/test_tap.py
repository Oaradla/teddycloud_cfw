#!/usr/bin/env python3
"""
Playlists (TAP) and lossless TAF splitting:

- /api/tafSplit writes every chapter of a TAF as a TAF of its own plus a playlist
- /api/tapBuild puts the TAF of a playlist together from TAF files without encoding
- a tonie with a playlist as source gets its TAF built when the playlist changed

The source TAF is encoded by the server from generated noise (needs ffmpeg).
The written files are checked on the ogg level: block aligned pages, checksums,
the TAF header (hash, size, chapters) and that the opus packets are kept.

Run via: make test_py TESTS=tap
"""

import hashlib
import io
import json
import os
import shutil
import struct
import time
import unittest
import wave
from pathlib import Path
from urllib.parse import quote

from test_hardening import Base, request

TRACK_SECONDS = [3, 2, 3]
RATE = 4000  # low rate: the test upload helper only handles small bodies, the server resamples
BLOCK = 4096
SANDBOX = os.environ.get("TC_SANDBOX")
LIBRARY = Path(SANDBOX) / "data" / "library" if SANDBOX else None
DIR = "__tap"


def noise_wav(seconds):
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(1)
        w.setframerate(RATE)
        w.writeframes(os.urandom(RATE * seconds))
    return buf.getvalue()


def _crc_table():
    table = []
    for i in range(256):
        r = i << 24
        for _ in range(8):
            r = ((r << 1) ^ 0x04C11DB7) if r & 0x80000000 else (r << 1)
        table.append(r & 0xFFFFFFFF)
    return table


CRC_TABLE = _crc_table()


def ogg_crc(data):
    crc = 0
    for b in data:
        crc = ((crc << 8) ^ CRC_TABLE[((crc >> 24) & 0xFF) ^ b]) & 0xFFFFFFFF
    return crc


def varint(b, i):
    result = shift = 0
    while True:
        c = b[i]
        i += 1
        result |= (c & 0x7F) << shift
        shift += 7
        if c < 0x80:
            return result, i


class Taf:
    """parsed TAF: header fields, pages and opus packets"""

    def __init__(self, path):
        data = Path(path).read_bytes()
        self.data = data
        size = struct.unpack(">I", data[:4])[0]
        proto = data[4 : 4 + size]
        self.tracks = []
        i = 0
        while i < len(proto):
            key, i = varint(proto, i)
            field, wire = key >> 3, key & 7
            if wire == 0:
                value, i = varint(proto, i)
                if field == 2:
                    self.num_bytes = value
                elif field == 3:
                    self.audio_id = value
            else:
                length, i = varint(proto, i)
                value = proto[i : i + length]
                i += length
                if field == 1:
                    self.sha1 = value
                elif field == 4:
                    j = 0
                    while j < len(value):
                        page, j = varint(value, j)
                        self.tracks.append(page)

        self.pages = []
        pos = BLOCK
        while pos < len(data):
            assert data[pos : pos + 4] == b"OggS", f"no page at {pos}"
            nseg = data[pos + 26]
            lacing = data[pos + 27 : pos + 27 + nseg]
            length = 27 + nseg + sum(lacing)
            page = data[pos : pos + length]
            packets, start, plen = [], 27 + nseg, 0
            for lace in lacing:
                plen += lace
                if lace < 255:
                    packets.append(page[start : start + plen])
                    start += plen
                    plen = 0
            self.pages.append(
                {
                    "offset": pos - BLOCK,
                    "length": length,
                    "flags": page[5],
                    "granule": struct.unpack("<q", page[6:14])[0],
                    "serial": struct.unpack("<I", page[14:18])[0],
                    "seq": struct.unpack("<I", page[18:22])[0],
                    "crc_ok": struct.unpack("<I", page[22:26])[0] == ogg_crc(page[:22] + b"\0\0\0\0" + page[26:]),
                    "packets": packets,
                }
            )
            pos += length

    def audio_packets(self, first_block=0, end_block=None):
        """the opus packets after the two header pages, of pages starting in [first_block, end_block)"""
        packets = []
        for page in self.pages[2:]:
            block = page["offset"] // BLOCK
            if block >= first_block and (end_block is None or block < end_block):
                packets.extend(page["packets"])
        return packets


def _frame_length(p, i):
    if p[i] < 252:
        return p[i], i + 1
    return p[i + 1] * 4 + p[i], i + 2


def opus_frames(p):
    """the TOC configuration and frames of an opus packet (RFC 6716 3.2), without any padding:
    the remuxer may pad packets, which also turns them into code 3 packets"""
    toc, code = p[0] & 0xFC, p[0] & 3
    if code == 0:
        return toc, [p[1:]]
    if code == 1:
        half = (len(p) - 1) // 2
        return toc, [p[1 : 1 + half], p[1 + half :]]
    if code == 2:
        length, i = _frame_length(p, 1)
        return toc, [p[i : i + length], p[i + length :]]
    count, i = p[1] & 0x3F, 2
    padding = 0
    if p[1] & 0x40:
        while True:
            b = p[i]
            i += 1
            padding += 254 if b == 255 else b
            if b != 255:
                break
    end = len(p) - padding
    if p[1] & 0x80:
        lengths = []
        for _ in range(count - 1):
            length, i = _frame_length(p, i)
            lengths.append(length)
        lengths.append(end - i - sum(lengths))
    else:
        lengths = [(end - i) // count] * count
    frames = []
    for length in lengths:
        frames.append(p[i : i + length])
        i += length
    return toc, frames


def audio(packets):
    return [opus_frames(p) for p in packets]


class TafCheck(unittest.TestCase):
    def assertValidTaf(self, taf):
        self.assertEqual(hashlib.sha1(taf.data[BLOCK:]).digest(), taf.sha1, "sha1 of the audio data")
        self.assertEqual(len(taf.data) - BLOCK, taf.num_bytes)
        self.assertTrue(all(p["crc_ok"] for p in taf.pages), "page checksums")
        self.assertEqual([p["seq"] for p in taf.pages], list(range(len(taf.pages))), "page sequence")
        self.assertEqual({p["serial"] for p in taf.pages}, {taf.audio_id}, "serial is the audio id")
        self.assertEqual(taf.pages[0]["flags"], 2, "BOS on the first page only")
        self.assertTrue(all(p["flags"] & 2 == 0 for p in taf.pages[1:]))
        self.assertEqual(taf.pages[0]["packets"][0][:8], b"OpusHead")
        self.assertEqual(taf.pages[1]["packets"][0][:8], b"OpusTags")
        # every page after block 0 starts a block, no page crosses one
        for page in taf.pages:
            start, end = page["offset"], page["offset"] + page["length"] - 1
            self.assertEqual(start // BLOCK, end // BLOCK, f"page at {start} crosses a block")
            if start >= BLOCK:
                self.assertEqual(start % BLOCK, 0, f"page at {start} does not start a block")
        # chapters start at a page
        starts = {p["offset"] // BLOCK for p in taf.pages if p["offset"] % BLOCK == 0}
        self.assertEqual(taf.tracks[0], 0)
        self.assertTrue(set(taf.tracks) <= starts, f"chapters {taf.tracks} not at page starts")
        self.assertEqual(taf.tracks, sorted(set(taf.tracks)))
        granules = [p["granule"] for p in taf.pages if p["granule"] != -1]
        self.assertEqual(granules, sorted(granules), "granule positions grow")


@unittest.skipUnless(shutil.which("ffmpeg") and SANDBOX, "needs ffmpeg and the sandbox from tests/py/with_server.sh")
class Tap(Base, TafCheck):
    RUID = "0000051000000510"

    def setUp(self):
        super().setUp()
        sources = []
        for i, seconds in enumerate(TRACK_SECONDS):
            name = f"__tap{i}.wav"
            self.put_library(name, noise_wav(seconds))
            sources.append(name)
        status, text = request("POST", "/api/dirCreate?special=library", DIR)
        self.assertEqual(status, 200, text)
        status, text = self.encode(sources, f"{DIR}/album.taf")
        self.assertEqual(status, 200, text)
        self.source = Taf(LIBRARY / DIR / "album.taf")
        self.assertEqual(len(self.source.tracks), len(TRACK_SECONDS))

    def tearDown(self):
        if LIBRARY is not None and (LIBRARY / DIR).exists():
            shutil.rmtree(LIBRARY / DIR)
        super().tearDown()

    def post(self, endpoint, form):
        status, text = request("POST", endpoint, form, {"Content-Type": "application/x-www-form-urlencoded"}, timeout=60)
        return status, json.loads(text) if text.startswith("{") else text

    def split(self, titles=()):
        form = "&".join([f"path={quote(DIR + '/album.taf')}"] + [f"title={quote(t)}" for t in titles])
        return self.post("/api/tafSplit?special=library", form)

    def build(self, tap):
        return self.post("/api/tapBuild?special=library", f"path={quote(tap)}")

    def test_split_writes_every_chapter_and_a_playlist(self):
        status, result = self.split(["Erstes Kapitel", "Zwei/Drei", ""])
        self.assertEqual(status, 200, result)
        self.assertEqual(
            result,
            {"folder": f"{DIR}/album", "tap": f"{DIR}/album/album.tap", "chapters": 3, "original": f"{DIR}/album/album.taf"},
        )

        names = ["01 - Erstes Kapitel.taf", "02 - Zwei_Drei.taf", "03 - Chapter 3.taf"]
        folder = LIBRARY / DIR / "album"
        # the original moves into the folder with its chapters and the playlist
        self.assertEqual(sorted(p.name for p in folder.iterdir()), sorted(names + ["album.tap", "album.taf"]))
        self.assertFalse((LIBRARY / DIR / "album.taf").exists())

        tap = json.loads((folder / "album.tap").read_text())
        self.assertEqual(tap["type"], "tap")
        # the playlist builds a TAF of its own, the original stays as it is
        self.assertEqual(tap["filepath"], f"lib://{DIR}/album/album.tap.taf")
        self.assertFalse((folder / "album.tap.taf").exists())
        self.assertEqual(tap["audio_id"], self.source.audio_id, "the playlist keeps the audio id, and so the cover")
        self.assertEqual([f["filepath"] for f in tap["files"]], [f"lib://{DIR}/album/{n}" for n in names])

        bounds = self.source.tracks + [None]
        for i, name in enumerate(names):
            chapter = Taf(folder / name)
            self.assertValidTaf(chapter)
            self.assertEqual(chapter.tracks, [0])
            expected = self.source.audio_packets(bounds[i], bounds[i + 1])
            got = chapter.audio_packets()
            self.assertEqual(len(got), len(expected), f"packets of chapter {i + 1}")
            self.assertEqual(audio(got), audio(expected))

    def test_split_and_build_gives_the_chapters_back(self):
        self.assertEqual(self.split()[0], 200)
        original_audio_id = self.source.audio_id
        time.sleep(1.1)  # the playlist has to be newer than the TAF built from it
        Path(LIBRARY / DIR / "album" / "album.tap").touch()

        status, result = self.build(f"{DIR}/album/album.tap")
        self.assertEqual(status, 200, result)
        self.assertEqual(result["built"], True)
        self.assertEqual(result["remux"], True)

        rebuilt = Taf(LIBRARY / DIR / "album" / "album.tap.taf")
        self.assertValidTaf(rebuilt)
        self.assertNotEqual(rebuilt.audio_id, original_audio_id, "a changed TAF needs a new audio id")
        self.assertEqual(Taf(LIBRARY / DIR / "album" / "album.taf").audio_id, original_audio_id, "the original is not touched")
        # the header of the hidden TAF comes with the answer
        self.assertEqual(result["tafHeader"], {"audioId": rebuilt.audio_id, "sha1Hash": rebuilt.sha1.hex()})
        self.assertEqual(len(rebuilt.tracks), len(TRACK_SECONDS))
        self.assertEqual(
            audio(rebuilt.audio_packets()), audio(self.source.audio_packets())
        )

        # current now: nothing to do
        status, result = self.build(f"{DIR}/album/album.tap")
        self.assertEqual((status, result["built"]), (200, True))
        self.assertEqual(Taf(LIBRARY / DIR / "album" / "album.tap.taf").audio_id, rebuilt.audio_id)

    def test_reordered_playlist(self):
        self.assertEqual(self.split()[0], 200)
        tap_path = LIBRARY / DIR / "album" / "album.tap"
        tap = json.loads(tap_path.read_text())
        tap["files"] = [tap["files"][2], tap["files"][0]]
        time.sleep(1.1)
        tap_path.write_text(json.dumps(tap))

        self.assertEqual(self.build(f"{DIR}/album/album.tap")[0], 200)
        rebuilt = Taf(LIBRARY / DIR / "album" / "album.tap.taf")
        self.assertValidTaf(rebuilt)
        self.assertEqual(len(rebuilt.tracks), 2)
        third = Taf(LIBRARY / DIR / "album" / "03 - Chapter 3.taf").audio_packets()
        first = Taf(LIBRARY / DIR / "album" / "01 - Chapter 1.taf").audio_packets()
        self.assertEqual(audio(rebuilt.audio_packets()), audio(third + first))

    def test_split_into_a_taken_name_uses_a_new_folder(self):
        (LIBRARY / DIR / "album").mkdir()
        status, result = self.split()
        self.assertEqual(status, 200, result)
        self.assertEqual(result["folder"], f"{DIR}/album (2)")
        self.assertEqual(result["original"], f"{DIR}/album (2)/album.taf")

    def test_tonie_with_playlist_gets_the_rebuilt_taf(self):
        if request("GET", f"/content/json/get/{self.RUID}")[0] == 200:
            self.skipTest(f"content JSON for {self.RUID} already exists, not touching it")
        self.assertEqual(self.split()[0], 200)
        tap_path = LIBRARY / DIR / "album" / "album.tap"
        tap = json.loads(tap_path.read_text())
        tap["files"] = tap["files"][1:]
        time.sleep(1.1)
        tap_path.write_text(json.dumps(tap))
        try:
            status, text = request(
                "POST",
                f"/content/json/set/{self.RUID}",
                "source=" + quote(f"lib://{DIR}/album/album.tap"),
                {"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 200, text)
            # loading the content of the tonie (set loads it first) builds the TAF of the changed playlist
            status, text = request(
                "POST",
                f"/content/json/set/{self.RUID}",
                "hide=false",
                {"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 200, text)
            rebuilt = Taf(LIBRARY / DIR / "album" / "album.tap.taf")
            self.assertValidTaf(rebuilt)
            self.assertEqual(len(rebuilt.tracks), 2)
        finally:
            request("POST", "/api/fileDelete", f"{self.RUID[:8]}/{self.RUID[8:]}.json")
            request("POST", "/api/dirDelete", self.RUID[:8])

    def header(self, folder, name):
        status, text = request("GET", f"/api/fileIndexV2?special=library&path={quote(folder)}")
        entry = {e["name"]: e for e in json.loads(text)["files"]}[name]
        return str(entry["tafHeader"]["audioId"]), entry["tafHeader"]["sha1Hash"]

    def test_tonie_follows_the_original_into_the_folder(self):
        if request("GET", f"/content/json/get/{self.RUID}")[0] == 200:
            self.skipTest(f"content JSON for {self.RUID} already exists, not touching it")
        try:
            status, text = request(
                "POST",
                f"/content/json/set/{self.RUID}",
                "source=" + quote(f"lib://{DIR}/album.taf"),
                {"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 200, text)
            self.assertEqual(self.split()[0], 200)
            status, text = request("GET", f"/content/json/get/{self.RUID}")
            self.assertEqual(status, 200, text)
            self.assertEqual(json.loads(text)["source"], f"lib://{DIR}/album/album.taf")
        finally:
            request("POST", "/api/fileDelete", f"{self.RUID[:8]}/{self.RUID[8:]}.json")
            request("POST", "/api/dirDelete", self.RUID[:8])

    def test_playlist_and_folder_show_the_cover(self):
        audio_id, sha1 = self.header(DIR, "album.taf")
        model = {
            "model": "__tap-cover",
            "audio_id": [audio_id],
            "hash": [sha1],
            "title": "Album",
            "series": "Album",
            "pic": "/custom_img/__tap-cover.png",
        }
        status, text = request("POST", "/api/toniesCustomJsonUpsert", json.dumps(model), {"Content-Type": "application/json"})
        self.assertEqual(status, 200, text)
        try:
            self.assertEqual(self.split()[0], 200)
            status, text = request("GET", f"/api/fileIndexV2?special=library&path={quote(DIR + '/album')}")
            self.assertEqual(status, 200, text)
            entries = {e["name"]: e for e in json.loads(text)["files"]}
            self.assertEqual(entries["album.tap"].get("tonieInfo", {}).get("picture"), model["pic"])
            # the folder of the album shows its one picture
            status, text = request("GET", f"/api/fileIndexV2?special=library&path={quote(DIR)}")
            entries = {e["name"]: e for e in json.loads(text)["files"]}
            self.assertEqual(entries["album"].get("folderPicture"), model["pic"])
            # the playlist keeps it when the original is gone
            (LIBRARY / DIR / "album" / "album.taf").unlink()
            status, text = request("GET", f"/api/fileIndexV2?special=library&path={quote(DIR + '/album')}")
            entries = {e["name"]: e for e in json.loads(text)["files"]}
            self.assertEqual(entries["album.tap"].get("tonieInfo", {}).get("picture"), model["pic"])
        finally:
            request("POST", "/api/toniesCustomJsonDelete", json.dumps({"models": [model["model"]]}), {"Content-Type": "application/json"})

    def test_folder_with_two_pictures_has_none(self):
        self.assertEqual(self.split()[0], 200)
        a = self.header(f"{DIR}/album", "album.taf")
        b = self.header(f"{DIR}/album", "01 - Chapter 1.taf")
        models = [
            {"model": "__tap-a", "audio_id": [a[0]], "hash": [a[1]], "title": "A", "series": "A", "pic": "/custom_img/a.png"},
            {"model": "__tap-b", "audio_id": [b[0]], "hash": [b[1]], "title": "B", "series": "B", "pic": "/custom_img/b.png"},
        ]
        for m in models:
            self.assertEqual(request("POST", "/api/toniesCustomJsonUpsert", json.dumps(m), {"Content-Type": "application/json"})[0], 200)
        try:
            status, text = request("GET", f"/api/fileIndexV2?special=library&path={quote(DIR)}")
            entries = {e["name"]: e for e in json.loads(text)["files"]}
            self.assertNotIn("folderPicture", entries["album"])
        finally:
            request("POST", "/api/toniesCustomJsonDelete", json.dumps({"models": [m["model"] for m in models]}), {"Content-Type": "application/json"})

    def listed(self, folder, endpoint="fileIndexV2"):
        status, text = request("GET", f"/api/{endpoint}?special=library&path={quote(folder)}")
        self.assertEqual(status, 200, text)
        return {e["name"] for e in json.loads(text)["files"]}

    def move(self, source, target):
        return self.post("/api/fileMove?special=library", f"source={quote(source)}&target={quote(target)}")

    def built_playlist(self):
        self.assertEqual(self.split()[0], 200)
        self.assertEqual(self.build(f"{DIR}/album/album.tap")[0], 200)
        self.assertTrue((LIBRARY / DIR / "album" / "album.tap.taf").exists())

    def test_the_built_taf_is_not_listed(self):
        self.built_playlist()
        for endpoint in ("fileIndexV2", "fileIndex"):
            names = self.listed(f"{DIR}/album", endpoint)
            self.assertIn("album.tap", names)
            self.assertNotIn("album.tap.taf", names, endpoint)
        # without its playlist it shows up again
        (LIBRARY / DIR / "album" / "album.tap").unlink()
        self.assertIn("album.tap.taf", self.listed(f"{DIR}/album"))

    def test_renamed_playlist_takes_its_taf_along(self):
        self.built_playlist()
        self.assertEqual(self.move(f"{DIR}/album/album.tap", f"{DIR}/album/neu.tap")[0], 200)
        folder = LIBRARY / DIR / "album"
        self.assertFalse((folder / "album.tap.taf").exists())
        self.assertTrue((folder / "neu.tap.taf").exists())
        tap = json.loads((folder / "neu.tap").read_text())
        self.assertEqual(tap["filepath"], f"lib://{DIR}/album/neu.tap.taf")
        self.assertNotIn("neu.tap.taf", self.listed(f"{DIR}/album"))

    def test_renamed_playlist_not_built_yet_builds_at_the_new_place(self):
        self.assertEqual(self.split()[0], 200)
        self.assertEqual(self.move(f"{DIR}/album/album.tap", f"{DIR}/album/neu.tap")[0], 200)
        tap = json.loads((LIBRARY / DIR / "album" / "neu.tap").read_text())
        self.assertEqual(tap["filepath"], f"lib://{DIR}/album/neu.tap.taf")

    def test_moved_folder_keeps_playlist_and_tonie_working(self):
        if request("GET", f"/content/json/get/{self.RUID}")[0] == 200:
            self.skipTest(f"content JSON for {self.RUID} already exists, not touching it")
        self.built_playlist()
        try:
            status, text = request(
                "POST",
                f"/content/json/set/{self.RUID}",
                "source=" + quote(f"lib://{DIR}/album/album.tap"),
                {"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 200, text)
            self.assertEqual(self.move(f"{DIR}/album", f"{DIR}/Hörspiel")[0], 200)

            tap = json.loads((LIBRARY / DIR / "Hörspiel" / "album.tap").read_text())
            self.assertEqual(tap["filepath"], f"lib://{DIR}/Hörspiel/album.tap.taf")
            self.assertTrue(all(f["filepath"].startswith(f"lib://{DIR}/Hörspiel/") for f in tap["files"]), tap["files"])
            status, text = request("GET", f"/content/json/get/{self.RUID}")
            self.assertEqual(json.loads(text)["source"], f"lib://{DIR}/Hörspiel/album.tap")
            # and it still builds from the moved chapters
            time.sleep(1.1)
            (LIBRARY / DIR / "Hörspiel" / "album.tap").touch()
            status, result = self.build(f"{DIR}/Hörspiel/album.tap")
            self.assertEqual((status, result.get("built")), (200, True), result)
        finally:
            request("POST", "/api/fileDelete", f"{self.RUID[:8]}/{self.RUID[8:]}.json")
            request("POST", "/api/dirDelete", self.RUID[:8])

    def test_a_folder_with_a_similar_name_is_left_alone(self):
        self.assertEqual(self.split()[0], 200)
        (LIBRARY / DIR / "album2").mkdir()
        other = {"type": "tap", "audio_id": 1, "filepath": f"lib://{DIR}/album2/x.tap.taf", "name": "x",
                 "files": [{"filepath": f"lib://{DIR}/album2/a.taf", "name": "a"}]}
        (LIBRARY / DIR / "album2" / "x.tap").write_text(json.dumps(other))
        self.assertEqual(self.move(f"{DIR}/album", f"{DIR}/moved")[0], 200)
        self.assertEqual(json.loads((LIBRARY / DIR / "album2" / "x.tap").read_text()), other)

    def test_deleted_playlist_takes_its_taf_along(self):
        self.built_playlist()
        status, text = request("POST", "/api/fileDelete?special=library", f"{DIR}/album/album.tap")
        self.assertEqual(status, 200, text)
        self.assertFalse((LIBRARY / DIR / "album" / "album.tap.taf").exists())
        self.assertTrue((LIBRARY / DIR / "album" / "album.taf").exists(), "the original stays")

    def test_deleting_a_folder_takes_everything_in_it(self):
        self.built_playlist()
        folder = LIBRARY / DIR / "album"
        (folder / "sub").mkdir()
        (folder / "sub" / "x.txt").write_text("x")
        (folder / "album.taf.json").write_text("{}")  # a hidden sidecar
        outside = LIBRARY.parent / "__keep_me.txt"
        outside.write_text("keep")
        os.symlink(LIBRARY.parent, folder / "link")
        try:
            status, text = request("POST", "/api/fileDelete?special=library", f"{DIR}/album")
            self.assertEqual(status, 200, text)
            self.assertFalse(folder.exists())
            self.assertTrue(outside.exists(), "a link is removed, never followed")
        finally:
            outside.unlink(missing_ok=True)

    def test_the_library_itself_is_never_deleted(self):
        # (an empty body is never read by the server, nothing is deleted then either)
        for path in ("/", ".", "/./", "x/..", "__tap/.."):
            status, _ = request("POST", "/api/fileDelete?special=library", path)
            self.assertNotEqual(status, 200, repr(path))
            self.assertTrue((LIBRARY / DIR / "album.taf").exists(), repr(path))

    def test_rejects_paths_outside_the_library(self):
        # not a playlist, or outside the library
        for path in ("../config/config.overlay.ini", f"{DIR}/album.taf", "../../escape.tap"):
            self.assertEqual(self.build(path)[0], 400, path)
        playlist = {
            "type": "tap",
            "filepath": "lib://../escape.taf",
            "name": "x",
            "files": [{"filepath": f"lib://{DIR}/album.taf", "name": "a"}],
        }
        (LIBRARY / DIR / "bad.tap").write_text(json.dumps(playlist))
        status, _ = self.build(f"{DIR}/bad.tap")
        self.assertEqual(status, 400)
        self.assertFalse((LIBRARY.parent / "escape.taf").exists())


if __name__ == "__main__":
    unittest.main()
