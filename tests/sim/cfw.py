"""Messages of the CC3200 custom firmware (CFW): the log records a CFW box sends, a protobuf decoder for
the server's answers and command frames, TBS settings files and slot images."""

import hashlib
import io
import os
import struct
import time
import zipfile

from . import rtnl

FUNC_HELLO = 32257
FUNC_SETTINGS_CHANGED = 32258
FUNC_REMOTE_RESULT = 32260
FUNC_STATUS = 32261
FUNC_BATTERY = 32262
GROUP = 22


def battery(mv, station=False, low=False, critical=False, implausible=False, reason=1, state=0, step=8, adc=0):
    """payload of the battery report record"""
    flags = int(station) | int(low) << 1 | int(critical) << 2 | int(implausible) << 3
    return struct.pack("<5I", mv, flags, reason, state | step << 8, adc)


def record(function, payload, uptime, sequence, group=GROUP):
    return rtnl.frame(rtnl.log2(uptime, sequence, group, function, payload, field3=1, field9=rtnl.CRLF))


def tag_valid(uid_printed):
    """payload of record 8627 (group 15) as the custom firmware sends it: the low half of the UID
    big-endian first, then the high half (E0 04 03 50 ...)"""
    raw = bytes.fromhex(uid_printed)
    return raw[4:] + raw[:4]


def hello(version, capabilities, uptime, sequence, result=0, rolled_back=0):
    return record(FUNC_HELLO, struct.pack("<IIII", version, capabilities, result, rolled_back), uptime, sequence)


def freshness_request(uid, audio_id):
    """TonieFreshnessCheckRequest with one tonie"""
    info = rtnl._tag(1, 1) + struct.pack("<Q", uid) + rtnl._tag(2, 5) + struct.pack("<I", audio_id)
    return rtnl._bytes(1, info)


def _varint(data, pos):
    result = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return result, pos


def fields(data):
    """[(field, value)] of a protobuf message; length-delimited values as bytes"""
    out, pos = [], 0
    while pos < len(data):
        key, pos = _varint(data, pos)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _varint(data, pos)
        elif wire == 2:
            length, pos = _varint(data, pos)
            value, pos = data[pos:pos + length], pos + length
        else:
            size = {1: 8, 5: 4}[wire]
            value, pos = data[pos:pos + size], pos + size
        out.append((field, value))
    return out


class FrameReader:
    """Command frames on a log connection: a 4-byte big-endian length that counts itself, then the message"""

    def __init__(self, sock):
        self.sock = sock
        self.data = b""

    def frames(self, timeout):
        self.sock.settimeout(timeout)
        try:
            self.data += self.sock.recv(4096)
        except TimeoutError:
            pass
        out = []
        while len(self.data) >= 4 and len(self.data) >= struct.unpack(">I", self.data[:4])[0]:
            length = struct.unpack(">I", self.data[:4])[0]
            out.append(fields(self.data[4:length]))
            self.data = self.data[length:]
        return out


def crc32(data):
    crc = 0
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7 if crc & 0x80000000 else crc << 1) & 0xFFFFFFFF
    return crc


def tbs_body(file):
    """the body of a valid TBS file"""
    length = file[6] | file[7] << 8
    assert file[:4] == b"TBS1" and len(file) == 16 + length
    assert struct.unpack("<I", file[12 + length:])[0] == crc32(file[:12 + length])
    return file[12:12 + length]


def slot_image(build, version=b"CFW_0.2.0", family=b"CFW1", code_size=800):
    """an application image with build block and digest text"""
    body = bytes(64) + version + b"\x00" + os.urandom(code_size)
    block = struct.pack("<IIII", 0xBEAC0005, 0, build, 0) + b"abc1234\x00" + b"05 Oct 14:32".ljust(61, b"\x00")
    block += bytes([1, 2, 0, 1, 0, 1, 14, 0]) + family + bytes(3) + struct.pack("<III", 2, 0, 0xBEAC0005)
    data = body + block
    return data + hashlib.sha256(data).hexdigest().encode()


def esp32_fix(image):
    """checksum and appended SHA-256 of a one-segment app image (without digest text) after a change"""
    data = bytearray(image[:-33])
    length = struct.unpack_from("<I", data, 28)[0]
    checksum = 0xEF
    for b in data[32: 32 + length]:
        checksum ^= b
    data += bytes([checksum])
    return bytes(data) + hashlib.sha256(data).digest()


def esp32_build_fields(build):
    """time and date of an app description for a build number (UTC, as __TIME__ and __DATE__)"""
    tm = time.gmtime(build)
    months = "JanFebMarAprMayJunJulAugSepOctNovDec"
    date = "%s %2d %04d" % (months[3 * (tm.tm_mon - 1): 3 * tm.tm_mon], tm.tm_mday, tm.tm_year)
    return time.strftime("%H:%M:%S", tm).encode().ljust(16, b"\x00") + date.encode().ljust(16, b"\x00")


def esp32_image(build, project=b"toniebox-cfw-esp32", version=b"CFW_0.3.0", code_size=4000, digest_text=True):
    """an app image of the ESP32-S3 (ESP-IDF "App Image Format"): one segment with the app description
    (its build date and time the build number) and the server block, checksum and
    appended SHA-256; with the digest text after it"""
    desc = struct.pack("<II", 0xABCD5432, 0) + bytes(8) + version.ljust(32, b"\x00") + project.ljust(32, b"\x00")
    desc += esp32_build_fields(build)
    desc = desc.ljust(256, b"\x00")
    server = b"CFWSRV" + b"01" + bytes(72)
    segment = desc + server + bytes(code_size)
    header = bytes([0xE9, 1, 2, 0x3F]) + struct.pack("<I", 0x40370000) + bytes([0xEE, 0, 0, 0]) + struct.pack("<H", 9)
    header += bytes(9) + bytes([1])  # chip revisions, reserved, hash appended
    assert len(header) == 24
    data = header + struct.pack("<II", 0x3C000020, len(segment)) + segment
    checksum = 0xEF
    for b in segment:
        checksum ^= b
    data += bytes(15 - len(data) % 16) + bytes([checksum])
    data += hashlib.sha256(data).digest()
    return data + (hashlib.sha256(data).hexdigest().encode() if digest_text else b"")


def esp32_original_image(version=b"v5.233.1", date=b"", time_=b"", code_size=4000):
    """an app image standing in for the original firmware of the ESP32 box (project toniebox-esp32-eu): the app
    description (date and time empty, as observed) and the two vendor hosts as strings, no server
    block"""
    desc = struct.pack("<II", 0xABCD5432, 0) + bytes(8) + version.ljust(32, b"\x00") + b"toniebox-esp32-eu".ljust(32, b"\x00")
    desc += time_.ljust(16, b"\x00") + date.ljust(16, b"\x00")
    desc = desc.ljust(256, b"\x00")
    strings = b"\x00https://prod.de.tbs.toys\x00rtnl.bxcl.de\x00"
    segment = desc + strings + bytes(code_size)
    header = bytes([0xE9, 1, 2, 0x3F]) + struct.pack("<I", 0x40370000) + bytes([0xEE, 0, 0, 0]) + struct.pack("<H", 9)
    header += bytes(9) + bytes([1])
    data = header + struct.pack("<II", 0x3C000020, len(segment)) + segment
    checksum = 0xEF
    for b in segment:
        checksum ^= b
    data += bytes(15 - len(data) % 16) + bytes([checksum])
    return data + hashlib.sha256(data).digest()


def esp32_flash_dump(slots):
    """an 8 MB flash dump of the ESP32 box with the partition table of the original firmware and the given
    app images in ota_0, ota_1, ota_2 (None: an erased slot)"""
    dump = bytearray(b"\xff" * 0x800000)
    dump[0] = 0xE9  # the bootloader at 0
    table = [(1, 1, 0xA000, 0x1000, b"phy_init"), (1, 2, 0xB000, 0x4000, b"nvs"), (1, 0x81, 0xF000, 0x160000, b"assets"),
             (1, 0, 0x16F000, 0x2000, b"otadata"), (0, 0x10, 0x180000, 0x220000, b"ota_0"), (0, 0x11, 0x3A0000, 0x220000, b"ota_1"),
             (0, 0x12, 0x5C0000, 0x220000, b"ota_2")]
    for i, (kind, sub, offset, size, label) in enumerate(table):
        dump[0x9000 + 32 * i: 0x9000 + 32 * (i + 1)] = b"\xaa\x50" + bytes([kind, sub]) + struct.pack("<II", offset, size) + label.ljust(16, b"\x00") + bytes(4)
    for slot, image in zip((0x180000, 0x3A0000, 0x5C0000), slots):
        if image is not None:
            dump[slot: slot + len(image)] = image
    return bytes(dump)


def esp32_server_block(body):
    """host and port of the server block in a delivered body"""
    at = body.find(b"CFWSRV" + b"01")
    return body[at + 8: at + 72].rstrip(b"\x00").decode(), struct.unpack_from("<H", body, at + 72)[0]


def page_version(page):
    """the value of a setup page in item 7"""
    return crc32(page) >> 1


def release_package(files, compressed=False):
    """a release package: a zip of the given {name: bytes}, stored as tools/release.sh writes it"""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return out.getvalue()
