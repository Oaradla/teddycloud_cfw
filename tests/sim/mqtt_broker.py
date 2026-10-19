"""
A minimal MQTT 3.1.1 broker for the tests: one client at a time (teddyCloud), QoS 0 only.
It answers CONNECT, SUBSCRIBE and PINGREQ, keeps what the client publishes and subscribes,
and publishes to the client what a test sends.
"""

import socket
import struct
import threading
import time


def _length(n):
    out = bytearray()
    while True:
        byte, n = n % 128, n // 128
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _string(s):
    data = s.encode()
    return struct.pack(">H", len(data)) + data


class MqttBroker:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(4)
        self.port = self.server.getsockname()[1]
        self.published = {}
        self.subscribed = set()
        self.client = None
        self.lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self.server.close()
        if self.client:
            self.client.close()

    def _accept(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            self.client = conn
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _read(self, conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise ConnectionError
            data += chunk
        return data

    def _serve(self, conn):
        try:
            while True:
                header = self._read(conn, 1)[0]
                length, shift = 0, 0
                while True:
                    byte = self._read(conn, 1)[0]
                    length |= (byte & 0x7F) << shift
                    shift += 7
                    if not byte & 0x80:
                        break
                body = self._read(conn, length)
                kind = header >> 4
                if kind == 1:  # CONNECT
                    conn.sendall(b"\x20\x02\x00\x00")
                elif kind == 3:  # PUBLISH
                    n = struct.unpack(">H", body[:2])[0]
                    topic = body[2:2 + n].decode()
                    rest = body[2 + n:]
                    if (header >> 1) & 3:
                        packet_id, rest = rest[:2], rest[2:]
                        conn.sendall(b"\x40\x02" + packet_id)
                    with self.lock:
                        self.published[topic] = rest.decode(errors="replace")
                elif kind == 8:  # SUBSCRIBE
                    packet_id, pos, granted = body[:2], 2, b""
                    while pos < len(body):
                        n = struct.unpack(">H", body[pos:pos + 2])[0]
                        with self.lock:
                            self.subscribed.add(body[pos + 2:pos + 2 + n].decode())
                        pos += 2 + n + 1
                        granted += b"\x00"
                    conn.sendall(b"\x90" + _length(2 + len(granted)) + packet_id + granted)
                elif kind == 12:  # PINGREQ
                    conn.sendall(b"\xd0\x00")
                elif kind == 14:  # DISCONNECT
                    return
        except (ConnectionError, OSError):
            return

    def publish(self, topic, payload):
        body = _string(topic) + payload.encode()
        self.client.sendall(b"\x30" + _length(len(body)) + body)

    def wait_subscribed(self, topic, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                if topic in self.subscribed:
                    return True
            time.sleep(0.2)
        return False

    def value(self, topic):
        with self.lock:
            return self.published.get(topic)
