"""Tests for PCAP/PCAPNG import parsing and the import endpoint."""

import os
import struct
import tempfile
import unittest

from simtrace2_pysniff.pcap import (
    build_pcap, parse_pcap, parse_pcapng, wrap_gsmtap, extract_gsmtap,
    LINKTYPE_ETHERNET,
)
from simtrace2_pysniff.gsmtap import build_gsmtap_packet, GSMTAP_SIM_ATR, GSMTAP_SIM_APDU


def _gsmtap_hdr(sub_type):
    return build_gsmtap_packet(sub_type, b'')[:16]


def _pcapng_block(block_type, body):
    body = body + b'\x00' * ((-len(body)) % 4)
    total = 8 + len(body) + 4
    return struct.pack('>II', block_type, total) + body + struct.pack('>I', total)


def _build_pcapng(packets):
    """Build a minimal big-endian PCAPNG with one Ethernet interface.

    *packets* is a list of (gsmtap_hdr, data, ts_hi, ts_lo) tuples.
    """
    shb = _pcapng_block(0x0A0D0D0A, struct.pack('>IHHq', 0x1A2B3C4D, 1, 0, -1))
    idb = _pcapng_block(0x00000001,
                        struct.pack('>HHI', LINKTYPE_ETHERNET, 0, 65535) +
                        struct.pack('>HH', 0, 0))
    out = shb + idb
    for gsmtap_hdr, data, ts_hi, ts_lo in packets:
        frame = wrap_gsmtap(gsmtap_hdr + data)
        epb = _pcapng_block(
            0x00000006,
            struct.pack('>IIIII', 0, ts_hi, ts_lo, len(frame), len(frame)) + frame)
        out += epb
    return out


class TestParsePcap(unittest.TestCase):
    def test_roundtrip(self):
        packets = [
            (_gsmtap_hdr(GSMTAP_SIM_ATR), b'\x3b\x00', 1.0),
            (_gsmtap_hdr(GSMTAP_SIM_APDU), b'\x80\xf2\x00\x00\x00', 2.5),
        ]
        data = build_pcap(packets)
        parsed = [(round(ts, 1), t, payload) for ts, t, payload in parse_pcap(data)]
        self.assertEqual(parsed, [
            (1.0, 'atr', b'\x3b\x00'),
            (2.5, 'tpdu', b'\x80\xf2\x00\x00\x00'),
        ])

    def test_no_gsmtap(self):
        # A packet that is not GSMTAP-SIM yields nothing.
        frame = wrap_gsmtap(b'\x03' + b'\x00' * 15)  # type=3, not SIM
        # build a fake pcap with an Ethernet frame that has no GSMTAP
        packets = [(b'', b'\x00' * 64, 1.0)]
        data = build_pcap(packets)
        self.assertEqual(list(parse_pcap(data)), [])


class TestParsePcapng(unittest.TestCase):
    def test_parse(self):
        data = _build_pcapng([
            (_gsmtap_hdr(GSMTAP_SIM_ATR), b'\x3b\x04', 0, 0),
            (_gsmtap_hdr(GSMTAP_SIM_APDU), b'\x80\xf2\x00\x00\x00', 0, 1),
        ])
        parsed = [(t, payload) for _ts, t, payload in parse_pcapng(data)]
        self.assertEqual(parsed, [
            ('atr', b'\x3b\x04'),
            ('tpdu', b'\x80\xf2\x00\x00\x00'),
        ])

    def test_no_gsmtap(self):
        # IDB + EPB carrying a GSMTAP header whose type != SIM → no messages.
        shb = _pcapng_block(0x0A0D0D0A, struct.pack('>IHHq', 0x1A2B3C4D, 1, 0, -1))
        idb = _pcapng_block(0x00000001,
                            struct.pack('>HHI', LINKTYPE_ETHERNET, 0, 65535) +
                            struct.pack('>HH', 0, 0))
        non_sim = struct.pack('!BBBBHBBIBBBB', 2, 4, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0) + b'\x00'
        epb = _pcapng_block(0x00000006,
                            struct.pack('>IIIII', 0, 0, 0, len(non_sim), len(non_sim)) + non_sim)
        self.assertEqual(list(parse_pcapng(shb + idb + epb)), [])


class TestImportEndpoint(unittest.TestCase):
    def _handler(self, body):
        from simtrace2_pysniff.server.server import RequestHandler
        from simtrace2_pysniff.server.database import Database

        class Fake(RequestHandler):
            def __init__(self, body, db):
                self.db = db
                self._body = body
                self._status = None
                self._json = None

            def _read_body(self):
                return self._body

            def _send_json(self, data, status=200):
                self._status = status
                self._json = data

            def _send_error(self, status, message):
                self._status = status
                self._json = {'error': message}

        tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        tmp.close()
        db = Database(tmp.name)
        self.addCleanup(lambda: (db._conn.close(), os.remove(tmp.name)))
        return Fake(body, db), tmp.name

    def test_import_pcap_creates_session(self):
        packets = [
            (_gsmtap_hdr(GSMTAP_SIM_ATR), b'\x3b\x00', 1.0),
            (_gsmtap_hdr(GSMTAP_SIM_APDU), b'\x80\xf2\x00\x00\x00', 2.0),
        ]
        h, _ = self._handler(build_pcap(packets))
        h._handle_import_pcap({'name': ['mytrace']})
        self.assertEqual(h._status, 200)
        self.assertEqual(h._json['name'], 'mytrace')
        self.assertEqual(h._json['message_count'], 2)
        self.assertEqual(h.db.count_messages(h._json['session_id']), 2)

    def test_import_no_gsmtap_400(self):
        # Ethernet frame with no GSMTAP → no usable data.
        h, _ = self._handler(build_pcap([(b'', b'\x00' * 64, 1.0)]))
        h._handle_import_pcap({'name': ['empty']})
        self.assertEqual(h._status, 400)
        self.assertIn('No GSMTAP data', h._json['error'])
        self.assertEqual(h.db.count_sessions(), 0)


class TestVersion(unittest.TestCase):
    def test_package_version(self):
        from simtrace2_pysniff import __version__
        self.assertEqual(__version__, '1.1.0')

    def test_status_includes_version(self):
        import os
        from simtrace2_pysniff.server.server import RequestHandler
        from simtrace2_pysniff.server.database import Database
        from simtrace2_pysniff import __version__

        class FakeCapture:
            active = False
            session_id = None

        class Fake(RequestHandler):
            def __init__(self, db):
                self.db = db
                self.capture = FakeCapture()
                self._json = None

            def _send_json(self, data, status=200):
                self._json = data

        tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        tmp.close()
        db = Database(tmp.name)
        self.addCleanup(lambda: (db._conn.close(), os.remove(tmp.name)))

        h = Fake(db)
        h._handle_status()
        self.assertEqual(h._json['version'], __version__)


if __name__ == '__main__':
    unittest.main()
