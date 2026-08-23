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


class TestTsresol(unittest.TestCase):
    def test_nanoseconds_after_padded_option(self):
        from simtrace2_pysniff.pcap import _parse_tsresol
        # if_name (code 2, len 2, "lo") then if_tsresol (code 9, len 1, 9), LE.
        opts = (struct.pack('<HH', 2, 2) + b'lo' + b'\x00\x00' +
                struct.pack('<HH', 9, 1) + b'\x09' + b'\x00\x00\x00' +
                struct.pack('<HH', 0, 0))
        self.assertEqual(_parse_tsresol(opts, '<'), 1e-9)

    def test_default_microseconds(self):
        from simtrace2_pysniff.pcap import _parse_tsresol
        self.assertEqual(_parse_tsresol(struct.pack('<HH', 0, 0), '<'), 1e-6)

    def test_parse_pcapng_nanoseconds(self):
        # IDB with if_tsresol=9 → EPB timestamps in nanoseconds → seconds.
        shb = _pcapng_block(0x0A0D0D0A, struct.pack('>IHHq', 0x1A2B3C4D, 1, 0, -1))
        idb = _pcapng_block(0x00000001,
                            struct.pack('>HHI', LINKTYPE_ETHERNET, 0, 65535) +
                            struct.pack('>HH', 9, 1) + b'\x09' + b'\x00\x00\x00' +
                            struct.pack('>HH', 0, 0))
        # epoch 1600000000.5 s → 1600000000500000000 ns
        raw = 1600000000500000000
        ts_hi, ts_lo = raw >> 32, raw & 0xFFFFFFFF
        frame = wrap_gsmtap(_gsmtap_hdr(GSMTAP_SIM_ATR) + b'\x3b\x04')
        epb = _pcapng_block(0x00000006,
                            struct.pack('>IIIII', 0, ts_hi, ts_lo, len(frame), len(frame)) + frame)
        parsed = list(parse_pcapng(shb + idb + epb))
        self.assertEqual(len(parsed), 1)
        self.assertAlmostEqual(parsed[0][0], 1600000000.5, places=6)


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

    def test_import_session_window_from_timestamps(self):
        from datetime import datetime
        # Two packets one hour apart in epoch time.
        t0 = 1600000000.0
        packets = [
            (_gsmtap_hdr(GSMTAP_SIM_ATR), b'\x3b\x00', t0),
            (_gsmtap_hdr(GSMTAP_SIM_APDU), b'\x80\xf2\x00\x00\x00', t0 + 3600.0),
        ]
        h, _ = self._handler(build_pcap(packets))
        h._handle_import_pcap({'name': ['window']})
        session = h.db.get_session(h._json['session_id'])
        started = datetime.fromisoformat(session['started'])
        ended = datetime.fromisoformat(session['ended'])
        self.assertEqual((ended - started).total_seconds(), 3600.0)

    def test_import_synthetic_ts_falls_back(self):
        # SPB-style synthetic timestamps (0, 1, …) → keep wall-clock fallback.
        packets = [
            (_gsmtap_hdr(GSMTAP_SIM_ATR), b'\x3b\x00', 0.0),
            (_gsmtap_hdr(GSMTAP_SIM_APDU), b'\x80\xf2\x00\x00\x00', 1.0),
        ]
        h, _ = self._handler(build_pcap(packets))
        h._handle_import_pcap({'name': ['synth']})
        session = h.db.get_session(h._json['session_id'])
        self.assertTrue(session['ended'] is not None)


class TestVersion(unittest.TestCase):
    def test_package_version(self):
        from simtrace2_pysniff import __version__
        self.assertEqual(__version__, '1.15.1')

    def test_status_includes_version(self):
        import os
        from simtrace2_pysniff.server.server import RequestHandler
        from simtrace2_pysniff.server.database import Database
        from simtrace2_pysniff import __version__

        class FakeCapture:
            active = False
            session_id = None
            device_connected = None

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


class TestCaptureDisabled(unittest.TestCase):
    def _handler(self, capture_mode):
        import os
        from simtrace2_pysniff.server.server import RequestHandler
        from simtrace2_pysniff.server.database import Database

        class Fake(RequestHandler):
            def __init__(self, db, capture_mode):
                self.db = db
                self.capture = None
                self.capture_mode = capture_mode
                self._status = None
                self._json = None

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
        return Fake(db, capture_mode)

    def test_status_reports_disabled(self):
        h = self._handler('disabled')
        h._handle_status()
        self.assertEqual(h._json['capture_mode'], 'disabled')
        self.assertFalse(h._json['capture_active'])
        self.assertIsNone(h._json['session_id'])

    def test_capture_start_403(self):
        h = self._handler('disabled')
        h._handle_capture_start()
        self.assertEqual(h._status, 403)
        self.assertIn('Capture disabled', h._json['error'])

    def test_capture_stop_403(self):
        h = self._handler('disabled')
        h._handle_capture_stop()
        self.assertEqual(h._status, 403)

    def test_status_reports_gsmtap(self):
        h = self._handler('gsmtap')
        h._handle_status()
        self.assertEqual(h._json['capture_mode'], 'gsmtap')


if __name__ == '__main__':
    unittest.main()
