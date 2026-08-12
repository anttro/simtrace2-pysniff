"""Tests for PCAP generation and Content-Disposition filename."""

import struct
import unittest

from simtrace2_pysniff.pcap import build_pcap, PCAP_MAGIC, LINKTYPE_GSMTAP
from simtrace2_pysniff.server.server import _content_disposition


class TestBuildPcap(unittest.TestCase):
    def _gsmtap_hdr(self, sub_type):
        import struct
        return struct.pack('!BBBBHBBIBBBB', 2, 4, 7, 0, 0, 0, 0, 0, sub_type, 0, 0, 0)

    def test_empty(self):
        data = build_pcap([])
        self.assertEqual(len(data), 24)  # just the global header
        magic, vmaj, vmin, _tz, _sig, snaplen, network = struct.unpack('<IHHiIII', data[:24])
        self.assertEqual(magic, PCAP_MAGIC)
        self.assertEqual((vmaj, vmin), (2, 4))
        self.assertEqual(snaplen, 65535)
        self.assertEqual(network, LINKTYPE_GSMTAP)

    def test_one_packet(self):
        pkt = build_pcap([(self._gsmtap_hdr(2), b'\xa0\xa4\x00\x00\x02\x3f\x00', 1234567890.5)])
        self.assertEqual(len(pkt), 24 + 16 + (16 + 7))  # global + pkt hdr + gsmtap hdr + data
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', data_bytes := pkt[24:40])
        self.assertEqual(ts_sec, 1234567890)
        self.assertEqual(ts_usec, 500000)
        self.assertEqual(incl_len, 23)
        self.assertEqual(orig_len, 23)

    def test_multiple_packets(self):
        packets = [
            (self._gsmtap_hdr(1), b'\x3b\x00', 1.0),
            (self._gsmtap_hdr(2), b'\x80\xf2\x00\x00\x00', 2.0),
        ]
        data = build_pcap(packets)
        # global header + 2 packets (each: 16 pkt hdr + 16 gsmtap hdr + data)
        self.assertEqual(len(data), 24 + (16 + 16 + 2) + (16 + 16 + 5))


class TestContentDisposition(unittest.TestCase):
    def test_ascii(self):
        h = _content_disposition('My Capture.pcap')
        self.assertIn('filename="My Capture.pcap"', h)

    def test_unicode(self):
        h = _content_disposition('Моя сессия.pcap')
        # ASCII fallback uses '?' replacements; UTF-8 filename* carries the real name
        self.assertIn("filename*=UTF-8''", h)
        self.assertIn('%D0%9C', h)  # 'М' = %D0%9C

    def test_special_chars(self):
        h = _content_disposition('a"b.pcap')
        self.assertIn('filename="a_b.pcap"', h)


if __name__ == '__main__':
    unittest.main()
