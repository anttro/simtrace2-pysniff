"""PCAP file writer for Wireshark analysis.

Writes a standard PCAP file with LINKTYPE_GSMTAP (155, 0x009b).
Each packet is a GSMTAP header + raw APDU/ATR data.
"""

import struct
import time

PCAP_MAGIC = 0xa1b2c3d4
LINKTYPE_GSMTAP = 155  # 0x009b

_PCAP_GLOBAL_HDR_FMT = '<IHHiIII'
_PCAP_GLOBAL_HDR_SIZE = struct.calcsize(_PCAP_GLOBAL_HDR_FMT)

_PCAP_PKT_HDR_FMT = '<IIII'
_PCAP_PKT_HDR_SIZE = struct.calcsize(_PCAP_PKT_HDR_FMT)


class PcapWriter:
    """Write sniffed messages as GSMTAP-encapsulated PCAP packets."""

    def __init__(self, path):
        self._f = open(path, 'wb')
        self._write_global_header()

    def _write_global_header(self):
        hdr = struct.pack(
            _PCAP_GLOBAL_HDR_FMT,
            PCAP_MAGIC,        # magic_number
            2,                 # version_major
            4,                 # version_minor
            0,                 # thiszone (GMT)
            0,                 # sigfigs
            65535,             # snaplen
            LINKTYPE_GSMTAP,   # network (LINKTYPE_GSMTAP)
        )
        self._f.write(hdr)

    def write_packet(self, gsmtap_hdr, data, ts=None):
        """Write a single GSMTAP-encapsulated packet.

        *gsmtap_hdr* is the 16-byte GSMTAP header (already packed).
        *data* is the raw APDU/ATR bytes.
        """
        if ts is None:
            ts = time.time()

        packet = gsmtap_hdr + data
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)

        pkt_hdr = struct.pack(
            _PCAP_PKT_HDR_FMT,
            ts_sec,            # ts_sec
            ts_usec,           # ts_usec
            len(packet),       # incl_len
            len(packet),       # orig_len
        )
        self._f.write(pkt_hdr + packet)

    def close(self):
        self._f.close()
