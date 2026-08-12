"""PCAP file writer for Wireshark analysis.

Writes a standard PCAP file with Ethernet (LINKTYPE 1, DLT_EN10MB)
encapsulation.  Each packet is Ethernet + IPv4 + UDP (port 4729) + GSMTAP,
matching a real ``tcpdump -i lo udp port 4729`` capture of GSMTAP-over-UDP
(simtrace2-sniff / simtrace2-pysniff output).
"""

import io
import struct
import time

PCAP_MAGIC = 0xa1b2c3d4
LINKTYPE_ETHERNET = 1  # DLT_EN10MB

GSMTAP_UDP_PORT = 4729

_LOOPBACK = b'\x7f\x00\x00\x01'

_PCAP_GLOBAL_HDR_FMT = '<IHHiIII'
_PCAP_GLOBAL_HDR_SIZE = struct.calcsize(_PCAP_GLOBAL_HDR_FMT)

_PCAP_PKT_HDR_FMT = '<IIII'
_PCAP_PKT_HDR_SIZE = struct.calcsize(_PCAP_PKT_HDR_FMT)


def _checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


def wrap_gsmtap(gsmtap_payload):
    """Wrap a GSMTAP message in Ethernet + IPv4 + UDP (port 4729) headers."""
    udp_len = 8 + len(gsmtap_payload)

    udp_nocs = struct.pack('!HHHH', GSMTAP_UDP_PORT, GSMTAP_UDP_PORT, udp_len, 0)
    pseudo = _LOOPBACK + _LOOPBACK + struct.pack('!BBH', 0, 17, udp_len)
    udp_csum = _checksum(pseudo + udp_nocs + gsmtap_payload)
    udp = struct.pack('!HHHH', GSMTAP_UDP_PORT, GSMTAP_UDP_PORT, udp_len, udp_csum) + gsmtap_payload

    ip_len = 20 + len(udp)
    ip_nocs = struct.pack('!BBHHHBBH4s4s', 0x45, 0x00, ip_len, 0, 0x4000, 64, 17, 0,
                          _LOOPBACK, _LOOPBACK)
    ip_csum = _checksum(ip_nocs)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0x00, ip_len, 0, 0x4000, 64, 17, ip_csum,
                     _LOOPBACK, _LOOPBACK) + udp

    eth = struct.pack('!6s6sH', b'\x00' * 6, b'\x00' * 6, 0x0800)
    return eth + ip


def build_pcap(packets):
    """Build a PCAP file in memory.

    *packets* is a list of ``(gsmtap_hdr, data, ts)`` tuples, where
    gsmtap_hdr is the packed 16-byte GSMTAP header and ts is a
    seconds-since-epoch float.  Returns the PCAP file contents as bytes.
    """
    buf = io.BytesIO()
    buf.write(struct.pack(
        _PCAP_GLOBAL_HDR_FMT,
        PCAP_MAGIC,
        2,
        4,
        0,
        0,
        65535,
        LINKTYPE_ETHERNET,
    ))
    for gsmtap_hdr, data, ts in packets:
        packet = wrap_gsmtap(gsmtap_hdr + data)
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        buf.write(struct.pack(
            _PCAP_PKT_HDR_FMT,
            ts_sec,
            ts_usec,
            len(packet),
            len(packet),
        ))
        buf.write(packet)
    return buf.getvalue()


class PcapWriter:
    """Write sniffed messages as Ethernet/IP/UDP/GSMTAP PCAP packets."""

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
            LINKTYPE_ETHERNET, # network (Ethernet)
        )
        self._f.write(hdr)

    def write_packet(self, gsmtap_hdr, data, ts=None):
        """Write a single GSMTAP-encapsulated packet (wrapped in IP/UDP/Eth).

        *gsmtap_hdr* is the 16-byte GSMTAP header (already packed).
        *data* is the raw APDU/ATR bytes.
        """
        if ts is None:
            ts = time.time()

        packet = wrap_gsmtap(gsmtap_hdr + data)
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
