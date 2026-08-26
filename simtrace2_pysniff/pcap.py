"""PCAP file writer and reader for Wireshark analysis.

Writes a standard PCAP file with Ethernet (LINKTYPE 1, DLT_EN10MB)
encapsulation.  Each packet is Ethernet + IPv4 + UDP (port 4729) + GSMTAP,
matching a real ``tcpdump -i lo udp port 4729`` capture of GSMTAP-over-UDP
(simtrace2-sniff / simtrace2-pysniff output).

Reads classic PCAP (micro/nano, both byte orders) and PCAPNG files,
extracting GSMTAP-SIM packets (APDU/ATR/PPS) for import into a session.
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

# --- GSMTAP ---
GSMTAP_TYPE_SIM = 0x04
GSMTAP_SIM_APDU = 0x00
GSMTAP_SIM_ATR = 0x01
GSMTAP_SIM_PPS_REQ = 0x02
GSMTAP_SIM_PPS_RSP = 0x03
GSMTAP_SIM_RST_EVENT = 0x10  # sigrok-iso7816-stream custom sub-type
GSMTAP_SIM_VCC_EVENT = 0x11  # sigrok-iso7816-stream custom sub-type
_GSMTAP_HDR_FMT = '!BBBBHBBIBBBB'
_GSMTAP_HDR_SIZE = struct.calcsize(_GSMTAP_HDR_FMT)  # 16 bytes

# --- Link types (DLT values) we can unwrap to IP/UDP ---
LINKTYPE_NULL = 0
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108       # Linux SLL
LINKTYPE_LOOP_V2 = 113    # Linux SLL2
LINKTYPE_IPV4 = 228
LINKTYPE_SLL2 = 276

_SUB_TYPE_NAMES = {
    GSMTAP_SIM_APDU: 'tpdu',
    GSMTAP_SIM_ATR: 'atr',
    GSMTAP_SIM_PPS_REQ: 'pps',
    GSMTAP_SIM_PPS_RSP: 'pps',
    GSMTAP_SIM_RST_EVENT: 'rst',
    GSMTAP_SIM_VCC_EVENT: 'vcc',
}

# pcapng block types
_PNG_SHB = 0x0A0D0D0A
_PNG_IDB = 0x00000001
_PNG_EPB = 0x00000006
_PNG_SPB = 0x00000003

_PNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D


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


# ──────────────────── Readers (import) ────────────────────

def _ipv4_udp_payload(ip):
    """Extract the UDP payload from an IPv4 packet (bytes)."""
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl + 8 or ip[9] != 17:  # protocol UDP
        return None
    udp = ip[ihl:]
    udp_len = struct.unpack('!H', udp[4:6])[0]
    if udp_len < 8 or len(udp) < 8:
        return None
    return udp[8:udp_len]


def _frame_to_udp_payload(frame, linktype):
    """Unwrap a link-layer frame down to the UDP payload (bytes or None)."""
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = frame[12:14]
        if ethertype == b'\x08\x00':      # IPv4
            return _ipv4_udp_payload(frame[14:])
        # IPv6 and non-IP ethertypes are not GSMTAP-over-UDP for our use
        return None
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4):
        return _ipv4_udp_payload(frame)
    if linktype == LINKTYPE_NULL:
        if len(frame) < 4:
            return None
        family = struct.unpack('<I', frame[:4])[0]
        if family == 2:                   # AF_INET
            return _ipv4_udp_payload(frame[4:])
        return None
    if linktype == LINKTYPE_LOOP:         # Linux SLL (16-byte header)
        if len(frame) < 16:
            return None
        proto = struct.unpack('!H', frame[14:16])[0]
        if proto == 0x0800:
            return _ipv4_udp_payload(frame[16:])
        return None
    if linktype in (LINKTYPE_LOOP_V2, LINKTYPE_SLL2):  # Linux SLL2 (20-byte)
        if len(frame) < 20:
            return None
        proto = struct.unpack('!H', frame[0:2])[0]
        if proto == 0x0800:
            return _ipv4_udp_payload(frame[20:])
        return None
    return None


def _parse_gsmtap_hdr(data):
    """Parse a GSMTAP header; return (sub_type, payload, flags) or None."""
    if len(data) < _GSMTAP_HDR_SIZE:
        return None
    (version, hdr_len, pkt_type, _ts, _arfcn, _noise, _signal,
     _frame, sub_type, _ant, _slot, res) = struct.unpack(
        _GSMTAP_HDR_FMT, data[:_GSMTAP_HDR_SIZE])
    if version != 0x02 or pkt_type != GSMTAP_TYPE_SIM:
        return None
    hdr_size = hdr_len * 4
    if hdr_size < _GSMTAP_HDR_SIZE or len(data) < hdr_size:
        return None
    return sub_type, data[hdr_size:], res


def _scan_gsmtap(frame):
    """Fallback: scan a frame for a GSMTAP-SIM header, return (sub_type, payload, flags)."""
    for off in range(0, len(frame) - _GSMTAP_HDR_SIZE + 1):
        parsed = _parse_gsmtap_hdr(frame[off:])
        if parsed is not None:
            return parsed
    return None


def extract_gsmtap(frame, linktype):
    """Extract a GSMTAP-SIM message from a link-layer frame.

    Returns ``(sub_type, payload, flags)`` or ``None`` if the frame carries
    no GSMTAP-SIM data.
    """
    udp = _frame_to_udp_payload(frame, linktype)
    if udp:
        parsed = _parse_gsmtap_hdr(udp)
        if parsed is not None:
            return parsed
    # Unknown linktype or UDP parse failure → heuristic scan.
    return _scan_gsmtap(frame)


def _gsmtap_to_msg(sub_type, payload):
    """Map a GSMTAP SIM sub_type to a message type; None if unsupported."""
    return _SUB_TYPE_NAMES.get(sub_type)


def parse_pcap(data):
    """Parse a classic PCAP file, yielding (ts, msg_type, payload) tuples.

    Supports micro/nanosecond timestamps and both byte orders.
    Only GSMTAP-SIM packets are yielded.
    """
    if len(data) < _PCAP_GLOBAL_HDR_SIZE:
        return
    magic = struct.unpack('<I', data[:4])[0]
    if magic == 0xa1b2c3d4:
        endian, ns = '<', False
    elif magic == 0xd4c3b2a1:
        endian, ns = '>', False
    elif magic == 0xa1b23c4d:
        endian, ns = '<', True
    elif magic == 0x4d3cb2a1:
        endian, ns = '>', True
    else:
        return

    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(
        endian + 'HHIIII', data[4:_PCAP_GLOBAL_HDR_SIZE])

    off = _PCAP_GLOBAL_HDR_SIZE
    n = len(data)
    while off + _PCAP_PKT_HDR_SIZE <= n:
        ts_sec, ts_frac, incl_len, _orig = struct.unpack(
            endian + 'IIII', data[off:off + _PCAP_PKT_HDR_SIZE])
        off += _PCAP_PKT_HDR_SIZE
        if incl_len > n - off:
            break
        frame = data[off:off + incl_len]
        off += incl_len
        ts = ts_sec + ts_frac / (1_000_000_000 if ns else 1_000_000)
        parsed = extract_gsmtap(frame, linktype)
        if parsed is None:
            continue
        sub_type, payload, flags = parsed
        msg_type = _gsmtap_to_msg(sub_type, payload)
        if msg_type is not None:
            yield ts, msg_type, payload, flags


def parse_pcapng(data):
    """Parse a PCAPNG file, yielding (ts, msg_type, payload) tuples.

    Only GSMTAP-SIM packets are yielded.  Timestamps are raw
    (ts_high << 32 | ts_low) scaled by each interface's resolution.
    """
    if len(data) < 12 or struct.unpack('<I', data[:4])[0] != _PNG_SHB:
        return

    bom = data[8:12]  # Byte-Order Magic lives in the SHB body
    if bom == b'\x1a\x2b\x3c\x4d':
        endian = '>'
    elif bom == b'\x4d\x3c\x2b\x1a':
        endian = '<'
    else:
        return

    linktypes = {}      # interface_id -> linktype
    tsresols = {}       # interface_id -> seconds per tick
    spb_ts = 0          # file-order timestamp for SPB blocks (no timestamp)
    off = 0
    n = len(data)
    while off + 8 <= n:
        block_type = struct.unpack(endian + 'I', data[off:off + 4])[0]
        total_len = struct.unpack(endian + 'I', data[off + 4:off + 8])[0]
        if total_len < 12 or off + total_len > n:
            break
        body = data[off + 8:off + total_len - 4]
        off += total_len

        if block_type == _PNG_IDB and len(body) >= 8:
            linktype, _res, _snaplen = struct.unpack(
                endian + 'HHI', body[:8])
            iface = len(linktypes)  # IDBs are numbered by appearance
            linktypes[iface] = linktype
            tsresols[iface] = _parse_tsresol(body[8:], endian)
        elif block_type == _PNG_EPB and len(body) >= 20:
            iface, ts_hi, ts_lo, cap_len, _orig = struct.unpack(
                endian + 'IIIII', body[:20])
            if cap_len <= len(body) - 20:
                frame = body[20:20 + cap_len]
                ts = _scale_ts(ts_hi, ts_lo, tsresols.get(iface))
                parsed = extract_gsmtap(frame, linktypes.get(iface))
                if parsed is not None:
                    sub_type, payload, flags = parsed
                    msg_type = _gsmtap_to_msg(sub_type, payload)
                    if msg_type is not None:
                        yield ts, msg_type, payload, flags
        elif block_type == _PNG_SPB and len(body) >= 4:
            cap_len, = struct.unpack(endian + 'I', body[:4])
            if cap_len <= len(body) - 4:
                frame = body[4:4 + cap_len]
                # SPB has no timestamp and no interface; use file-order ts.
                parsed = _scan_gsmtap(frame)
                if parsed is not None:
                    sub_type, payload, flags = parsed
                    msg_type = _gsmtap_to_msg(sub_type, payload)
                    if msg_type is not None:
                        yield float(spb_ts), msg_type, payload, flags
                        spb_ts += 1


def _parse_tsresol(options, endian):
    """Parse if_tsresol from IDB options; return seconds per timestamp tick."""
    i = 0
    n = len(options)
    while i + 4 <= n:
        code, length = struct.unpack(endian + 'HH', options[i:i + 4])
        i += 4
        if code == 9 and length == 1:
            b = options[i]
            if b & 0x80:
                return 2 ** (-(b & 0x7F))
            return 10 ** (-b)
        i += length + ((-length) % 4)  # options are padded to a 32-bit boundary
    return 1e-6  # default: microseconds


def _scale_ts(ts_hi, ts_lo, tsresol):
    """Combine 64-bit pcapng timestamp into seconds since epoch (approx)."""
    raw = (ts_hi << 32) | ts_lo
    return raw * (tsresol if tsresol is not None else 1e-6)
