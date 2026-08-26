"""GSMTAP UDP sender for Wireshark integration.

GSMTAP header format (big-endian, 16 bytes). Based on libosmocore's gsmtap.h.
"""

import struct
import socket

GSMTAP_VERSION = 0x02
GSMTAP_HDR_LEN = 4  # in 32-bit words (16 bytes)
GSMTAP_TYPE_SIM = 0x04

GSMTAP_SIM_APDU = 0x00
GSMTAP_SIM_ATR = 0x01
GSMTAP_SIM_PPS_REQ = 0x02
GSMTAP_SIM_PPS_RSP = 0x03
# Custom sub-types from the sigrok-iso7816-stream decoder
# (github.com/anttro/sigrok_iso7816_stream): line-level events.
GSMTAP_SIM_RST_EVENT = 0x10
GSMTAP_SIM_VCC_EVENT = 0x11

GSMTAP_UDP_PORT = 4729

_GSMTAP_HDR_FMT = '!BBBBHBBIBBBB'  # 16 bytes, big-endian
_GSMTAP_HDR_SIZE = struct.calcsize(_GSMTAP_HDR_FMT)


def build_gsmtap_packet(sub_type, data, slot_nr=0):
    """Build a GSMTAP packet as bytes.

    Returns *gsmtap_hdr* + *data* as a single bytes object.
    """
    hdr = struct.pack(
        _GSMTAP_HDR_FMT,
        GSMTAP_VERSION,    # version
        GSMTAP_HDR_LEN,    # hdr_len (in 32-bit words)
        GSMTAP_TYPE_SIM,   # type
        0,                 # timeslot
        0,                 # arfcn
        0,                 # noise_db
        0,                 # signal_db
        0,                 # frame_number
        sub_type,          # sub_type
        0,                 # antenna_nr
        slot_nr,           # sub_slot
        0,                 # res
    )
    return hdr + data


class GsmtapSender:
    """Send ATR/APDU data as GSMTAP UDP packets."""

    def __init__(self, host='127.0.0.1', port=GSMTAP_UDP_PORT):
        self._addr = (host, port)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_atr(self, data, slot_nr=0):
        packet = build_gsmtap_packet(GSMTAP_SIM_ATR, data, slot_nr)
        self._sock.sendto(packet, self._addr)

    def send_apdu(self, data, slot_nr=0):
        packet = build_gsmtap_packet(GSMTAP_SIM_APDU, data, slot_nr)
        self._sock.sendto(packet, self._addr)

    def close(self):
        self._sock.close()


class GsmtapReceiver:
    """Receive GSMTAP-SIM packets over UDP (compatible with simtrace2-sniff)."""

    def __init__(self, bind_ip='127.0.0.1', bind_port=GSMTAP_UDP_PORT):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_ip, bind_port))
        self._sock.settimeout(1.0)

    def read_packet(self):
        """Block until a GSMTAP-SIM packet arrives.

        Returns ``(sub_type, data)`` on success or ``(None, None)``
        on timeout.  *sub_type* is ``GSMTAP_SIM_ATR`` or ``GSMTAP_SIM_APDU``.
        Raises ``ValueError`` for non-SIM or unknown GSMTAP packets.
        """
        try:
            packet, addr = self._sock.recvfrom(65536)
        except (socket.timeout, OSError):
            return None, None

        if len(packet) < _GSMTAP_HDR_SIZE:
            raise ValueError(f'GSMTAP packet too short: {len(packet)} bytes')

        (version, hdr_len, pkt_type, _timeslot, _arfcn, _noise, _signal,
         _frame, sub_type, _antenna, sub_slot, _res) = \
            struct.unpack(_GSMTAP_HDR_FMT, packet[:_GSMTAP_HDR_SIZE])

        if pkt_type != GSMTAP_TYPE_SIM:
            raise ValueError(f'Not a GSMTAP SIM packet (type={pkt_type})')

        data = packet[_GSMTAP_HDR_SIZE:]
        return sub_type, data

    def close(self):
        self._sock.close()
