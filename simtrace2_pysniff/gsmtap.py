"""GSMTAP UDP sender for Wireshark integration.

GSMTAP header format (big-endian, 16 bytes). Based on libosmocore's gsmtap.h.
"""

import struct
import socket

GSMTAP_VERSION = 0x02
GSMTAP_HDR_LEN = 4  # in 32-bit words (16 bytes)
GSMTAP_TYPE_SIM = 0x07

GSMTAP_SIM_ATR = 0x01
GSMTAP_SIM_APDU = 0x02

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
